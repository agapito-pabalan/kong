package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	"github.com/go-redis/redis/v8"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

const REQUEST_JWT_TYPE string = "permissionsJwt"
const REQUEST_AUTHORIZATION_HEADER string = "authorization"
const BEARER_PREFIX string = "Bearer "
const REQUEST_TIMESTAMP_HEADER string = "request-timestamp"
const REQUIRES_AUTH_HEADER string = "requires-auth"
const CLOUD_SIGNATURE_HEADER string = "x-cloud-signature"
const PROCESSING_PERIOD int = 1

type CloudServiceRequest struct {
	Type         string `json:"type"`
	App          string `json:"app"`
	Organization string `json:"organization,omitempty"`
	ResourcePath string `json:"resource_path,omitempty"`
}

type CloudRequestEnvelope struct {
	Data CloudServiceRequest `json:"data"`
}

type CloudResponse struct {
	Type         string `json:"type"`
	App          string `json:"app"`
	Organization string `json:"organization"`
	Token        string `json:"token"`
}

type CloudResponseEnvelope struct {
	Data CloudResponse `json:"data"`
}

type JwksAutoRefresh interface {
	Configure(url string, options ...jwk.AutoRefreshOption)
	Fetch(ctx context.Context, url string) (jwk.Set, error)
}

type Config struct {
	CloudEndpoint       string `json:"cloud_endpoint"`
	CloudSignatureKey   string `json:"cloud_signature_key"`
	LdSdkKey            string `json:"ld_sdk_key"`
	Auth0Url            string `json:"auth0_url"`
	CacheUrl            string `json:"cache_url"`
	JwksRefreshInterval int    `json:"jwks_refresh_interval"`
}

type Globals struct {
	AutoRefresh JwksAutoRefresh
	CacheClient *redis.Client
	JwkCtx      context.Context
	CacheCtx    context.Context
}

var globals = Globals{}

type GlobalOption func(*Globals)

func WithCacheClient(cacheClient *redis.Client) GlobalOption {
	return func(globals *Globals) {
		globals.CacheClient = cacheClient
	}
}

func WithAutoRefresh(autoRefresh JwksAutoRefresh) GlobalOption {
	return func(globals *Globals) {
		globals.AutoRefresh = autoRefresh
	}
}

func InitializeGlobals(opts ...GlobalOption) {
	globals.JwkCtx = context.Background()
	globals.CacheCtx = context.Background()

	for _, opt := range opts {
		opt(&globals)
	}

	if globals.AutoRefresh == nil {
		globals.AutoRefresh = jwk.NewAutoRefresh(globals.JwkCtx)
	}
}

func New() interface{} {
	return &Config{}
}

func (conf *Config) Access(kong *pdk.PDK) {
	kong.Log.Debug("begin access")

	path, _ := kong.Request.GetPath()

	skipAuthPaths := []string{
		"/.well-known/acme-challenge",
		"/_health",
		"/webhook",
		"/connections/auth",
		"/docs/",
		"/public_portal/",
		"/networks/.+/items/.+/image",
		"/networks/.+/kits/.+/image",
		"/shopify_extensions/v2",
		"/v1/connections/shopify/by_nonce",
	}

	for _, pathRegex := range skipAuthPaths {
		match, _ := regexp.MatchString(pathRegex, path)

		if match {
			return
		}
	}

	cloudSignatureHeader, err := kong.Request.GetHeader(CLOUD_SIGNATURE_HEADER)
	if err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to read header")
		kong.Response.Exit(500, []byte(err.Error()), nil)
		return
	}

	// If we have a cloud signature header, verify it and set requires auth and early return.
	// The cloud service can be trusted to have already done all of the validation that happens
	// below this block
	if cloudSignatureHeader != "" {
		// first we validate the request-timestamp to be within the PROCESSING_PERIOD number of minutes
		timestamp, _ := kong.Request.GetHeader(REQUEST_TIMESTAMP_HEADER)
		requestTime, err := time.Parse(time.RFC1123, timestamp)
		if err != nil {
			kong.Log.Err("error: ", err.Error(), " invalid request-timestamp")
			kong.Response.Exit(400, []byte(err.Error()), nil)
			return
		}
		processing_period := time.Duration(PROCESSING_PERIOD) * time.Minute
		if time.Since(requestTime) > processing_period {
			kong.Log.Err("error: request-timestamp is out of sync")
			kong.Response.Exit(400, []byte("invalid request-timestamp"), nil)
			return
		}

		// then we verify the cloud signature
		verified, err := jws.Verify([]byte(cloudSignatureHeader), jwa.HS256, []byte(conf.CloudSignatureKey))
		if err != nil {
			kong.Log.Err("error: ", err.Error(), " failed to verify cloud signature")
			kong.Response.Exit(400, []byte(err.Error()), nil)
			return
		}

		method, _ := kong.Request.GetMethod()
		expected := []byte(fmt.Sprintf("%s.%s.%s", method, path, timestamp))

		if !bytes.Equal(expected, verified) {
			kong.Log.Err("error: payload does not match cloud signature")
			kong.Response.Exit(400, []byte("Invalid Cloud Signature"), nil)
			return
		}

		err = kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, "true")
		if err != nil {
			kong.Log.Err("error: ", err.Error(), " unable to insert \"requires-auth\" header")
			kong.Response.Exit(500, []byte(err.Error()), nil)
			return
		}

		// Best effort to strip the header out from the downstream request to prevent any security concerns
		err = kong.ServiceRequest.ClearHeader(CLOUD_SIGNATURE_HEADER)
		if err != nil {
			kong.Log.Err("error: ", err.Error(), " Failed to clear cloud signature header")
			return
		}

		return
	}

	auth0Token, err := getAuth0Token(kong)
	if err != nil {
		kong.Log.Warn("warning: ", err.Error())
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}

	globals.AutoRefresh.Configure(conf.Auth0Url, jwk.WithMinRefreshInterval(time.Duration(conf.JwksRefreshInterval)*time.Minute))

	keyset, err := globals.AutoRefresh.Fetch(globals.JwkCtx, conf.Auth0Url)
	if err != nil {
		kong.Log.Err("failed to fetch Auth0 JWKS keys: ", err)
		kong.Response.Exit(500, []byte(err.Error()), nil)
		return
	}

	parsedAuth0Token, err := jwt.Parse(auth0Token, jwt.WithKeySet(keyset), jwt.WithValidate(true), jwt.WithAcceptableSkew(2*time.Minute))
	if err != nil {
		kong.Log.Warn("warning: invalid Auth0 token - ", err.Error())
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}

	permissionsToken, err := conf.cacheFetchPermissionsToken(string(auth0Token), parsedAuth0Token, kong)
	if err != nil {
		kong.Log.Warn("warning: ", err.Error(), " unable to exchange Auth0 token for permissions token")
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}

	var tokenHeaderValue strings.Builder
	tokenHeaderValue.WriteString(BEARER_PREFIX)
	tokenHeaderValue.WriteString(permissionsToken)
	tokenHeaderValueStr := tokenHeaderValue.String()

	err = kong.ServiceRequest.SetHeader(REQUEST_AUTHORIZATION_HEADER, tokenHeaderValueStr)
	if err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to insert token in authorization header")
		kong.Response.Exit(500, []byte(err.Error()), nil)
		return
	}

	err = kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, "true")
	if err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to insert \"requires-auth\" header")
		kong.Response.Exit(500, []byte(err.Error()), nil)
		return
	}

	kong.Log.Debug("Success! Swapped [", auth0Token, "] for [", permissionsToken, "]")
}

func (conf *Config) RedisClient() *redis.Client {
	if globals.CacheClient == nil {
		opts, _ := redis.ParseURL(conf.CacheUrl)
		globals.CacheClient = redis.NewClient(opts)
	}
	return globals.CacheClient
}

func getAuth0Token(kong *pdk.PDK) ([]byte, error) {
	auth0Token, err := kong.Request.GetHeader(REQUEST_AUTHORIZATION_HEADER)
	if err != nil {
		return nil, err
	}

	headerValueArr := strings.Split(auth0Token, BEARER_PREFIX)

	if len(headerValueArr) != 2 {
		return nil, fmt.Errorf("invalid token format, expected \"%s\"", BEARER_PREFIX)
	}

	return []byte(headerValueArr[1]), nil
}

// cacheFetchPermissionsToken exchanges the Auth0 token for a permissions token
// by calling the cloud-service API. It will first attempt to retrieve the
// permissions token from the cache. If it is not found, it will call the
// cloud-service API and store the permissions token in the cache.
func (conf *Config) cacheFetchPermissionsToken(rawToken string, auth0Token jwt.Token, kong *pdk.PDK) (string, error) {
	permissionsToken := ""
	auth0UserID := auth0Token.Subject()
	cacheClient := conf.RedisClient()

	var err error
	var app string

	org, _ := kong.Request.GetHeader("tenant-id")
	networkId, _ := kong.Request.GetHeader("x-network-id")

	stordAdmin, _ := regexp.Match(".*@stord\\.com$", []byte(auth0UserID))
	integrations, _ := regexp.Match(".*@clients$", []byte(auth0UserID))

	if (org == "" && networkId == "") || (stordAdmin || integrations) {
		app = "oms_admin"
		org = "stord"
		networkId = ""
	} else {
		app = "oms"
	}

	cachePrefix := "kong:cloud:" + app + ":"
	if networkId != "" {
		cachePrefix += "network:" + networkId + ":"
	} else {
		cachePrefix += "tenant:" + org + ":"
	}

	cacheKey := cachePrefix + auth0UserID

	permissionsToken, err = cacheClient.Get(globals.CacheCtx, cacheKey).Result()

	if err == nil {
		return permissionsToken, nil
	}

	permissionsToken, err = conf.exchangeAuth0ForCloudToken(app, org, networkId, rawToken)

	if err != nil {
		return "", err
	}

	processing_period := time.Duration(PROCESSING_PERIOD) * time.Minute
	cachedTokenTTL := auth0Token.Expiration().Sub(auth0Token.IssuedAt().Add(processing_period))
	err = cacheClient.SetEX(globals.CacheCtx, cacheKey, permissionsToken, cachedTokenTTL).Err()
	if err != nil {
		kong.Log.Warn("warning: ", err.Error(), " unable to store internal token in cache")
	}

	return permissionsToken, nil
}

// exchangeAuth0ForCloudToken exchanges the Auth0 token for a permissions token
// by calling the Cloud Service API.
func (conf *Config) exchangeAuth0ForCloudToken(app string, org string, networkId string, rawToken string) (string, error) {
	requestEnvelope := CloudRequestEnvelope{Data: CloudServiceRequest{
		Type: "orion",
		App:  app,
	}}

	if networkId != "" {
		requestEnvelope.Data.ResourcePath = "/networks/" + networkId
	} else {
		requestEnvelope.Data.Organization = org
	}

	requestBody, err := json.Marshal(requestEnvelope)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", conf.CloudEndpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("unexpected status code from Cloud: %d", response.StatusCode)
	}

	var responseEnvelope CloudResponseEnvelope

	err = json.NewDecoder(response.Body).Decode(&responseEnvelope)

	if err != nil {
		return "", err
	}

	return responseEnvelope.Data.Token, nil
}

const Version = "1.0.0"
const Priority = 1

func main() {
	f, err := os.OpenFile("/tmp/auth.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	InitializeGlobals()
	err = server.StartServer(New, Version, Priority)
	if err != nil {
		log.Fatalf("error starting server: %v", err)
	}
	log.Println("plugin server started")
}
