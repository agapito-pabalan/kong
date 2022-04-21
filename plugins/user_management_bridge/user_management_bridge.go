package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/go-redis/redis/v8"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

const REQUEST_JWT_TYPE string = "permissionsJwt"
const REQUEST_AUTHORIZATION_HEADER string = "authorization"
const BEARER_PREFIX string = "Bearer "
const REQUIRES_AUTH_HEADER string = "requires-auth"
const PROCESSING_PERIOD int = 1

type UserManagementResponseAttributes struct {
	PermissionsJwt string `json:"permissionsJwt"`
}

type UserManagementResponse struct {
	Attributes UserManagementResponseAttributes `json:"attributes"`
	Type       string                           `json:"type"`
}

type ResponseEnvelope struct {
	Data UserManagementResponse `json:"data"`
}

type Response struct {
	Message string `json:"message"`
}

type UserManagementRequestAttributes struct {
	Auth0UserID string `json:"auth0UserId"`
}

type UserManagementRequest struct {
	Attributes UserManagementRequestAttributes `json:"attributes"`
	Type       string                          `json:"type"`
}

type RequestEnvelope struct {
	Data UserManagementRequest `json:"data"`
}

type Config struct {
	UserManagementEndpoint string `json:"user_management_endpoint"`
	Auth0Url               string `json:"auth0_url"`
	CacheUrl               string `json:"cache_url"`
	JwksRefreshInterval    int    `json:"jwks_refresh_interval"`
	AutoRefresh            *jwk.AutoRefresh
	CacheClient            *redis.Client
	JwkCtx                 context.Context
	CacheCtx               context.Context
}

func New() interface{} {
	conf := Config{}
	conf.JwkCtx = context.Background()
	conf.CacheCtx = context.Background()
	conf.AutoRefresh = jwk.NewAutoRefresh(conf.JwkCtx)
	conf.CacheClient = nil
	return &conf
}

func (conf Config) Access(kong *pdk.PDK) {
	kong.Log.Debug(fmt.Sprintf("begin access"))

	path, _ := kong.Request.GetPath()

	match, _ := regexp.MatchString("/.well-known/acme-challenge", path)
	if match {
		return
	}

	match, _ = regexp.MatchString("/_health", path)
	if match {
		return
	}

	match, _ = regexp.MatchString("/webhook", path)
	if match {
		return
	}

	match, _ = regexp.MatchString("/finops", path)
	if match {
		return
	}

	auth0Token, err := getAuth0Token(kong)
	if err != nil {
		kong.Log.Warn("warning: ", err.Error())
		kong.Response.Exit(401, "Unauthorized", nil)
		return
	}

	conf.AutoRefresh.Configure(conf.Auth0Url, jwk.WithMinRefreshInterval(time.Duration(conf.JwksRefreshInterval)*time.Minute))

	keyset, err := conf.AutoRefresh.Fetch(conf.JwkCtx, conf.Auth0Url)
	if err != nil {
		kong.Log.Err("failed to fetch Auth0 JWKS keys: ", err)
		kong.Response.Exit(500, err.Error(), nil)
		return
	}

	parsedAuth0Token, err := jwt.Parse(auth0Token, jwt.WithKeySet(keyset), jwt.WithValidate(true), jwt.WithAcceptableSkew(2*time.Minute))
	if err != nil {
		kong.Log.Warn("warning: invalid Auth0 token - ", err.Error())
		kong.Response.Exit(401, "Unauthorized", nil)
		return
	}

	permissionsToken, err := conf.memoPermissionsToken(parsedAuth0Token, kong)
	if err != nil {
		kong.Log.Warn("warning: ", err.Error(), " unable to exchange Auth0 token for permissions token")
		kong.Response.Exit(401, "Unauthorized", nil)
		return
	}

	var tokenHeaderValue strings.Builder
	tokenHeaderValue.WriteString(BEARER_PREFIX)
	tokenHeaderValue.WriteString(permissionsToken)
	tokenHeaderValueStr := tokenHeaderValue.String()

	err = kong.ServiceRequest.SetHeader(REQUEST_AUTHORIZATION_HEADER, tokenHeaderValueStr)
	if err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to insert user_management token in authorization header")
		kong.Response.Exit(500, err.Error(), nil)
		return
	}

	err = kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, "true")
	if err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to insert \"requires-auth\" header")
		kong.Response.Exit(500, err.Error(), nil)
		return
	}

	kong.Log.Debug("Success! Called UserManagement API and swapped [", auth0Token, "] for [", permissionsToken, "]")
	return
}

func (conf Config) RedisClient() *redis.Client {
	if conf.CacheClient == nil {
		opts, _ := redis.ParseURL(conf.CacheUrl)
		conf.CacheClient = redis.NewClient(opts)
	}
	return conf.CacheClient
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

func (conf Config) memoPermissionsToken(auth0Token jwt.Token, kong *pdk.PDK) (string, error) {
	permissionsToken := ""
	auth0UserID := auth0Token.Subject()
	cacheClient := conf.RedisClient()

	permissionsToken, err := cacheClient.Get(conf.CacheCtx, auth0UserID).Result()
	if err == nil {
		return permissionsToken, nil
	}

	permissionsToken, err = conf.exchangeAuth0ForPermissionsToken(auth0UserID)
	if err != nil {
		return "", err
	}

	processing_period := time.Duration(PROCESSING_PERIOD) * time.Minute
	cachedTokenTTL := auth0Token.Expiration().Sub(auth0Token.IssuedAt().Add(processing_period))
	err = cacheClient.SetEX(conf.CacheCtx, auth0UserID, permissionsToken, cachedTokenTTL).Err()
	if err != nil {
		kong.Log.Warn("warning: ", err.Error(), " unable to store internal token in cache")
	}

	return permissionsToken, nil
}

func (conf Config) exchangeAuth0ForPermissionsToken(auth0UserID string) (string, error) {
	requestEnvelope := RequestEnvelope{Data: UserManagementRequest{
		Attributes: UserManagementRequestAttributes{
			Auth0UserID: auth0UserID,
		},
		Type: REQUEST_JWT_TYPE,
	}}

	requestBody, err := json.Marshal(requestEnvelope)
	if err != nil {
		return "", err
	}

	response, err := http.Post(conf.UserManagementEndpoint, "application/vnd.api+json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("unexpected status code from UserManagement: %d", response.StatusCode)
	}

	var responseEnvelope ResponseEnvelope

	err = json.NewDecoder(response.Body).Decode(&responseEnvelope)

	if err != nil {
		return "", err
	}

	return responseEnvelope.Data.Attributes.PermissionsJwt, nil
}
