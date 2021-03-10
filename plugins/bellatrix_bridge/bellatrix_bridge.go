package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

const REQUEST_JWT_TYPE string = "permissionsJwt"
const REQUEST_JWT_HEADER string = "jwt"
const REQUEST_AUTHORIZATION_HEADER string = "authorization"
const BEARER_PREFIX string = "Bearer "
const REQUIRES_AUTH_HEADER string = "requires-auth"

type BellatrixResponseAttributes struct {
	PermissionsJwt string `json:"permissionsJwt"`
}

type BellatrixResponse struct {
	Attributes BellatrixResponseAttributes `json:"attributes"`
	Type       string                      `json:"type"`
}

type ResponseEnvelope struct {
	Data BellatrixResponse `json:"data"`
}

type BellatrixRequestAttributes struct {
	Auth0Jwt string `json:"auth0Jwt"`
}

type BellatrixRequest struct {
	Attributes BellatrixRequestAttributes `json:"attributes"`
	Type       string                     `json:"type"`
}

type RequestEnvelope struct {
	Data BellatrixRequest `json:"data"`
}

type Response struct {
	Message string `json:"message"`
}

type Config struct {
	BellatrixEndpoint   string `json:"bellatrix_endpoint"`
	Auth0Url            string `json:"auth0_url"`
	JwksRefreshInterval int    `json:"jwks_refresh_interval"`
	AutoRefresh         *jwk.AutoRefresh
	Ctx                 context.Context
}

func New() interface{} {
	conf := Config{}
	conf.Ctx = context.Background()
	conf.AutoRefresh = jwk.NewAutoRefresh(conf.Ctx)
	return &conf
}

func (conf Config) Access(kong *pdk.PDK) {
	kong.Log.Debug(fmt.Sprintf("begin access"))
	auth0JWT, err := getAuth0Token(kong)
	if err != nil {
		kong.Log.Warn("warning: ", err.Error())
		kong.Response.Exit(401, "Unauthorized", nil)
		return
	}

	conf.AutoRefresh.Configure(conf.Auth0Url, jwk.WithMinRefreshInterval(time.Duration(conf.JwksRefreshInterval)*time.Minute))

	keyset, err := conf.AutoRefresh.Fetch(conf.Ctx, conf.Auth0Url)
	if err != nil {
		kong.Log.Err("failed to fetch Auth0 JWKS: ", err)
		kong.Response.Exit(500, err.Error(), nil)
		return
	}

	_, err = jwt.Parse(auth0JWT, jwt.WithKeySet(keyset), jwt.WithValidate(true))
	if err != nil {
		kong.Log.Warn("warning: invalid Auth0 JWT - ", err.Error())
		kong.Response.Exit(401, "Unauthorized", nil)
		return
	}

	bellatrixJWT, err := conf.exchangeJWT(string(auth0JWT))
	if err != nil {
		kong.Log.Warn("warning: ", err.Error(), " unable to exchange Auth0 JWT for Bellatrix JWT")
		kong.Response.Exit(401, "Unauthorized", nil)
		return
	}

	var tokenHeaderValue strings.Builder
	tokenHeaderValue.WriteString(BEARER_PREFIX)
	tokenHeaderValue.WriteString(bellatrixJWT)
	tokenHeaderValueStr := tokenHeaderValue.String()

	err = kong.ServiceRequest.SetHeader(REQUEST_JWT_HEADER, tokenHeaderValueStr)
	if err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to insert bellatrix token in jwt header")
		kong.Response.Exit(500, err.Error(), nil)
		return
	}

	err = kong.ServiceRequest.SetHeader(REQUEST_AUTHORIZATION_HEADER, tokenHeaderValueStr)
	if err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to insert bellatrix token in authorization header")
		kong.Response.Exit(500, err.Error(), nil)
		return
	}

	err = kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, requiresAuthBackdoor(kong))
	if err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to insert \"requires-auth\" header")
		kong.Response.Exit(500, err.Error(), nil)
		return
	}

	kong.Log.Debug("Success! Called Bellatrix API and swapped [", auth0JWT, "] for [", bellatrixJWT, "]")
	return
}

func requiresAuthBackdoor(kong *pdk.PDK) string {
	requiresAuthValue, err := kong.Request.GetHeader(REQUIRES_AUTH_HEADER)
	if err != nil {
		return "true"
	}

	if strings.Compare("false", requiresAuthValue) == 0 {
		return "false"
	}

	return "true"
}

func getAuth0Token(kong *pdk.PDK) ([]byte, error) {
	auth0JWT := ""
	auth0JWT, _ = kong.Request.GetHeader(REQUEST_JWT_HEADER)
	if strings.Compare("", auth0JWT) != 0 {
		return extractToken(&auth0JWT)
	}

	auth0JWT, _ = kong.Request.GetHeader(REQUEST_AUTHORIZATION_HEADER)
	if strings.Compare("", auth0JWT) != 0 {
		return extractToken(&auth0JWT)
	}

	return nil, errors.New("unable to find access token in headers")
}

func extractToken(headerValue *string) ([]byte, error) {
	headerValueArr := strings.Split(*headerValue, BEARER_PREFIX)

	if len(headerValueArr) != 2 {
		return nil, fmt.Errorf("invalid token format, expected \"%s\"", BEARER_PREFIX)
	}
	return []byte(headerValueArr[1]), nil
}

func (conf Config) exchangeJWT(auth0Jwt string) (string, error) {

	requestEnvelope := RequestEnvelope{Data: BellatrixRequest{
		Attributes: BellatrixRequestAttributes{
			Auth0Jwt: auth0Jwt,
		},
		Type: REQUEST_JWT_TYPE,
	}}

	requestBody, err := json.Marshal(requestEnvelope)
	if err != nil {
		return "", err
	}

	response, err := http.Post(conf.BellatrixEndpoint, "application/vnd.api+json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("unexpected status code from Bellatrix: %d", response.StatusCode)
	}

	var responseEnvelope ResponseEnvelope

	err = json.NewDecoder(response.Body).Decode(&responseEnvelope)

	if err != nil {
		return "", err
	}

	return responseEnvelope.Data.Attributes.PermissionsJwt, nil
}
