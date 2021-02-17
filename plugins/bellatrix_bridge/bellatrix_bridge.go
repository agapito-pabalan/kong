package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Kong/go-pdk"
)

const REQUEST_JWT_TYPE string = "permissionsJwt"
const REQUEST_JWT_HEADER string = "jwt"
const REQUEST_AUTHORIZATION_HEADER string = "authorization"
const BEARER_PREFIX string = "Bearer "
const REQUIRES_AUTH_HEADER string = "requires-auth"
const TRUE_HEADER_VALUE string = "true"

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

type Config struct {
	BellatrixEndpoint string
}

func New() interface{} {
	return &Config{}
}

func (conf Config) Access(kong *pdk.PDK) {
	kong.Log.Debug(fmt.Sprintf("begin access"))
	auth0JWT, err := getAuth0Token(kong)
	if err != nil {
		kong.Log.Warn("warning: ", err.Error())
		kong.Response.Exit(401, "Unauthorized", nil)
		return
	}

	bellatrixJWT, err := conf.exchangeJWT(auth0JWT)
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

	err = kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, TRUE_HEADER_VALUE)
	if err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to insert \"requires-auth\" header")
		kong.Response.Exit(500, err.Error(), nil)
		return
	}

	kong.Log.Debug("Success! Called Bellatrix API and swapped [", auth0JWT, "] for [", bellatrixJWT, "]")
	return
}

func getAuth0Token(kong *pdk.PDK) (string, error) {
	auth0JWT, _ := kong.Request.GetHeader(REQUEST_JWT_HEADER)
	if strings.Compare("", auth0JWT) != 0 {
		return extractToken(auth0JWT)
	}

	auth0JWT, _ = kong.Request.GetHeader(REQUEST_AUTHORIZATION_HEADER)
	if strings.Compare("", auth0JWT) != 0 {
		return extractToken(auth0JWT)
	}

	return "", errors.New("unable to find access token in headers")
}

func extractToken(headerValue string) (string, error) {
	headerValueArr := strings.Split(headerValue, BEARER_PREFIX)

	if len(headerValueArr) != 2 {
		return "", fmt.Errorf("invalid token format, expected \"%s\"", BEARER_PREFIX)
	}
	return headerValueArr[1], nil
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
