package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/request"
)

const REQUEST_JWT_TYPE string = "permissionsJwt"
const REQUEST_JWT_HEADER string = "jwt"
const REQUEST_AUTHORIZATION_HEADER string = "authorization"
const BEARER_PREFIX string = "Bearer "
const REQUIRES_AUTH_HEADER string = "requires-auth"

type BellatrixResponseAttributes struct {
	PermissionsJwt string `json:"permissionsJwt"`
	RequiresAuth   bool   `json:"requiresAuth"`
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
	auth0JWT, err := getAuth0Token(&kong.Request)
	handleError(kong, err, 401)

	bellatrixJWT, requiresAuth, err := conf.exchangeJWT(auth0JWT)
	handleError(kong, err, 401)

	var tokenHeaderValue strings.Builder
	tokenHeaderValue.WriteString(BEARER_PREFIX)
	tokenHeaderValue.WriteString(bellatrixJWT)
	tokenHeaderValueStr := tokenHeaderValue.String()

	err = kong.ServiceRequest.SetHeader(REQUEST_JWT_HEADER, tokenHeaderValueStr)
	handleError(kong, err, 500)

	err = kong.ServiceRequest.SetHeader(REQUEST_AUTHORIZATION_HEADER, tokenHeaderValueStr)
	handleError(kong, err, 500)

	err = kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, strconv.FormatBool(requiresAuth))
	handleError(kong, err, 500)

	kong.Log.Info(fmt.Sprintf("Success! Called Bellatrix API and swapped [%s] for [%s]", auth0JWT, bellatrixJWT))
}

func getAuth0Token(request *request.Request) (string, error) {
	auth0JWT, jwtErr := request.GetHeader(REQUEST_JWT_HEADER)
	if jwtErr == nil {
		return extractToken(auth0JWT)
	}

	auth0JWT, authErr := request.GetHeader(REQUEST_AUTHORIZATION_HEADER)
	if authErr == nil {
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

func handleError(kong *pdk.PDK, err error, statusCode int) {
	if err != nil {
		kong.Log.Err(err)
		kong.Response.ExitStatus(statusCode)
	}
}

func (conf Config) exchangeJWT(auth0Jwt string) (string, bool, error) {

	requestEnvelope := RequestEnvelope{Data: BellatrixRequest{
		Attributes: BellatrixRequestAttributes{
			Auth0Jwt: auth0Jwt,
		},
		Type: REQUEST_JWT_TYPE,
	}}

	requestBody, err := json.Marshal(requestEnvelope)
	if err != nil {
		return "", "", err
	}

	response, err := http.Post(conf.BellatrixEndpoint, "application/vnd.api+json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", "", err
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", "", fmt.Errorf("Unexpected status code from Bellatrix: %d", response.StatusCode)
	}

	var responseEnvelope ResponseEnvelope

	err = json.NewDecoder(response.Body).Decode(&responseEnvelope)

	if err != nil {
		return "", "", err
	}

	return responseEnvelope.Data.Attributes.PermissionsJwt, responseEnvelope.Data.Attributes.RequiresAuth, nil
}
