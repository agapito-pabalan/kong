package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Kong/go-pdk"
)

const REQUEST_JWT_TYPE string = "permissionsJwt"
const REQUEST_JWT_HEADER string = "jwt"
const REQUEST_AUTHORIZATION_HEADER string = "authorization"
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

type Config struct {
	BellatrixEndpoint string
}

func New() interface{} {
	return &Config{}
}

func (conf Config) Access(kong *pdk.PDK) {
	auth0JWT, err := getAuth0Token(kong)
	handleError(kong, err, 401)

	bellatrixJWT, err := conf.exchangeJWT(auth0JWT)
	handleError(kong, err, 401)

	err = kong.ServiceRequest.SetHeader(REQUEST_JWT_HEADER, bellatrixJWT)
	handleError(kong, err, 500)

	err = kong.ServiceRequest.SetHeader(REQUEST_AUTHORIZATION_HEADER, bellatrixJWT)
	handleError(kong, err, 500)

	err = kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, "true")
	handleError(kong, err, 500)

	kong.Log.Info(fmt.Sprintf("Success! Called Bellatrix API and swapped [%s] for [%s]", auth0JWT, bellatrixJWT))
}

func getAuth0Token(kong *pdk.PDK) (string, error) {
	auth0JWT, jwtErr := kong.Request.GetHeader(REQUEST_JWT_HEADER)
	if jwtErr == nil {
		return auth0JWT, nil
	}

	auth0JWT, authErr := kong.Request.GetHeader(REQUEST_AUTHORIZATION_HEADER)
	if authErr == nil {
		return auth0JWT, nil
	}

	return "", errors.New("Unable to find access token in headers")
}

func handleError(kong *pdk.PDK, err error, statusCode int) {
	if err != nil {
		kong.Log.Err(err)
		kong.Response.ExitStatus(statusCode)
	}
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
		return "", errors.New(fmt.Sprintf("Unexpected status code from Bellatrix: %d", response.StatusCode))
	}

	var responseEnvelope ResponseEnvelope

	err = json.NewDecoder(response.Body).Decode(&responseEnvelope)

	if err != nil {
		return "", err
	}

	return responseEnvelope.Data.Attributes.PermissionsJwt, nil
}
