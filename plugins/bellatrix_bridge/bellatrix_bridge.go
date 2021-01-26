package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/request"
	"github.com/rs/zerolog"
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
	Logger            zerolog.Logger
	BellatrixEndpoint string
}

func New() interface{} {
	logLevel := convertLogLevel(os.Getenv("PLUGIN_LOG_LEVEL"))
	zerolog.SetGlobalLevel(logLevel)
	return &Config{
		Logger: zerolog.New(os.Stderr).With().Timestamp().Logger(),
	}
}

func (conf Config) Access(kong *pdk.PDK) {
	auth0JWT, err := getAuth0Token(&kong.Request)
	if err != nil {
		kong.Response.Exit(401, "Unauthorized", nil)
		return
	}
	bellatrixJWT, requiresAuth, err := conf.exchangeJWT(auth0JWT)
	if err != nil {
		kong.Response.Exit(401, "Unauthorized", nil)
		return
	}

	var tokenHeaderValue strings.Builder
	tokenHeaderValue.WriteString(BEARER_PREFIX)
	tokenHeaderValue.WriteString(bellatrixJWT)
	tokenHeaderValueStr := tokenHeaderValue.String()

	err = kong.ServiceRequest.SetHeader(REQUEST_JWT_HEADER, tokenHeaderValueStr)
	if err != nil {
		kong.Response.Exit(500, err.Error(), nil)
		return
	}
	err = kong.ServiceRequest.SetHeader(REQUEST_AUTHORIZATION_HEADER, tokenHeaderValueStr)
	if err != nil {
		kong.Response.Exit(500, err.Error(), nil)
		return
	}
	err = kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, strconv.FormatBool(requiresAuth))
	if err != nil {
		kong.Response.Exit(500, err.Error(), nil)
		return
	}

	conf.Logger.Info().Msg(fmt.Sprintf("Success! Called Bellatrix API and swapped [%s] for [%s]", auth0JWT, bellatrixJWT))
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

func (conf Config) exchangeJWT(auth0Jwt string) (string, bool, error) {

	requestEnvelope := RequestEnvelope{Data: BellatrixRequest{
		Attributes: BellatrixRequestAttributes{
			Auth0Jwt: auth0Jwt,
		},
		Type: REQUEST_JWT_TYPE,
	}}

	requestBody, err := json.Marshal(requestEnvelope)
	if err != nil {
		return "", true, err
	}

	response, err := http.Post(conf.BellatrixEndpoint, "application/vnd.api+json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", true, err
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", true, fmt.Errorf("unexpected status code from Bellatrix: %d", response.StatusCode)
	}

	var responseEnvelope ResponseEnvelope

	err = json.NewDecoder(response.Body).Decode(&responseEnvelope)

	if err != nil {
		return "", true, err
	}

	return responseEnvelope.Data.Attributes.PermissionsJwt, responseEnvelope.Data.Attributes.RequiresAuth, nil
}

func convertLogLevel(level string) zerolog.Level {
	switch level {
	case "TRACE":
		return zerolog.TraceLevel
	case "DEBUG":
		return zerolog.DebugLevel
	case "INFO":
		return zerolog.InfoLevel
	case "WARN":
		return zerolog.WarnLevel
	case "ERROR":
		return zerolog.ErrorLevel
	case "FATAL":
		return zerolog.FatalLevel
	case "PANIC":
		return zerolog.PanicLevel
	default:
		return zerolog.WarnLevel
	}
}
