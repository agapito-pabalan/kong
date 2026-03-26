package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
)

const REQUEST_JWT_TYPE string = "permissionsJwt"
const REQUEST_AUTHORIZATION_HEADER string = "authorization"
const BEARER_PREFIX string = "Bearer "
const REQUEST_TIMESTAMP_HEADER string = "request-timestamp"
const REQUIRES_AUTH_HEADER string = "requires-auth"
const CLOUD_SIGNATURE_HEADER string = "x-cloud-signature"
const CLOUD_IDENTITY_HEADER string = "x-cloud-identity"
const CLOUD_ROLES_HEADER string = "x-cloud-roles"
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

type JwksCache interface {
	Register(url string, options ...jwk.RegisterOption) error
	Get(ctx context.Context, url string) (jwk.Set, error)
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
	Cache       JwksCache
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

func WithCache(cache JwksCache) GlobalOption {
	return func(globals *Globals) {
		globals.Cache = cache
	}
}

func InitializeGlobals(opts ...GlobalOption) {
	globals.JwkCtx = context.Background()
	globals.CacheCtx = context.Background()

	for _, opt := range opts {
		opt(&globals)
	}

	if globals.Cache == nil {
		globals.Cache = jwk.NewCache(globals.JwkCtx)
	}
}

func New() interface{} {
	return &Config{}
}

func (conf *Config) Access(kong *pdk.PDK) {
	kong.Log.Debug("begin access")

	// Strip x-cloud-identity and x-cloud-roles from incoming requests to prevent spoofing.
	// These headers may only be set by Kong via the /global/ auth flow.
	if err := kong.ServiceRequest.ClearHeader(CLOUD_IDENTITY_HEADER); err != nil {
		kong.Log.Err("error: failed to clear header ", CLOUD_IDENTITY_HEADER, ": ", err)
		kong.Response.Exit(500, []byte("Internal Server Error"), nil)
		return
	}
	if err := kong.ServiceRequest.ClearHeader(CLOUD_ROLES_HEADER); err != nil {
		kong.Log.Err("error: failed to clear header ", CLOUD_ROLES_HEADER, ": ", err)
		kong.Response.Exit(500, []byte("Internal Server Error"), nil)
		return
	}

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
		verified, err := jws.Verify([]byte(cloudSignatureHeader), jws.WithKey(jwa.HS256, []byte(conf.CloudSignatureKey)))
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

	// Handle /global/ prefix with simplified auth flow
	if strings.HasPrefix(path, "/global/") {
		conf.handleGlobalAuth(kong)
		return
	}

	auth0Token, err := getAuth0Token(kong)
	if err != nil {
		kong.Log.Warn("warning: ", err.Error())
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}

	tokenStr := string(auth0Token)

	// App key path — exchange via cloud-service, same pattern as Auth0 exchange
	if isAppKey(tokenStr) {
		err = conf.handleAppKeyToken(kong, tokenStr)
		if err != nil {
			kong.Log.Warn("warning: app key auth error - ", err.Error())
			kong.Response.Exit(401, []byte("Unauthorized"), nil)
		}
		return
	}

	if conf.isCloudJWT(tokenStr) {
		err = conf.handleDelegationToken(kong, tokenStr)
		if err != nil {
			kong.Log.Warn("warning: delegation token error - ", err.Error())
			kong.Response.Exit(401, []byte("Unauthorized"), nil)
		}
		return
	}

	// Continue with existing Auth0 flow
	if err := globals.Cache.Register(conf.Auth0Url, jwk.WithMinRefreshInterval(time.Duration(conf.JwksRefreshInterval)*time.Minute)); err != nil {
		kong.Log.Err("failed to register Auth0 JWKS cache: ", err)
		kong.Response.Exit(500, []byte("Internal Server Error"), nil)
		return
	}

	keyset, err := globals.Cache.Get(globals.JwkCtx, conf.Auth0Url)
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

// isCloudJWT checks if the token is a Cloud JWT by examining the sso_provider claim
func (conf *Config) isCloudJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	var claimsMap map[string]interface{}
	if err := json.Unmarshal(claims, &claimsMap); err != nil {
		return false
	}

	// Check for Cloud SSO provider
	if provider, ok := claimsMap["sso_provider"].(string); ok {
		return provider == "cloud"
	}
	return false
}

func (conf *Config) fetchCloudPublicKeys() (jwk.Set, error) {
	cacheKey := "kong:cloud:jwks"
	cachedKeys, err := conf.RedisClient().Get(globals.CacheCtx, cacheKey).Result()
	if err == nil {
		keyset, err := jwk.Parse([]byte(cachedKeys))
		if err == nil {
			return keyset, nil
		}
	}

	jwksURL := conf.cloudBaseURL() + "/.well-known/jwks.json"

	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("JWKS fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	keyset, err := jwk.Parse(body)
	if err != nil {
		bodyPreview := string(body)
		if len(bodyPreview) > 200 {
			bodyPreview = bodyPreview[:200] + "..."
		}
		return nil, fmt.Errorf("failed to parse JWKS (body preview: %s): %w", bodyPreview, err)
	}

	// Cache for 1 hour
	if err := conf.RedisClient().SetEx(globals.CacheCtx, cacheKey, string(body), time.Hour).Err(); err != nil {
		log.Printf("warning: failed to cache JWKS in Redis: %v", err)
	}

	return keyset, nil
}

// validateCloudJWT validates a Cloud/Orion JWT using the fetched public keys
func (conf *Config) validateCloudJWT(token string) (jwt.Token, error) {
	keyset, err := conf.fetchCloudPublicKeys()
	if err != nil {
		return nil, err
	}

	parsedToken, err := jwt.Parse(
		[]byte(token),
		jwt.WithKeySet(keyset),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(2*time.Minute),
	)
	if err != nil {
		return nil, err
	}

	return parsedToken, nil
}

// handleDelegationToken handles Cloud/Orion delegation tokens
func (conf *Config) handleDelegationToken(kong *pdk.PDK, token string) error {
	// Validate token
	parsedToken, err := conf.validateCloudJWT(token)
	if err != nil {
		return err
	}

	// Exchange Cloud token for Orion JWT
	kong.Log.Debug("Exchanging Cloud token for Orion JWT")
	orionToken, err := conf.exchangeCloudForOrionToken(token, parsedToken, kong)
	if err != nil {
		kong.Log.Err("Failed to exchange Cloud token for Orion JWT: ", err.Error())
		return fmt.Errorf("token exchange failed: %w", err)
	}
	kong.Log.Debug("Successfully exchanged for Orion JWT")

	// Set headers for downstream services with the Orion token
	err = kong.ServiceRequest.SetHeader(REQUEST_AUTHORIZATION_HEADER, BEARER_PREFIX+orionToken)
	if err != nil {
		return err
	}

	err = kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, "true")
	if err != nil {
		return err
	}

	userID := parsedToken.Subject()
	sessionID := extractSessionID(parsedToken)
	cacheKey := fmt.Sprintf("kong:delegation:%s:%s", userID, sessionID)

	expiration := parsedToken.Expiration()
	ttl := time.Until(expiration)
	if err := conf.RedisClient().SetEx(globals.CacheCtx, cacheKey, orionToken, ttl).Err(); err != nil {
		kong.Log.Warn("warning: failed to cache delegation token in Redis: ", err.Error())
	}

	return nil
}

// exchangeCloudForOrionToken exchanges a Cloud JWT for an Orion JWT
// by calling the Cloud Service API endpoint
func (conf *Config) exchangeCloudForOrionToken(cloudToken string, parsedToken jwt.Token, kong *pdk.PDK) (string, error) {
	// Extract org_id from the Cloud token
	var orgID string
	if org, ok := parsedToken.Get("org_id"); ok {
		orgID, _ = org.(string)
	} else if org, ok := parsedToken.Get("org"); ok {
		orgID, _ = org.(string)
	}

	if orgID == "" {
		return "", fmt.Errorf("no org_id found in Cloud token")
	}

	cacheKey := fmt.Sprintf("kong:cloud:orion:%s", orgID)
	cacheClient := conf.RedisClient()

	cachedToken, err := cacheClient.Get(globals.CacheCtx, cacheKey).Result()
	if err == nil && cachedToken != "" {
		// TODO: Could validate the cached token is still valid
		return cachedToken, nil
	}

	requestEnvelope := CloudRequestEnvelope{Data: CloudServiceRequest{
		Type:         "orion",
		App:          "oms",
		Organization: orgID,
	}}

	requestBody, err := json.Marshal(requestEnvelope)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", conf.CloudEndpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cloudToken)
	req.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		body, _ := io.ReadAll(response.Body)
		return "", fmt.Errorf("unexpected status code from Cloud: %d, body: %s", response.StatusCode, string(body))
	}

	var tokenEnvelope CloudResponseEnvelope
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(body, &tokenEnvelope)
	if err != nil {
		return "", err
	}

	orionToken := tokenEnvelope.Data.Token
	if orionToken == "" {
		return "", fmt.Errorf("no token in Cloud service response")
	}

	// Cache the token for 5 minutes (shorter than the actual expiry for safety)
	ttl := 5 * time.Minute
	err = cacheClient.SetEx(globals.CacheCtx, cacheKey, orionToken, ttl).Err()
	if err != nil {
		kong.Log.Warn("warning: unable to cache Orion token: ", err.Error())
	}

	return orionToken, nil
}

// extractSessionID extracts the session ID from a delegation token
func extractSessionID(token jwt.Token) string {
	if delegationContext, ok := token.Get("delegation_context"); ok {
		if ctx, ok := delegationContext.(map[string]interface{}); ok {
			if sessionID, ok := ctx["session_id"].(string); ok {
				return sessionID
			}
		}
	}
	if delegation, ok := token.Get("delegation"); ok {
		if del, ok := delegation.(map[string]interface{}); ok {
			if sessionID, ok := del["session_id"].(string); ok {
				return sessionID
			}
		}
	}
	return "unknown"
}

// cloudBaseURL extracts the base URL from the configured CloudEndpoint.
// e.g. "https://api.cloud.stord.com/v1/auth/token" -> "https://api.cloud.stord.com"
func (conf *Config) cloudBaseURL() string {
	baseURL := conf.CloudEndpoint
	if idx := strings.Index(baseURL, "/v1/"); idx != -1 {
		baseURL = baseURL[:idx]
	} else if idx := strings.LastIndex(baseURL, "/"); idx != -1 && idx > 8 {
		baseURL = baseURL[:idx]
	}
	return baseURL
}

// handleGlobalAuth implements the simplified auth flow for /global/ prefix routes.
// It calls /v1/me and /v1/me/roles on the cloud service, sets x-cloud-identity and
// x-cloud-roles headers with the filtered response data, and clears the Authorization header.
func (conf *Config) handleGlobalAuth(kong *pdk.PDK) {
	token, err := getAuth0Token(kong)
	if err != nil {
		kong.Log.Warn("warning: ", err.Error())
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}

	rawToken := string(token)
	baseURL := conf.cloudBaseURL()

	// Fetch /v1/me
	meData, err := conf.fetchCloudMe(baseURL, rawToken)
	if err != nil {
		kong.Log.Warn("warning: failed to fetch /v1/me - ", err.Error())
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}

	// Fetch /v1/me/roles
	rolesData, err := conf.fetchCloudMeRoles(baseURL, rawToken)
	if err != nil {
		kong.Log.Warn("warning: failed to fetch /v1/me/roles - ", err.Error())
		kong.Response.Exit(401, []byte("Unauthorized"), nil)
		return
	}

	// Remove "organizations" from me data
	delete(meData, "organizations")

	identityJSON, err := json.Marshal(meData)
	if err != nil {
		kong.Log.Err("error: failed to marshal identity: ", err.Error())
		kong.Response.Exit(500, []byte("Internal Server Error"), nil)
		return
	}

	rolesJSON, err := json.Marshal(rolesData)
	if err != nil {
		kong.Log.Err("error: failed to marshal roles: ", err.Error())
		kong.Response.Exit(500, []byte("Internal Server Error"), nil)
		return
	}

	if err := kong.ServiceRequest.SetHeader(CLOUD_IDENTITY_HEADER, string(identityJSON)); err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to set x-cloud-identity header")
		kong.Response.Exit(500, []byte(err.Error()), nil)
		return
	}

	if err := kong.ServiceRequest.SetHeader(CLOUD_ROLES_HEADER, string(rolesJSON)); err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to set x-cloud-roles header")
		kong.Response.Exit(500, []byte(err.Error()), nil)
		return
	}

	if err := kong.ServiceRequest.ClearHeader(REQUEST_AUTHORIZATION_HEADER); err != nil {
		kong.Log.Err("error: ", err.Error(), " unable to clear authorization header")
		kong.Response.Exit(500, []byte("Internal Server Error"), nil)
		return
	}

	// requires-auth is intentionally not set for global routes
}

// fetchCloudMe calls GET /v1/me on the cloud service and returns response.data as a map.
func (conf *Config) fetchCloudMe(baseURL string, token string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", baseURL+"/v1/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cloud /v1/me returned status %d: %s", resp.StatusCode, string(body))
	}

	var envelope struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode /v1/me response: %w", err)
	}

	return envelope.Data, nil
}

// fetchCloudMeRoles calls GET /v1/me/roles on the cloud service and returns the
// filtered roles array containing only the fields needed by downstream services.
func (conf *Config) fetchCloudMeRoles(baseURL string, token string) ([]map[string]interface{}, error) {
	req, err := http.NewRequest("GET", baseURL+"/v1/me/roles", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	q := req.URL.Query()
	for _, alias := range []string{"oms", "oms_admin"} {
		q.Add("filter[app_aliases][]", alias)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cloud /v1/me/roles returned status %d: %s", resp.StatusCode, string(body))
	}

	var envelope struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode /v1/me/roles response: %w", err)
	}

	return filterRoles(envelope.Data), nil
}

// filterRoles reduces each role entry to only the fields needed by downstream services:
// app.alias, organization.{alias,id,name}, realm.{name,resource_path} (if non-null), and role.
func filterRoles(roles []map[string]interface{}) []map[string]interface{} {
	filtered := make([]map[string]interface{}, 0, len(roles))
	for _, role := range roles {
		entry := map[string]interface{}{}

		// app -> keep only alias
		if app, ok := role["app"].(map[string]interface{}); ok {
			entry["app"] = map[string]interface{}{
				"alias": app["alias"],
			}
		}

		// organization -> keep alias, id, name
		if org, ok := role["organization"].(map[string]interface{}); ok {
			entry["organization"] = map[string]interface{}{
				"alias": org["alias"],
				"id":    org["id"],
				"name":  org["name"],
			}
		}

		// realm -> keep name and resource_path if non-null
		if realm, ok := role["realm"]; ok && realm != nil {
			if realmMap, ok := realm.(map[string]interface{}); ok {
				entry["realm"] = map[string]interface{}{
					"name":          realmMap["name"],
					"resource_path": realmMap["resource_path"],
				}
			} else {
				entry["realm"] = nil
			}
		} else {
			entry["realm"] = nil
		}

		// role
		entry["role"] = role["role"]

		filtered = append(filtered, entry)
	}
	return filtered
}

// isAppKey checks if the token is a cloud-service app key (stord_ak_ prefix)
func isAppKey(token string) bool {
	return strings.HasPrefix(token, "stord_ak_")
}

// extractAppKeyHeader returns a safe cache identifier from an app key.
// Takes the first segment after stord_ak_ (split on _) so the full key
// is never stored in cache keys. Works for both production keys
// (stord_ak_{header}_{secret}) and local dev keys (stord_ak_ai_admin).
func extractAppKeyHeader(appKey string) string {
	prefix := "stord_ak_"
	if !strings.HasPrefix(appKey, prefix) || len(appKey) <= len(prefix) {
		return appKey
	}
	keyBody := appKey[len(prefix):]
	if idx := strings.Index(keyBody, "_"); idx > 0 {
		return keyBody[:idx]
	}
	return keyBody
}

// handleAppKeyToken exchanges an app key for an Orion JWT via cloud-service.
// This mirrors the Auth0 token exchange flow — Kong authenticates the app key
// through cloud-service (the sole identity authority), caches the resulting
// Orion token, and sets downstream headers. The app key never reaches OMS.
func (conf *Config) handleAppKeyToken(kong *pdk.PDK, appKey string) error {
	org, _ := kong.Request.GetHeader("tenant-id")
	networkId, _ := kong.Request.GetHeader("x-network-id")

	// App keys are service-to-service. Kong only fronts OMS services today,
	// so oms_admin is the correct default. When other services need app key
	// exchange through Kong, support an x-cloud-app header to override:
	//   x-cloud-app: parcel
	app := "oms_admin"
	if cloudApp, _ := kong.Request.GetHeader("x-cloud-app"); cloudApp != "" {
		app = cloudApp
	}

	// Build cache key scoped by app + org/network + key prefix
	cachePrefix := "kong:appkey:" + app + ":"
	if networkId != "" {
		cachePrefix += "network:" + networkId + ":"
	} else if org != "" {
		cachePrefix += "tenant:" + org + ":"
	}
	// App keys follow the format stord_ak_{publicHeader}_{secret}.
	// Use the public header as the cache identifier — never the full key.
	keyIdentifier := extractAppKeyHeader(appKey)
	cacheKey := cachePrefix + keyIdentifier

	// Check cache first
	cacheClient := conf.RedisClient()
	cachedToken, err := cacheClient.Get(globals.CacheCtx, cacheKey).Result()
	if err == nil && cachedToken != "" {
		kong.Log.Debug("app key token cache hit")
		err = kong.ServiceRequest.SetHeader(REQUEST_AUTHORIZATION_HEADER, BEARER_PREFIX+cachedToken)
		if err != nil {
			return err
		}
		return kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, "true")
	}

	// Exchange app key for Orion token via cloud-service
	kong.Log.Debug("exchanging app key for Orion token")
	orionToken, err := conf.exchangeAppKeyForOrionToken(appKey, app, org, networkId)
	if err != nil {
		return fmt.Errorf("app key exchange failed: %w", err)
	}

	// Cache for 5 minutes (shorter than token expiry for safety)
	ttl := 5 * time.Minute
	if cacheErr := cacheClient.SetEx(globals.CacheCtx, cacheKey, orionToken, ttl).Err(); cacheErr != nil {
		kong.Log.Warn("warning: unable to cache app key token: ", cacheErr.Error())
	}

	err = kong.ServiceRequest.SetHeader(REQUEST_AUTHORIZATION_HEADER, BEARER_PREFIX+orionToken)
	if err != nil {
		return err
	}
	return kong.ServiceRequest.SetHeader(REQUIRES_AUTH_HEADER, "true")
}

// exchangeAppKeyForOrionToken calls cloud-service's /v1/auth/token endpoint
// with the app key to get an Orion JWT. Cloud-service authenticates the app key,
// checks service_grants on the target app, and returns a scoped Orion token.
func (conf *Config) exchangeAppKeyForOrionToken(appKey string, app string, org string, networkId string) (string, error) {
	requestEnvelope := CloudRequestEnvelope{Data: CloudServiceRequest{
		Type: "orion",
		App:  app,
	}}

	// oms_admin has no realms (networks are realms of the "oms" app).
	// Always use organization for oms_admin, defaulting to "stord" — same
	// as cacheFetchPermissionsToken does for internal @stord.com users.
	if app == "oms_admin" {
		if org != "" {
			requestEnvelope.Data.Organization = org
		} else {
			requestEnvelope.Data.Organization = "stord"
		}
	} else if networkId != "" {
		requestEnvelope.Data.ResourcePath = "/networks/" + networkId
	} else if org != "" {
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
	req.Header.Set("Authorization", BEARER_PREFIX+appKey)
	req.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		body, _ := io.ReadAll(response.Body)
		return "", fmt.Errorf("cloud-service returned %d: %s", response.StatusCode, string(body))
	}

	var responseEnvelope CloudResponseEnvelope
	if err := json.NewDecoder(response.Body).Decode(&responseEnvelope); err != nil {
		return "", err
	}

	if responseEnvelope.Data.Token == "" {
		return "", fmt.Errorf("no token in cloud-service response")
	}

	return responseEnvelope.Data.Token, nil
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
	err = cacheClient.SetEx(globals.CacheCtx, cacheKey, permissionsToken, cachedTokenTTL).Err()
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
