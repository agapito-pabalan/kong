package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kong/go-pdk/test"
	"github.com/go-redis/redismock/v9"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

func getGlobalTestConfig(handlerFunc http.HandlerFunc) (*Config, redismock.ClientMock, *httptest.Server) {
	redisClient, redisMock := redismock.NewClientMock()
	httpMock := httptest.NewServer(handlerFunc)

	config := &Config{
		Auth0Url:            "http://localhost:8000",
		CacheUrl:            "localhost:6379",
		JwksRefreshInterval: 1000,
		CloudSignatureKey:   "cloudSignatureKey",
		CloudEndpoint:       fmt.Sprintf("%s/v1/auth/token", httpMock.URL),
	}
	InitializeGlobals(
		WithCache(&JwksCacheMock{keySet: jwk.NewSet()}),
		WithCacheClient(redisClient),
	)

	return config, redisMock, httpMock
}

func TestGlobalAuthHappyPath(t *testing.T) {
	meResponse := `{"data":{"id":"user-123","email":"test@stord.com","name":"Test User","organizations":[{"id":"org-1"}]}}`
	rolesResponse := `{"data":[{"app":{"alias":"oms","name":"OMS","id":"app-1"},"organization":{"alias":"banana","id":"org-1","name":"Banana Org","description":"desc","apps":[]},"realm":{"name":"My Network","resource_path":"/networks/12345","full_resource_name":"networks","resource_id":"12345","description":"Its real","links":[]},"role":"admin"},{"app":{"alias":"cloud","name":"Cloud","id":"app-2"},"organization":{"alias":"stord","id":"org-2","name":"STORD","description":"Internal","apps":[]},"realm":null,"role":"viewer"}]}`

	config, redisMock, httpMock := getGlobalTestConfig(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/me":
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(meResponse))
		case "/v1/me/roles":
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			// Verify filter query params
			aliases := r.URL.Query()["filter[app_aliases][]"]
			assert.Equal(t, []string{"oms", "oms_admin"}, aliases)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(rolesResponse))
		default:
			t.Errorf("Unexpected request to %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer httpMock.Close()

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com/global/v1/search?q=test",
		Headers: map[string][]string{"authorization": {"Bearer test-token"}},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)

	// Verify x-cloud-identity header
	identityHeader := env.ServiceReq.Headers.Get(CLOUD_IDENTITY_HEADER)
	assert.NotEmpty(t, identityHeader)

	var identity map[string]interface{}
	err = json.Unmarshal([]byte(identityHeader), &identity)
	assert.NoError(t, err)
	assert.Equal(t, "user-123", identity["id"])
	assert.Equal(t, "test@stord.com", identity["email"])
	assert.Equal(t, "Test User", identity["name"])
	// organizations should be removed
	_, hasOrgs := identity["organizations"]
	assert.False(t, hasOrgs, "organizations field should be removed from identity")

	// Verify x-cloud-roles header
	rolesHeader := env.ServiceReq.Headers.Get(CLOUD_ROLES_HEADER)
	assert.NotEmpty(t, rolesHeader)

	var roles []map[string]interface{}
	err = json.Unmarshal([]byte(rolesHeader), &roles)
	assert.NoError(t, err)
	assert.Len(t, roles, 2)

	// First role - with realm
	assert.Equal(t, map[string]interface{}{"alias": "oms"}, roles[0]["app"])
	assert.Equal(t, map[string]interface{}{"alias": "banana", "id": "org-1", "name": "Banana Org"}, roles[0]["organization"])
	assert.Equal(t, map[string]interface{}{"name": "My Network", "resource_path": "/networks/12345"}, roles[0]["realm"])
	assert.Equal(t, "admin", roles[0]["role"])

	// Second role - null realm
	assert.Equal(t, map[string]interface{}{"alias": "cloud"}, roles[1]["app"])
	assert.Equal(t, map[string]interface{}{"alias": "stord", "id": "org-2", "name": "STORD"}, roles[1]["organization"])
	assert.Nil(t, roles[1]["realm"])
	assert.Equal(t, "viewer", roles[1]["role"])

	// Authorization header should be cleared
	assert.Empty(t, env.ServiceReq.Headers.Get("Authorization"))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGlobalAuthNonGlobalPathSkipsFlow(t *testing.T) {
	subject := "Subject1"
	signedJwt, keySet, err := generateJwkKeys(subject)
	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"token":"RESULT"}}`))
	}))
	defer httpMock.Close()

	cacheKey := "kong:cloud:oms_admin:tenant:stord:" + subject
	redisMock.ExpectGet(cacheKey).RedisNil()
	redisMock.ExpectSetEx(cacheKey, "RESULT", 60*1e9).SetVal("1")

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com/v1/items?q=search",
		Headers: map[string][]string{"authorization": {fmt.Sprintf("Bearer %s", signedJwt)}},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	// Should go through normal auth flow and set Bearer RESULT
	assert.Equal(t, "Bearer RESULT", env.ServiceReq.Headers.Get("Authorization"))
	// Should NOT have x-cloud-identity or x-cloud-roles
	assert.Empty(t, env.ServiceReq.Headers.Get(CLOUD_IDENTITY_HEADER))
	assert.Empty(t, env.ServiceReq.Headers.Get(CLOUD_ROLES_HEADER))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestSpoofedCloudHeadersAreStripped(t *testing.T) {
	subject := "Subject1"
	signedJwt, keySet, err := generateJwkKeys(subject)
	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"token":"RESULT"}}`))
	}))
	defer httpMock.Close()

	cacheKey := "kong:cloud:oms_admin:tenant:stord:" + subject
	redisMock.ExpectGet(cacheKey).RedisNil()
	redisMock.ExpectSetEx(cacheKey, "RESULT", 60*1e9).SetVal("1")

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items?q=search",
		Headers: map[string][]string{
			"authorization":    {fmt.Sprintf("Bearer %s", signedJwt)},
			CLOUD_IDENTITY_HEADER: {`{"id":"spoofed","email":"evil@attacker.com"}`},
			CLOUD_ROLES_HEADER:    {`[{"role":"admin"}]`},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)

	// Spoofed headers must be stripped
	assert.Empty(t, env.ServiceReq.Headers.Get(CLOUD_IDENTITY_HEADER))
	assert.Empty(t, env.ServiceReq.Headers.Get(CLOUD_ROLES_HEADER))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGlobalAuthCloudMeError(t *testing.T) {
	config, redisMock, httpMock := getGlobalTestConfig(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid token"}`))
	}))
	defer httpMock.Close()

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com/global/v1/search?q=test",
		Headers: map[string][]string{"authorization": {"Bearer bad-token"}},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 401, env.ClientRes.Status)

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestGlobalAuthNoToken(t *testing.T) {
	config, redisMock, httpMock := getGlobalTestConfig(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Should not make any cloud requests without a token")
	}))
	defer httpMock.Close()

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/global/v1/search?q=test",
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 401, env.ClientRes.Status)

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestFilterRoles(t *testing.T) {
	input := []map[string]interface{}{
		{
			"app": map[string]interface{}{
				"alias":   "oms",
				"name":    "OMS",
				"id":      "app-1",
				"api_host": "http://localhost",
			},
			"organization": map[string]interface{}{
				"alias":       "banana",
				"id":          "org-1",
				"name":        "Banana Org",
				"description": "desc",
				"apps":        []interface{}{},
			},
			"realm": map[string]interface{}{
				"name":               "My Network",
				"resource_path":      "/networks/12345",
				"full_resource_name": "networks",
				"resource_id":        "12345",
			},
			"role": "admin",
		},
		{
			"app": map[string]interface{}{
				"alias": "cloud",
				"name":  "Cloud",
			},
			"organization": map[string]interface{}{
				"alias": "stord",
				"id":    "org-2",
				"name":  "STORD",
			},
			"realm": nil,
			"role":  "viewer",
		},
	}

	result := filterRoles(input)
	assert.Len(t, result, 2)

	// First role: realm present
	assert.Equal(t, map[string]interface{}{"alias": "oms"}, result[0]["app"])
	assert.Equal(t, map[string]interface{}{"alias": "banana", "id": "org-1", "name": "Banana Org"}, result[0]["organization"])
	assert.Equal(t, map[string]interface{}{"name": "My Network", "resource_path": "/networks/12345"}, result[0]["realm"])
	assert.Equal(t, "admin", result[0]["role"])

	// Second role: null realm
	assert.Equal(t, map[string]interface{}{"alias": "cloud"}, result[1]["app"])
	assert.Equal(t, map[string]interface{}{"alias": "stord", "id": "org-2", "name": "STORD"}, result[1]["organization"])
	assert.Nil(t, result[1]["realm"])
	assert.Equal(t, "viewer", result[1]["role"])
}

func TestCloudBaseURL(t *testing.T) {
	config := &Config{CloudEndpoint: "https://api.cloud.stord.com/v1/auth/token"}
	assert.Equal(t, "https://api.cloud.stord.com", config.cloudBaseURL())

	config2 := &Config{CloudEndpoint: "http://localhost:4801/v1/auth/token"}
	assert.Equal(t, "http://localhost:4801", config2.cloudBaseURL())
}
