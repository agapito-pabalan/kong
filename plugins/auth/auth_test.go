package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Kong/go-pdk/test"
	"github.com/go-redis/redismock/v9"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
)

// a mock struct for jwk.Cache
type JwksCacheMock struct {
	keySet jwk.Set
}

func (m *JwksCacheMock) Register(url string, options ...jwk.RegisterOption) error {
	return nil
}

func (m *JwksCacheMock) Get(ctx context.Context, url string) (jwk.Set, error) {
	return m.keySet, nil
}

func generateJwkKeys(subject string) ([]byte, jwk.Set, error) {
	kid := "kid1"

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to create private key: %s", err)
		return nil, nil, err
	}

	keySet := jwk.NewSet()
	// Add some bogus keys
	k1, _ := jwk.FromRaw([]byte("abracadavra"))
	keySet.AddKey(k1)
	k2, _ := jwk.FromRaw([]byte("opensasame"))
	keySet.AddKey(k2)
	// Add the real thing
	pubkey := privKey.Public()
	k3, _ := jwk.FromRaw(pubkey)
	k3.Set(jwk.KeyIDKey, kid)
	k3.Set(jwk.AlgorithmKey, jwa.RS256)
	keySet.AddKey(k3)

	signingKey, err := jwk.FromRaw(privKey)
	if err != nil {
		fmt.Printf("failed to create JWK: %s\n", err)
		return nil, nil, err
	}
	signingKey.Set(jwk.KeyIDKey, kid)

	token := jwt.New()
	token.Set(jwt.SubjectKey, subject)
	now := time.Now()
	token.Set(jwt.IssuedAtKey, now.Unix())
	token.Set(jwt.ExpirationKey, now.Add(120*time.Second).Unix())

	// Sign the token and generate a payload
	signedJwt, _ := jwt.Sign(token, jwt.WithKey(jwa.RS256, signingKey))

	return signedJwt, keySet, nil
}

func getTestConfig(keySet jwk.Set, handlerFunc http.HandlerFunc) (*Config, redismock.ClientMock, *httptest.Server) {
	redisClient, redisMock := redismock.NewClientMock()
	httpMock := httptest.NewServer(http.HandlerFunc(handlerFunc))

	config := &Config{
		Auth0Url:            "http://localhost:8000",
		CacheUrl:            "localhost:6379",
		JwksRefreshInterval: 1000,
		CloudSignatureKey:   "cloudSignatureKey",
		CloudEndpoint:       fmt.Sprintf("%s/cloudEndpoint", httpMock.URL),
	}
	InitializeGlobals(
		WithCache(&JwksCacheMock{
			keySet: keySet,
		}),
		WithCacheClient(redisClient),
	)

	return config, redisMock, httpMock
}

func TestCacheMiss(t *testing.T) {
	subject := "Subject1"
	signedJwt, keySet, err := generateJwkKeys(subject)

	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cloudEndpoint" {
			t.Errorf("Expected to request '/cloudEndpoint', got: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"token":"RESULT"}}`))
	}))
	defer httpMock.Close()

	cacheKey := "kong:cloud:oms_admin:tenant:stord:" + subject
	redisMock.ExpectGet(cacheKey).RedisNil()
	redisMock.ExpectSetEx(cacheKey, "RESULT", 60*time.Second).SetVal("1")

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com/v1/items?q=search&x=9",
		Headers: map[string][]string{"authorization": {fmt.Sprintf("Bearer %s", signedJwt)}},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	assert.Equal(t, "true", env.ServiceReq.Headers.Get("requires-auth"))
	assert.Equal(t, "Bearer RESULT", env.ServiceReq.Headers.Get("Authorization"))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestCacheHit(t *testing.T) {
	subject := "Subject2"
	signedJwt, keySet, err := generateJwkKeys(subject)

	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// this should never reach out to UserManagementEndpoint
		assert.Equal(t, false, true)
	}))
	defer httpMock.Close()

	cacheKey := "kong:cloud:oms_admin:tenant:stord:" + subject
	redisMock.ExpectGet(cacheKey).SetVal("(ORION TOKEN)")

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://kong/v1/items?q=search&x=9",
		Headers: map[string][]string{"authorization": {fmt.Sprintf("Bearer %s", signedJwt)}},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	assert.Equal(t, "true", env.ServiceReq.Headers.Get("requires-auth"))
	assert.Equal(t, "Bearer (ORION TOKEN)", env.ServiceReq.Headers.Get("Authorization"))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestCloudSignatureValid(t *testing.T) {
	subject := "Subject1"
	_, keySet, err := generateJwkKeys(subject)

	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer httpMock.Close()

	method := "GET"
	path := "/v1/items"
	timestamp := time.Now().Format(time.RFC1123)
	rawSignature := fmt.Sprintf("%s.%s.%s", method, path, timestamp)
	signature, err := jws.Sign([]byte(rawSignature), jws.WithKey(jwa.HS256, []byte("cloudSignatureKey")))

	assert.NoError(t, err)

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items?q=search&x=9",
		Headers: map[string][]string{
			"authorization":     {"Bearer STORDCLOUD"},
			"x-cloud-signature": {string(signature)},
			"request-timestamp": {time.Now().Format(time.RFC1123)},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	assert.Equal(t, "true", env.ServiceReq.Headers.Get("requires-auth"))
	assert.Equal(t, "Bearer STORDCLOUD", env.ServiceReq.Headers.Get("Authorization"))
	assert.Empty(t, env.ServiceReq.Headers.Get("x-cloud-signature"))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestCloudSignatureInvalidKey(t *testing.T) {
	subject := "Subject1"
	_, keySet, err := generateJwkKeys(subject)

	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer httpMock.Close()

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items?q=search&x=9",
		Headers: map[string][]string{
			"authorization":     {"Bearer STORDCLOUD"},
			"x-cloud-signature": {"not-valid"},
			"request-timestamp": {time.Now().Format(time.RFC1123)},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 400, env.ClientRes.Status)

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestCloudSignatureInvalidTimestamp(t *testing.T) {
	subject := "Subject1"
	_, keySet, err := generateJwkKeys(subject)

	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer httpMock.Close()

	method := "GET"
	path := "/v1/items"
	timestamp := (time.Now().Add(time.Duration(-5) * time.Minute)).Format(time.RFC1123)
	rawSignature := fmt.Sprintf("%s.%s.%s", method, path, timestamp)
	signature, _ := jws.Sign([]byte(rawSignature), jws.WithKey(jwa.HS256, []byte("cloudSignatureKey")))

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items?q=search&x=9",
		Headers: map[string][]string{
			"authorization":     {"Bearer STORDCLOUD"},
			"x-cloud-signature": {string(signature)},
			"request-timestamp": {timestamp},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 400, env.ClientRes.Status)

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestCloudEnabled(t *testing.T) {
	subject := "Subject1"
	signedJwt, keySet, err := generateJwkKeys(subject)

	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cloudEndpoint" {
			t.Errorf("Expected to request '/cloudEndpoint', got: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"token":"RESULT"}}`))
	}))
	defer httpMock.Close()

	cacheKey := "kong:cloud:oms_admin:tenant:stord:" + subject
	redisMock.ExpectGet(cacheKey).RedisNil()
	redisMock.ExpectSetEx(cacheKey, "RESULT", 60*time.Second).SetVal("1")

	env, err := test.New(t, test.Request{
		Method:  "GET",
		Url:     "http://example.com/v1/items?q=search&x=9",
		Headers: map[string][]string{"authorization": {fmt.Sprintf("Bearer %s", signedJwt)}},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	assert.Equal(t, "true", env.ServiceReq.Headers.Get("requires-auth"))
	assert.Equal(t, "Bearer RESULT", env.ServiceReq.Headers.Get("Authorization"))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// --- App Key Tests ---

func TestIsAppKey(t *testing.T) {
	assert.True(t, isAppKey("stord_ak_abc123_secret"))
	assert.True(t, isAppKey("stord_ak_"))
	assert.False(t, isAppKey("stord_ak"))
	assert.False(t, isAppKey("Bearer eyJhbGciOi..."))
	assert.False(t, isAppKey(""))
}

func TestExtractAppKeyHeader(t *testing.T) {
	// Production keys: stord_ak_{header}_{secret} — extracts first segment
	assert.Equal(t, "pubHdr123", extractAppKeyHeader("stord_ak_pubHdr123_secretpart"))
	assert.Equal(t, "hdr", extractAppKeyHeader("stord_ak_hdr_secret_with_underscores"))

	// Local/dev keys: first segment before _
	assert.Equal(t, "ai", extractAppKeyHeader("stord_ak_ai_admin"))

	// Single segment, no underscore after prefix
	assert.Equal(t, "local", extractAppKeyHeader("stord_ak_local"))

	// Edge cases
	assert.Equal(t, "stord_ak_", extractAppKeyHeader("stord_ak_"))
	assert.Equal(t, "stord_ak", extractAppKeyHeader("stord_ak"))
}

func TestAppKeyCacheMiss(t *testing.T) {
	_, keySet, err := generateJwkKeys("unused")
	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/cloudEndpoint", r.URL.Path)
		assert.Equal(t, "Bearer stord_ak_testhdr_secretvalue123", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"token":"ORION_TOKEN"}}`))
	}))
	defer httpMock.Close()

	appKey := "stord_ak_testhdr_secretvalue123"
	cacheKey := "kong:appkey:oms_admin:tenant:test-org:testhdr"
	redisMock.ExpectGet(cacheKey).RedisNil()
	redisMock.ExpectSetEx(cacheKey, "ORION_TOKEN", 5*time.Minute).SetVal("1")

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items",
		Headers: map[string][]string{
			"authorization": {fmt.Sprintf("Bearer %s", appKey)},
			"tenant-id":     {"test-org"},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	assert.Equal(t, "true", env.ServiceReq.Headers.Get("requires-auth"))
	assert.Equal(t, "Bearer ORION_TOKEN", env.ServiceReq.Headers.Get("Authorization"))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestAppKeyCacheHit(t *testing.T) {
	_, keySet, err := generateJwkKeys("unused")
	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not call cloud-service on cache hit")
	}))
	defer httpMock.Close()

	appKey := "stord_ak_testhdr_secretvalue123"
	cacheKey := "kong:appkey:oms_admin:tenant:test-org:testhdr"
	redisMock.ExpectGet(cacheKey).SetVal("CACHED_ORION_TOKEN")

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items",
		Headers: map[string][]string{
			"authorization": {fmt.Sprintf("Bearer %s", appKey)},
			"tenant-id":     {"test-org"},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	assert.Equal(t, "true", env.ServiceReq.Headers.Get("requires-auth"))
	assert.Equal(t, "Bearer CACHED_ORION_TOKEN", env.ServiceReq.Headers.Get("Authorization"))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestAppKeyWithNetworkId(t *testing.T) {
	_, keySet, err := generateJwkKeys("unused")
	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"token":"NETWORK_TOKEN"}}`))
	}))
	defer httpMock.Close()

	appKey := "stord_ak_nethdr_secretvalue456"
	cacheKey := "kong:appkey:oms_admin:network:net-123:nethdr"
	redisMock.ExpectGet(cacheKey).RedisNil()
	redisMock.ExpectSetEx(cacheKey, "NETWORK_TOKEN", 5*time.Minute).SetVal("1")

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items",
		Headers: map[string][]string{
			"authorization": {fmt.Sprintf("Bearer %s", appKey)},
			"tenant-id":     {"test-org"},
			"x-network-id":  {"net-123"},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	assert.Equal(t, "true", env.ServiceReq.Headers.Get("requires-auth"))
	assert.Equal(t, "Bearer NETWORK_TOKEN", env.ServiceReq.Headers.Get("Authorization"))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestAppKeyWithCustomCloudApp(t *testing.T) {
	_, keySet, err := generateJwkKeys("unused")
	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"token":"PARCEL_TOKEN"}}`))
	}))
	defer httpMock.Close()

	appKey := "stord_ak_parcelhdr_secretvalue789"
	cacheKey := "kong:appkey:parcel:tenant:test-org:parcelhdr"
	redisMock.ExpectGet(cacheKey).RedisNil()
	redisMock.ExpectSetEx(cacheKey, "PARCEL_TOKEN", 5*time.Minute).SetVal("1")

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items",
		Headers: map[string][]string{
			"authorization": {fmt.Sprintf("Bearer %s", appKey)},
			"tenant-id":     {"test-org"},
			"x-cloud-app":   {"parcel"},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	assert.Equal(t, "true", env.ServiceReq.Headers.Get("requires-auth"))
	assert.Equal(t, "Bearer PARCEL_TOKEN", env.ServiceReq.Headers.Get("Authorization"))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestAppKeyExchangeFailure(t *testing.T) {
	_, keySet, err := generateJwkKeys("unused")
	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"invalid app key"}`))
	}))
	defer httpMock.Close()

	appKey := "stord_ak_badhdr_invalidsecret"
	cacheKey := "kong:appkey:oms_admin:tenant:test-org:badhdr"
	redisMock.ExpectGet(cacheKey).RedisNil()

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items",
		Headers: map[string][]string{
			"authorization": {fmt.Sprintf("Bearer %s", appKey)},
			"tenant-id":     {"test-org"},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 401, env.ClientRes.Status)

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestAppKeyEmptyTokenResponse(t *testing.T) {
	_, keySet, err := generateJwkKeys("unused")
	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"token":""}}`))
	}))
	defer httpMock.Close()

	appKey := "stord_ak_emptyhdr_secretvalue000"
	cacheKey := "kong:appkey:oms_admin:tenant:test-org:emptyhdr"
	redisMock.ExpectGet(cacheKey).RedisNil()

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items",
		Headers: map[string][]string{
			"authorization": {fmt.Sprintf("Bearer %s", appKey)},
			"tenant-id":     {"test-org"},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 401, env.ClientRes.Status)

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestAppKeyLocalDevKey(t *testing.T) {
	_, keySet, err := generateJwkKeys("unused")
	assert.NoError(t, err)

	config, redisMock, httpMock := getTestConfig(keySet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"token":"SHORT_TOKEN"}}`))
	}))
	defer httpMock.Close()

	appKey := "stord_ak_ai_admin"
	cacheKey := "kong:appkey:oms_admin:tenant:test-org:ai"
	redisMock.ExpectGet(cacheKey).RedisNil()
	redisMock.ExpectSetEx(cacheKey, "SHORT_TOKEN", 5*time.Minute).SetVal("1")

	env, err := test.New(t, test.Request{
		Method: "GET",
		Url:    "http://example.com/v1/items",
		Headers: map[string][]string{
			"authorization": {fmt.Sprintf("Bearer %s", appKey)},
			"tenant-id":     {"test-org"},
		},
	})
	assert.NoError(t, err)

	env.DoHttps(config)
	assert.Equal(t, 200, env.ClientRes.Status)
	assert.Equal(t, "Bearer SHORT_TOKEN", env.ServiceReq.Headers.Get("Authorization"))

	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}
