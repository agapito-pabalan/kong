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
	"github.com/go-redis/redismock/v8"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

// a mock struct for jwk.AutoRefresh
type JwksAutoRefreshMock struct {
	keySet jwk.Set
}

func (m *JwksAutoRefreshMock) Configure(url string, options ...jwk.AutoRefreshOption) {
}

func (m *JwksAutoRefreshMock) Fetch(ctx context.Context, url string) (jwk.Set, error) {
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
	k1, _ := jwk.New([]byte("abracadavra"))
	keySet.Add(k1)
	k2, _ := jwk.New([]byte("opensasame"))
	keySet.Add(k2)
	// Add the real thing
	pubkey, _ := jwk.PublicRawKeyOf(privKey)
	k3, _ := jwk.New(pubkey)
	k3.Set(jwk.KeyIDKey, kid)
	k3.Set(jwk.AlgorithmKey, jwa.RS256)
	keySet.Add(k3)

	signingKey, err := jwk.New(privKey)
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
	signedJwt, err := jwt.Sign(token, jwa.RS256, signingKey)

	return signedJwt, keySet, nil
}

func getTestConfig(keySet jwk.Set, handlerFunc http.HandlerFunc) (*Config, redismock.ClientMock, *httptest.Server) {
	redisClient, redisMock := redismock.NewClientMock()
	httpMock := httptest.NewServer(http.HandlerFunc(handlerFunc))

	config := &Config{
		UserManagementEndpoint: fmt.Sprintf("%s/userManagementEndpoint", httpMock.URL),
		Auth0Url:               "http://localhost:8000",
		CacheUrl:               "localhost:6379",
		JwksRefreshInterval:    1000,
		CloudSignatureKey:      "cloudSignatureKey",
	}
	InitializeGlobals(
		WithAutoRefresh(&JwksAutoRefreshMock{
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
		if r.URL.Path != "/userManagementEndpoint" {
			t.Errorf("Expected to request '/fixedvalue', got: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"type":"jwtPermissions","attributes":{"permissionsJwt":"RESULT"}}}`))
	}))
	defer httpMock.Close()

	redisMock.ExpectGet(subject).RedisNil()
	redisMock.ExpectSetEX(subject, "RESULT", 60*time.Second).SetVal("1")

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

	redisMock.ExpectGet(subject).SetVal("(ORION TOKEN)")

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
	signature, err := jws.Sign([]byte(rawSignature), jwa.HS256, []byte("cloudSignatureKey"))

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
	signature, err := jws.Sign([]byte(rawSignature), jwa.HS256, []byte("cloudSignatureKey"))

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
