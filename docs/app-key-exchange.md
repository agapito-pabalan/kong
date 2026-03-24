# Kong: App Key Token Exchange

## Summary

The Kong auth plugin (`plugins/auth/auth.go`) now supports a fourth authentication path: **app key exchange**. When a request arrives with a `stord_ak_*` Bearer token, Kong exchanges it with cloud-service for an Orion JWT — the same pattern used for Auth0 tokens.

## Why

Stord's internal services (AI assistant, automations engine) need to call OMS APIs without a user context. Cloud-service now supports `service_grants` — a declarative way for apps to authorize other apps. But these services route through Kong, and Kong didn't know how to handle app keys.

Previously Kong only handled:
1. `x-cloud-signature` — trusted bypass from cloud-service
2. Cloud JWTs (`sso_provider: "cloud"`) — delegation token exchange
3. Auth0 JWTs — user token exchange

App keys (`stord_ak_*`) fell through all three paths and resulted in failed JWT parsing.

## What Changed

### New in `auth.go`

Three additions:

**`isAppKey(token string) bool`** — Detects `stord_ak_` prefix on the Bearer token.

**`handleAppKeyToken(kong, appKey)`** — Main handler:
1. Reads `tenant-id` / `x-network-id` headers for org/network scoping
2. Checks Redis cache (`kong:appkey:{app}:{scope}:{keyPrefix}`)
3. On miss: calls `exchangeAppKeyForOrionToken`
4. Caches result for 5 minutes
5. Sets `authorization` and `requires-auth` headers downstream

**`exchangeAppKeyForOrionToken(appKey, app, org, networkId)`** — Calls cloud-service's `POST /v1/auth/token` with the app key as Bearer auth. Request body: `{type: "orion", app: <target>, organization/resource_path}`. Returns the Orion JWT from the response.

### Flow in `Access()`

```
getAuth0Token() extracts Bearer token
    │
    ├── isAppKey("stord_ak_...") → handleAppKeyToken()     ← NEW
    │
    ├── isCloudJWT() → handleDelegationToken()              (unchanged)
    │
    └── Auth0 flow → cacheFetchPermissionsToken()           (unchanged)
```

The app key check is inserted **before** `isCloudJWT`, since app keys are not JWTs and would fail JWT parsing.

## Security Model

- **Cloud-service is the sole identity authority.** Kong never validates app keys itself — it always exchanges through cloud-service's `/v1/auth/token` endpoint.
- **App key never reaches OMS.** Only the resulting Orion JWT is set on the downstream request.
- **Same trust model as Auth0 exchange.** Kong trusts cloud-service to authenticate the credential and return an appropriately scoped token.
- **Redis caching** prevents repeated round-trips. Cache key includes app + scope + key prefix (first 20 chars, not the full secret).

## Target App Resolution

The target app for the token exchange defaults to `oms_admin` since Kong only fronts OMS services. Callers can override this with the `x-cloud-app` header:

```
Authorization: Bearer stord_ak_ai_admin
x-cloud-app: parcel
tenant-id: some-org-id
```

This is useful when Kong fronts additional services in the future, or when an app key holder needs to target a specific app.

## Cache Key Format

```
kong:appkey:{app}:network:{networkId}:{keyPrefix}
kong:appkey:{app}:tenant:{org}:{keyPrefix}
```

TTL: 5 minutes (fixed). Note: the Auth0/delegation token caches use each token's actual expiration, not a fixed TTL.

## Configuration

No new Kong configuration needed. The app key exchange uses the existing `CloudEndpoint` and `CacheUrl` settings.

## Testing

- Existing Auth0 and delegation flows: **no changes** — verify with existing test suite
- App key flow: send `Authorization: Bearer stord_ak_...` with `tenant-id` header → should receive valid Orion JWT downstream
- Cache behavior: second request with same app key + scope should hit Redis cache
- Invalid app key: cloud-service returns 401 → Kong returns 401

## Deployment

This change is **backwards compatible**. App keys were previously rejected (fell through to Auth0 parsing, which failed). Now they're handled explicitly. No existing traffic is affected.

Deploy after cloud-service has the `service_grants` feature and the router change allowing apps on `/v1/auth/token`. If Kong is deployed before cloud-service, app key requests will get 401s from cloud-service (same as today) — no regression.
