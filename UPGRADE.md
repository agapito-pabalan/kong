# Kong Gateway Upgrade: 3.7.1 → 3.9.1

## Current State

| Component | Current |
|---|---|
| Base image | `kong:3.7.1` |
| Go PDK | `v0.11.0` |
| DB mode | DB-less (`KONG_DATABASE=off`) |
| Declarative config | `_format_version: "1.1"` |
| Plugins | `correlation-id`, `opentelemetry`, `cors`, `request-size-limiting`, `auth` (custom Go) |
| Entrypoint | `stord-entrypoint.sh` → `envsubst` → `/docker-entrypoint.sh kong docker-start` |

## Upgrade Path: 3.7.1 → 3.9.1

The image can be bumped directly to `kong:3.9.1`. No intermediate stops are required for DB-less mode (no migrations to run). The notes below still call out important changes introduced in 3.8.x and 3.9.x that must be reviewed before the direct upgrade.

---

## Breaking / High-Impact Changes

### 1. OpenTelemetry `endpoint` field deprecated (3.8.0)

The `endpoint` config field was deprecated in 3.8.0 in favor of `traces_endpoint`. As of 3.9.1, Kong **rejects** the config if only `endpoint` is set — validation now requires at least one of `traces_endpoint` or `logs_endpoint` to be non-empty. This is a **blocking change**.

**Action required** — in `kong.conf.d/kong.yml`, change:

```yaml
# Before
- name: opentelemetry
  config:
    endpoint: $OTEL_COLLECTOR_ENDPOINT

# After
- name: opentelemetry
  config:
    traces_endpoint: $OTEL_COLLECTOR_ENDPOINT
```

### 2. correlation-id plugin priority changed: 1 → 100001 (3.9.0)

The `correlation-id` plugin now runs **very early** in the plugin chain instead of last. This means the `x-request-id` header is set before the custom `auth` plugin executes.

**Risk**: Low. The auth plugin (`plugins/auth/auth.go`) does not read or depend on `x-request-id`. The change is actually beneficial — correlation IDs will be present in auth plugin logs and downstream error responses.

**Action**: Validate in nonprod that request tracing and auth behavior are unchanged.

### 3. Docker base OS changed (3.9.0)

Kong 3.9.x images moved from **Debian Bullseye** to **Debian Bookworm** (or Ubuntu Noble depending on tag variant).

**Impact on Dockerfile**:
- `apt-get install gettext` — still available in Bookworm, no change needed.
- The Go builder stage uses `golang:1.24.1-bullseye`. The compiled Go binary is statically-ish linked and should run fine on Bookworm. Verify with a test build.
- If pinning to a specific OS variant, use `kong:3.9.1-debian` or check available tags.

### 4. Internal Unix sockets moved to subdirectory (3.8.0)

Kong moved internal sockets to `$PREFIX/sockets/`. The upstream Docker entrypoint handles cleanup automatically. Our custom `stord-entrypoint.sh` delegates to the upstream entrypoint, so no changes needed.

**Action**: If any Kubernetes probes or sidecar configs reference Kong socket paths directly, update them.

### 5. `Via` response header added (3.8.0)

Kong now appends a `Via` header to proxied responses per RFC 7230/9110 (e.g., `Via: 1.1 kong/3.9.1`).

**Action**: Check if any downstream consumers, CDNs, or load balancers parse or reject unexpected response headers. Low risk but worth noting for debugging.

---

## Plugin-Specific Changes

### opentelemetry

| Version | Change | Impact |
|---|---|---|
| 3.8.0 | `endpoint` → `traces_endpoint` (deprecated) | Must rename (see above) |
| 3.8.0 | `batch_span_count` → `queue.max_batch_size` (deprecated) | Not used by us |
| 3.8.0 | `batch_flush_delay` → `queue.max_coalescing_delay` (deprecated) | Not used by us |
| 3.8.0 | `header_type` → `propagation` (deprecated) | We already use `propagation` block |
| 3.8.0 | Sampling decision accuracy improved | May change which requests are sampled if `sampling_rate` is set |
| 3.8.0 | Queue `concurrency_limit` param added (default 1) | No action unless tuning needed |
| 3.9.0 | Array/Map span attributes supported | No action needed |

Our `propagation` config (`extract: [w3c, datadog, gcp, b3, jaeger, aws, ot]`, `inject: [w3c]`) and `resource_attributes` remain fully supported.

### correlation-id

| Version | Change | Impact |
|---|---|---|
| 3.8.0 | Null generator edge case fixed | Positive — fixes potential edge case |
| 3.9.0 | Priority changed 1 → 100001 | See breaking change #2 above |

### cors

| Version | Change | Impact |
|---|---|---|
| 3.8.0 | Multi-origin wildcard handling fixed | Low risk — we use regex origins, not wildcards |

### request-size-limiting

| Version | Change | Impact |
|---|---|---|
| 3.8.0 | Body check with file buffering fixed | Validate 128MB payload limit still behaves correctly |

---

## Go Plugin Server Compatibility

| Item | Status |
|---|---|
| Plugin server protocol | No changes between 3.7 and 3.9 |
| `KONG_PLUGINSERVER_*` env vars | Still supported |
| `go-pdk v0.11.0` | Compatible with Kong 3.9.x |
| Optional: `go-pdk v0.11.2` | Minor fixes (mock fix for `service.request.set_raw_body`, dep bumps) |

**Long-term note**: The `go-pdk` project is marked as "no longer actively maintained" despite continued patch releases. No immediate action needed, but worth tracking for future plugin strategy decisions.

---

## Declarative Config

- `_format_version: "1.1"` remains valid through 3.9.x. No format version bump required.
- All route regex patterns in `kong.yml` use standard PCRE2-compatible syntax and should work without modification (PCRE2 engine was introduced in 3.7.0, already in our current image).
- Run `kong config parse` against the declarative config after upgrade to validate.

---

## Nginx / Buffer Configuration

All `KONG_NGINX_*` env vars in the Dockerfile remain valid:

- `KONG_NGINX_HTTP_CLIENT_MAX_BODY_SIZE="0"`
- `KONG_NGINX_HTTP_PROXY_BUFFERS="16 32M"`
- `KONG_NGINX_HTTP_PROXY_BUFFER_SIZE="32M"`
- `KONG_NGINX_PROXY_CLIENT_BODY_BUFFER_SIZE="32M"`
- `KONG_NGINX_PROXY_CLIENT_HEADER_BUFFER_SIZE="64k"`
- `KONG_NGINX_PROXY_LARGE_CLIENT_HEADER_BUFFERS="8 64k"`
- `KONG_NGINX_WORKER_PROCESSES="2"`

No breaking changes to the nginx directive passthrough mechanism.

---

## Security Patches Included

- OpenSSL updated to 3.2.3 (TLSv1.3 session memory fix, CVE patches)
- libexpat bumped to 2.6.4 (XML parser crash fix)

---

## Docker Build Test Results (kong:3.9.1)

Tested on 2026-05-04 with `kong:3.9.1` (Ubuntu 24.04 Noble).

| Check | Result |
|---|---|
| Base image OS | Ubuntu 24.04.4 LTS (Noble) — changed from Debian Bullseye |
| `apt-get install gettext` | Passes — package available in Noble repos |
| Go auth plugin binary | Loads correctly (`ProtoBuf:1` protocol) |
| Plugin server discovery | `loaded #1 external plugins info` — working |
| OpenTelemetry `endpoint` field | **Rejected** — must use `traces_endpoint` |
| `resource_attributes` validation | Now requires `length >= 1` when evaluated — not an issue at runtime with `envsubst` |
| Service URL parsing | Expected failures without env vars — `envsubst` handles at runtime |

**Docker build warnings** (informational, non-blocking):
- `SecretsUsedInArgOrEnv` for `KONG_PLUGINSERVER_AUTH_QUERY_CMD` and `KONG_PLUGINSERVER_AUTH_START_CMD` — false positive, these contain command paths not secrets.

---

## No Action Required

- `KONG_DATABASE=off` — no changes to DB-less mode
- `KONG_PLUGINS` list format — unchanged
- `KONG_CLUSTER_LISTEN=off` — unchanged
- `KONG_PORT_MAPS`, `KONG_PROXY_LISTEN`, `KONG_STATUS_LISTEN`, `KONG_ADMIN_LISTEN` — unchanged
- Custom entrypoint pattern (`envsubst` + upstream entrypoint) — still works
- `stord-entrypoint.sh` — no changes needed

---

## Upgrade Checklist

- [x] Bump `Dockerfile` base image: `kong:3.7.1` → `kong:3.9.1`
- [x] Rename `endpoint` → `traces_endpoint` in `kong.conf.d/kong.yml` OpenTelemetry config
- [ ] (Optional) Bump `go-pdk` from `v0.11.0` → `v0.11.2` in `plugins/auth/go.mod`
- [x] Build Docker image locally — verify `apt-get install gettext` works on new base OS
- [x] Run `kong config parse` against the interpolated declarative config
- [ ] Deploy to nonprod and validate:
  - [ ] Auth plugin processes requests correctly (correlation-id now runs first)
  - [ ] OpenTelemetry traces are received by the collector
  - [ ] CORS headers are returned correctly for `*.stord.com` origins
  - [ ] Large payload uploads (up to 128MB) succeed
  - [ ] `x-request-id` correlation header is present on responses
  - [ ] `/status` and `/_health` endpoints respond correctly
  - [ ] Check for `Via` header in responses — confirm no downstream issues
- [ ] Monitor logs for deprecation warnings post-deploy
- [ ] Cut release and promote to prod
