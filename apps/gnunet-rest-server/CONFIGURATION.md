# REST configuration

The [server](README.md) uses ordinary GNUnet configuration and standard PROGRAM
options. Keys in `[rest-rust]` select explicit Rust resource/provider profiles.

## HTTP and access

| `[rest]` key | Meaning or default |
| --- | --- |
| `HTTP_PORT` | 7776; range 1–65535 |
| `BIND_TO`, `BIND_TO6` | Numeric IPv4/IPv6 addresses; defaults 127.0.0.1 and ::1 |
| `UNIXPATH` | Optional native local endpoint |
| `USERNAME` | Configured Unix process identity or required Windows token identity |
| `BASIC_AUTH_ENABLED` | YES |
| `BASIC_AUTH_SECRET_FILE` | Required explicit secret path when authentication is enabled |
| `REST_ALLOW_ORIGIN` | Up to 64 complete comma-separated origins in 4096 bytes; absent allows no ordinary origin |
| `REST_ECHO_ORIGIN_WEBEXT` | Explicit extension-origin support |
| `REST_ALLOW_CREDENTIALS`, `REST_ALLOW_HEADERS` | CORS response fields |
| `UNIX_MATCH_UID`, `UNIX_MATCH_GID` | Native Unix peer checks; unavailable Unix credentials are not replaced with a synthetic Windows identity |

Origins match complete scheme, host and effective-port tuples. Invalid/empty
entries and credentialed `*` are rejected. Dynamic responses use `Vary: Origin`.
`[rest-rust] BASIC_AUTH_USERNAME` supplies an explicit Basic username.

## Resource bounds

| `[rest-rust]` key | Default; ceiling where separately imposed |
| --- | --- |
| `MAX_CLIENTS` | 16; 64 |
| `MAX_BODY_BYTES` | 65535 |
| `MAX_OUTPUT_BYTES` | 262144; 1048576 |
| `MAX_RECORD_TEXT_BYTES` | 262140 |
| `MAX_ITEMS` | 1024 |
| `JSON_NODES` | 4096; 8192 |
| `JSON_WORK` | 4000000; 16000000 |
| `MAX_HTTP_WIRE_BYTES` | 131072; 262144 |
| `IO_SLICE_BYTES` | 4096; 65535 |
| `REQUEST_LIFETIME` | 30 s |
| `OUTPUT_LIFETIME`, `SHUTDOWN_GRACE` | 5 s |

Time bounds must be finite, nonzero and representable by the native clock.
`CONFIG_OUTPUT` selects an explicit absolute private configuration output.
The shared `[identity]`, `[namestore]`, `[reclaim]` and `[gns]` CLIENT configuration
supplies service endpoints and Resolver selection.

## OpenID Connect

Build feature `oidc` and `[rest-rust] OIDC_ENABLED=YES` are both required.
`OIDC_ORIGIN` supplies the issuer; `[reclaim-rest-plugin] address` supplies the
login UI. `[reclaim-rest-plugin] oidc_json_web_algorithm` accepts `RS256` (default)
or `HS512`; HS512 requires `jwt_secret`. Optional `OIDC_CLIENT_HMAC_SECRET` selects
confidential clients; otherwise clients must use public PKCE.

`[rest-rust] OIDC_STATE_DIRECTORY` must be an explicit absolute new or qualified
private OIDC namespace. Startup restores the matched signer, issuer, login UI,
client-secret and artifact domain, refusing mismatched/corrupt state. A fresh
RS256 namespace creates its RSA2048 signer and commits initial state before
readiness. The foreground always selects the persistent provider.

| `[rest-rust]` key | Default; ceiling |
| --- | --- |
| `OIDC_SESSIONS` | 64; 1024 |
| `OIDC_GRANTS` | 16; 128 |
| `OIDC_ACCESS_TOKENS` | 32; 1024 |
| `OIDC_CACHE_BYTES` | 1 MiB; 8 MiB |
| `OIDC_SNAPSHOT_BYTES` | Cache plus bounded metadata; 64 MiB |
| `OIDC_CONSUME_STATUS_PROFILE` | `canonical`, or explicit `c-native-little` |

`[reclaim-rest-plugin] expiration_time` supplies the finite TTL, default 300 s
and maximum one day. Persisted grants and access artifacts retain original expiry
and one-use redemption. HTTP scopes, reservations and sessions are not restored.
An admitted persistence job survives canceled HTTP waits; shutdown observes the
original worker's results and join. Directory barriers remain platform capability
observations rather than invented durability.
