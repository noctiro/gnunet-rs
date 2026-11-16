# HOSTLIST configuration

The [command](README.md) reads the ordinary `[hostlist]` options and explicit
Rust resource limits from `[hostlist-rust]`. Numeric capacities use GNUnet number
syntax; time options use GNUnet duration syntax. Time bounds must be finite,
nonzero and representable by the native monotonic clock.

## Ordinary options

| Key | Meaning |
| --- | --- |
| `SERVERS` | Whitespace-separated bootstrap URLs; required when bootstrapping |
| `HTTPPORT` | Publication port, 1–65535; required when providing |
| `BINDTOIPV4`, `BINDTOIPV6` | Numeric publication addresses; absent values select wildcard addresses |
| `EXTERNAL_DNS_NAME` | Advertised hostname or IP; absent selects the native local FQDN |
| `HOSTLISTFILE` | Base path whose `.rust-hostlist` sibling holds qualified learned metadata |
| `PROXY`, `PROXY_TYPE` | Explicit HTTP/SOCKS proxy selection |
| `PROXY_USERNAME`, `PROXY_PASSWORD` | Proxy credentials, excluded from diagnostics |
| `USERNAME` | Native process identity selection |

## Capacity profiles

| Keys in `[hostlist-rust]` | Bound |
| --- | --- |
| `MAX_URLS`, `MAX_LEARNED` | Configured and learned URL state |
| `MAX_HELLOS`, `HELLO_BYTES`, `MAX_PEERS` | Retained HELLO and peer state |
| `HTTP_CLIENTS`, `HTTP_CLIENTS_PER_IP` | Total and per-address inbound HTTP clients |
| `IO_SLICE_BYTES` | Native I/O work per provider turn |
| `HELLO_FRAME_BYTES`, `ADDRESS_BYTES`, `MAX_ADDRESSES` | HELLO parsing and address extents |
| `BODY_BYTES`, `HTTP_WIRE_BYTES` | Decoded download body and original wire bytes |
| `HTTP_HEADER_BYTES`, `HTTP_HEADERS`, `HTTP_FRAMES`, `HTTP_PROBES` | HTTP parsing, framing and address-probe work |
| `JSON_BYTES`, `RETAINED_PUBLICATION_BYTES` | JSON and retained publication storage |
| `STORE_BYTES` | Qualified learned-metadata snapshot body |

## Time and wire profiles

`OPERATION_LIFETIME`, `HTTP_LIFETIME`, `RETIREMENT_GRACE`, `DAEMON_LIFETIME`,
`TICK_INTERVAL`, `REBUILD_INTERVAL`, `SAVE_INTERVAL` and `STARTUP_TIMEOUT`
select their respective original bounds and periodic intervals. Progress and
canceled wait futures do not renew an admitted operation's deadline.

`HELLO_PROFILE` is `reference029` by default, or explicit `deterministic`.
`CORE_CLASS_ORDER` accepts `native`, `little` or `big` and defaults to `native`.
These profiles are selected before authentication; failures do not trigger guessing.

Defaults and admission checks are implemented in [settings.rs](src/settings.rs),
with domain limits in the [HOSTLIST core](../../crates/gnunet-hostlist/src/state.rs)
and [native runtime](../../adapters/hostlist-std/src/runtime.rs).
