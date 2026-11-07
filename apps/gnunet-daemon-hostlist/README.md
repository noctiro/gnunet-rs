# HOSTLIST foreground

`gnunet-daemon-hostlist -b -e -p -a -c <config>` selects the active official bootstrap, learn, provide and advertise roles through shared GETOPT/PROGRAM. With no bootstrap/learning/providing role it exits normally. Shared configuration/defaults/logging/process clock, original parent FD/control capture, configured UID/GID drop and signal handling precede native owners/workers. It creates no C helper or daemon process.

Official [hostlist] SERVERS, HTTPPORT, BINDTOIPV4, BINDTOIPV6, EXTERNAL_DNS_NAME, HOSTLISTFILE, PROXY, PROXY_TYPE, PROXY_USERNAME and PROXY_PASSWORD are consumed. Literal IPv4/IPv6 public bindings use separate owned sockets; alternate bind failures are reported. The C BINDTOIP key typo is not copied. If no external DNS name is configured, the existing native local-FQDN startup port supplies the same kind of local claim as C; this is not reachability proof. Foreign inherited IPC/readiness listeners are refused because active hostlist has NOARMBIND and its own public HTTP binding, while original parent control remains owned.

The mutable process Resolver broker is driven by the same foreground PROGRAM task as native HOSTLIST. Remote HTTP/proxy DNS never falls back to host DNS. READY requires CORE, general PEERSTORE, and monitor SYNC where providing; bound HTTP listener count and selected signature profile are explicit. It does not claim successful Internet bootstrap. The first signal starts bounded original cancellation/drain; a second signal/grace bound closes owners. Network cleanup precedes final metadata commit/drain/join and resolver destruction. STOPPED distinguishes an absent, actually joined or failed/unknown worker.

For client roles HOSTLISTFILE selects a new sibling qualified directory by appending `.rust-hostlist`. The old C file is never read/imported or replaced. The directory must be new or already marker-qualified Namespace::Hostlist; all foreign/unmarked stores are rejected before body interpretation. Only bounded learned URL/quality/retry metadata is serialized, with worker receipts. No live source/job or key is persisted. Authentication/URI values are redacted.

[hostlist-rust] supports MAX_URLS, MAX_LEARNED, MAX_HELLOS, HELLO_BYTES, MAX_PEERS, HTTP_CLIENTS, HTTP_CLIENTS_PER_IP, IO_SLICE_BYTES, OPERATION_LIFETIME, HTTP_LIFETIME, RETIREMENT_GRACE, DAEMON_LIFETIME, TICK_INTERVAL, REBUILD_INTERVAL, SAVE_INTERVAL, STARTUP_TIMEOUT, HELLO_FRAME_BYTES, ADDRESS_BYTES, MAX_ADDRESSES, BODY_BYTES, HTTP_WIRE_BYTES, HTTP_HEADER_BYTES, HTTP_HEADERS, HTTP_FRAMES, HTTP_PROBES, JSON_BYTES, RETAINED_PUBLICATION_BYTES and STORE_BYTES. HELLO_PROFILE is reference029 (metadata-only address coverage) or explicit deterministic; CORE_CLASS_ORDER is native/little/big. All time profiles are finite; defaults match the official role intervals with explicit native resource caps.

HELLO_PROFILE describes remote HELLO verification. HOSTLIST has no local PILS
derivation/signing client, so this remote policy remains independent of the
node's `[PILS] PROFILE`. A configured remote profile is never guessed or changed
after authentication failure.

No process, network, key, crypto, worker/store or model execution occurred in preparation. See the native adapter README for ownership and unproved interoperability/qualification.

`hostlist.conf` contains the pinned official installed-defaults input, including
`gnunet-daemon-hostlist -b`. Place it in the configured project defaults directory
when packaging the executable; this repository does not silently install system
configuration. SDK consumers use `official-hostlist`, with separate `hostlist`
and `hostlist-alloc` protocol/state features.

Ordinary PROGRAM diagnostics use the same selected Logger and SharedClock for
`-L`/`-l`, including parent declarations, startup warnings, Resolver/provider
observations and original cleanup errors. Public READY/STOPPED stdout remains
functional output and is explicitly flushed. The first logging or secondary
cleanup failure wakes/stops new foreground work and physically closes original
network owners before durable worker drain/join. Original business, diagnostic
and bounded cleanup causes remain separate even when logging itself fails. Help/version stop before runtime with success; logging setup failure remains an
failure even when the upstream PROGRAM return index is positive.

Once the owned selected/default Logger has handled preparation or execution,
its complete failure chain carries a private app marker. The outer executable
returns failure without printing those errors to stderr again; only errors
before this logging boundary use the direct startup fallback.

The concrete Resolver cleanup owner is established immediately after broker
construction, before PROGRAM receives a callback/future. Early construction
returns, rejected/unpolled tasks and scoped cancellation retain the same actual
disconnect error; normal cleanup makes one explicit attempt. If PROGRAM drops an
active task, Runtime Drop closes its network owners and Worker Drop stops its
channels and actually joins the original thread. This emergency join has no
final-save/Joined receipt and is not reported as normal durable shutdown success.
