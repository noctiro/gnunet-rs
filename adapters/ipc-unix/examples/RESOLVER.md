# Official resolver owner and normal C probe

`gnunet_ipc_unix::resolver::Resolver<R,N>` drives the official bounded resolver
client over Unix/TCP streams. It owns its core, immutable transmit frame,
partial read/write cursors, virtual connection epoch, socket retry, and timer.
It never calls the system DNS resolver for an ordinary `ip_get` query.

Construct with an explicit Unix path or an owned official `Configuration`.
Construction is lazy and can run outside Tokio; drive it on a Tokio runtime.
`R` bounds all live/draining/terminal slots, `N` each forward hostname, and
`Limits` bounds frame storage and the maximum bytes per socket write.
These local capacities add no fields or protocol messages. Query timeout uses
`gnunet_types::Duration` in microseconds; `u64::MAX` is official FOREVER.

Call `connect(config)`, `ip_get`, `hostname_get`, `request_cancel` and
`disconnect` synchronously. `connect` matches the official reconfiguration
operation: replace the configuration used for future MQ creation and reset
resolver backoff, preserving any current MQ, endpoint, partial RX/TX, pending
callbacks and original deadlines. The callback controller also exposes it. New
queries admitted after reconfiguration still use an existing old MQ until it
closes; a later MQ uses the new configuration. An invalid configuration is
stored rather than rejected, and a later valid configuration can restore
non-fast admission without discarding independent local tasks.
Then loop over `drive(wait_deadline, callback)`, processing one callback at a
time. `Event::Reply` contains address, reverse name/numeric fallback or terminal
core events. During a value callback the controller can cancel that token or
admit another query before the next buffered value/END. Terminal events retire
the token first. IDs are valid only in their original owner; same-owner stale
generations are checked, with no claim of foreign-owner detection.

The optional drive deadline bounds that wait only. Canceling a drive future
preserves partially read headers/bodies, immutable pending TX bytes, write
cursor, connection and original query deadline. Dropping the owner closes its
own socket/connect future and never fabricates a completion callback.

Sent cancellation suppresses future value/terminal callbacks and drains the
original END. If every remote query is canceled, driving the one-millisecond
idle timer closes the MQ and reclaims canceled slots. Drive that timer or call
`disconnect` after requests finish; there is no detached background task that
closes sockets while the owner is not driven. Physical initial connection
failures retain the original virtual MQ and envelope. Established connection
or protocol failure retires the epoch and retries the same query wire ID with
its original deadline. No cancel frame, private handshake or remote status
field exists.

`check_config` follows C semantics: existing UNIXPATH suffices; otherwise
HOSTNAME must be numeric or one of the two loopback names. Numeric forward and
loopback fast paths bypass configuration; numeric reverse requires it. A valid
check with no usable MQ endpoint remains pending, reports
`ConnectionUnavailable`, and obeys its original timeout. A physically absent
Unix service reports socket retries instead. Actual errors remain available
through `take_connect_error` / `take_io_error`. Oversized input/output is an
explicit capacity failure, not a successful empty DNS result.

`hostname_resolve` gets the native hostname through `gnunet-native`, then
uses the same official forward path. `local_fqdn_get` delegates to the native
normal-profile implementation: gethostname then getaddrinfo with genuinely
NULL service/hints, retaining only the first canonical name or original raw
hostname on successful lookup. It preserves non-UTF8 OS bytes and native
errors; it can block and consult NSS/mDNS/DNS. Run that synchronous convenience
off the async executor when needed. It is not used by ordinary queries. The
native package owns the audited OS FFI; this IPC crate still forbids unsafe
code. This batch does not execute the host's FQDN lookup because native
name services can cause network activity through a separate host process.

Automatic native AF profiles currently cover Linux/Android and Apple Unix;
other Unix platforms must supply their profile through explicit profile
constructors. IPv6 AF is native local IPC ABI (Darwin 30, Linux 10), not an
invented portable field. Generic C client configuration can dereference a
missing HOSTNAME in a Unix-only configuration; safe Rust does not reproduce
that source crash.

The independent local byte-fixture tests cover Unix and loopback TCP, FIFO,
sent-cancel drain, callback cancellation, timeout/FOREVER/late-ID replay,
invalid MQ configuration, short writes, cancellation during partial RX/TX,
explicit response capacity loss, initial socket retries and owner drop. They
encode the fixture responses independently of the production codec.

## normal C interoperability

Build the Rust consumer:

```sh
cargo build -p gnunet-ipc-unix --example resolver --locked
```

The example accepts `CONFIG MODE VALUE`. Modes `forward`, `forward4`,
`forward6`, `reverse`, `numeric-reverse`, `cancel-first`, and `cancel-before`
use the owner and print callbacks. The example has a 1024-byte
hostname capacity and one-byte physical writes; this is an explicit probe
profile, not an official maximum.

The normal reference must be an unchanged v0.29.1 Meson Resolver build with
`resolver-build-result.json` and its bound base receipt. Use the
[reference build tools](../../../tools/reference/README.md) to prepare a fresh
private build; existing reference prefixes must not be replaced or patched.

```sh
python3 adapters/ipc-unix/examples/resolver_oracle.py --selftest
python3 adapters/ipc-unix/examples/resolver_oracle.py \
  --reference /path/to/new/normal-build/resolver-build-result.json \
  --rust target/debug/examples/resolver --output /new/evidence/directory
```

This macOS oracle applies an OS sandbox denying **all IPv4/IPv6 output**, first
verifying that both sendto families return EPERM. It runs the unchanged
build-tree C daemon (whose original rpath resolves its normal util library),
then the Rust example. Only a private Unix socket in an owned temporary
directory is used. It reads but never changes /etc files; their hashes, the C
source/artifact hashes, Rust source/binary hashes, raw logs, clean SIGTERM exit
and owned-directory cleanup are checked in the receipt.

An non-fast alias is selected from the existing hosts file. The oracle
requires the daemon's request log for successful hosts and cancel cases,
so numeric/localhost fast paths cannot pass as service interoperability.
Numeric IPv4/IPv6, Any-loopback ordering, numeric reverse and pre-submit cancel
are reported as separate fast cases. Resolving reverse traverses the daemon;
its DNS sends are OS-denied and the original client timeout produces numeric
fallback. No positive recursive DNS, PTR, CNAME, dynamic cache, native FQDN or
complete Rust resolver daemon claim follows from these checks. Those need the
contained DNS/service batch described in the audit design.
