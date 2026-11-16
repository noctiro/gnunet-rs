# HOSTLIST foreground

`gnunet-daemon-hostlist` composes official HOSTLIST bootstrap, learning, HTTP
publication and peer advertisement with native CORE, PEERSTORE, STATISTICS,
HTTP/TLS and snapshot storage. Linux, macOS, FreeBSD and Windows share the
[HOSTLIST host](../../adapters/hostlist-std/README.md).

## Building

```sh
cargo build --release -p gnunet-daemon-hostlist
```

The TLS provider requires a native C toolchain and target SDK headers.

## Roles and configuration

```sh
gnunet-daemon-hostlist -b -e -p -a -c hostlist.conf
```

`-b` enables bootstrap, `-e` learning, `-p` HTTP publication and `-a`
advertisement. With no bootstrap, learning or publication role it exits normally.
Standard PROGRAM options select configuration, logging, help and version.

`[hostlist]` consumes `SERVERS`, `HTTPPORT`, `BINDTOIPV4`, `BINDTOIPV6`,
`EXTERNAL_DNS_NAME`, `HOSTLISTFILE`, `PROXY`, `PROXY_TYPE`, `PROXY_USERNAME`
and `PROXY_PASSWORD`. IPv4 and IPv6 bind independently, retaining alternate bind
errors. Windows uses exclusive listener ownership; Unix permits address reuse.
The external DNS name, or the native local FQDN when absent, is an advertised
claim without reachability proof. Hostnames must be valid Unicode; they are not
converted with lossy native-path encoding.

[hostlist.conf](hostlist.conf) contains official installed defaults, including the
bootstrap launcher. Packaging places it in the configured defaults directory.
Explicit `[hostlist-rust]` resource and time profiles are described by the
[configuration reference](CONFIGURATION.md). `HELLO_PROFILE` selects
remote HELLO verification independently of the local `[PILS] PROFILE`.

## Native lifecycle

Startup captures original inheritance and refuses inherited service listeners.
Unix applies configured process privileges; Windows verifies the configured
primary-token SID. The first stop check precedes HTTP binds and metadata workers.
Shared PROGRAM scheduling retains the original foreground future through
scheduler cancellation, sets its stop latch and drives its existing cleanup.

The same foreground drives one shared Resolver and the HOSTLIST providers.
Remote HTTP/proxy DNS uses that Resolver. `READY` requires actual CORE and
PEERSTORE readiness, including monitor SYNC when providing. The first stop
begins finite cancellation; a second native stop or the original grace bound
closes network owners. Metadata commit, drain and worker join follow network
retirement. `STOPPED` distinguishes an absent, joined or failed/unknown worker.
Filesystem and standard-stream calls retain native OS blocking semantics.

Selected diagnostics use the same Logger and SharedClock, including startup and
cleanup errors. Functional READY/STOPPED output is flushed. Original product,
logging and cleanup failures remain independent; an already selected diagnostic
failure is not printed again through fallback stderr.

## Storage and source layout

For client roles, `HOSTLISTFILE` selects a sibling `.rust-hostlist` directory.
Only a new or marker-qualified `Namespace::Hostlist` store is admitted. It stores
bounded learned URL, quality and retry metadata with matched worker receipts.
Live sources, operations and keys are not restored from metadata. URI and
proxy-authentication values are redacted.

`main.rs` selects PROGRAM options and identity; `foreground.rs` retains the
Resolver and shared scheduler; `drive.rs` owns provider progress and retirement;
`failure.rs` retains independent terminal causes. Protocol and native provider
state remain in their respective library layers.

SDK consumers enable `official-hostlist`; pure protocol/state users select
`hostlist` or `hostlist-alloc`. External qualification follows the shared
[compatibility contract](../../spec/gnunet/compatibility.md).
