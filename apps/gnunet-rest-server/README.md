# REST server

`gnunet-rest-server` serves GNUnet CONFIG, IDENTITY, NAMESTORE, RECLAIM and GNS
HTTP routes through their native Rust clients. Optional OpenID Connect uses the
same RECLAIM source and an explicit persistent provider. Linux, macOS, FreeBSD
and Windows share the application and [REST host](../../adapters/rest-std/README.md).

## Building and running

```sh
cargo build --release -p gnunet-rest-server
./target/release/gnunet-rest-server -c rest.conf
```

Enable build feature `oidc` to include OpenID Connect. Its AWS-LC backend requires
a native C toolchain and target SDK headers. The active official REST daemon uses
plain HTTP; TLS termination is outside this process.

```ini
[rest]
HTTP_PORT = 7776
BIND_TO = 127.0.0.1
BIND_TO6 = ::1
BASIC_AUTH_SECRET_FILE = /absolute/private/path/rest-secret
```

The secret parent must already exist and have a protected native namespace.
Standard PROGRAM `-c`, `-L`, `-l`, `-h` and `-v` options apply. Endpoint, access,
CORS, resource and OpenID options are in the [configuration reference](CONFIGURATION.md).

## Authentication and native startup

Startup captures original listeners and parent control before other native
owners. Unix applies the configured process identity; Windows verifies its
primary-token SID. A configured identity mismatch fails before worker or listener
startup. Stop subscriptions use native signals/console events and the original
parent channel. Inherited listeners retain their original ownership.

Basic authentication defaults to enabled. The configured secret is an owned
private ordinary file with 1–4096 bytes, opened without following its leaf link.
An absent secret is generated from OS entropy, staged with private permissions,
synchronized and explicitly closed before no-replacement publication. A
concurrently created credential is qualified and read without replacement.
The default username comes from native account lookup, including the actual
primary-token SID on Windows. `[rest-rust] BASIC_AUTH_USERNAME` overrides it.
Secrets, authentication headers, tokens and request bodies stay out of diagnostics.

## Configuration publication

`[rest-rust] CONFIG_OUTPUT` explicitly selects the CONFIG output. Otherwise the
shared project/XDG user-output selection applies independently of PROGRAM `-c`.
Its existing parent must be owned and protected; existing output and lock files
must be private ordinary files.

The single bounded worker retains the original directory, target and writer-lock
handles. Shared serialization produces standard GNUnet INI. Publication stages
private bytes in that directory, synchronizes and closes the original writer,
rechecks the original target and request bounds, then replaces the name atomically.
Cleanup operates on the original staged file. Replaced namespace/file selections
are refused. Stage, publication uncertainty, writer-close and cleanup errors stay
independent. Windows reports directory synchronization as `Unavailable`; file
publication does not manufacture a directory-durability receipt.

`LiveConfiguration` and the HTTP result change only after the matched worker
receipt. Dropping an HTTP wait does not abandon or replay an admitted write.
Listener/authentication policy, signer and process identity remain fixed until
restart; later client selectors use the new configuration snapshot.

## Shutdown and ownership

Shared PROGRAM scheduling retains the original product future through scheduler
failure and drives its existing cleanup. The first stop fixes one native grace
bound across HTTP and worker retirement. It stops new admissions, closes original
HTTP jobs/listeners, disconnects the Resolver and fairly drains the CONFIG and
optional OpenID workers until their actual joins. Expiry is an independent error,
not proof that a pending filesystem call was canceled.

`READY` reports local construction and binding; remote service initialization is
per request. `STOPPED` retains actual local cancellation and worker results,
without claiming rollback of remote mutations. Standard-stream and filesystem
calls retain native OS blocking semantics. Selected logging and independent
cleanup failures remain available together.

## Source layout and constraints

`main.rs` selects PROGRAM and native identity; `early.rs` transfers startup
resources; `settings.rs` selects finite profiles; `authorization.rs` owns CORS and
Basic credentials; `foreground.rs` drives original providers through cleanup;
`lifecycle.rs` retains the Resolver and selected diagnostic boundary. Protocol and
HTTP behavior remain in the REST libraries.

Responses use bounded JSON, record, body and output pools. A result exceeding a
configured limit is an explicit failure. Each request freezes related CLIENT
selectors together before native admission. Qualification follows the shared
[compatibility contract](../../spec/gnunet/compatibility.md).
