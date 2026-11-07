# Shared GNUnet service runtime

Shared native sockets, framed IPC, clocks and ownership primitives for GNUnet
services and clients. Domain protocol engines remain in their own crates. The
behavior reference is GNUnet v0.29.1, revision
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`; compatibility requirements are defined
by the [central protocol contract](../../spec/gnunet/README.md).

## Platform boundaries

TCP listeners, address ACLs, connections, clocks and framing are shared across
Linux, macOS, Windows and FreeBSD. Activation, local Unix sockets, Unix peer
credentials, descriptor readiness and process supervision currently use Unix
backends. Remaining native backends are tracked in
[implementation status](../../IMPLEMENTATION_STATUS.md).

`BoundListeners::bind_tcp(&config, section)` binds official TCP IPC from `PORT`,
`BINDTO` and `DISABLEV6`. `PORT` must be nonzero. It does not open `UNIXPATH` or
adopt inherited handles. Unix listeners set `SO_REUSEADDR`; Windows listeners set
`SO_EXCLUSIVEADDRUSE` before bind. IPv6 sockets set `IPV6_V6ONLY`. Binding is
nonblocking with backlog 5. At most 64 resolved addresses are admitted. If all
endpoints fail, binding fails; partial success retains alternate errors in
`failures()`.

Call these methods within the caller's entered Tokio runtime. BINDTO resolution
is synchronous during startup; numeric addresses avoid native DNS. Listener
references borrow their `BoundListeners` owner and cannot outlive it.

```rust,no_run
use gnunet_config::Configuration;
use gnunet_service_runtime::BoundListeners;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
let _entered = runtime.enter();
let mut config = Configuration::default();
config.set_number(b"example", b"PORT", 2086)?;
config.set_value(b"example", b"BINDTO", Some(b"127.0.0.1"))?;
let listeners = BoundListeners::bind_tcp(&config, b"example")?;
# Ok(())
# }
```

## Admission and connection ownership

`service_options` parses the section's IPv4/IPv6 ACLs and `TOLERANT`, retaining the
caller's shutdown policy. The accepting driver must enforce these options; a
successful bind or connection grants no protocol or peer authority.

`Listener::poll_canonical_connection` initializes the original accepted stream
before domain admission. Native initialization retains ordered bounded
diagnostics and the primary fatal error; fatal failure closes the original
stream. Reactor initialization has no select descriptor-number ceiling. Windows
uses Winsock nonblocking mode, native handle inheritance control and TCP_NODELAY.
Unix additionally applies its platform-specific signal and descriptor policy.

`connection::Connection` owns one stream and an optional `ConnectionLease`.
The lease drops before the stream. Attaching a second lease returns both original
owners unchanged. CLIENT endpoint selection and Resolver effects are owned by
[gnunet-client-host](../client-std/README.md).

## Framing and cancellation

`framing::Framed<Origin>` owns the connection, persistent RX/TX cursors and immutable
`OwnedFrame` bodies. Canceling a waiting future retains the socket, bytes, cursor
and origin. Only zero-written frames can be removed; a started tail must drain or
retire its whole physical connection. Fatal I/O requires retiring that owner
before reconnecting; Interrupted and canceled waits preserve the cursor.

`reserve` preflights queue metadata. `enqueue_owned` moves the final allocation
without copying; rejection returns its original secure bytes and origin.
Whole-frame or remaining-wire accounting and separate control budgets are
explicit choices. These budgets exclude spare vector capacity, RX storage and
metadata; they are not exact resident-memory caps. Domains own deadlines,
fairness, resource policy and nonce admission.

Each tagged positive write reports its original origin and byte count once.
Report progress to the domain before handling subsequent RX. `Framed<()>` also
supports untracked batching with up to 64 stack IoSlices, bounded by the original
I/O quantum and one native write per poll. Reads do not overread the next header.
A completed frame remains borrowed until explicit `release_frame`; `frame_mut`
permits erasing its secrets. Release, retirement and Drop wipe retained RX and
removed TX bodies. No payload Debug or mutable admitted-body API is exposed.

## Clocks and waits

`clock::RuntimeClock`, subscriptions and deadlines carry the caller's logical
time source. Each service owns its clock and subscriptions; framing does not
sample an independent clock or manufacture deadline completion. A caller wait
budget is separate from a protocol operation's original deadline.

On Unix, `RegisteredReadiness` exclusively owns one unchanged descriptor until
it deregisters before `into_owned`. It confirms cached readiness using
nonconsuming native polling and distinguishes IN, HUP, ERR and invalid handles.
Canceled waits retain registration and ownership. `RegisteredIo` attempts at
most one caller operation per poll. A cached hint followed by WouldBlock schedules
one cooperative turn to register the current waker; it does not retry the syscall
internally, replace the descriptor or relax the deadline.

## Unix activation and local paths

Call unsafe `capture()` exactly once during fresh single-threaded startup,
before creating runtimes, configuration files or logging resources. Its documented
exclusive foreign-descriptor contract applies. Validation finishes before
ownership transfer; later adoption failures are fatal. Numeric `LISTEN_FDNAMES`
selects actual, possibly nonconsecutive descriptors. Stdio listeners relocate
before their old slots receive `/dev/null`. Capture makes listeners nonblocking
and CLOEXEC and removes only `LISTEN_FDS`. Inherited paths are never unlinked.

`BoundListeners::bind(config, section, activation).await` adopts nonempty
activation or binds configured `UNIXPATH` and TCP endpoints. A missing/zero PORT
permits Unix-only operation. `prepare_before_identity` binds inherited/TCP
resources first; `ListenerPreparation::finish_with_access` creates local paths
after the caller's identity transition. These methods do not change identity.

New Unix binds run under a serialized temporary umask 077, restored synchronously
on every exit. Exclude unrelated process-wide umask users and file creators during
startup. Existing parent permissions remain unchanged. `UnixListenerAccess`
selects new endpoint/parent modes: UID 0700/0700, group 0770/0750, otherwise
0777/0755. The accepting driver separately checks kernel peer credentials.

Stale-path probing considers only socket inodes and has a five-second bound.
`CreatedPath` removes only an absent or matching device/inode path. Listeners close
before path guards run. Metadata checking and unlink are separate operations;
callers must control concurrent path replacement. Register only newly owned paths,
never inherited or foreign endpoints.

`PrivateListener` and private-bind variants expose explicit backlog and permission
ordering for ARM. The shared [process contract](PROCESS.md) describes native
command preparation, original child/control capabilities and consuming waits.
Signal policy, persistence and application control files remain service-owned.

## Verification

`cargo xtask verify runtime` executes shared native TCP, CLIENT and Resolver
scenarios. Unix workspace tests additionally exercise activation, local path
ownership, readiness and process boundaries. Official C comparisons and platform
execution coverage are described in the [test guide](../../tests/README.md).
