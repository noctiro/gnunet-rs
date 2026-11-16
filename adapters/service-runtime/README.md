# Shared GNUnet service runtime

Shared native sockets, framed IPC, clocks and ownership primitives for GNUnet
services and clients. Domain protocol engines remain in their own crates. The
behavior reference is GNUnet v0.29.1, revision
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`; compatibility requirements are defined
by the [central protocol contract](../../spec/gnunet/README.md).

## Platform boundaries

TCP listeners, address ACLs, connections, clocks and framing are shared across
Linux, macOS, Windows and FreeBSD. Native AF_UNIX transport is available through
`local`; configured local listener preparation, credentials and process ownership
have separate platform contracts. Remaining native backends are tracked in
[implementation status](../../IMPLEMENTATION_STATUS.md).

`BoundListeners::bind_tcp(&config, section)` binds official TCP IPC from `PORT`,
`BINDTO` and `DISABLEV6`. `PORT` must be nonzero. It does not open `UNIXPATH` or
adopt inherited handles. Unix listeners set `SO_REUSEADDR`; Windows listeners set
`SO_EXCLUSIVEADDRUSE` before bind. IPv6 sockets set `IPV6_V6ONLY`. Binding is
nonblocking with backlog 5. At most 64 resolved addresses are admitted. If all
endpoints fail, binding fails; partial success retains alternate errors in
`failures()`.

`BoundListeners::bind_local(path, access)` binds one explicit local endpoint using
the same native preparation as configured services. Permissions or Windows ACLs
are established before listen; original socket/path cleanup and preparation
diagnostics remain on the returned owner. It grants no peer-credential proof.

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

## Local streams

`local::Listener` and `local::Stream` use Tokio's Unix owners on Unix. Windows
validates original Winsock AF_UNIX stream/listener roles before registering the
same handle. A private Tokio/Mio carrier supplies generic socket I/O and readiness;
native accept avoids IP-address conversion and TCP options. WouldBlock uses Mio's
rearm path as well as clearing Tokio readiness. No per-connection worker or timer
polling is used. Windows native runtime qualification remains open.

The Windows transport constructor takes an already bound/listening socket;
transport Drop closes only that socket. `BoundListeners::bind_configured` owns
configured endpoint permissions and filesystem cleanup. A local transport grants
no SID or POSIX UID/GID authority. Requested POSIX credential checks continue to
fail explicitly on Windows. `Connection::unix_peer_process_id` observes the
original AF_UNIX socket through the SDK's `SIO_AF_UNIX_GETPEERPID`; TCP returns
None. This is PID metadata, not SID/UID admission, and never reopens a numeric PID.

CLIENT attempts use this transport for Windows `UNIXPATH`, including shared
official path shortening. Windows socket names must be Unicode encoded as UTF-8,
fit native sun_path bounds and contain no NUL. The official `/` shortening
delimiter and hash suffix are preserved. These constraints differ from general
Windows filesystem paths, which can preserve isolated UTF-16 units.

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

`poll_shutdown` begins only with an empty TX queue. The first native shutdown
poll freezes new TX admission across canceled waits; the original connection
and its receive half remain owned. Domains drain original write receipts, poll
write-side shutdown, then retire that connection. Local shutdown does not prove
peer delivery. Native failures retain their cause and require source retirement.

## Clocks and waits

`clock::RuntimeClock`, subscriptions and deadlines carry the caller's logical
time source. Each service owns its clock and subscriptions; framing does not
sample an independent clock or manufacture deadline completion. A caller wait
budget is separate from a protocol operation's original deadline.

`clock::Bounds` admits fixed canonical and monotonic targets without creating a
waiter. It anchors the monotonic target before sampling the canonical source and
checks that target both before and after subsequent samples. `BoundsError`
distinguishes actual expiry, overflow and clock-source failure; a clock failure
whose cause is `Deadline` must not become an operation timeout. NAT primitives
and helper supervision share this contract without depending on each other.

`readiness::RegisteredListener` verifies a real stream listen role and owns its
nonconsuming registration. Unix uses an original AsyncFd; Windows uses a private
Tokio/Mio Winsock carrier. Native poll0 confirms cached hints without accepting
or reading. One poll performs at most one confirmation; a stale hint schedules
one guarded turn to register the current waker. The original socket remains
available for checked child transfer. Descriptor registration, descriptor I/O
and listener registration have separate source modules.

On Unix, `RegisteredReadiness` exclusively owns one unchanged descriptor until
it deregisters before `into_owned`. It confirms cached readiness using
nonconsuming native polling and distinguishes IN, HUP, ERR and invalid handles.
Canceled waits retain registration and ownership. `RegisteredIo` attempts at
most one caller operation per poll. A cached hint followed by WouldBlock schedules
one cooperative turn to register the current waker; it does not retry the syscall
internally, replace the descriptor or relax the deadline.

## Configured local listeners

`local_listener::prepare(path, access, backlog).await` returns an unregistered
original socket, its path guard and native option diagnostics. Normal services
register it as an accepting listener; ARM registers it for nonconsuming demand.
Both use the same private bind, bounded stale probe and access preparation.
Cancellation during a stale probe leaves the observed existing entry intact.
Native access is set before the first listen. Aggregate field order closes the
socket before retiring its path on failure or Drop.

`BoundListeners::bind_configured(config, section, access).await` binds `UNIXPATH`
and configured TCP endpoints on Unix and Windows without adopting activation.
A missing/zero PORT permits local-only operation. Alternate endpoint failures
remain available when at least one listener succeeds. `LocalListenerAccess`
selects owner, group or everyone filesystem access; drivers separately enforce
peer admission. The `From<UnixAccess>` mapping selects creation permissions only.

Windows creates missing parents with protected inheritable DACLs. Existing
parents retain their security; the final parent must be an ordinary directory
owned by the process user, SYSTEM or Administrators without mutation grants to
other principals. Read/list/traverse grants are allowed. Unsupported ACE forms
fail explicitly. Exclude namespace/ACL mutation and thread impersonation during
startup. The new AF_UNIX node receives its protected DACL before listen; group
access uses the process token's actual primary group SID.

`path.rs` selects native parent preparation behind `private_parents`. Unix keeps
its mode/ownership contract in `path/unix.rs`; Windows reuses the native protected
directory implementation in `path/windows.rs`. Application hosts do not create
parallel platform-specific directory policies.

Windows stale-node probes hold an original file handle without automatic
deletion. Only connection refusal permits reclamation. New node owners reopen
their original object for DELETE and apply extended POSIX disposition; replacement
paths are never looked up for removal. Volumes without that disposition and
sharing violations return errors. `BoundListeners::close` closes sockets first
and retains each failed path owner for retry. Drop cleanup is best effort.

## Windows activation

`Activation::from_sockets` validates owned stream-listener roles and native
families before conversion. `from_imported` consumes actual descriptors from
[native one-shot import](../native-std/SOCKET-ACTIVATION.md). The private collection
cannot be populated without validation. Both paths admit at most 4096 listeners.
`BoundListeners::from_activation` registers the original nonblocking set without
rebinding endpoints or acquiring inherited path-cleanup leases. Enter an
I/O-enabled runtime and retain creator leases separately.

## Unix activation and path ownership

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
startup. Existing parent permissions remain unchanged. `LocalListenerAccess`
selects new endpoint/parent modes: owner 0700/0700, group 0770/0750, everyone
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

`signals::Termination` owns native stop subscriptions shared by normal service
hosts. Construct it under an entered runtime after console detachment. Unix
observes interrupt/terminate; Windows observes console interrupt/break/close and
shutdown. Subscription failure or an ended stream remains an error. Drop releases
subscriptions without promising restoration of Tokio's process-global handlers.

The `process` module shares registry-branded child identities across platform
backends. Windows owns original process HANDLEs, bounded active/completed credit
and kernel exit notifications; it exposes explicit native command/handle inputs.
`reap_child` consumes only the selected original child's actual exit receipt,
leaving unrelated active owners and queued receipts intact. Credit releases once.
Unix retains its descriptor/helper/control port. See the
[process contract](PROCESS.md) for launch, cancellation, errors and the remaining
application/activation integration.

`cargo xtask verify runtime` executes native local/TCP, CLIENT/Resolver and
startup, snapshot/restart scenarios and the normal STATISTICS service and Resolver
CLI. Windows uses original child
handles and private byte pipes. Unix workspace tests additionally exercise
activation and credential transitions. Official C comparisons and platform
execution coverage are described in the [test guide](../../tests/README.md).

## Configured command arguments

`process::parse_command` preserves quoted spaces, empty quoted arguments and
escaped bytes, with finite argument capacity and lossless native string decoding.
Only unquoted literal spaces delimit. Apostrophes, tabs, dollar signs and percent
syntax stay literal; the first NUL ends the input. Malformed quotes and trailing
escapes fail before process admission. This corrects the C helper's in-place
compaction defects rather than exposing those defects as a Rust command contract.
Literal executable/fixed arguments in `compose_arguments` are never tokenized.
