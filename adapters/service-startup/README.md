# Generic service startup

Native process startup boundaries shared by GNUnet service executables. Protocol
and application state remain outside this package. Configuration selection is
shared; identity and process mechanisms follow the native OS.

## Module ownership

`account.rs` and `ready_status.rs` contain shared configuration/status contracts.
`unix.rs` and `windows.rs` are platform facades with explicit reexports. Their
directories separate capture, control, identity/privileges and readiness owners;
Windows child creation, parent qualification, detached re-exec and managed console
detachment remain separate from Unix fork/setsid ownership. The
[Windows launch port](src/windows/launch.rs) owns native child creation and
bootstrap; the [daemon adapter](src/windows/daemon/launch.rs) adds console,
standard-stream and source-listener retention policy.
Linux, macOS and FreeBSD reuse the Unix policy with native syscall differences
inside the owning module. Protocol/domain state does not depend on these paths.

## Client PROGRAM startup

`ClientStartup::capture` is the unsafe, once-only early capture for non-listening
clients. Call it before configuration, logging, files, runtime or threads, under
the same exclusive inheritance contract as native capture. It rejects service
listeners, retains original parent control and reports ignored Unix control
hints separately. Capture failure requires startup exit rather than retry.

`StopSignals::for_client` consumes that parent declaration on the caller's runtime
and subscribes to native termination. It publishes no service readiness byte.
`ClientError` preserves the native cause; failed Unix reactor registration keeps
the original descriptor with the error. CORE, DATASTORE and NAMECACHE commands
use this shared boundary instead of separate platform capture implementations.

## Stop subscriptions

`StopSignals::new` retains an optional already registered parent receiver and
installs native termination subscriptions on the caller's runtime. `poll_stop`
observes interrupt/terminate control bytes and native Unix or Windows stop
notifications without spawning a task. Parent EOF closes only that receiver;
unknown bytes consume one bounded turn. Callers retain readiness, diagnostics,
grace and cleanup policy. `StopError` preserves the original parent/native
failure through its error source.

## Configuration

`configured_user(config, section)` reads `USERNAME` through dollar expansion.
Unix also applies the official filename expansion. Missing configuration
keeps the selected account. Present values are resolved by the platform's
account lookup during identity preparation.

## Windows identity

`verify_configured_identity(config, section)` queries the process primary-token
user and checks a configured account using native SIDs. It returns the actual SID
or a configuration, Win32 query or identity-mismatch error. Mismatch retains both
observed SIDs. It does not map identities to Unix UID/GID numbers, impersonate a
thread or change the invoking process account. A supervisor must launch under the
required account before constructing the service.

ARM can start a service under a verified Windows batch-logon
token. It builds the target environment from the loaded Windows profile and
starts a detached child with closed standard streams. It grants access to the
private control pipe to the target SID and qualifies the connection against the
original child process. The native process handle governs profile retirement.
The original child can receive managed IPv4 and IPv6 TCP listeners and
AF_UNIX listeners protected for its verified account before listen. A
same-session launch inherits the read-only section and verifies its
publisher before importing protected AF_UNIX listeners. For a launch into
another session, the parent duplicates the sealed read-only handle into the
original suspended process and sends a signed grant after resume.
[Windows activation](../native-std/SOCKET-ACTIVATION.md#ownership-and-startup-order)

The native SID owner retains only validated identifier bytes. Token handles close
through unique ownership; the SID can outlive the query handle without retaining
privileges. This observation grants no file access, elevation, group membership
or TCP peer authentication. Process launching follows
[the original-process contract](../service-runtime/PROCESS.md).

## Windows parent bootstrap

The parent reserves a runtime `PipeListener` before native child creation and
places its endpoint in the child's explicit `GNUNET_OS_CONTROL_PIPE` environment.
On Windows this implementation-local hint names a private local pipe; on Unix it
contains the original hexadecimal FD. It is not a service IPC frame or network
address. Do not pass the Windows hint to a child expecting Unix FD capture.

Unsafe `capture_from_environment()` runs once at fresh process startup, before
files, logging owners or runtime registration. It consumes and removes private
hints, including malformed values. A nonempty `GNUNET_RS_DETACH_PIPE` must match the control
endpoint; it declares the one-shot launcher role without granting identity,
readiness or console authority. Nonempty Unix `LISTEN_FDS`/`LISTEN_FDNAMES`
declarations are refused on Windows.

`CapturedStartup::activation` owns optional read-only native activation metadata
from an inherited handle or a cross-session grant. During a session crossing
the child reads a bounded startup prefix with a 30-second deadline. It
authenticates the grant with the original launch's verification key and
checks the target PID and kernel section owner before adopting the handle.
After any managed console detachment, materialize and validate the original
sockets before reactor registration. Capture/import failure or abandonment
requires startup exit; the [native transfer contract](../native-std/SOCKET-ACTIVATION.md)
defines ownership and provider reservations. `ParentControl::register()`
registers the original early client if the child received a grant. Otherwise
it opens a fresh overlapped client under an entered I/O-enabled Tokio runtime.

The parent's `ParentBootstrap` binds its listener to the registry's original
child token and process-object identity lease. The kernel-observed connected PID
must match that pinned object. Qualification failure retires the physical pipe;
its buffered read state cannot be assigned to another peer. The pin releases
after qualification. It proves identity, never continued child liveness. A
separate original-process exit observer remains registered while connection is
pending. Pre-connect exit returns the real full-width exit code instead of
waiting indefinitely; it consumes no registry reap receipt. Terminal connect
failures are sticky and release the original listener/identity/wait owners.

After any activation grant, the parent direction carries signed 8-bit
control values and the child direction carries the official `.` / `I` / `S`
startup bytes. Only an actual `.` reports readiness. Child control closes
when the parent disconnects.
Canceled waits retain their original connection, reader and admitted byte.
Readiness permits only its first immutable intent; same-status resumption does
not send again. Control admission requires a live record in the exact registry.

`ReadySubmission` and `WriteSubmission` confirm acceptance by Tokio/Mio only.
They do not confirm native overlapped completion or peer consumption; native
write loans may outlive the logical writer. Last-connection-owner Drop requests
native cancellation best effort without waiting; accepted bytes may be canceled.
Mio retains its OVERLAPPED/buffer loans until completion. Only an actual `.` read
from the qualified connection creates the parent's `ReadyReceipt`. Each direction has
one owner; dropping a direction is not native half-close. No destructor waits
for the child or manufactures a readiness/exit result. Native execution
qualification is tracked in
[implementation status](../../IMPLEMENTATION_STATUS.md).

## Windows supervised creation

`launch::launch(registry, Command, limits)` creates one original child with an
explicit image, argv0, literal arguments, working directory, standard streams and
console selection. `ParentRole::Supervisor` and `ParentRole::DetachLauncher`
select the bootstrap purpose independently of console state. Private bootstrap
and Unix descriptor hints override inherited environment entries using native
case-insensitive name ordering. An empty detach marker selects the supervisor
role. The parent environment remains unchanged.

Nonempty borrowed listener sets use suspended creation, provider publication and
one resume. Callers retain the source listeners until actual qualified readiness,
or until the original child is explicitly retired after failure or abandonment.
No pathname cleanup ownership transfers. `LaunchFailure::child` identifies any
already admitted child; the caller retains its registry, failure and source
listeners through explicit retirement. Creation failure, publication failure and
independent start-revocation failure retain their original errors.

The returned `Parent` exposes `poll_connect` and `poll_ready` for the caller's
reactor, and `wait` for async composition. These operations spawn no task and keep
endpoint, qualification, read and exit-observation state across cancellation.
`take_control` transfers the qualified outbox once; obtaining control does not
prove readiness. Actual child creation, connection qualification, startup status
and consuming process exit remain separate observations.

## Windows detachment

`daemon::launch(registry, Reexec, limits)` composes the same native launch port
with `DETACHED_PROCESS` and the one-shot launcher role. Nonempty `Reexec::activation` uses a
suspended original child, native publication and one explicit resume before
readiness; an empty set performs ordinary creation. Source listener copies remain
owned until actual readiness confirms import; cancellation preserves those owners.
Failed setup retains them in `LaunchFailure` until explicit child retirement. Image, argv0, literal arguments and cwd
stay separate. The uniquely owned explicit environment receives child-only
bootstrap hints; no global environment, parent stdio or shell state changes.
stdin/stdout use NUL. `PreparedStderr` pins file/pipe sources by original handle,
selects NUL for character devices and keeps absent stderr closed. It cannot
retarget a source whose caller/table owner changes after preparation.

The re-exec child retains its daemon option and captured `DetachLauncher` role
prevents another launch. The original parent returns only after actual qualified
readiness. Pre-connect exit, failure status, EOF and native errors remain failures.
A post-admission `LaunchFailure` retains the child token in `child`; its original
process stays owned by the caller's registry for explicit cleanup. Dropping the
parent or registry never terminates or waits for a live daemon. Job-object
breakaway and account switching are not implied by detachment. Setup failure
revokes an unconsumed start permission; independent revocation failure remains
attached to `LaunchFailure`. Original process termination/reaping is explicit.

`daemon::retire_child` borrows the caller's registry and acts only on the exact
original child. It observes an existing exit before termination, retains
termination and observation errors independently, and consumes only that child's
actual receipt. Canceling its wait retains the registry/process authority;
unrelated completion receipts remain queued. `Parent::take_control` transfers its
qualified original outbox once without manufacturing readiness.

An already supervised service calls unsafe `daemon::detach_managed()` before
runtime/handler installation. It redirects stdin/stdout in Win32 and UCRT and
calls `FreeConsole` in the original process; the supervisor's process token and
control endpoint remain valid. File/pipe/absent stderr stays, character stderr
becomes NUL. Preparation refuses aliased native standard routes before mutation.
Each later error identifies the applied standard-stream/console stage; partial
failure requires recovery or startup exit. The same native installation mechanism
preserves independent process-owned and CRT-owned handles for every affected slot.

## Unix early resources

Call unsafe `capture_from_environment` as the first fresh-exec operation, before
opening unrelated descriptors or creating a runtime, threads or logging owners.
Its explicit inherited mode adopts listeners or retains their close-after-bind
ownership. Parent control is captured at the same boundary so duplicate raw-FD
aliases are rejected before ownership transfer. Later adoption failure requires
startup exit; do not retry capture or log through a declared foreign stdio slot.

Original inherited descriptors are neither reopened by number nor reconstructed
later. Listener borrowing and newly created pathname cleanup follow the
[shared runtime contract](../service-runtime/README.md).

## Unix account transitions

`resolve_user` constructs a native account plan. `apply_privileges` is an explicit
fresh-process operation after privileged listener preparation and before unrelated
async work. It follows the selected initgroups capability, native gid/uid order
and fallback, retaining the failed stage, errno and observed IDs on refusal.
Partial transition failure requires process exit. A successful fallback does not
prove supplementary groups were reset or saved credentials were discarded.

Library embedding checks that the caller already has the selected identity;
it must not mutate the entire process behind the embedding application's back.
Native command and original child ownership are described by
[the process contract](../service-runtime/PROCESS.md).

## Unix detachment and readiness

Unsafe `daemon::split` requires a fresh single-threaded process after early
capture and flushed option/log selection, before account lookup, runtimes,
threads, children or path guards. One fork and child setsid detach the process;
stdin/stdout redirect to `/dev/null`. Captured listener/control and selected log
owners remain. New private pipe ends are lifted above stdio before replacement.
This is not an async embedding API.

The original parent drops captured copies and waits for its one status-pipe byte,
not for the live daemon to exit. The kernel reparents the daemon when that parent
exits; no later reaping result is invented. The status reports `.` once after host
readiness, `I` for initialization failure and `S` for stop-before-ready. EOF and
read errors fail startup. Drop never reports ready; `finish` retains the original
service error and independent status-write failure. Post-ready failure cannot
retract the earlier readiness observation.

## Verification

[Native runtime tests](../../tests/README.md) exercise shared TCP services and
platform identity observations. Unix process tests use owned children and private
files/sockets. Credential-changing or device profiles require their documented
native setup; ordinary embedding tests perform neither operation.
The standalone `windows_bootstrap`, `windows_daemon` and `windows_activation`
tests exercise original children, private pipes, detached re-exec, supervised
in-place detachment and original AF_UNIX/IPv4/IPv6 listeners. Activation covers
queued connections, canceled startup waits, retained sources on refusal and
creator-owned node cleanup. These cases require Windows execution; cross
compilation does not qualify their runtime behavior.
