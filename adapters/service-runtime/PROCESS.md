# Native process ownership

The shared `process` port separates original child ownership from launch policy,
service readiness and protocol callbacks. Unix and Windows use their actual
process mechanisms. Applications retain a registry independently of launcher or
host borrows; canceling a drive future does not discard its children.

## Shared identities and capacity

`OriginalChild` names one registry allocation, monotonic generation and original
PID. Cloning it copies lookup identity only. Actions validate the complete live
token before touching native resources; a numeric PID cannot reconstruct it.
Retired tokens cannot target a replacement or another registry.

Active children and untaken completions share bounded admission credit.
Generation exhaustion refuses new admission without preventing existing cleanup.
Each completed receipt releases credit exactly once when taken. Native errors
preserve original records unless the OS proves ownership has already been lost.
Callers explicitly drain the final registry. Drop closes local resources without
terminating children, inventing exit receipts or waiting for child exit.

## Command parsing

The shared [command parser](src/process/command.rs) implements the official two-pass command-text
grammar without shell expansion. Only literal spaces delimit arguments;
apostrophes and tabs remain data. Parsing stops at the first NUL. Unix tokens
retain native bytes; Windows tokens use the lossless local string boundary and
reject malformed encoding. This grammar is independent of native process creation
and Windows CRT argument quoting. `LaunchError` preserves native/configuration
causes through its error source.

`compose_arguments` parses only prefix/options fragments around literal native
program and fixed arguments. Windows ARM client and normal SERVICE use this
boundary to retain native path characters instead of reparsing Windows paths as
Unix escapes. The native process producer performs final Windows CRT quoting.

## Unix command preparation

`NativeCommand` carries filename separately from argv0, literal arguments,
environment changes, child cwd, standard slots and borrowed descriptor mappings.
The SIMPLE profile preserves PREFIX as executable, expanded BINARY as argv0 and
whole OPTIONS as one argument. The argv entry accepts an empty
argument vector; command text requires a first argument. Embedded NULs are errors.
Only recognized stdio/control bits are applied.

`spawn` preflights resource bounds and executable access before native admission.
Absolute and `./` names use literal paths. PATH selects its first regular existing
candidate before X_OK. UID zero uses successful access directly; other UIDs also
perform the required stat. A directory can pass checks and fail later at exec.
Access, stat, spawn admission and target exec remain distinct observations.

Sources are privately duplicated above the complete explicit target range.
Advertised targets have live reservations, protecting overlapping/cyclic maps
and avoiding same-number dup/CLOEXEC assumptions. Parent originals and FD flags
stay unchanged. Actual targets form numeric colon-separated LISTEN_FDNAMES and
LISTEN_FDS; there is no fd3, systemd-name or LISTEN_PID assumption. Explicit
environment changes follow generated hints. Parent control advertises its read
FD as hexadecimal GNUNET_OS_CONTROL_PIPE; disabling control removes that key.

Stdio is sampled before temporary resources so originally closed/CLOEXEC slots
can be restored by the fresh helper. Unmapped slots use null. The helper restores
the selected SIGPIPE class and cwd, then calls native execvp with the separate
filename and argv. Helper admission retains an original child even when target
exec later fails. STARTING establishes neither target exec nor service READY.

## Unix control and completion

The registry retains PID/wait authority and optional control writers. External
concurrent waits violate its ownership contract. ECHILD retires the original
record and reports lost ownership without inventing an exit or acting on a
reused PID. Completed events retain credit until consumed.

Signal operations validate the live token, then attempt an exact one-byte control
write. A short write or error falls back to native kill of that same unreaped
child. Failure preserves the original writer; `signal_report` retains the write
class and errno. Neither delivery nor a successful kill request proves processing
or death. The port never changes the parent's SIGPIPE handler or mask: default,
unblocked SIGPIPE can terminate the caller before an EPIPE fallback is reached.

ARM-self closes its newly created control writer after admission, matching its
source wrapper lifetime. Managed children retain theirs. The independent registry
keeps wait authority after the launching host borrow ends.

## Windows launch

Windows `NativeCommand` uses `gnunet-native::process::Spawn`: an absolute executable
path, independent argv0, literal arguments, explicit environment/cwd, three `Stdio` selections,
console policy and optional `ExportedHandle` entries. UTF-16 code units, including
isolated surrogates, are preserved. Arguments use Windows CRT quoting. There is
no implicit shell, executable PATH search or account switch.

Environment names use fallible native case-insensitive ordinal ordering. The last
explicit value wins; generated handle exports override explicit values of the
same name. Duplicate export names fail. Native per-drive directory variables are
preserved. Command, environment, argument and handle budgets are explicit.

Only private copies of the selected kernel handles become inheritable. The
CreateProcessW extended attribute list limits inheritance to those copies. Parent
originals, global environment, cwd and stdio slots are unchanged. A shared launch
lock covers the temporary inheritance window; callers exclude unrelated legacy
CreateProcess calls that inherit all inheritable handles during that operation.
All private parent copies close after the attempt, including refusal.

An exported environment value identifies the actual child copy in hexadecimal.
Recipients own that copy and clear its inheritance before unrelated launches.
This is a kernel-handle interface, not Winsock socket duplication or POSIX FD
activation. Detached creation selects the native console relationship; image
initialization, application admission and readiness remain separate operations.

## Windows exit notification

The registry retains the original process HANDLE returned by creation and never
reopens a PID. `ProcessWait` uses a kernel threadpool wait without polling timers
or a worker per child. Notifications are hints: a zero-time wait must establish
termination before GetExitCodeProcess supplies the full unsigned exit code.
Completed code 259 remains valid and is not confused with STILL_ACTIVE.

Registrations stay in the registry across canceled futures. Cancellation stops
native waiting and cancels queued callbacks. A running callback acquires its own
notification Arc and disassociates before locking or waking caller code; teardown
synchronizes only that initial acquisition, not arbitrary Wake code. Notification
state owns no process handle after native cancellation. The registry cancels its
registration and releases its own process-handle owner before publishing a
completion receipt. Explicit read-only `ProcessIdentity` or exit-observer loans
may pin the same object longer. Identity loans cannot wait or terminate;
`exit_observer` supplies a separate nonconsuming native wait without taking the
registry's reap credit. Neither reconstructs a process from its PID.

`terminate` requests forced termination of the original HANDLE with an unsigned
exit code. It is not a POSIX signal or an observed-exit receipt. Registration or
query failure leaves the original record available for handling/retry. Creation
failure installs no record and preserves the native error.

## Integration and verification

The [ARM host](../arm-std/README.md) composes the Unix launch/control interfaces.
Windows cooperative control and exact startup statuses use
[qualified private byte pipes](../service-startup/README.md#windows-parent-bootstrap)
above this registry. Write submission, actual parent receipt and observed exit
remain separate operations.
Remaining Windows service/supervisor composition and native qualification are tracked
in [implementation status](../../IMPLEMENTATION_STATUS.md). Process creation does
not establish those higher-level capabilities.

`cargo test -p gnunet-service-runtime --all-targets --all-features --locked` runs
the host's native cases. Windows standalone children cover literal arguments,
handle export, full-width exit codes, registry credit, stale tokens, canceled
waits and teardown while caller Wake code is blocked. These require execution on
Windows; cross compilation alone does not qualify their runtime behavior.

## Windows suspended setup

`spawn_suspended` records the original process and primary thread before startup.
`original` lends that exact process for native publication without reopening a
PID. `resume` consumes start permission once. `cancel_preparation` revokes it
following setup failure; resume failure also enters a non-retryable phase.
Neither transition creates an exit receipt. Explicit termination and actual
reaping remain available through the same registry token in every phase.

The registry reserves record backing before creation; native creation reserves
its process-owner allocation before admission. Drop closes local owners only,
including the original primary-thread handle. A suspended child must be resumed
or explicitly terminated/drained. Listener sharing follows the
[native activation contract](../native-std/SOCKET-ACTIVATION.md).

## Windows launch snapshots

`EnvironmentSnapshot` retains an explicit native environment and absolute working
directory under finite UTF-16/entry bounds. Its lookup is fallible and uses cached
native ordinal keys with last-input-wins duplicates, including per-drive entries.
It preserves isolated UTF-16 surrogates and never changes process-global state.
The snapshot is a launch context; native `Spawn` and the startup launch port still
perform their own complete admission and generated-hint validation.

`EnvironmentSnapshot::absolute_path` resolves root-relative and per-drive paths
from that same snapshot. `resolve_executable` checks explicit paths or searches
its PATH for bare names, allowing an `.exe` suffix when no extension was supplied.
It never consults ambient cwd/PATH or invokes a shell.

## Windows resource observations

`enable_resource_usage()` selects collection before any child admission. Each
selected child reserves its counter backing before native creation. Consuming
exit observation queries the same original handle before releasing it, and
keeps that result with the exit receipt. Disabled collection adds no per-child
counter allocation. `take_completed_with_usage()` and `reap_child_with_usage()`
transfer those observations; exit-only methods deliberately discard them.

CPU uses [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes),
converting native 100-nanosecond counters to microseconds. Memory uses
[GetProcessMemoryInfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo)
through its K32 entry. I/O uses
[GetProcessIoCounters](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessiocounters).
Each query preserves its own success or original error, including unavailable
memory information after exit. These values are neither Unix block/context-switch
counters nor wall-clock estimates. Query failure does not erase another field or
prevent the actual original-process exit from being consumed.
