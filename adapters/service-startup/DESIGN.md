# Generic service startup: frozen design v1

This design follows v0.29.1 commit346358e26d4dcc2dc4f51bef5d52dca29c7d8165. It covers early descriptor ownership and process-local privilege primitives;
it does not declare the remaining generic service runtime complete.

## Three distinct parent channels

CLOSE_LSOCKS is service option bit4, not an environment variable and not a second
FD list. setup_service takes the single LISTEN_FDS/FDNAMES declaration, moves it
to csocks, binds configured listeners, and closes csocks after successful bind. It does not write a status byte. Failure also releases child ownership; EOF alone
cannot distinguish full startup success from failure. The close phase precedes
daemonization, USERNAME changes and application initialization.

The official ARM client actually creates a pipe and passes its WRITE end through
process_option_inherit_lsock. The misleading socket_box_native name checks only
fcntl(F_GETFD); it accepts that pipe. Thus CloseAfterBind capture validates unique
open inherited descriptors without requiring socket type. AdoptListeners retains
the current strict listener validation and its recorded safe differences. The two routes are mutually exclusive ownership variants from one early capture.

The internal daemonize pipe is different: its parent reads one byte. The child
reports '.' after registering service accept tasks and before service_init_cb;
initialization failure reports'I', and a scheduler/server that did not start
reports'S'. The field comment mentioning'!' is not the implementation. An unknown
byte or EOF means parent failure. These bytes are not Resolver/STATISTICS wire.

GNUNET_OS_CONTROL_PIPE is a third channel. os_process creates a READ end for the
child and exports its descriptor in hex, independently of LISTEN_FDNAMES. A byte
represents a process signal; the scheduler raises it in the child. The raw C
parser permits trailing text after initial hex digits. Capture accounts for this
channel in the same uniqueness validation, preventing aliasing with readiness or
activation. A control reader primitive owns it; service-loop signal
integration remains a separately listed obligation.

## Early ownership

A single unsafe capture_from_environment(mode) runs before opening config/log
files, runtime creation, account switching or other Rust owners for foreign fds. Its one-shot guard covers all outcomes. It reads the complete declaration and
control channel, validates every unique open fd before ownership transfer, rejects
aliases, and then routes exactly one owner per raw descriptor. Distinct descriptor
numbers that refer to the same kernel object remain distinct valid owners.

Foreign descriptors0/1/2 move to fresh CLOEXEC fds>=3 before dup2 restores the
advertised stdio slots to /dev/null. This keeps libstd handles from borrowing
listener/readiness/control resources. Every move is reserved before restoration. Failure after the first adoption/move is fatal startup failure, with no retry
using the same numbers. Owned Drop releases resources; no later close(rawfd) is
allowed. LISTEN_FDS is consumed, names/PID retained; the control hint is emptied
inside this fresh child only, mirroring the C channel consumption. Tests never
mutate the orchestration process environment or its credentials.

RebindHold::complete_after_bind requires a borrowed BoundListeners value, releases
only its owned inherited descriptors and reports the local phase. Drop/abort also
release them, without claiming success. It cannot be passed to the listener
runtime as an Activation. ReadyWriter takes an already owned fd, attempts exactly
one one-byte write, and releases ownership on every outcome. Neither
release nor write return proves that a parent processed the indication.

## USERNAME

The C option is fetched through get_value_filename, including native path/dollar
expansion, rather than raw get_value_string. A present invalid Rust configuration
is an explicit startup error rather than silently continuing as a different user. Account lookup preserves opaque Unix name bytes through uzers, returning an
explicit AccountUnavailable when native lookup returns no account/error. No
unreliable fabricated errno or UTF8 requirement is introduced.

The native sequence is exactly short-circuit setgid, setegid, conditional
initgroups, setuid, seteuid. If any primary step fails, execute setregid(gid,gid)
and then setreuid(uid,uid), again short-circuiting. C returns success when that
fallback succeeds even if initgroups failed. The result therefore reports its
branch and whether supplementary groups were initialized; it cannot claim
that every old supplementary group or saved privilege was removed. Failure may
leave partially changed credentials, so the startup caller must exit without
continuing or attempting a rollback. These operations affect only the service
process, after privileged listener creation and before asynchronous work/threads.

Maintained safe nix/uzers wrappers supply identity access and set-id operations. On Darwin nix omits initgroups; the only added raw ABI operation is libc
initgroups(CStr, c_int gid), in a documented native boundary. Linux can use nix's
safe initgroups. Existing pinned dependencies are nix0.31.3(user/fs), uzers0.12.2,
libc0.2.191, socket2 0.6.5 and the existing shared service-runtime types. No new
registry package is proposed. Raw fd borrowing/adoption and early environment
consumption remain the other audited unsafe boundaries.

## Inventory and pending work

inventory.json lists source-bound obligations for the complete native service
CLI/config/startup/logger/daemonization/scheduler profile. The exact standalone
service path differs from PROGRAM_run2 and registered/monolith startup. In
particular, service_run does not process GNUNET_ARGS, has no built-in priority or
nice option, and os_priority.c implements control/command helpers rather than
setpriority. Process priority is inherited; ARM PREFIX may launch an external
command such as nice, which is not a new service configuration key.

This batch implements and verifies descriptor and privilege primitives, not a
fork/reexec supervisor, full CLI parser, logging engine, parent-control reactor,
NLS/clock-skew setup or full scheduler lifecycle. Those remain pending entries,
not relabeled completed merely because an adapter rejects them. No workspace,
existing runtime source, frozen C source or old receipt is edited.

## Verification plan

Every native test uses a newly exec'd child and only its own transferred fds. Actual pipe EOF/readiness phase, low stdio relocation, duplicate/invalid/alias
refusal, failed own-bind release, descriptor-number reuse and one-shot behavior
are observed through parent-owned pipes and bounded loopback sockets. An unchanged
normal C public SERVICE_run caller supplies independent CloseAfterBind pipe and
USERNAME outcomes. Current uid/gid, missing user and process-local primary/
fallback paths are safe native cases. A clearly separate deterministic component
trace may inject syscall failures only to verify original C ordering; it must not
pretend a kernel privilege change occurred. No system account, DNS, /etc file or
external service is changed, and no privileged transition to another account is
tested in this environment.
