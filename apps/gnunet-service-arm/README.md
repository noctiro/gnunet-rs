# ARM service executable

`gnunet-service-arm` runs the official ARM service over the shared
[host](../../adapters/arm-service-std/README.md) and bounded protocol state machine.
It accepts normal SERVICE options, including `-c CONFIG` and `-d`.
Protocol layouts follow the [central contract](../../spec/gnunet/README.md).

## Entry and startup

The entry files perform fresh-process platform actions before providers, runtime
registration or competing native owners. Unix captures inherited descriptors and
splits daemon startup before changing configured credentials. Windows captures
native activation and parent declarations, detaches a supervised console before
provider import when requested, and verifies the actual configured account.
Standalone Windows detachment uses the shared re-exec launcher; supervised
Windows detachment preserves the original process and control connection.

Both platforms use the same foreground reactor, selected logging, stop
subscriptions and cleanup deadlines. Readiness follows control/managed listener
setup, caller-pool preparation and settled default-start attempts. It does not
assert that managed children reached their own readiness. Parent EOF does not
request termination. Normal operation emits no internal READY/STOPPED lines to
stdout; diagnostics use the selected logger.

Unix ARM's original close-after-bind set is released after configured binding.
Windows imported listeners keep their original endpoints and backlog, and gain
no creator-path cleanup lease. The publisher retains source ownership until
qualified import/readiness or original-child retirement.

## Configuration and resource bounds

`BINARY`, `CONFIG`, `GLOBAL_PREFIX`, `GLOBAL_POSTFIX`, `PIPECONTROL`,
`IMMEDIATE_START`, `START_ON_DEMAND` and category selection use the shared
registry. `[arm-rust]` selects finite service/client/child/listener/frame/output
limits, work budgets and fixed `SHUTDOWN_GRACE`/`KILL_GRACE` targets. Both grace
periods default to five seconds. ABI selects `align8` or `align4`; 64-bit native
entries default to the GNU 64-bit `align8` wire profile.

Unix requires the shared `gnunet-arm-spawn-helper`, colocated with the executable
or installed in ProjectData's libexec directory. `SPAWN_HELPER` selects an
explicit path. Its command, environment and auxiliary budgets count bytes;
descriptor limits bound actual child mappings.

Windows creates the selected image directly from an explicit environment/cwd
snapshot. `MAX_COMMAND_BYTES` bounds local command text. `MAX_ARGUMENTS` includes
argv0; `MAX_COMMAND_UNITS` and `MAX_ENVIRONMENT_UNITS` count native UTF-16 units.
`MAX_ENVIRONMENT_ENTRIES`, `MAX_HANDLES` and `MAX_LISTENERS_PER_CHILD` bound native
resources. Unix helper, auxiliary-byte, environment-byte and descriptor options
are rejected on Windows instead of being silently ignored.

## Resource diagnostics

Optional `[arm] RESOURCE_DIAGNOSTICS` opens a normal output file and enables
collection before admitting any managed child. Open failure is a warning and
disables collection. Records remain backpressured until taken and written;
ordinary diagnostic queue limits do not discard them. Write/flush failure stops
the service and preserves its original error.

Unix records use actual consuming wait4 counters: configured BINARY(pid), CPU
seconds with three fractional digits, native maxrss, block operations and context
switches. Windows records label CPU microseconds, peak memory bytes, I/O operation
counts and transfer bytes. Each independent Windows query either supplies its
actual counters or records its native error. No zero or elapsed-time estimate
replaces a failed query. These platform records are diagnostics, not ARM frames.

## Shutdown and recovery

Normal self-stop keeps the original requester socket until child reaps and
formal listener/timer cleanup finish. Cooperative control and native termination
remain separate from observed death. Grace expiry forces original-process
termination and continues consuming waits. Repeated stop notices never extend
the first deadline.

Clock/native failures retire physical service I/O and perform bounded native
cleanup. `Unreaped` reports remaining native debt. Its `recovery()` provides native cleanup actions and consuming waits;
`into_recovery()` transfers the original registry with its dependent source/control
owners. The recovery API keeps that pair together, exposes original child tokens,
and releases auxiliary owners after recorded retirement. Retained exit/resource
observations remain available through `take_completed_with_usage()`.
Neither Drop nor an accepted termination request proves child death.

## Native tests

The Windows `windows_process` target launches the normal executable, verifies
qualified startup and managed `-d`, exchanges official TEST/LIST/STOP frames,
checks cooperative child shutdown, consumes the original service exit and reads
native resource records. It requires a Windows runner. Unix host process tests
require building the shared helper first. Current native qualification remains
tracked in [implementation status](../../IMPLEMENTATION_STATUS.md).
