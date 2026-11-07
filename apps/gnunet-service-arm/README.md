# gnunet-service-arm

standalone ARM SERVICE entry; `gnunet-arm` remains the separate client. The app exclusively captures CLOSE_LSOCKS descriptors first, uses shared SERVICE
c/d/h/L/l/v parsing and selected Logger, then the shared fresh-process daemon
split. No fixture program or foreign C service is launched as ARM itself.

The host loads standard [arm] configuration, performs configured USER
transition, binds its configured control listeners, closes only the original
inherited close-set, and runs the ARM reactor/process backend. That early
EOF is only own-listener startup ownership release. A detached parent receives
its separate ready byte only after control/managed listeners, SIGCHLD
port, caller pools and original default-start attempts are settled (Serving). It is not proof that children reached their own readiness.

Use normal SERVICE options, for example `gnunet-service-arm -c CONFIG`, with
optional `-d`. Runtime execution was not performed during source preparation. The reviewed `gnunet-arm-spawn-helper` must be colocated or installed in the
ProjectData libexec directory; [arm-rust] SPAWN_HELPER explicitly selects another
reviewed path. BINARY/CONFIG/GLOBAL_PREFIX/GLOBAL_POSTFIX/PIPECONTROL/IMMEDIATE_START
and service category selection are handled by the existing registry.

[arm-rust] exposes finite MAX_SERVICES/MAX_CLIENTS/MAX_CHILDREN/MAX_LISTENERS,
ADDRESSES_PER_SERVICE, FRAME_BYTES/FRAME_SLOTS/TX_BYTES/TX_FRAMES, IO_SLICE_BYTES,
SETTLEMENT_BUDGET/DIAGNOSTICS, command/environment/argument/descriptor budgets,
and SHUTDOWN_GRACE/KILL_GRACE (both5s by default). All combined cleanup targets
are checked and fixed at the first stop, never renewed by another signal. ABI is explicitly align8/align4; only known64-bit Unix C layouts default align8. No32-bit interoperability qualification is implied by allowing explicit align4.

Healthy manual shutdown preserves the self-stop requester's original socket
until child reaps and formal listener/timer cleanup finish. TERM uses the
normal shared pipe-first policy. After original TERM grace, exact original
children receive native SIGKILL (bypassing the signal pipe); successful kill is
never counted as death. The same reactor consumes exits before normal
source closure. Clock/native failures take clock-free physical IO retirement
and bounded original-native cleanup. Remaining uninterruptible/unowned waits
cause failure with an Unreaped error retaining the ChildRegistry; a PID
list or signal result is never called successful reap. A fresh process exits
failure with that explicit debt; an embedding caller may recover the registry.

Optional [arm] RESOURCE_DIAGNOSTICS opens the requested ordinary log file and
enables shared exact-PID wait4 collection before any managed child. File open
failure is a warning and disables collection, as in C. Every usage
record is retained in a single backpressured slot until the foreground takes
and writes it; ordinary diagnostic queue overflow cannot silently lose usage. The configured BINARY(pid), user/systemseconds to3decimals, raw maxrss, in/out
blocks and voluntary/involuntary switches use kernel data. CPU conversion
uses correct microseconds/1e6 rather than C's10e6 fractional-time defect. Maxrss
keeps native units (macOSbytes/LinuxKiB). Write failures are reported and stop the
service; no zeros or elapsed-time estimates substitute for missing rusage.

Native supervision and official
ARM interoperability remain unqualified; successful compilation does not prove
runtime readiness, child termination or complete GNUnet interoperability.
