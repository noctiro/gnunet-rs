# Interface and ownership

production types use `LocalLauncher<'registry>` and `ClientHost<'core, 'registry>`.
`ChildRegistry::new(capacity)` creates a caller-owned bounded original-PID and
SIGCHLD port owner. `LocalLauncher::new/with_environment` take
`&'registry mut ChildRegistry`. They never own/drop that caller's registry.
`reap_completed` and cancellation-safe `drain_children` are available directly on
the registry or forwarded while the host borrows it. Host/launcher cancellation or
Drop releases MQ/readiness resources but the caller immediately retains the same
original wait authority, and can drain it after Drop without killing the child.
The registry itself is an explicit process owner, like std::process::Child:
retain/drain it rather than intentionally discarding active children. No background
thread, arbitrary waitpid(-1), implicit daemon signal or unbounded Drop wait exists.

`MonitorHost::drive` also supplies a `MonitorContext` callback argument whose
stop method closes its original physical MQ immediately while borrowed STATUS
bytes stay alive until callback return. `CallbackContext::disconnect` likewise
closes physical resources immediately but dispatches remaining failure callbacks
after the current user callback, rather than recursively reentering user code.

The final code uses the new public `gnunet_ipc_unix::transport` façade exclusively;
all absolute staging `#[path]` imports were removed. Source holds immutable config
inputs across logical MQ recreation; Endpoint snapshots and ConnectionAttempt
futures remain owned per original MQ/socket attempt. Child helper arguments are
its cwd (empty means inherit native cwd), sampled native SIGPIPE inheritance
class, original closed/CLOEXEC stdio mask, then exact parsed target argv. The
fresh dedicated helper restores the sampled disposition and original closed
stdio slots before calling native `execvp` directly. Rust `Command::exec` would
reset SIGPIPE and is deliberately not used. Signal masks are inherited.
Only the fresh helper changes cwd; neither parent env nor cwd/FD flags change.
Native launch refreshes the environment and uses the formal process-global
`ProjectData::libexec_binary_path`; explicit isolated contexts use the caller-shared
`BinaryPathCache` through `libexec_binary_path_with`. The environment snapshot port
models a fixed parent-process context; it does not support
concurrent process-global environment/cwd mutation as an implicit configuration API.

Live configuration mutation is a remaining API gap. Official C retains a const
configuration pointer while callers may legally update that same configuration:
new logical MQs revalidate all endpoint inputs, and later Unix attempts within
one MQ reread UNIXPATH, while TCP host/port were cached at MQ creation. The current
owned Rust snapshot has no update port for those changes. Initial/static-config
comparisons do not establish parity for this branch; it remains pending.

Local request admission is synchronous and returns an operation ID; local OS setup
is performed by drive, preserving cancel/ownership across asynchronous Rust calls.
This is an explicit Rust reactor API decomposition, not a claim of C ABI or that
calling request_service_start without driving already forked a child. Once actual
setup starts it reports exactly one stored outcome and original read-end lifetime.
Canceled-before-setup requests never create a new child; already created children
continue and their caller-owned registry retains wait authority. Native public
comparisons must drive the admitted operation before matching setup/callback traces.

Bounded startup effects use the core's `take_effect_with_startup_capacity` port.
No new StartArm is leased without both a free signal slot and original child/wait
credit. Existing cleanup and MQ connect remain available. A genuinely leased
setup keeps that credit through an explicit pre-spawn error/retry. Actual spawn
outcomes are saved before core reporting so retry cannot duplicate a child.
The host polls its registry SIGCHLD port while a child remains outstanding;
reaping returns Activity so callers can consume wait metadata and release
credit even while an established MQ is quiet. Completed wait metadata retains
credit until explicitly consumed. All waits refer only to original owned PIDs.

Low-stdio safety is an explicit native representation difference: normal C can
reuse a closed original stdio slot for readiness, and then replace that very pipe
with /dev/null during stdio mapping. Rust lifts all private pipe sources and
reserved targets above 2 before mappings, then restores inherited original
closed/CLOEXEC stdio in the fresh helper. The 80-profile observation retains 62
matches and 18 C defects/differences separately; it is never 80 native
matches. This preserves usable readiness and safe ownership without inventing a
new GNUnet message, daemon readiness acknowledgement or business success.
