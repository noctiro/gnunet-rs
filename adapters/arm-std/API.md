# ARM host interfaces and ownership

## Control and monitor

`ClientHost<'core, 'registry>` borrows caller buffers through the pure ARM
`Client` and borrows the independent native child registry through `LocalLauncher`.
`MonitorHost` owns a separate logical and physical MQ. Both expose cancellation-safe
`drive` calls with a caller-selected wait bound and synchronous borrowed callbacks.

`CallbackContext` admits operations and can cancel their callback authority or
disconnect the original owner. Disconnect closes physical IPC immediately;
remaining failure callbacks drain after the active callback returns, without
recursive callback entry. `MonitorContext::stop` closes the original monitor MQ
while STATUS bytes stay borrowed until the callback returns.

A canceled drive future preserves connection attempts, frame cursors, timers and
original callback identity. No wire request is replayed to compensate for future
cancellation. Checked LIST/STATUS data cannot outlive its synchronous callback.

## Local launch

`LocalLauncher::new` owns a configuration snapshot and captures the native
process context. On Unix its arguments include the explicit helper path; on
Windows it uses the shared native process producer directly. `with_environment`
selects an explicit environment/cwd and caller-owned `BinaryPathCache`.
`command_plan` performs preparation without starting a child.

Requesting local ARM start admits an operation. A later drive performs the
original launch effect once and records its real result before reporting it to
the core. Setup diagnostics remain separate from official `NotKnown`, `Failed`
and `Starting` outcomes. Process creation alone is not exec or service readiness.

Unix retains the source readiness-pipe readability/EOF and timeout behavior.
Windows observes actual qualified bootstrap readiness; peer exit, EOF and a
startup failure byte remain errors. Its launcher uniquely owns each pending
bootstrap and publishes an immutable completion observation to the operation.
Cancel/disconnect can release that observation without abandoning the bootstrap.

## Native child ownership

The caller creates and retains `ChildRegistry`. The launcher forwards
`reap_completed`, `take_reaped`, `pending_children` and `drain_children` while it
borrows that registry. Windows `settle_startups` advances only pending bootstrap sources and can
finish while the service remains alive; `drain_children` also waits for child exit; retain the launcher until those sources are settled. Explicitly consume
completion receipts to release finite registry credits.

Cancellation, disconnect and Drop never signal or wait for a live child. Failed
native launch setup can explicitly request termination of an already admitted
original process; its actual exit still requires consuming reap. Windows retains
the original HANDLE and full exit code; Unix retains original PID/wait authority.
No process is reopened by a reused numeric PID.

See the shared [process contract](../service-runtime/PROCESS.md) and
[configuration read points](LIVE_CONFIGURATION.md).
