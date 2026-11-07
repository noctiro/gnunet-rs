# PROGRAM design

## Modules

- GETOPT owns option tables, native argument bytes, permutation and once-only cleaners.
- Configuration observers route diagnostics synchronously through the selected logger.
- Logger owns policy, append/rotation files, callbacks, source metadata and formatting.
- Locale uses the selected trusted native gettext provider.
- SharedClock exposes one canonical authority and separate subscriptions.
- Scoped execution owns bounded tasks and original generation-bound task IDs.
- DAEMON registration snapshots a launch before reserving scheduler capacity.

## Ownership

Preparation returns either a main capability or an early option-processing result.
A positive parse index alone cannot grant main authority after logging failure.
Callbacks observe borrowed configuration without retaining a logger or a mutable
guard across async work. Local diagnostic observation overrides the persistent
observer for that operation, avoiding duplicate output.

Logger files and process stderr are separate resources. Process locale/stderr
installation requires its native capability; dropping an ordinary logger cannot
claim to restore process-global state. Normal resource errors are typed results.
A fail-stop is limited to a broken declared native invariant.

Tasks are polled by the caller. Stop/Drop retires pending work outside bookkeeping
borrows; original TaskIds cannot cancel a replacement run. Clock/Resolver startup
and cleanup belong to that execution scope.

The single-thread Reporter shares the selected logger/clock, retains its first
failure and wakes the waiting task. Taking an error does not clear its failure
latch. Applications own their bounded shutdown after reporting failure.

See [public interfaces](API.md), [native contracts](NATIVE-CONTRACT.md) and
[locale behavior](LOCALE-INVENTORY.md).
