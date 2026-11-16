# ARM service host

`gnunet-arm-service-host` hosts the official ARM IPC registry, managed listeners
and process/timer state machine over `gnunet-arm-service-core`.
[gnunet-service-arm](../../apps/gnunet-service-arm/README.md) supplies the normal
SERVICE entry. Wire messages follow the [central protocol contract](../../spec/gnunet/README.md).

## Source and platform layers

| Module | Responsibility |
| --- | --- |
| `registry.rs` | Configuration selection, bounded native command recipes and borrowed core specs |
| `addresses.rs` | Native family probes, exact ARM resolution hints and endpoint ordering |
| `listeners.rs`, `listeners/bind.rs` | Original listener ownership, preparation state and one-shot core readiness leases |
| `framed.rs` | Retained official frame cursors and bounded output FIFO |
| `process.rs`, `process/` | Typed platform launch context, original-child registry bridge, native image selection and retained control state |
| `reactor.rs` | Public state, borrowed driver and resource limits |
| `reactor/children.rs` | Original process launch, signal and consuming-reap settlements |
| `reactor/clients.rs` | Accepted sources, RX/TX and output handoff |
| `reactor/timers.rs`, `reactor/drive.rs` | Absolute restart targets, bounded settlements and source rotation |
| `service/` | Shared configuration/foreground/diagnostics, platform startup and native limits, recovery owners |

Registry, address collection, framing, managed listeners and reactor scheduling
share code across Linux, macOS, FreeBSD and Windows. Unix uses the shared exec
helper and consuming PID waits; Windows uses native image creation, provider
activation, qualified bootstrap and original-handle waits. Standalone SERVICE shares its foreground loop with
separate Unix/Windows startup and native limit profiles. Native qualification and remaining entry points are
tracked in [implementation status](../../IMPLEMENTATION_STATUS.md).

## Configuration and public ownership

`Registry::from_config` selects configured services and composes immutable
recipes. Missing category switches enable both system and per-user services.
Explicit selection, `IMMEDIATE_START`, `START_ON_DEMAND`, `NOARMBIND`, `PIPECONTROL`,
prefixes, options and per-service configuration retain their documented source
meaning. Source-form GNUnet commands and SIMPLE executable/argv0/whole-options
remain distinct. Local native bytes are not protocol text.

The caller owns Registry/spec views, core scope/slots/frame storage, formal
Owner, ManagedListeners, a dedicated external ChildRegistry, State, LIST scratch,
a typed `process::LaunchContext`. Unix contexts borrow configuration, helper and
environment; Windows contexts borrow an explicit native environment/cwd snapshot.
Driver only borrows them. Reborrowing a driver
retains original native capabilities, pending receipts, RX/TX and timers. Owner
identity and immutable registry bindings are checked independently of slot reuse.
An unrelated live/completed child never becomes a successful ARM reap.

## Native command arguments

Windows normal-service recipes preserve the binary and fixed configuration/debug
arguments as native strings. Only configured prefix/options fragments use the
shared GNUnet command parser. The shared process layer composes the argument array
and resolves its image against the explicit environment/cwd, so native path
backslashes and spaces never pass through Unix escaping. Explicit textual recipes
retain their documented parser contract.

## Listener preparation and cancellation

`bind_registry(...).await` and `bind_address(..., LocalListenerAccess).await`
prepare actual native endpoints. Whole-registry preparation starts once and
reports `NotStarted`, `Incomplete` or `Complete`. Cancellation or failure retains
all earlier listeners; restarting preparation from zero is refused. Drop the
retained owner to abort. Nonfatal endpoint failures remain inspectable even when
preparation completes.

Local paths and access are prepared through the shared
[listener boundary](../service-runtime/README.md#configured-local-listeners).
Unix uses private modes; Windows uses owner/primary-group/Everyone DACL policy.
TCP uses Unix address reuse or Windows exclusive address ownership. IPv6-only
and backlog settings are applied before reactor registration. Inherited listeners
acquire no new pathname cleanup authority.

Readiness observes the original listening socket without accepting or reading.
A canceled wait retains its registration and one-shot lease. A child later
inherits the original listener and consumes backlog itself. Closing a listener
releases its socket before its owned path guard. See the detailed
[reactor ownership contract](REACTOR.md) for source retirement and shutdown.

## Process, output and error contracts

Native admission proves process creation; it does not prove exec, readiness or
remote work. Admitted children enter both native and core mappings before
fallible later acknowledgements. Consuming exit observations remain retained
until acknowledged. Capacity refusal creates no ghost child; original setup,
clock, I/O and cleanup failures retain their causes. Native recovery retains
private publisher descriptors and control owners together with the original
registry, including children that have not confirmed import.

Output handoff copies a complete borrowed frame before releasing its ticket.
Partial frames/writes retain cursors. A blocked client cannot prevent another
source's close or original child retirement. RX/TX and source classes rotate;
empty TX and disarmed listeners do not suppress idle restarts. A timer retains
its original UTC target and native subscription across canceled waits and clock
changes. Cooperative settlement yields preserve unfinished effects.

Managed listeners close before shutdown stop effects. Manual drain keeps ARM control
IPC available until final cleanup. Persisted self-stop requester sockets remain
owned until explicit State drop. Original child registries must be drained even
when a driver view is dropped.

## Reference tools

`tools/verify.py` covers native listener profiles; `tools/reactor_verify.py`
adds current-source C/Rust client/daemon combinations. Both require an unchanged
normal official C build receipt. Generated sources, binaries and logs belong in
a fresh directory beneath the repository's `target/` tree. The template mirrors
current dependency kinds, features and platform guards; a mismatch is a failure.

On Unix, host process tests require building the shared helper first:

```sh
cargo build -p gnunet-arm-host --bin gnunet-arm-spawn-helper --locked
cargo test -p gnunet-arm-service-host --all-features --locked
```

The Windows `windows_reactor` target uses fresh native child processes, private
working directories and loopback listeners. It covers queued listener transfer,
qualified readiness, canceled driver reborrowing, cooperative control and native
termination followed by consuming exit. Cross compilation checks its source;
execution requires a Windows runner.
