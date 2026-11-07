# Standard TCP statistics production composition

The standard app injects the shared Producer with subsystem
`communicator-tcp`, six exact pinned official names and nonpersistent flags. Runtime/pure code have no IPC/statistics protocol dependency. The app alone owns
that concrete publisher; no hidden task, second broker or replacement clock is made.

`foreground_prepared_with_services_and_statistics` attempts the factory once,
after the original Stop/Logger/native guards and before any peer class can produce
a nonzero baseline. Business Ready follows that attempt; it does not require the
asynchronous STATISTICS MQ to be connected. Constructor/source failure fences only
that publisher while healthy TCP continues. Explicit embedding entry points use
NoStatistics; the installed app supplies the genuine Factory.

The publisher has a seventh fair class beside PILS, Pool, address publication,
reversal, accepts and original CREATE. Its native guard also runs before the loop's
canonical close transition, and before each Resolver/event wait. Snapshot refresh
submits no IO or success fact and cannot extend an admitted mutation's deadline. No source is recreated after Unknown, no relative delta is replayed, and logger
failure aborts the original publisher before another IO class.

Snapshots come from the Pool after construction, each selected poll
(including error/terminal polls), and immediately before consuming its real
quiescence proof. They are retained outside the Pool scope. A forced abort retains
the last still-owned inventory, not an invented zero after Drop. Normal
retirement reads the empty live inventory and accumulated retired counters. The replay-recovery Manager/Pool consumer retains original Session counters exactly
once at retirement, using the common plain-u64 Metrics API.

Only after the original business scope ends does the publisher freeze final
coordinates once, with a separately fixed five-second drain hard. Error/clock/
logger stop uses clock-free abort. The original replay::finish future remains
pinned and polled until its worker drain/join completes, without cancellation
or a new grace. Its surrounding observation wrapper checks the original publisher
hard first and fairly drives that publisher plus the SAME Resolver while waiting. After worker completion, remaining original statistics debt drains under that
same hard; the original broker disconnect comes last.

`StatisticsReport<R>` preserves the TCP report, last metrics and
native publisher report separately. `StatisticsFailure<E,R>` retains the original
TCP/worker/frontier error, successful TCP report if an independent owner failed,
statistics first/cleanup failures, native write/Unknown/Destroy report,
Resolver-drain failure and original disconnect refusal. No frame whole-write,
processing acknowledgement or persistence is guessed from diagnostics or idleness
outside the existing shared Producer contract.

Queue timing uses the Rust local QueueAdd/Delete lifecycle rather than the C
queue map's temporary handshake allocation. Counter observations are component
checks and do not establish native TCP, NAT, crypto or storage interoperability.