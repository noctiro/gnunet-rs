# Standard RECLAIM SERVICE

`gnunet-service-reclaim` implements official RECLAIM IPC using the
[shared native SERVICE driver](../../adapters/program-std/README.md#service-startup).
It accepts `-c/-d/-h/-L/-l/-v` options and no positional arguments or private-key path.

## Configuration and startup

```sh
gnunet-service-reclaim -c gnunet.conf
```

The Unix and Windows entries capture inherited listeners and parent control
before other native owners. Unix applies `[reclaim] USERNAME` before completing
local endpoints; Windows verifies the configured process token and imports native
activation. `UNIX_MATCH_UID/GID` default to false. On Windows they require
owner or primary-group access on the original AF_UNIX listener. Standard TCP
ACL/TOLERANT policies govern TCP admission. The pinned `OPTION_NONE` selects
immediate shutdown.

The listener, Server, explicit OS provider and configured native clients
are constructed before readiness notification. READY retains the accurate
`namestore=client-not-yet-attached gns=client-not-yet-attached` description. Actual native attachment is a later original Connected/Source event; it is not
invented or made a new startup prerequisite. One original SharedClock Arc and
one caller-driven Resolver are shared with all providers and STATISTICS. The native CSPRNG is requested only by an admitted identifier operation, retaining
its platform error and never falling back to a different source. Zones
arrive only through existing ACL-controlled official IPC and retain original
zeroizing ownership. JWT presentation retains the
[provider authentication contract](../../adapters/reclaim-std/README.md#real-provider-path).

## Resource and provider policy

`[reclaim-rust]` keeps existing bounded resource/job/iterator/provider policies. New local diagnostic policies STATISTICS_TIMEOUT and STATISTICS_SHUTDOWN_GRACE
both default 5s, positive finite native targets. Resource/phase limits add no wire
fields. `TICKET_REFRESH_INTERVAL` remains the official setting; GNS recursion
remains 128, the pinned ordinary public API default. Production configuration can
keep explicit UNIX_MATCH_UID=YES rather than relying on absent-field defaults.

## Exact official persistent lookup counters

The subsystem is `reclaim`; every UPDATE uses the official persistent
flag. Persistence/processing belongs to the external STATISTICS service, and a
local whole write is never called a durable commit or remote acknowledgement.

* `attribute_lookup_time_total` — elapsed monotonic microseconds for actual
  referenced-attribute callbacks.
* `attribute_lookups_count` — number of those callbacks.
* `reclaim_authz_lookup_time_total` — elapsed monotonic microseconds for actual
  ticket-authorization callbacks.
* `reclaim_authz_lookups_count` — number of those callbacks.

Both authorization and reference lookups use ANY0 in the current business
planner. Their role is therefore read from the exact original Effect and its
ConsumeAuth/ConsumeRef phase by the new readonly LookupKind seam; it is not
inferred from labels, record types, logs or the eventual ticket result. After
native lookup admission, the original Query row keeps role, start Instant,
query/epoch/source/Effect and one callback-recorded bit. Only a matching valid
Answer, including zero records, increments its two counters once, before
fallible business record allocation/completion. Refused, Lost, cancel, late
cancelled results and mismatched identities never become callbacks. Source/slot
replacement cannot retag the original measurement. Elapsed uses the original
monotonic start, so UTC correction cannot fabricate a duration. Finite integer
overflow fences diagnostic publication without manufacturing a business result.

The publisher is a small native owner over the existing shared STATISTICS
handle, adapted from the admitted REGEX delta-owner pattern. One pending UPDATE
prevents mutation coalescing ambiguity. Local completion requires the same actual
connected epoch and whole-write/idle observation with no intervening loss. A
lost/expired/uncertain mutation is recorded as Unknown, physically retired and
never replayed on a replacement source. Four cumulative snapshots do not create
four new MQs or per-request threads. The original native hard is registered
before canonical waits and is never renewed by polling. STATISTICS failure
fences only that diagnostic owner; healthy business continues with the original
error/report retained for final propagation.

Selected logging uses the shared Reporter (same Logger/clock, single
thread), severity-stable site IDs, permanent first-error latch and original
registered waker. Signal/parent-control and logging failure stop original
business admission; cleanup runs outside callbacks and does not require a
successful canonical clock sample. Existing close_all retires IPC,
NAMESTORE/GNS and scan sources, retains exposure/Unknown facts and records
independent cleanup errors. There is no invented wire CANCEL/ACK or query replay. Normal stop then drains the frozen final statistics snapshot/Destroy under
its first finite native hard while Resolver stays alive, and only afterwards
attempts Resolver disconnect. Failure uses clock-free statistics abort and
retains its Unknown/report. Original business, cleanup, statistics, independent
Resolver disconnect and stdout errors have separate owned slots/source chains. Drop fallback performs physical retirement without claiming quiescence.
