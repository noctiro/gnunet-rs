# ARM complete source-derived scope and first core

Baseline: v0.29.1,346358e26d4dcc2dc4f51bef5d52dca29c7d8165.

## Public surface

`gnunet_arm_service.h` exposes `connect`, `disconnect`, `operation_cancel`,
`request_service_list`, `request_service_stop`, `request_service_start`,
`monitor_start` and `monitor_stop`, with connection/result/list/monitor callbacks.
The [public API inventory](../../spec/gnunet/api/README.md) tracks declarations;
declaration presence does not prove runtime behavior.

`gnunet_testing_arm_lib.h` is a separate testing library, not silently omitted: start-peer/stop-peer commands and2 generated get/make trait pairs (arm_handle/config), macro expansion and interpreter/testbed/config/process ownership remain host/testing integration scope. The CLI also remains distinct: end/init/kill/all/start/restart/delete/monitor/quiet/timeout/info/no-stdout/no-stderr. Its `-T` deadline is not a library request timeout.

## Exact wire

All semantic fields are network byte order except names/string-pool bytes. ARM structs themselves are not globally packed: GNUNET_NETWORK_STRUCT_BEGIN is empty. Actual normal-build flags/full unchanged headers prove ARM_Message16 align8, Result24, ListResult prefix24, ServiceInfo28 align4, Status8. `ArmAbi` is explicit; the align4 profile encodes Result20/List20 but has no real32-bit platform interoperability proof yet. Neither Rust pointer width nor thumbv6m compilation selects a peer ABI. Tail padding is accepted even nonzero, never treated as a new reserved field. Canonical output uses zero allocation padding as C MQ does. Common size/type header is4 bytes, total legal maximum65535. `GNUNET_MAX_MESSAGE_SIZE` is65536 and change_service rejects total>=that constant. No scope/version/private header/cancel is added.

| Assignment | Direction | Complete layout |
|---|---|---|
|8 START|client→ARM|header4,reservedBE32,request_idBE64,name+NUL; minimum17|
|9 STOP|client→ARM|same16-byte prefix+name+NUL|
|10 RESULT|ARM→client|header4,reservedBE32,idBE64,resultBE32,4 native tail-padding bytes; exact24 for proven align8 profile|
|11 STATUS|ARM→monitor|header4,statusBE32,name+NUL; minimum9|
|12 LIST|client→ARM|header4,reservedBE32,idBE64; exact16|
|13 LIST_RESULT|ARM→client|header4,reservedBE32,idBE64,countBE16,6 native prefix-tail bytes; fixed24 for proven align8 profile, then count×28 entries and string pool|
|14 MONITOR|monitor→ARM|exact header4|
|15 TEST|both|exact header4|

One28-byte entry: name_indexBE16,binary_indexBE16,last_exit_status16,padding16,statusBE32,restart_atUTC64,last_started_atUTC64. String indices are offsets relative to pool after all entries. Source `pool_get` permits indices inside another string and overlapping strings; only in-range index plus an eventual NUL are checked. Count0 plus unused trailing bytes is accepted. Nonzero reserved/padding and unknown result/status values are preserved/ignored as in C, not rejected. C native ServiceInfo `last_exit_status` receives `ntohs` promoted to int, so FFFF is65535; the Rust public projection must not silently change it to-1. Variable names require final wire NUL but effective name stops at first interior NUL. Fixed registered-message tails are malformed; legal unregistered message types are ignored by the corresponding owner handler registry.

Anchors: arm.h41..163; arm_api349..462; arm_monitor_api135..179; gnunet-service-arm1145..1448,2208..2231. Request stdio inheritance is never encoded: it is used only for local start of ARM itself.

## Control owner

C `GNUNET_CLIENT_connect` creates an MQ before OS connection; the core's connection epoch therefore names the MQ, not an individual socket connect attempt. Successful MQ creation queues TEST. `currently_up` becomes true only on TEST confirmation; duplicate confirms have no connection callback. Request counters start1, skip0 on wrap and survive MQ reconnection. Ordinary remote operations have no timeout and are not replayed after MQ loss. Request matching uses BE64 IDs, with independent bounded internal slot generations. CANCEL only suppresses callback; an already queued request remains an MQ envelope and can still execute. Unknown reply IDs are ignored. Receiving the other registered response kind retires the found operation without a callback if its callback type is absent in C; it does not invent a type failure wire result.

On MQ error: complete a pending ARM-self-stop first with SentOk/Stopped, then fail pending operations in original order with Disconnected (result/list undefined), then connectionNO; schedule reconnect at current backoff, then double max(1ms,current) capped15min. Initial current backoff0 means first reconnect delay0, next2ms,4ms. TEST success does not reset it. Explicit disconnect fails ordinary pending callbacks, destroys MQ and reconnect task, and suppresses future callbacks. Source's separate stop waiter is not traversed/freed by explicit disconnect; Rust must reclaim/suppress it rather than reproduce the leak.

Stopping service name arm is case insensitive. Its STOPPING reply is not delivered immediately; move that operation to an EOF waiter. Any subsequent MQ error yields Stopped per the C API, which is an IPC loss observation, not waitpid proof of process death. Cancel that waiter suppresses its later callback while retaining the tombstone until EOF. Source C unconditionally invokes that callback on EOF, so cancellation can lead to NULL invocation; do not reproduce that undefined behavior. If two ARM-stop waiters collide, source uses a mismatched callback/closure for the older waiter; retain correct original logical ownership and document the safe discrepancy.

Starting a non-ARM service is ordinary START, and stdio flags are ignored. Starting ARM when confirmed up schedules asynchronous AlreadyStarted, followed by another connectionYES if still up after callback. When not confirmed up, emit an explicit local host StartArm effect carrying original operation ID and raw inherited-stdio flags. The host actually creates signal pipe, expands [arm] BINARY/PREFIX/OPTIONS/CONFIG, selects native libexec path, applies TESTING WEAKRANDOM/HOSTFILE daemonize rule, executes command and reports the result. STARTING requests reconnect if no MQ. A signal read endpoint waits at most60s; readiness/EOF/timeout all notify the stored starting result without reading a protocol payload. It does not transform timeout to failure or prove readiness. Pipe-creation failure schedules notification immediately. Operation cancel closes its signal endpoint and suppresses callback but never claims the spawned child was stopped. The original60s deadline must survive host drive cancellation and unrelated later activity.

Pure API is a caller-owned bounded Client owner, independent Monitor, queued frames stored in an aggregate byte pool, scoped operation/connection/TX tickets, explicit MQ admission/loss and host-start reports. Callback completion events have no fabricated undefined values: disconnected Result/List variants carry no successful payload. Successful list view borrows the complete input frame; it cannot escape callback/RX ownership. Host callbacks occur synchronously after each core transition; completion retirement occurs before exposing the event, preventing double free and stale cancel authority. No detached tasks or hidden OS clocks.

## Monitor owner

A distinct handle creates its own MQ and queues4-byte MONITOR. It accepts only STATUS, including numeric unknown statuses and raw/non-UTF8 effective C-string names. No initial snapshot: service sends only status0/name arm after subscription. On MQ error destroy MQ and retry current0,2ms,4ms...15min, without reset on notification. A failed `GNUNET_CLIENT_connect` creation invokes service=NULL/statusSTOPPED and returnsNULL at initial construction; a retry-time configuration failure emits that observation and does not schedule a new reconnect task in C. INIT_TIMEOUT5s macro is never used and must not become a Rust timer. Stop destroys MQ/task and all later old-epoch events are rejected.

## Daemon/service lifecycle and host closure (not claimed implemented by first client core)

Service discovery scans every configuration section except arm, requires BINARY, classifies RUN_PER_USER and global START_USER_SERVICES/START_SYSTEM_SERVICES. Both absent enables both; explicitly disabling both errors. Per-service CONFIG then PATHS/DEFAULTCONFIG is used only if stat succeeds. Initial backoff1ms, restart_atFOREVER, force_start from IMMEDIATE_START; NOARMBIND skips listeners only for immediate services; otherwise START_ON_DEMAND gates binding. PIPECONTROL sets process flags.

ARM separately owns child listen sockets, does not accept the queued connection, and passes every descriptor to a child. Readability triggers spawn; spawn pauses all read-watch tasks. Bind uses PORT/UNIXPATH/BINDTO/DISABLEV6/abstract paths/native longpath/perms/V6ONLY and backlog5. Explicit START sets force_start before checking existing proc, returns AlreadyStarted if present, otherwise spawn determines Starting/StartFailed. Stop arm broadcastsStopping, repliesStopping,persists that client, then manual global shutdown. Other STOP clears force_start before in_shutdown, handles unknown/shutdown/alreadykilling/alreadystopped, otherwise broadcastsStopping/signalsTERM and waits for reaping beforeStopped result. EOF clears only killing_client pointer; service/process still completes, no cancel frame.

Process command construction uses per-service PREFIX or GLOBAL_PREFIX, GLOBAL_POSTFIX with all{} substitutions then serviceOPTIONS, dollar expansion, DEBUG and TYPE GNUNET/SIMPLE. SIMPLE gets no GNUnet flags; GNUNET uses libexec binary and optional -c/-LDEBUG. Stdioout/err inherited, PIPECONTROL optional. A successful run command records UTC start and broadcastsStarting; it is not readiness. A failed run command destroys proc and reportsStartFailed, without pretending listeners were rearmed by that function.

Child death is SIGCHLD self-pipe+nonblocking wait/wait4 (optional resource diagnostics). Ignore still-running/stopped/unknown. Actual exit/signalled destroys proc,broadcastsStopped, completes original killing client, then either frees during shutdown or updates last_exit_status. Normal exit0 sets restart_at0 and rearms demand watchers, without directly scheduling force-start restart. Abnormal exit reduces backoff by minute count calculated from source's restart_at (not last_started_at), schedules now+reducedbackoff, doubles future backoff, and schedules idle delayed restart. Preserve/report that exact source calculation rather than silently correcting it. Delayed restart spawns force-start services when due, otherwise rearms demand listeners; earliest future restart determines next wakeup. ServiceInfo status derives proc present/killing/globalshutdown versus neverstarted/lastexit0/nonzero. Source does not synthesize status3/4 result codes merely because enum values exist.

MONITOR subscriptions use optional notification queue1024 and may drop notifications under pressure. All ARM clients are marked generic monitor clients. Default generic flags are MANUAL_SHUTDOWN|CLOSE_LSOCKS. Global shutdown cancels restarts, closes all owned child listeners, TERM-signals running children, frees alreadydown services, and defers final generic shutdown until all children are actually reaped. No timeout/escalation-to-KILL is invented. Self-stop client remains persisted so IPC closes after service teardown. GLIBC malloc tuning and optional wait4 diagnostics are separate platform surfaces.

## Tests

The first candidate implements codec/client operation/monitor state only, using current gnunet-types/wire; no new external/noalloc dependency. Tests use literal official bytes and bounded state methods. Native spawn/exec/fd inheritance/config/readiness pipes/waitpid, daemon process inventory and CLI/testing wrappers remain explicitly pending, not automatically complete because pure types exist. Future ordinary-user C probe should use self-owned Unix peers or harmless local mock child; never public DNS, system daemon management or account/configuration changes.
