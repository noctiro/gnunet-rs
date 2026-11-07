# Native CORE client

`Client<P,S>` and `Monitor` drive official CORE application and monitor IPC over
the existing CLIENT endpoint and common `Framed` owner. Construct with an external
pure `Instance`, subscriptions, explicit `EndpointSource`, and finite `Limits`. The source selects the canonical process clock and Resolver domain. No resolver,
background task, callback registry, CORE service implementation or NSE owner is
created here. SDK feature `official-core-client` exposes `core_client_host`
independently of `official-core`.

`Message::copy_from` creates an immutable, securely erased original source. `Message::try_from_owned` freezes an existing Vec without copying; refusal returns
that unchanged Vec to its caller. `send` retains that same `SendOperation<Message>`; no source is regenerated or
automatically replayed after loss. Retained source allocation capacities (including spare bytes), operation metadata,
retained outgoing frames/bytes and complete receive frames are separately bounded. Every payload write updates the pure original owner before another input
frame can be processed. Full local writing is not remote application delivery. The terminal `Finished` action returns the original source allocation.

`Activity.payload` is a private-minted per-send `PayloadWrite`, present only
after positive CORE_SEND bytes. It retains the original epoch, peer,
SendId and cumulative byte range; INIT and send-request bytes have no such
receipt. `Finished.payload` retains exact zero/partial/full physical state. These counts include the local IPC envelope and never assert remote receipt. `request_available` observes original request/frontier/native allocation capacity
without reserving it or consuming an ID. This local admission observation is
separate from the later wire SendReady. `poll` and `clock` expose the same driver
and source clock for containing coordinators.

Canceling a `drive` future preserves original attempts, timers, partial RX and TX. A waiting deadline expires only that wait. `cancel` removes only a wholly
unwritten prepared payload; its already admitted request still drains. A started
payload drains its immutable suffix or its whole physical MQ retires. Peer loss
makes an unstarted payload terminal so that it cannot be sent to a newer peer
generation. Partial payloads retain uncertain delivery semantics.

All events carry original physical epoch authority, and peer events, traffic and
completions retain peer-generation tokens. `Ready.local` is the actual
self-loopback peer. MQ loss retires the original physical owner before pure loss,
then `drive` returns old sources and all old peer-loss notices before another
epoch starts. `close` uses that same draining path before returning `Closed`. The caller should drain it when it needs terminal results rather than dropping
the entire client.

A pure receive capacity refusal returns `Capacity(epoch)` and retains the exact
complete original frame. Repeated calls do not partially apply it. Pending
operation completion can free capacity; persistent peer/tombstone exhaustion may
require explicit `reconnect`. A disconnect of one peer never automatically closes
healthy peers' shared MQ. Unsettled same-PID finite request frontiers survive
same-MQ reconnect, bounded by P and the existing unanswered-ID window.

Clock, timer and Resolver refusals preserve their original marked cause until
explicit `recover_ports`. A permanently closed application or monitor refuses
recovery and cannot acquire another clock listener. Recovery replaces only the refused original port work;
it does not swap clocks, invoke hidden host DNS or replay application messages. A complete traffic frame is copied into bounded owned output before the pure
receive consumes it; allocation refusal leaves the original RX frame retained.

The Unix tests cover partial cancellation, exact original sources, loss
and reconnection ordering, canceled waits, retained capacity and source-port
refusals. `native-core-probe` exercises this driver against unchanged normal C
CORE application/monitor IPC. These profiles do not establish remote CAKE,
complete CORE service, native NSE or complete node interoperability.
