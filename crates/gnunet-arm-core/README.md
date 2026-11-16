# Official ARM operation core

The core implements GNUnet v0.29.1 ARM/monitor messages and pure operation
ownership in safe, allocation-free `no_std` Rust. Native processes and service
composition belong to the [ARM host](../../adapters/arm-service-std/README.md);
command behavior belongs to the [ARM application](../../apps/gnunet-arm/README.md).

## Wire ABI

Use `wire::ArmAbi` explicitly. The normal native C build/full headers establish Message16, RESULT24 and LIST_RESULT prefix24 (uint64 alignment8), ServiceInfo28, STATUS8. GNUNET_NETWORK_STRUCT_BEGIN is empty; these ARM structs are not globally packed. The align4 profile gives20/20 and is implemented explicitly but has no normal32-bit platform interoperability evidence. Rust pointer width and no_std cross-compilation never choose the peer ABI.

The `normal_bytes.c` reference helper constructs frames with unchanged official
headers and native allocation/field assignments. `examples/wire_trace.rs`
exposes the Rust codecs for independent byte comparison.

Unknown result/monitor/list-status numeric values and nonzero existing reserved/padding bytes are accepted. Canonical encoders zero padding like MQ allocation. List indices may point into another string; every in-range eventual-NUL name/binary is checked before exposing rows, without UTF8 assumptions. The source C public exit status promotes ntohs to int, soFFFF becomes65535. Request totals65535 are legal and65536 rejects atomically. Legal framed unregistered directions are ignored per the owner handler registry; registered malformed input follows MQ-error processing.

## Caller state and host contract

`Client::new(operations, frame_slots, aggregate_tx_bytes, epoch, abi)` borrows initialized caller slices. Metadata is small, with one aggregate frame byte pool independent from65535 maximum individual frame width. Caller may safely fallibly reserve/initialize Vec backing or use no_std static slices. Nonzero epochs must not be reused resetting the same backing. Operation/connection/TX tickets carry original scope and non-reused generations. Finite slot/generation/wire-counter exhaustion refuses admission atomically; unlike C's theoretical uint64 wrap, a Rust owner never reuses an exhausted wire counter.

`take_effect(now)` leases real-MQ Connect, StartArm or CloseStartupSignal. Repeated calls retain the same outstanding effect. Report MQ creation/config failure separately from OS socket connection retry, then send the queued TEST. Only TEST confirmation sets currently_up. Pending failure callbacks drain before reconnect. Ordinary remote START/STOP/LIST have no implicit deadline and are not replayed after MQ loss. CANCEL suppresses callback authority while an already queued MQ frame still executes. Source-result callbacks with the other registered response kind retire silently when no matching callback type exists.

`take_frame`, `frame`, `frame_written`, `current_frame` retain original immutable bytes across partial writes/canceled drive calls. A host driver must persist its cursor and not report full frame write before completion. Local full write never means remote ARM processing. Aggregate compaction preserves a leased frame and old TX/MQ completions cannot release a replacement.

`receive` returns an owned Event or a successful List view borrowing the RX frame. Dispatch callbacks synchronously after each transition and drain next_event before further I/O. Callback authority retires before exposure. The list cannot outlive RX storage and a frame borrow cannot survive mutable write completion; exact-code UI tests plus successful controls check these public types.

ARM-self STOPPING becomes a waiter until MQ loss, then yields SentOk/Stopped before remaining Disconnected callbacks and connectionNO. This is the source API's MQ-loss observation, not waitpid proof of process death. A canceled waiter retains a callback-suppressed tombstone; Rust does not reproduce C's NULL callback. A second waiter uses the correct original operation for its NotKnown result instead of C's mismatched callback/closure. Explicit disconnect reclaims the separate waiter rather than retaining C's leaked object.

Local start of ARM itself when confirmed up queues asynchronous AlreadyStarted followed by a repeated connectionYES if still up. Otherwise StartArm requires a host report. The host must perform official configuration/libexec/command/stdio/signal-pipe work; the core never fakes it. A genuinely returned read pipe waits at most the original60s; readiness/EOF/expiration all notify the stored startup result, not a fabricated Timeout or readiness guarantee. Cancel/EOF during a leased startup retains original resource ownership until the report; cleanup closes only that original signal endpoint, never claims the child was stopped. Explicit disconnect closes the logical owner after immediate failure/resource obligations drain; returned MQ identity is a required host close obligation.

`Monitor` is separate, queues MONITOR rather than TEST, receives STATUS without an initial snapshot, preserves source current0/2ms/4ms…15min retry, and never resets it on status. The source5s INIT_TIMEOUT macro is unused and no artificial deadline is added. Real initial/retry MQ creation failures return explicit Unavailable observation (C service=NULL/statusSTOPPED); retry-time failure does not fabricate another retry timer. Stop returns the original MQ close obligation and rejects all later old-epoch input.

## Host interfaces

Current tests execute codecs and core transitions. They cover exact maximum request size, native ABI tails, count/pool bounds, queued cancellation, list/result routing, EOF failure ordering, local startup deadlines/reports, original cleanup authority, aggregate compaction, stale generations and monitor retry ceiling. No C UB experiment is performed.

`tools/public_pair.py` runs normal libgnunetarm and Rust owners in two
owned Unix scenarios. All eight C public functions are invoked; control callbacks,
monitor callbacks, outgoing frames and supplied peer bytes match per connection. Cross-connection interleaving is recorded without imposing a total order. This
fixture does not replace either production ARM daemon.

Native startup and readiness belong to the
[ARM client adapter](../../adapters/arm-std/README.md). Registry, listener,
child and shutdown ownership belong to the
[service host](../../adapters/arm-service-std/README.md). Platform and
interoperability qualification is tracked in
[Implementation status](../../IMPLEMENTATION_STATUS.md).
