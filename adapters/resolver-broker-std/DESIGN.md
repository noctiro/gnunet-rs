# Shared process Resolver broker

The pinned official source hashes and complete public/behavior inventory are in
inventory.json. The shared broker is integrated into workspace constructors;
full subsystem acceptance still requires the remaining recorded obligations.

One `broker::<R,N>` returns cloned `Context` admissions and a unique `Driver`. All clones share the gnunet-client ResolverHandle, remote FIFO, counter,
backoff and timer state. One driver owns the MQ stream, original connect
future and RX cursor. Shared State owns preallocated immutable MQ envelopes,
so source-synchronous Context admission commits them before returning even if
no later driver poll occurs. The unique driver alone advances their TX cursors. Nothing starts a background task. The wire remains official type4/type5 with the caller's explicit AF profile.

`connect(Configuration)` owns a new selected cfg identity; `connect_live` retains
an explicitly mutable store. Selection resets backoff1ms without wake/I/O or
replacement of a live MQ. Admission reads current selected check_config without
resetting backoff, using the core's dedicated admissibility port. New MQ creation
validates current selection and caches TCP; its later Unix attempts retain that
MQ's original live store even if selection changes elsewhere.

MQ resources differ from operation slots: an expired head's already-copied
message survives in the MQ even when the next head is submitted. Shared State has
an immutable bounded envelope queue, and Context reserves a remote MQ credit
before acceptance. A credit survives as long as the original remote core slot
or its orphan envelope exists. It is never released merely because a callback
slot was freed. Frames are preallocated; all fallible buffer construction occurs
before use. Failed capacity admission consumes no new core ID. Queue pressure
cannot block draining the very frame needed to regain progress.

Queries expose one callback-duration `Delivery` lease. It owns copied raw name
bytes in a preallocated reusable scratch and borrows its Query until returned. While a lease is held, the driver's next core callback/timer effect is blocked,
so cancellation/reconfiguration during an address/name callback happens before
the next buffered value or END. Dropping only a waiting future preserves the
query; dropping Query cancels its original authority. Dropping Driver really
closes sockets and reports OwnerLost, never a successful DNS END. Explicit
Driver.disconnect retains native preconditions and closes synchronously.

PROGRAM can call `Context::connect(config.duplicate()?)` before main. It does not
need driver authority just to select cfg. The independent RuntimeClock has
sample/revision/poll_changed and permits backwards logical time. Admissions use
the original logical deadline with saturating addition; the driver recalculates
remaining Sleep after revisions. A drive budget is always Tokio time. PROGRAM implements the reverse clock trait, avoiding a dependency cycle.

The shared CLIENT hook uses one explicit `ResolutionContext` port. Every
service endpoint in one process domain must reuse the same broker context. TCP
success retains the original DNS drain lease inside Connection; subsequent
addresses are ignored, DNS END retires only that lease, and the service
stream stays usable. No `getaddrinfo` fallback substitutes for ordinary DNS. Configured CLIENT, ARM, monitor and STATISTICS constructors require this shared
context, as recorded in INTEGRATION.json. The former per-query ResolverQuery
implementation has been removed; its review snapshot remains under audits.

C source-defined limitations and unsafe cases remain explicit in inventory.json. The exact reconnect/check_disconnect original-body component observes the orphan
retry schedules without executing shim callbacks or inventing a network success. Normal public C/R literal peers, normal C daemon profiles, Rust host tests and
PROGRAM composition are separate scopes. No test count replaces full completion.
