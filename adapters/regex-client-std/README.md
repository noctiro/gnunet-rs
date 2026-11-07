# Native REGEX client

`gnunet-regex-client-host` implements the public GNUnet v0.29.1 REGEX IPC
announcement and search API over the existing shared CLIENT, Resolver,
RuntimeClock and retained Framed transport. The primary source is pinned commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`,
`src/service/regex/{regex_ipc.h,regex_api_search.c,regex_api_announce.c}`. No production C FFI or new registry dependency is used.

Each `Announcement` or `Search` retains one immutable registration intent. `new` validates/encodes and reserves clock ownership; it opens no socket. `drive` selects a Unix/TCP endpoint through the supplied EndpointSource. Actual
EOF/native IO loss physically detaches the old MQ before `SourceLost` reports
its original epoch, typed cause and zero/prefix/whole write exposure. The same
logical job then reconnects and registers the complete unchanged request on a
new MQ, as the official SDK does. An old partial frame is retired, not continued
on a new socket. At most one connection/attempt and one physical TX exist. Announcement is a connection registration: prior DHT publications may outlive
its loss; re-registration grants no publication acknowledgement. Protocol,
resource, clock, cancellation, explicit suffix retirement and original deadline
failures still end the intent permanently. No task or implicit new logical job
is created, and historical results retain their old source metadata.

A caller-owned stable `Instance` can be shared by bounded dynamic handle slots. Its checked atomic allocation counter never recycles. Typed Job/Epoch/WriteId
compare both domain address and allocation serial. Each actual
attachment gets fresh epoch/write identities; the logical Job never changes. Exhaustion returns
Overflow. No process-global allocator of identity or leaked per-job instance is
needed. The caller chooses handle count; this library creates no threads/tasks.

`Progress::Queued` is emitted only after the exact immutable request entered its
Framed TX queue, before any native first write. `Submitted` is a whole
local write only. Announcements have no wire ACK; searches have no RID or DONE. A source loss, timeout, empty path or zero results never means a completed search. Neither local write nor an RESULT proves a DHT operation, peer reachability,
expression correctness or continuing provider availability.

`Search::result` borrows the one complete retained RESULT frame. Both GET/PUT
identity paths are checked by the shared official codec. `release_result` consumes
that frame without an ACK. `take_result` performs one combined-path allocation
and copy, preserving original job, epoch, ordinal and observed-at read-turn
sample; failed allocation leaves RX intact. Retained input applies backpressure. Caller-owned historical results never become fresh after another search starts. No unbounded internal result queue or automatic deduplication is present.

Deadlines are absolute microseconds in the EndpointSource's original RuntimeClock. `send_until` bounds the first complete send, including endpoint selection and
partial writes. Once discharged it is not restarted or repurposed for a new MQ. Every subsequent registration remains within the unchanged original job budget. A search additionally
requires `first_result_until`; it ends local interest if no complete valid first
RESULT arrives by that original time. `until` bounds the whole original job and
never extends on a result. The first-result target must be between send and job
targets. Announcement first_result_until must be None. All targets are finite. Dropping a drive future retains attempts, RX/TX suffixes, identity and targets. A caller's optional Tokio observation deadline neither cancels nor extends work. Every active drive checks original clock and logical deadlines before returning
an observation timeout or a still-borrowable result. Clock/subscription/timer
failure closes the original MQ independently of the failed port.

`cancel` and `close` immediately physically retire the original attempt/MQ without
sampling clocks or inventing a CANCEL frame. `Submission` retains exact local
zero/prefix/whole exposure; cancellation is not a remote revocation receipt. Optional `stop_after_send` finishes only an already positive-written original
suffix, suppressing further input and retaining the first fixed bound
`min(original until, first call time + grace)`, additionally capped by the
original send_until until the first whole send. While detached it closes the
logical intent immediately, preserving the last source/write receipt; it
never opens a replacement MQ to finish an old suffix. A wholly
unwritten request is closed without sending. Repeating this call never renews
its grace. No partial frame can be moved to another MQ. Drop also closes the
original native owner without calling user code.

Default logical resources per handle: one immutable registration frame and one
frame of at most65535 bytes each for RX/TX, one result slot, one CLIENT attempt,
at most two clock
subscriptions while a Deadline is registered, and syscall quanta <=65535 bytes. `frame_bytes`, `path_entries`, syscall quantum and suffix grace are explicit. RX/TX buffers retain the shared framing zeroization behavior. The caller's
explicit owned-result copies and shared Resolver limits are separate resources.

The sole `tests/native.rs` model uses local Unix IPC with a controlled
actor. Its synthetic RESULT records test exact peer/GET/PUT paths, a canceled
wait across partial input, multiple results, exact search/announcement restoration on new physical epochs,
unchanged deadlines, historical result identity, write without ACK,
immediate partial-request cancel, clock-failure physical EOF and no connection
after cancellation. It is not an
REGEX service/DHT or full GNUnet qualification claim.
