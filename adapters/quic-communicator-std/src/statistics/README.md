# Rust QUIC / HTTP3 connection-inventory publication

This implements Rust standard-communicator observability using two gauge-key
intentions visible in pinned GNUnet public source. It is not evidence of an
existing C STATISTICS query behavior or a verified C interoperability failure.

The pinned raw QUIC file explicitly has `Setup stats handler properly` in its
TODO list. It declares a static `stats` pointer and calls SET for `# peers active`
at 563/1061, but never creates or non-NULL-assigns that handle. The pinned HTTP3
file similarly declares the pointer and calls SET for `# connections active` at
927/3037 without creating it; cleanup only checks/destroys a non-NULL handle. Both SETs request nonpersistent values. No official subsystem label is established
by those incomplete code paths. The exact sources/commit are in the handoff.

The Rust public STATISTICS subsystem labels chosen here are `communicator-quic`
and `communicator-http3`. Their gauge keys follow those source intentions. They
are local diagnostic names, not a new peer protocol or an authentication claim. The values count owned Runtime row objects, including rows whose original
connection/FC/native-driver retirement is pending. A connection attempt/claimed
peer is not declared authenticated, reachable, accepted remotely or delivered. Neither C map insertion/destruction timing nor its off-by-one update placement is
reproduced. The existing socket byte Statistics API remains separate and unchanged.

Runtime.metrics() reads the bounded row table without a clock sample,
allocation, entropy, global state, new Cell/atomic or source mutation. Both apps
supply Producer1 implementations through a source-independent GAT factory. Factory storage is constructed inside the same retained post-USERNAME native task;
its publisher borrows that stable local storage and shares the existing Resolver
and exact Runtime transport clock Arc. No runtime/protocol IPC or statistics
connection dependency is added. NoStatistics is only an explicit embedding choice;
the standard QUIC and HTTP3 binaries both call run_with_statistics::<Factory>.

Original publisher native hard guards run before Runtime/Resolver waits. Positive
native progress, signals and known logger failure are retained before later
classes; known stop/failure fences new observation work. Publisher failure retires
only that diagnostic source while healthy communication continues, without a new
publisher or unknown-value replay. The existing Runtime shutdown future stays
pinned until its endpoint/driver/loan cleanup completes, with its original
first-close hard. Original statistics IO/native hard and the same Resolver remain
fairly driven during that wait; no new source clock or deadline is invented.

Only after Runtime.shutdown actually takes/drops its original rows and restores
caller slabs is final inventory sampled. Its resulting zero is not inferred
from Drop or an error string. Normal retirement freezes that snapshot once
with an independent fixed five-second statistics drain. Error/logger/Resolver stop
uses physical clock-free abort, preserving uncertainty. Resolver disconnect remains
outside and after the original publisher/runtime retirement. Actual native report,
last metrics, full Runtime Closed report and all independent errors survive in the
aggregate; successful STOPPED output includes metrics/publisher metadata. A whole frame write is never described as remote processing or durability.
