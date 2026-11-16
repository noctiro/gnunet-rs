# GNUnet raw DNS stub owner

This `no_std` owner implements the seven v0.29.1 DNSSTUB
operations with explicit request, copied-byte and server capacities. It adds no
wire wrapper. Numeric DNS servers are configured explicitly and inserted at the
list head. Request selection uses up to 256 caller-provided random draws; the
last occupied choice is replaced with an explicit `Admission.evicted` failure
token. The caller must notify that original consumer of failure.

## Query storage

The default `DnsStub<R, N, S>` stores queries inline and requires no allocator.
With the `alloc` feature, `DnsStub::start_heap` returns a `HeapDnsStub` using
bounded heap buffers for configured slots. It constructs those buffers directly
on the heap, without a maximum-query-pool stack temporary. Both profiles use
the same request, cache and retry state machine. Allocation failure is explicit;
capacity and DNS bytes do not change with storage choice.

## Socket effects and response contracts

`next_action` produces lazy socket-open and send effects. A host reports the
bind result and calls `sent` after a send attempt, including syscall
errors. Retry and the server cursor advance before I/O. Read interest becomes
active only after that send attempt. Socket cache generations are independent
of request generations; cancellation keeps sockets for reuse, while stop
invalidates every token and requires the host to retire its original socket owners.

Responses are `UnverifiedDatagram` values: the raw stub checks a configured
source IP/port and the minimum twelve-byte header. It does not check DNS ID, QR,
questions or DNSSEC. Repeated responses do not complete the request or stop its
periodic retries. A late packet on a reused cached socket belongs to the current
raw callback and still needs higher-layer validation. A resolver owns its own
deadline and cancels only after validating or abandoning its query.

## Native addresses and bounds

Native IPv6 scope/flow values are retained for sending, while source matching
follows C's IP/port comparison. Native IPv4 padding is never read. Finite capacity,
generation and scheduler-counter exhaustion cause explicit errors without
silently replacing protocol data or reusing old authority.

The core contains no OS socket, clock, entropy source or detached task. Its tests
cover lazy effects, dual-family caches, stale results, admission refusal, retry,
FOREVER, cancellation, stop and bounded exhaustion. They do not alone certify a
complete DNS subsystem or prove that an effect opened a socket.
