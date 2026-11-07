# REGEX service core

The default build is no_std/noalloc and exposes a checked borrowed `StateBlock`
with complete destination/edge/proof/token validation and linear longest-edge
traversal. `alloc` adds the bounded `Core`, its complete existing REGEX
compiler, and original local operation/output tokens. There is no C FFI,
private wire, native DHT implementation, socket, background task or implicit
clock in this crate.

`Core` owns each IPC allocation and permits one ANNOUNCE and one SEARCH
independently on the same MQ, as the active official service does. ANNOUNCE
compiles the whole expression once, enumerates all state and synthetic
initial records, and progresses through each state PUT and each accepting
state's signature then accepting PUT. It waits for PILS identity. Each accepting state is signed; C's single pending-signature cancellation defect
is not copied. Real identity events advance a private signer generation, even
if a new PILS epoch repeats the same peer bytes. Old jobs/material cannot be
rebranded onto a new identity, client, query, cycle or Core allocation.

A refresh uses the retained automaton and fresh original material and PUT
expiries. Refresh0 remains immediately due after the current bounded cycle; it
is not one-shot, a one-second substitute or an unbounded internal loop. A late
cycle coalesces missed periodic work rather than accumulating unbounded cycles. FOREVER schedules no later refresh. `tick(Times)` prepares at most one job per
client. Scheduling is independently monotonic; record expiry uses logical
UTC and permits wall adjustment. Host native hard bounds remain external and
must never be reconstructed by retries or canonical-clock changes.

SEARCH starts at SHA512(first min(length,24) bytes) and a type22 GET with the
remaining suffix plus NUL. Each returned checked state chooses the first longest
nonempty matching token, and starts/joins the exact (key, position, type) query
for that SAME original search. Different offsets/types/search allocations never
merge merely because a state key is equal. At a fully consumed accepting state,
it starts type23 with exactly zero xquery bytes. Every type23 reply is
checked for original query key/type, DHT expiry, exact accepting block, actual
peer Ed25519 signature and signed expiry before producing an IPC result. Equality
with expiry is current. Search stays live after any result; there is no invented
ACK, cancellation frame, request RID or DONE.

Original accepting GET/PUT predecessor identities are retained in supplied order
for the RESULT622 payload. They are route metadata, not authentication. Bounded exact block fingerprints suppress duplicate replies; branches, live
queries, payload bytes, compiler work, output frames and path counts all have
separate admission limits. Capacity errors admit no half result/branch. Existing
queued result debt is preserved until original write/abort.

`next_work_with_sign(false)` never leases an additional signature while the real
single-slot signer is occupied; original Retire work has priority over all other
work, and GET/PUT progress remains available. `next_work()` delegates with true. A borrowed body/material is consumed or copied synchronously by the host
provider before reborrowing Core. A work token is not proof of native admission. The provider retains its original source, operation and finite logical /
native targets until its genuine terminal or physical retirement. Exact local
PUT transfer/API completion is not a remote ACK, replication or durability claim. Failed genuine admissions/signatures use `backend_failed`, never fake success. GET results are accepted only after `get_started` reports its original
admission, and the same GET can yield many replies. Invalid/expired replies do
not silently terminate that persistent query.

Physical IPC disconnect happens FIRST in the host, followed by Core.disconnect. This drops never-queued results, keeps Queued/Exposed output debt and creates
original backend retirement work. A normal operation has one pre-reserved
retirement credit. This credit remains held when a Stopping target completes
but its already-issued/queued Retire is still unquiescent. New work cannot reuse
that credit and deadlock cancellation. `retired` requires target operation
quiescence; cancel-command admission or dropping a future is insufficient. `backend_failed` rejects Retire work; failures of an already-Stopping target do
not close a healthy announcement merely because PILS rotated. Their actual
terminal removes only that target, retaining the original Retire debt.

Results progress Ready -> queued -> exposed/whole-written. Only a physically disconnected original MQ can abort queued debt. `release`
removes a closing client only when every backend and output debt is gone. `pending_jobs` is diagnostic metadata; `quiescent` requires all clients, backend
rows and outputs actually cleared by these lifecycles. No API here turns local
queue submission or a diagnostic counter into remote success.

The core consumes `gnunet-regex::accept`. Both PUT types use replication 5 and
expiry `now + 1h`: state uses options 1/type 22, accepting uses options 3/type 23.
Purpose-18 signed material expires at `now + 24h`. State/accepting wire bytes,
initial-prefix bytes and path ordering follow the pinned source contract.

This is pure service-state production code, not a complete deployed
service. The native IPC host, PILS owner and standard SERVICE coordinator
are separate layers. An caller-owned DHT production binding is required;
none is invented or obtained through the stopped native/network DHT task here. These compile/metadata checks execute no model, crypto, key, product
hash, entropy, store, worker, native, C or network path. They do not establish
official interoperability or measured performance.

`Metrics` exposes nine fixed official diagnostic names as a readonly cumulative
snapshot. All counters saturate as lower bounds and never fail business work. `put_admitted` counts only the first original provider admission, while
query admissions, inspected edges and retained verified accepting results
feed their factual counters. The C raw-state-cache replay counter stays zero:
this implementation does not perform that internal operation. The higher
`regex-program-std` layer owns nonpersistent STATISTICS traffic, original
epoch/whole-write accounting and uncertain-delta retirement. Counters are not
DHT acknowledgements, replication or durability proofs.
