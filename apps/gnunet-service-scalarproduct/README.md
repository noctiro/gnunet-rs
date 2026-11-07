# Ordinary ECC and Paillier SCALARPRODUCT services

One shared entrypoint library supplies the official installed executable names
`gnunet-service-scalarproduct-ecc-alice` and
`gnunet-service-scalarproduct-ecc-bob`, plus installed Paillier names
`gnunet-service-scalarproduct-alice` and `gnunet-service-scalarproduct-bob`. Each selects its ordinary
`scalarproduct-alice` or `scalarproduct-bob` endpoint; role is fixed by the
executable. The caller/CLI still chooses that normal configuration section. No private negotiation or new protocol message selects an algorithm.

Normal PROGRAM options, inherited listening descriptors, early daemon startup,
selected configuration/logger, configured username, Unix credentials and TCP
ACL use the shared process facilities. Defaults follow scalarproduct.conf:
UNIX_MATCH_UID=NO, UNIX_MATCH_GID=YES and immediate standard SERVICE shutdown. The explicit Resolver and native server share the same clock. SETI and CADET
selectors are frozen as one coherent configuration view before admission. Paillier Alice performs bounded shared key generation before READY and
business IPC admission. Its fixed startup clock covers all entropy/prime
work; signals, logging and Resolver remain live, and failure reaches the same
physical cleanup. Bob has no local private-key generation. There is no dummy
key, ECC fallback or readiness based on a timer. READY means the listeners
and role-specific IPC owner admit requests;
dependencies connect for each original computation. It is not a claim that a
peer is online or that an intersection, crypto operation or result succeeded.

Every computation keeps its original input, SETI/CADET sources and deadline. Session-key reservations include owners still cleaning up. No detached task,
replacement-epoch replay or foreign GNUnet runtime is introduced. Failed
individual computations retain their first original and independent cleanup
causes without stopping unrelated clients. Signal/logger/Resolver failure and
shutdown grace reach the same clock-free physical cleanup. STOPPED requires
zero remaining native/core debt; historical per-client failures remain visible.

`[scalarproduct-service-rust]` configures finite client/vector/session/aggregate
storage, input/operation/retirement/shutdown bounds, native syscall/frame sizes,
core point/DLOG work and dependency framing. HASH_BYTE_ORDER explicitly
selects the fixed C peer's native hash comparison profile; its default is the
local native profile. SETI_RESULT_PREFIX selects20/24, and
SETI_ELEMENT_TYPE_ORDER selects network/little/big without changing raw frames. Paillier defaults are derived coherently from its selected core rather
than the ECC core budget. CORE_RETAINED_BYTES, MAX_ROWS, PAILLIER_FRAME_BYTES,
OPERATION_TIMEOUT, WORK_UNITS, PAILLIER_KEY_CANDIDATES and PAILLIER_REJECTIONS
configure that profile before native reservation. Final policy validation
rejects inconsistent session/native/aggregate limits; it never silently changes
algorithms. Both startup and normal activity yield between bounded turns so
single-threaded runtime drivers remain schedulable. Storage reservations are not
resident-memory or throughput measurements.

All four ordinary binaries and their shared host/profile/keygen and
final-payload retirement composition are installed and passed selected offline
macOS/GNU Linux compiler and architecture checks.
