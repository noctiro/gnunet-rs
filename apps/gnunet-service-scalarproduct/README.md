# Ordinary ECC and Paillier SCALARPRODUCT services

One shared entrypoint library supplies the official installed executable names
`gnunet-service-scalarproduct-ecc-alice` and
`gnunet-service-scalarproduct-ecc-bob`, plus installed Paillier names
`gnunet-service-scalarproduct-alice` and `gnunet-service-scalarproduct-bob`. Each selects its ordinary
`scalarproduct-alice` or `scalarproduct-bob` endpoint; role is fixed by the
executable. The caller/CLI still chooses that normal configuration section. No private negotiation or new protocol message selects an algorithm.

## Native startup

Linux, macOS, FreeBSD and Windows share one application composition through the
[native SERVICE driver](../../adapters/program-std/README.md#service-startup).
It owns early inheritance, configured identity, detachment, selected diagnostics,
original stop subscriptions and bounded parent-readiness notification. Unix
applies configured privileges; Windows verifies its process token and imports
native activation.

Defaults are `UNIX_MATCH_UID = NO`, Unix-only `UNIX_MATCH_GID = YES` and immediate
SERVICE shutdown. Windows uses the native listener ACL and defaults both Unix
checks off; explicit UID/GID requests are refused rather than emulated. TCP ACLs
remain independent. The explicit Resolver and native server share the same clock. SETI and CADET
selectors are frozen as one coherent configuration view before admission. Paillier Alice performs bounded shared key generation before READY and
business IPC admission. Its fixed startup clock covers all entropy/prime
work; signals, logging and Resolver remain live, and failure reaches the same
physical cleanup. Bob has no local private-key generation. There is no dummy
key, ECC fallback or readiness based on a timer. READY means the listeners
and role-specific IPC owner admit requests;
dependencies connect for each original computation. It is not a claim that a
peer is online or that an intersection, crypto operation or result succeeded.

## Computation ownership

Every computation keeps its original input, SETI/CADET sources and deadline. Session-key reservations include owners still cleaning up. No detached task,
replacement-epoch replay or foreign GNUnet runtime is introduced. Failed
individual computations retain their first original and independent cleanup
causes without stopping unrelated clients. Signal/logger/Resolver failure and
shutdown grace reach the same clock-free physical cleanup. STOPPED requires
zero remaining native/core debt; historical per-client failures remain visible.

## Configuration and examples

```sh
gnunet-service-scalarproduct-ecc-alice -c gnunet.conf
gnunet-service-scalarproduct-ecc-bob -c gnunet.conf
```

Use the installed names without `ecc-` for Paillier. Each configured endpoint
belongs to one selected implementation. The [normal command](../gnunet-scalarproduct/README.md)
uses the same role sections.

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

Runtime and interoperability qualification is tracked in the central
[implementation status](../../IMPLEMENTATION_STATUS.md).
