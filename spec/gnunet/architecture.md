# Implementation contract

This contract defines what the Rust product must preserve. The
[architecture guide](../../ARCHITECTURE.md) describes its internal design;
[implementation status](../../IMPLEMENTATION_STATUS.md) tracks open work.

## Compatibility boundary

| Boundary | Required behavior |
| --- | --- |
| Network | Official framing, message/data formats, state transitions and supported protocol profiles |
| Cryptography | Correct key encodings, signature preimages, KDF contexts, nonces, proofs and authentication required by the selected protocol |
| Public service IPC | Compatible requests, replies, subscriptions, flow control and observable failure/cancellation behavior |
| Public data | Compatible keys, identifiers, URIs and imported/exported formats required by official features |
| Rust API | Safe access to the full required feature set, including its error and lifetime rules |

Rust API names/types, scheduling, queues, plugin organization, process composition
and internal storage layouts may differ. A drop-in C ABI and one Rust function
per C helper are not requirements. Static Rust registries may replace dynamic C
plugins while preserving their required behavior.

Versioned official source, registries and published specifications determine the
external contract. Record discrepancies rather than combining incompatible
profiles or reproducing unsafe reference bugs. See the
[compatibility policy](compatibility.md).

## Implementation and deployment

Protocol and service decisions are Rust implementations. Reference C software is
used for comparison and peer execution, not as a production `libgnunet` backend.
Private packet protocols, fallback wire modes and old-state migration layers are
excluded from the rewrite.

Wire codecs validate lengths and byte order. Cryptographic types keep identity,
zone and session contexts distinct. Domain engines own request/source identity,
authentication, flow control and recovery decisions. Native hosts own IO, storage,
workers and process lifecycle; applications select configuration and providers.

Native deployment profiles must expose required capabilities and official IPC.
A monolithic host is permitted when it preserves those boundaries. Constrained
embedded profiles declare their supported subset. Resource limits cause explicit
refusal/backpressure, not alternate encodings or silent truncation.

## Acceptance matrix

| Area | Required observations |
| --- | --- |
| Codecs and crypto | C→Rust and Rust→C data, independent vectors, malformed/boundary rejection |
| Service IPC | Unmodified C client→Rust service and Rust client→C service |
| Peer protocols | Mixed C/Rust nodes, required authentication and actual returned payloads/results |
| Lifecycle | Error, cancellation, loss, retransmit, rekey, reconnect, shutdown and restart/recovery behavior |
| Storage | Authenticated recovery, commit/unknown outcomes and cleanup of original operations |
| Rust API | Required capabilities accessible through the same implemented owners and feature profiles |
| Deployment/resources | Named platform/feature profiles, bounded work/queues/memory and measured workload behavior |

A local write is not a remote reply, a processing barrier is not a durable commit,
and process exit is not remote-effect quiescence. Validate each fact at its
observing boundary. Missing tools, empty test filters, ignored cases, disabled
targets and failed runs cannot produce verified capability credit.

Reference jobs use a clean selected revision, isolated configurations/data and
explicit endpoints. Public network access is not a default. Harnesses own their
children and retain command, exit, output and cleanup identities.

Generated outputs belong under `target/`. A result identifies its source inputs,
binaries, configuration, profile and assertions. Its scope cannot be widened or
its source identity refreshed after the run.

## Release requirements

Every required subsystem, foundation and external capability must be implemented
and qualified. Unknown external operations remain open work; internal C helper
mappings alone do not block release. Source inventories, passing builds and
component fixtures support review without replacing the complete acceptance
matrix.

Rust quality also requires valid dependency/feature boundaries, cancellation and
failure isolation, defined resource limits and comparable performance/memory
measurements. The executable completion gate and its data are defined in
[external release criteria](external/RELEASE.md).
