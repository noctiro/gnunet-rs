# Official protocol compatibility, Rust-native implementation

This contract records the user's 2026-10-27 clarification. The product must fully
interoperate with current official GNUnet protocols. Its internal implementation
should use appropriate Rust ownership, architecture and performance techniques.
The machine-readable decision is [compatibility-policy.json](compatibility-policy.json).
It supersedes interpretations that make copying C internals a product requirement.

## Required external compatibility

Preserve official network and required public service IPC message identifiers,
serialized fields, encodings, cryptography, authentication, state transitions,
flow control, protocol-defined ordering and public artifacts. Cover complete
service capabilities and relevant failure, cancellation, reconnect and restart
behavior. A successful write, a processing confirmation and a durable commit are
different outcomes.

The required feature breadth remains all 34 subsystem owners and eight shared
foundations. A codec or single-session test does not certify a complete service
or node. The target release, source revision, standards and supported protocol
variants remain explicit; changes require new affected interoperability evidence.

## Internal Rust design

Rust method signatures, object layout, allocation, channels, scheduling, queues,
process topology, plugin registration and internal database schema may differ.
Use static typed validators where appropriate; loading C dynamic modules is not
a prerequisite for interoperable BLOCK results. Use a suitable Rust runtime;
replicating C select, pass markers or every libutil entry point is not required.
Keep protocol-defined timing and observable operation results while allowing
different internal retry, batching and scheduling strategies.

Retain useful existing protocol, crypto and sans-I/O cores. Split crates or add
traits for real protocol, platform, ownership or substitution boundaries, rather
than mirroring C files or functions. Host services may use Vec, Arc, arenas and
ordinary async I/O where appropriate; constrained no_std profiles remain separate.
Safety improvements, explicit backpressure and correct cancellation remain
mandatory even where no C function has an equivalent Rust signature.

Implementation priority follows the user's 2026-10-29 direction: complete usable
capabilities and maintain clear ownership, bounded memory and efficient algorithms.
Validate affected code and critical official interoperability paths while building;
avoid repeated full matrices and elaborate evidence packaging for small steps.
The complete external acceptance requirement remains a release condition, and
performance improvements still require comparable measurements before a claim.

## Architecture priorities

1. Separate generic clock/framing/connection/lifecycle code from domain clients.
   Shared time, address policy and listener types now belong to the existing
   runtime, removing `service-runtime -> ipc-unix -> statistics`. A workspace
   production-closure guard protects this boundary. Continue shared host
   composition while keeping domain connection/Resolver effects in their adapter.
2. Compose existing service engines in one node host and standalone service
   binaries. Domain implementations depend on their cores and ports, not on the
   public `gnunet` facade or another domain hidden inside generic I/O.
3. Build a multi-session TCP communicator with shared process-level service
   connections. Each peer session owns its socket, crypto, cursors and credits;
   it does not duplicate every TRANSPORT/PEERSTORE connection.
4. Prioritize an actual bidirectional C/Rust TRANSPORT/CORE application-data path,
   then mixed-node overlay and upper-layer services. Do not postpone networking
   until an exhaustive C helper-function implementation has been completed.
5. Measure equivalent release workloads: handshake/rekey, multi-peer goodput,
   IPC overhead, later DHT/CADET latency, storage commits and restart. Record
   p50/p95/p99, CPU, allocations/copies, RSS and queue/FD counts. No speedup claim
   is made before measurement with the same protocol and security checks.

## Scope and gate migration

Keep the complete compiler/source reference inventories and existing observations.
A C function can explain both a real wire rule and an implementation detail;
review the relevant aspects separately. The required external capability matrix
comes from official protocol messages, service operations and state contracts.
It does not require a Rust counterpart or manual classification of every C helper.
An unknown external operation must be resolved before release; an unimplemented
internal C logging helper does not independently prevent interoperability.

The current strict API checker still couples C surface coverage to conformance.
Separating those outputs and evidence bindings is required follow-up work; this
document does not pretend that checker migration or full interoperability is
already complete. Preserve the owner/message inventory, prevent omission of
external features, and keep Rust quality checks distinct from official-C evidence.
Policy changes grant no completion credit and do not refresh historical receipts.
