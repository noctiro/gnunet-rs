# Architecture

The implementation separates protocol decisions from native resources and process
composition. External compatibility requirements are defined by the
[implementation contract](spec/gnunet/architecture.md).

## Layers

| Layer | Responsibility | Location |
| --- | --- | --- |
| Applications and facade | Configuration, command output, feature selection and composition | [apps/](apps/), [gnunet](crates/gnunet/) |
| Domain hosts | Sockets, files, workers and provider lifetimes | [adapters/](adapters/) |
| Protocol/domain engines | Business state, authentication, flow control and recovery policy | [crates/](crates/) |
| Foundations | Borrowed codecs, checked types, cryptography and resource primitives | [wire](crates/gnunet-wire/), [types](crates/gnunet-types/), [crypto](crates/gnunet-crypto/), [resources](crates/gnunet-resources/) |

Dependencies point down the table. Services do not depend on the public facade.
Pure engines accept ports/effects without selecting Tokio, a database or OS IO.
[Shared service runtime](adapters/service-runtime/) remains independent of domain
clients. The [dependency guard](tools/xtask/src/checks.rs) checks direct and
transitive production edges, including optional and platform-specific edges.

A crate represents a reusable ownership or deployment boundary. Modules separate
concerns within that owner. Share codecs and mechanisms when their contracts
match; keep protocol-specific state and recovery policy in their domain.

## Lifetimes

| Owner | Owns | Replacement rule |
| --- | --- | --- |
| Process/application | Listeners, logical ports, configuration and bounded backing | May survive a healthy identity change |
| Identity/peer generation | Matched keys, authenticated context, replay namespace and drivers | Retires before its resources are lent to a replacement |
| Operation | Request identity, source generation, fixed bounds and effects | Completes, cancels or transfers its actual debt |
| Result/history | Observed facts and durable progress | Cannot grant live authority for an old connection |

Use data-bearing states for mutually exclusive phases. Keep independent facts
separate: an exposed write, a failed source and a cleanup error can coexist.
Avoid a phase flag plus optional jobs that permit invalid ownership combinations.

A healthy update on the same identity observer differs from replacing that
physical source. Check the branded source, revision and freshness. An admitted
handshake, signature, ciphertext or call retains its original identity.

Examples of the lifetime split:

- [TCP](adapters/tcp-runtime-std/README.md) retains listeners above immutable-key
  generations and replay workers.
- [UDP](adapters/udp-communicator-std/README.md) retains default sockets and address
  intent above peer keys and matched journals.
- [QUIC/HTTP3](adapters/quic-communicator-std/README.md) retains its endpoint and
  backing until original connection drivers return their frame loans.
- [CADET](apps/gnunet-service-cadet/README.md) retains application MQs/ports while
  replacing its peer owner; Conversation retains each call's RingInfo target.

## Effects and recovery

| Observation | What it establishes |
| --- | --- |
| Admission | The owner accepted work and reserved its resources |
| Positive/whole native write | A prefix/all bytes reached the local IO boundary |
| Remote response | The corresponding peer/service produced that response |
| Durable commit | The storage owner confirmed its required commit barriers |

These outcomes are not interchangeable. A result remains observed when later
clock or cleanup work fails, but does not authorize overall success by itself.
Return the initiating cause together with independent cleanup failures.

Cancellation settles original children or transfers their debt before termination.
Do not replay ambiguous mutations or relabel old reliable-stream writes. Retain
facts without retaining dead sockets and wakeups.

The consuming domain selects recovery scope. HTTP transport preserves bytes and
producer failures; the caller decides whether a mapping, authorization or storage
operation succeeded. An operation failure must not silently become a service-wide
failure, or vice versa.

## Time, memory and storage

- Keep canonical absolute time, engine-relative monotonic time and native wait
  bounds in distinct typed domains. Capture bounds once; polling, clock changes
  and provider waits cannot renew them.
- Register native alarms before async clock/provider waits. Cleanup has a separate
  finite lifetime; an elapsed business deadline is not proof of child retirement.
- Bound tables, payloads, queues, traversal state and work at admission.
  Backpressure retains the same input/output rather than copying it per poll.
- Account shared bodies at their owner and charge indexes, spare capacity and new
  encodings. Idle owners wait on IO, capacity or timers.
- Recovery checks held storage identity and authenticated content. Unknown commits
  stay unknown. Replay/high-water history needs a safe retention or refusal policy;
  generic cache eviction cannot erase it.

## Configuration and changes

Linux, macOS, Windows and FreeBSD are full native implementation targets.
They share GNUnet wire formats, service behavior and application capabilities.
Platform adapters select the real socket, process, filesystem, credential and
device mechanisms; a different native mechanism does not justify a smaller
product surface. CI must compile and run equivalent service and recovery
scenarios on each platform. Platform-specific tests supplement that shared
coverage, and unfinished backends remain explicit open work.

Resolve identity profiles once at the configuration boundary. Local derivation,
remote HELLO coverage, Messenger layout and TLS/ALPN are separate contracts.
Verification does not try another profile after failure.

A design change should identify the owner or duplicated state it removes, the
external behavior it preserves and the resource boundary it improves. Validate
changed behavior with focused tests and the relevant interoperability profile.
Performance claims require measurements under equivalent protocol/security
behavior. Open design and qualification work belongs in
[implementation status](IMPLEMENTATION_STATUS.md).
