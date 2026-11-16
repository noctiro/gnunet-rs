# Architecture

GNUnet protocol decisions are separated from native resources and executable
composition. The [compatibility policy](spec/gnunet/compatibility.md) defines
external behavior; this page defines shared implementation rules.

## Layers

| Layer | Responsibility | Entry point |
| --- | --- | --- |
| Applications | Configuration, commands, output and process composition | [Applications](apps/README.md) |
| Public facade | Feature selection and stable Rust API paths | [SDK](crates/gnunet/README.md) |
| Domain hosts | Sockets, files, workers, provider lifetimes and effect execution | [Adapters](adapters/README.md) |
| Protocol engines | Authentication, business state, flow control and recovery policy | [Core libraries](crates/README.md) |
| Foundations | Borrowed codecs, checked types, cryptography and resource primitives | [Wire](crates/gnunet-wire/src/lib.rs), [types](crates/gnunet-types/src/lib.rs), [crypto](crates/gnunet-crypto/README.md), [resources](crates/gnunet-resources/src/lib.rs) |

Dependencies point toward engines and foundations. Services do not depend on the
public facade. Pure engines accept explicit ports and effects without selecting
a scheduler, database or OS I/O implementation. The shared service runtime does
not depend on domain clients. The [dependency guard](tools/xtask/src/checks.rs)
checks direct, transitive, optional and platform-specific production edges.

A crate represents a reusable ownership or deployment boundary. Modules divide
concerns within that boundary. Share mechanisms when their contracts match;
keep protocol policy in its domain. Library default features are empty so
allocation, storage and runtime tiers remain explicit. Executables may select
their normal command features locally.

## Lifetimes

| Owner | Owns | Replacement rule |
| --- | --- | --- |
| Process or application | Listeners, logical ports, configuration and bounded backing | May survive an identity or dependency change |
| Identity or physical source | Matched keys, authenticated context, replay namespace and drivers | Retires before its resources are lent to a replacement |
| Operation | Request identity, source generation, fixed bounds and effects | Completes, cancels or transfers its outstanding effects |
| Result or history | Observed outcomes and durable progress | Cannot grant authority to an expired connection |

Use data-bearing states for mutually exclusive phases. Keep independent facts
separate: an exposed write, source loss and cleanup failure can coexist.
Private instance and generation tokens bind callbacks to their original owner;
a copied peer ID, request number or pathname cannot recreate that authority.

A healthy identity update differs from physical observer replacement. Check the
observer identity, revision and freshness before admitting new work. An admitted
handshake, signature, ciphertext or call retains its original identity. Resolve
identity profiles at configuration time; verification failure does not select a
different profile. HELLO coverage, Messenger layout and TLS/ALPN remain separate
contracts.

## Effects and recovery

| Observation | Establishes |
| --- | --- |
| Admission | Work and its resource reservation were accepted |
| Native write | The observed byte prefix reached the local I/O boundary |
| Remote response | The corresponding peer or service produced that response |
| Durable commit | Storage confirmed the required commit barriers |

These outcomes are distinct. Preserve observed results when later clock or
cleanup work fails, and return the initiating cause with independent cleanup
errors. Diagnostic output and idleness establish none of these outcomes.

Domain input outcomes distinguish consumed work, local admission refusal and
physical-source failure. Capacity refusal for one peer cannot implicitly retire
unrelated sessions. Shared framing owns byte cursors and control capacity;
the consuming domain decides when that physical source must retire.

Canceling a wait retains its original operation and byte cursors. Explicit
cancellation settles children or transfers their outstanding effects before
termination. Remove only provably unwritten work; drain exposed stream prefixes
or retire their physical source. Do not replay ambiguous mutations, rewind
cryptographic state or relabel old writes as unsent.

The consuming domain chooses recovery scope. Retire old callbacks, drivers and
buffer loans before admitting a replacement. Preserve completed results without
retaining dead sockets or wakeups. A local operation failure and a shared service
failure have different scope and must be reported accordingly.

## Time, memory and storage

- Keep canonical absolute time, engine-relative monotonic time and native wait
  bounds in distinct typed domains. Capture bounds once; polling, clock changes
  and provider waits do not renew them.
- Share finite bounds and per-owner wake registration through the service runtime.
  Recheck native expiry after clock or subscription callbacks and before effects.
  Tightening wakes the original owner; a sampled timestamp is not reusable I/O
  authority across later waits.
- Register native alarms before asynchronous clock or provider waits. Cleanup
  has a separate finite allowance. Deadline expiry does not prove child exit or
  native cancellation.
- Bound tables, payloads, queues, traversal state and work at admission.
  Backpressure retains the same input or output rather than copying it per poll.
- Charge shared bodies at their owner, including indexes, spare capacity and
  additional encodings. Idle owners wait for I/O, capacity or timers.
- Recovery checks held storage identity and authenticated content. Unknown
  commits remain unknown. Replay history needs a safe retention or refusal
  policy; cache eviction cannot erase security history.

File publication separates content synchronization, name installation, writer
close and directory synchronization. Preserve uncertainty and failed cleanup
owners. A read-only observation can verify a tuple or absence; it cannot grant
mutation or cleanup ownership. Persisted metadata cannot recreate native device,
route, process or code-execution authority.

## Native platform boundaries

Linux, macOS, Windows and FreeBSD are full native implementation targets. Shared
protocol and service behavior sits above platform socket, process, filesystem,
credential and device mechanisms. Share Unix implementations where contracts
match; isolate differing syscalls, ABI layouts and lifecycle rules in native
modules. Missing capabilities and provider failures remain explicit errors.

Keep local filename and command encodings native until their protocol boundary.
Configuration expansion does not mutate the process environment or working
directory. Listener filesystem permissions, transport availability and peer
identity are separate admission checks.

Act on retained native objects rather than reopening numeric PIDs or paths.
Explicit close reports failures and retains retryable ownership; Drop is best
effort and does not wait for device destruction or child exit. Native creation,
process exit, application readiness and readiness-notification completion are
separate observations.

CI runs shared service and recovery scenarios on native targets, with additional
platform-specific tests. [Testing](tests/README.md) describes the configured
matrix; [Implementation status](IMPLEMENTATION_STATUS.md) records outstanding
platform work.

## Domain contracts

Detailed APIs and platform rules belong with their owning module:

| Area | Contract |
| --- | --- |
| Process startup, listeners and framing | [Service runtime](adapters/service-runtime/README.md), [startup](adapters/service-startup/README.md) |
| Commands, output and locale | [PROGRAM](adapters/program-std/README.md), [binary I/O](adapters/program-std/BINARY_IO.md), [native process contracts](adapters/program-std/NATIVE-CONTRACT.md) |
| Native files, processes and interfaces | [Native adapter](adapters/native-std/README.md) |
| Devices, routes and recovery | [TUN](adapters/tun-std/README.md), [recovery](adapters/tun-std/RECOVERY.md), [DNS interception](adapters/dns-service-std/README.md) |
| Transport and communicators | [TRANSPORT](crates/gnunet-transport/README.md), [TCP](adapters/tcp-runtime-std/README.md), [UDP](adapters/udp-communicator-std/README.md), [QUIC/HTTP3](adapters/quic-communicator-std/README.md) |
| Encrypted channels and calls | [CADET](adapters/cadet-std/README.md), [Conversation](crates/gnunet-conversation/README.md), [Messenger](adapters/messenger-std/README.md) |
| Durable files and publication | [Snapshots](adapters/snapshot-std/README.md), [DATASTORE](adapters/datastore-std/README.md), [FS](adapters/fs-std/README.md) |
| Multi-party rounds | [SET](crates/gnunet-set/README.md), [CONSENSUS](crates/gnunet-consensus/README.md), [SECRETSHARING](crates/gnunet-secretsharing/README.md) |
| Naming and publication | [GNS](adapters/gns-service-std/README.md), [NAMESTORE](adapters/namestore-std/README.md), [ZONEMASTER](adapters/zonemaster-std/README.md) |
| Test configuration and process trees | [TESTBED](adapters/testbed-std/README.md) |

## Documentation ownership

The root [README](README.md) is the project entry point. Package READMEs describe
purpose, public interfaces, configuration, examples and constraints. Long command
and interface references belong in linked topic files. Shared design belongs
here; unresolved work belongs in [Implementation status](IMPLEMENTATION_STATUS.md).
Protocol requirements belong in [spec/gnunet](spec/gnunet/README.md), and test
setup belongs in [tests](tests/README.md) or the owning tool's guide.

Keep contracts in one place and link to them. Remove superseded plans, dated
progress notes and repeated completion disclaimers. Generated logs, transcripts,
digests and verification reports belong under `target/`. Documentation changes
must preserve the actual scope of evidence and use valid relative links.
