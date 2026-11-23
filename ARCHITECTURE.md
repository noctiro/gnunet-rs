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

Validate required context where an operation or resource is created. Group
the validated fields into one value and keep construction private to that
boundary. States that can submit a native operation carry its original owner
and deadline. A state that observes an interface or socket identifier only
can report it or reject a mismatch. Atomic delivery requires a native
capability that selects and validates the original object.

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
Validate input against the protocol's limits before admitting its contents
against local budgets. A valid peer reply can be consumed even when some of its
candidates do not fit the local table.

Once a bounded owner has accepted a complete input, release the shared receive
cursor while semantic work waits for capacity, flow control or dependencies.
Keep the physical input only while ownership has not transferred. Protocol
reads and synchronization retain capacity independent of ordinary work, so
backpressure cannot block the messages needed to resolve it. Native cursor
metadata remains separate from authenticated graph and key authority.

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

The [native publication layer](adapters/native-std/src/filesystem/publication.rs)
synchronizes staged content and closes its writer before it installs the name.
It retains the original file through a separate read-only handle. The caller
owns recovery after an uncertain replacement. A directory barrier and cleanup
each have their own result. Read-only observations can verify identity or
absence. Persisted metadata cannot recreate native device, route, process or
code-execution authority.

## Native platform boundaries

Shared protocol and service behavior sits above platform socket, process,
filesystem, credential and device mechanisms. Share Unix implementations
where contracts match. Isolate differing syscalls, ABI layouts and lifecycle
rules in native modules. Missing capabilities and provider failures remain
explicit errors.
Automatic platform selection may omit an unavailable optional capability.
An explicit deployment selection must either satisfy its constraints or fail.
A configured trusted provider path must be absolute after variable expansion,
without resolving relative paths against the process directory.

The [embedded peer](adapters/node-std/README.md) composes the original native
services on the caller's runtime. It owns a bounded readiness and stop graph.
CORE, NSE, DHT and CADET start along their dependency chain and retire in
reverse. CORE and the communicators retire before TRANSPORT drains on the
original PILS connection.
TRANSPORT owns the aggregate sent to PILS. Communicators supply address changes
on their original IPC streams. The embedded readiness barrier holds publication
while local services establish their initial identity and listener ownership.
Optional communicators share the standalone runtime and configuration parser.
Raw QUIC and HTTP/3 own their UDP sockets and bounded frame pools. The UNIX
testing communicator binds a separate datagram socket inside the private IPC
namespace. Each enabled communicator joins the readiness barrier.
On the same physical PILS connection, a peer change fences local signing while
TRANSPORT withdraws the old managed records. Communicator streams and address
leases retain their owners. CORE reattaches under the replacement identity.
The operating system and ABI determine which native interfaces can be built.
Device capabilities and permissions determine which providers can run. The
deployment supplies lifecycle ownership. Apps and extensions use SDK callbacks
and their platform package format. Each application SDK build owns the source
layout and native binaries for its deliverable. Build automation consumes the
published path to check or distribute that same package.
The [direct embedded peer](crates/gnunet-direct-peer/README.md) binds one TCP
queue to its TRANSPORT validation and one CORE session. The firmware supplies
its socket, elapsed and absolute clocks, entropy and durable reservation ports.
Validation expiry retires CORE keys and retained input. CORE expiry runs
independently of output credit. Fragmentation retains exact CORE bytes until
the last BOX enters the original TCP queue. Socket readiness observes that
same owner without granting another close.

The [foreground node](apps/gnunet-node/README.md)
uses the same readiness and stop graph. The process supervisor supplies its
service identity, directories and stop signal. The
[image staging command](tools/xtask/node/README.md#stage-a-system-image-input)
combines the original Cargo executable with the Android or OpenHarmony
supervisor recipe. The Linux small-system image requires the original state
and IPC directories to belong to the selected mount before the node starts.
[Desktop prefix staging](tools/xtask/node/README.md#deploy-as-an-operating-system-service)
selects a systemd, launchd, FreeBSD rc.d or Windows SCM service recipe.
The process publishes systemd readiness and SCM running state from the
same node readiness callback. Unix signals and SCM stop requests enter
the same bounded retirement path. Process state under launchd and rc.d
does not imply node readiness.

The [node SDK](platform/sdk/README.md) gives native callers one handle
to a dedicated Rust worker, which is joined on destruction. Desktop route
sockets and Windows notification registrations deliver coalesced rescan hints.
The process owns the original subscription through retirement and cancels
native callbacks before returning its clean stop result.
An embedded Resolver selects one DNS authority at construction. A UDP network
snapshot replaces upstreams, retires their sockets and clears dynamic cache
entries. System policy delegates address and reverse lookups to the operating
system. Both backends use the same RESOLVER IPC and original deadlines. Each
native request holds its capacity until its cancellation or callback retires
the original resources. Linux and FreeBSD isolate blocking name-service calls
in a child using private RESOLVER pipes. A process supervisor owns its wait
through cancellation and node-runtime retirement.
Each scan reconciles only the addresses of its original interfaces. Native
adapters retain the original descriptors or SDK handles through cancellation
and completion.
For NAT reversal, a deployment can supply an installed observer and sender
pair to the node. The NAT service owns both through its existing interface
leases and child supervisor. Helper execution uses the deployment's native
authority and requires an unprotected socket policy.
[NAT reversal configuration](apps/gnunet-node/README.md#nat-reversal)

The VPN coordinator accepts application-owned raw IP sources and asynchronous
system settings. An application backend reports the original install, removal
and packet write results against the coordinator's source and request IDs.
The embedded node starts VPN after CADET and, for automatic exit discovery,
after REGEX connects to the original DHT and PILS services. VPN retires its
on-demand REGEX searches before releasing either dependency. The standalone
VPN uses the same discovery provider. REGEX results select a CADET peer for
the originating Internet flow.
The deployment supplies one socket policy at node construction. The runtime's
socket factory applies it before releasing each new Internet socket to its
native owner. Peer communicators, Resolver, NAT and direct-IP DHTU use the same
policy for their initial sockets and replacements. Unix protection retains its
provider context until the last policy owner is released.
The SDK uses the same control endpoint for application packets and native
raw-IP descriptors. A Unix descriptor is duplicated for the Rust worker and
retired before its original interface can be removed.
The application can fence packet traffic synchronously while the coordinator
keeps the original route and write receipts live for retirement. Pending work
retains its deadline, and uncertain writes keep their exposure state through
retirement. Desktop descriptors still carry their original interface and route
evidence. [Application providers](adapters/vpn-std/COORDINATOR.md#application-providers)

DNS interception processes typed DNS payloads in its pure engine. The host owns
real packet framing and request/source-bound reply permits. The Apple UDP flow
adapter retains original SDK flow and endpoint owners and gives each flow its
own bounded output and callback retirement debt. The same gateway and official
IPC process both packet and application-flow sources. The macOS system extension
and the iOS app extension each host that service on one worker. Both forward
TCP through bounded bidirectional relays and use Network.framework for upstream
traffic. Startup and stop stay bound to the original provider session and its
callback resource loans. The iOS provider waits for the native retirement
receipt and worker join before completing the OS stop callback.
Active DNS caches and retired callback owners have separate bounded storage, so
a canceled connection need not block the next generation. Native readiness and
send deadlines run independently of canonical time; expiry retains unresolved
SDK ownership until its actual callbacks retire.
The macOS containing application uses the AppKit main loop and serialized native
preference operations. Approval, reboot deferral, saved enablement and provider
readiness are distinct states; an expired wait cannot cancel an unknown native
effect. Signing, native activation and receiving-path
qualification follow the [backend contract](adapters/dns-service-std/NATIVE_BACKENDS.md).

Kernel interception must separate service capture admission from native receive
enforcement. Service disconnect revokes requests while the native owner keeps
its receive guard and original flow generations alive through outstanding
injections. Native completion cannot recreate reply authority or establish
application delivery. Driver unload has a separate rundown boundary; a filter
query cannot pin that owner.

On Windows, an independent kernel file pins the driver while WFP owns packet
callbacks. A separate maintenance file drives retirement and holds a WDM
request through release of the kernel file. The I/O manager owns final unload
after file and request rundown. The BFE subscription belongs to the stable
driver. Each packet generation owns distinct filters, callback registrations,
injection handles and a service file. Recovery revokes the old file, joins its
original packet and native ownership, then admits a fresh generation. The DNS
gateway cancels work from the lost packet source before attaching the replacement.

Linux transparent ingress uses native UDP metadata in place of a reconstructed
IP packet. Each request retains its original peer, local endpoint and ingress
for reply. Socket and mark ownership stays in the Linux adapter. The DNS
engine receives the same payload and reply-permit contract as other sources.

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
