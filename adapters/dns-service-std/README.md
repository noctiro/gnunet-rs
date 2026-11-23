# DNS interception host and helper transport

The host composes official DNS client IPC, the bounded interception engine,
DNSSTUB and an explicit packet source. The pure engine owns DNS payload phases;
the host validates raw IP/UDP packets or accepts original application-flow DNS
datagrams and retains source-bound reply permits. Platform modules own child
processes, pipes, devices, flow callbacks and routing controls. The
[backend architecture](NATIVE_BACKENDS.md) records native receiving-path and
deployment requirements.

## Interfaces and framing

`Server` owns accepted client connections, ACL checks, credentials and partial
frame cursors. Each client has at most one outstanding callback and decision.
`Gateway` owns the server, `PacketSource` and one `Upstream` with at most 16
DNSSTUB slots, the core DNS byte bound and four numeric exit entries.
`PacketSource::helper` adopts an original process/pipe owner;
`PacketSource::device` adopts an already configured `AsyncTun`. Windows
`PacketSource::capture` adopts the original upstream-port lease and opens its
WinDivert filter. On macOS and iOS, `PacketSource::application_flows` accepts original
SDK UDP flows through `admit_flow`. `Gateway::with_upstream` retains the configured
stub; `Gateway::admit_flow` delivers later flows to that same gateway. Resolver
admission failure drops its query without fabricating a DNS answer.

`Helper::spawn` launches the configured absolute executable with six official
arguments: interface, IPv6 address, IPv6 prefix, IPv4 address, IPv4 mask and the
skip-routing flag. Standard input/output use MQ214 and TUN_PI/raw-IP framing.
There is no helper setup acknowledgement or TUN-written acknowledgement.
Process creation and local pipe writes establish neither fact.

## Native packet devices

Native devices transfer normalized raw IP into a zeroizing packet owner. The
[packet adapter](src/packet.rs) checks actual transport bounds and checksums,
then borrows a typed DNS query for the engine. Each admitted request retains a
non-cloneable reply permit containing its original source, request and return
tuple. Raw helper/TUN permits refuse IPv6 unicast link-local and site-local
endpoints without their original zone.

Output builds directly into its final owned frame using the retained tuple and
current DNS response. The engine does not retain IP headers or construct helper
frames. Reply-frame encoding and allocation failures precede effect preparation;
a reply exceeding the native transport limit refuses only its request. A native write
retains one original effect, device write ID, byte extent and absolute deadline;
canceled waits preserve that operation.

Gateway reports distinguish helper pipe acceptance from native whole-packet
submission. `source_retirement` retains either the original process exit or
native device loss/close. Device-close receipts are captured during synchronous
shutdown, including `into_report`; helper processes still require exit polling.
A void Wintun close does not acknowledge final kernel interface removal.

## Apple application flows

The [native DNS boundary](../native-std/DNS_PROXY.md) supplies the original
UDP/TCP flow owners and Network.framework connections. The macOS 15+
[provider executable](../../apps/gnunet-service-dns/macos/README.md) and the
[iOS 18+ SDK](../../platform/ios/README.md) use the ordinary service foreground
and official client IPC.

`PacketSource::application_flows` creates a bounded UDP source inside Tokio.
Compose it once with `Server` and `Upstream::start_provider` through
`Gateway::with_upstream`; `Gateway::admit_flow` accepts subsequent original
`UdpFlow` owners. `RejectedFlow` preserves refused ownership for retirement.
Each input consumes DNS bytes with its original endpoint, and successful output
moves that noncloneable endpoint into its pending write. Pre-submission refusal
returns the same bytes and permit. Completion grants no replay authority.

Each flow has one native read, one bounded buffered batch and one write slot.
Other flows continue while an output retires. Request-record exhaustion pauses
new reads and buffered delivery, while existing callbacks and retirement remain
polled. Defaults allow 32 flows including closing flows, 16 datagrams and 128 KiB
of DNS allocation capacity per batch, 65519 bytes per DNS body and five seconds
to open. `FlowLimits` controls these source bounds.

`Upstream::start_provider` uses the same heap DNSSTUB scheduler and opaque
request/cache tokens as the standard socket owner. Network.framework UDP
connections are created lazily for the selected cache family and peer. At most
four configured server entries participate in the unchanged retry order. A bad
additional peer retires independently of healthy peers; a replacement cannot
reuse its peer slot before callback disposal. Failed cache generations move to
a preallocated retirement arena of twice the socket-slot count, allowing a new
generation to open while the original callbacks retire. Arena exhaustion retains
the original pending opening and applies backpressure. No bound socket address
or DNS result is fabricated. `standard_owner` exposes the actual socket backend
for callers that need original socket reservations.

`ProviderUpstreamLimits` bounds initial native readiness, each observed
Ready-to-Waiting interval and each submitted send. The defaults are five seconds
for readiness and 30 seconds for sending. Progress does not renew a deadline.
Expiry cancels that peer while retaining its callback debt; a busy peer refuses
a new attempt without replaying the old send, allowing the DNSSTUB scheduler to
try other configured peers.
The native guard runs before canonical-time checks: it polls these bounds and
retirement, leaving active receive results in their reserved slots until normal
DNS processing can resume.

TCP flows use `flow_relay::RelayPool`. Each relay retains one chunk and one
operation per direction, forwards bytes unchanged, propagates half-closes and
holds original cursors through canceled waits. The provider supplies an original
Network.framework connection bound to that exact native flow and its original
remote endpoint. Explicit interface bindings stay with the connection, and
macOS also carries application metadata. `TcpUpstream::socket` requires matching numeric endpoints
and IPv6 zones; constructing it establishes no provider recursion exemption.
Native TCP read callbacks larger than their reserved chunk fail without
returning a truncated stream.

Source, TCP relay and upstream cancellation retain separate callback debts.
Gateway shutdown waits for both source and upstream retirement before settling
its original requests. Reports distinguish timely writes, late acceptance and
unknown pending exposure. `into_report` initiates cleanup but cannot wait for
callbacks; drive to `Stopped` for a complete retirement observation. The
[backend qualification contract](NATIVE_BACKENDS.md#qualification) covers the
remaining signed-provider and original-route acceptance.

## Windows automatic capture

The capture backend uses the [native WinDivert boundary](../native-std/WINDIVERT.md)
with outbound UDP destination-port 53 filtering. Before filter creation, DNSSTUB
binds every upstream slot exclusively. The immutable filter excludes those
original ports by address family; the socket lease prevents their reuse even
when logical requests or the stub stop. Loss of an original socket generation
closes gateway admission before further upstream work.

Each intercepted request retains its opaque original reply address, including
the inbound identity selected from capture-time interface observations. Two
complete views bound the history; refresh keeps the original filter and native
I/O loans. Native observation failures have separate events and counters and
retain the previous views. Qualification or revalidation failure drops
only that query; subsequent captures qualify fresh routes without replaying the
old reply. The packet adapter builds the checksummed reply, and capture injects it
through the same session. Local checksum-offload fields are normalized after IP/UDP extent
validation. No helper envelope or alternate DNS wire format is introduced.
The source keeps one native receive and one original injection; canceled waits
retain their storage. Expiry cancels only that injection and waits for its
original native completion, with a fixed five-second retirement bound after
the first cancellation or hard deadline, whichever is earlier. Known packet-local native network errors also retire only their
query. Failed cancellation, violated packet extent or unconfirmed retirement
closes the source. Original injection completion is polled before logical-clock
work and cannot be stranded by a fresh clock refusal.

Injection admission, late whole acceptance and unknown exposure remain separate
from helper pipe prefixes and unsubmitted TUN packets. The pure engine settles
one stopped packet effect only after actual native retirement. An unsubmitted
TUN write can be canceled independently; partial helper-pipe output still
requires retiring its original source.

Shutdown retains filter-close errors synchronously when no I/O is outstanding;
otherwise retirement drives the original completion loans within the caller's
grace interval. An unconfirmed filter close retains its finite upstream-port
lease until process exit, including post-open setup failure. Atomic driver
classification/interface binding, check-to-injection races, subinterface
replacement and native driver execution remain in the central qualification
worklist.

## Process ownership and shutdown

The shared transport runs on Linux, macOS, Windows and FreeBSD. Unix children
remain exclusively wait-owned; failed wait authority fences PID-based signaling.
Windows uses direct `CreateProcessW`, selected inherited handles and owner-only
connected pipes. Parent ends use IOCP; child stdio ends remain synchronous.
Pipe creation and reactor registration precede child creation. No command shell
or standard-pipe blocking worker is introduced.

A failed exit-notification registration retains the created process for cleanup.
Windows graceful stop closes original stdio admission; the fixed grace deadline
requests termination on that process handle. Unix uses SIGTERM followed by
SIGKILL. Full native exit status, stop errors, wait errors, forced termination,
pending output and incomplete input prefixes remain separate observations.
Windows wait errors retain the original process handle for bounded observation;
Unix wait-authority failure fences further PID actions and wait retries. Neither
becomes an exit receipt. Forced process exit does not prove routing cleanup.

Dropping pipe owners stops local admission; pending IOCP operations remain
reactor-owned until native retirement. Neither write acceptance nor pipe close
establishes child consumption. `Drop` initiates stop; the service foreground
must drive exit and cleanup within its original grace interval.

## Linux interception policy

The Linux helper exclusively creates TUN, configures both address families,
MTU and link state, and pumps nonblocking stdio and native packet I/O. Only UDP
destination-port 53 queries and source-port 53 replies pass the packet filter.
IP structure and checksums use the shared VPN packet primitives.
Raw helper/TUN packets carry no native IPv6 zone. Automatic rules use the
`addrtype` matcher for both families and leave multicast, IPv4 broadcast and
unspecified endpoints on their original paths. IPv6 marking also excludes
mapped IPv4 endpoints and link-local and site-local endpoints. Gateway admission
requires the original zone for scoped endpoints.

Unless `SKIP_ROUTING_SETUP` is enabled, fixed-purpose `ip`, `iptables` and
`ip6tables` commands configure the selected mark and priority. The
[helper routing policy](../../apps/gnunet-service-dns/README.md#linux-helper-routing)
selects those values and the routing table together. The helper uses Linux
routing netlink to observe that table and install the original IPv4 and IPv6
default routes. A missing table is vacant. An incomplete inventory or an
occupied table or priority blocks setup. The helper owns a root-only locked
`/run/gnunet-dns-rust.lock`, tags its mangle rules, and installs routes before
marks. Teardown checks the family, table, device index and lease metric before
deleting the route. It conditionally restores captured `rp_filter` values.
Concurrent administrator changes can leave explicit cleanup uncertainty.

Control binaries come from fixed system paths and must be regular root-owned
files without group/world write permission. The helper requires effective root,
drops effective UID while pumping and regains it for cleanup. It never changes
GID. Daemon/helper group checks protect the upstream-DNS exemption from recursion.

## macOS and FreeBSD interfaces

These helpers create exclusive native utun/TUN interfaces, configure addresses,
MTU and link state, and pump the same IPC framing. The TUN adapter translates
native family headers. macOS accepts `utun` for kernel selection or `utunN` for
an exact unit. FreeBSD creates and optionally renames a new TUN after retiring
any checkpoint-qualified previous owner; a foreign existing interface is refused.
Cleanup remains with the original device owner.

Automatic policy uses an enabled PF instance, an administrator-delegated anchor
and unskipped native IP interfaces, verified after installation and during pumping.
Changed policy or the startup address scope stops the pump without adopting a
replacement. Its locked
durable record lets startup retire an exactly matching old
policy before a new installation. FreeBSD device startup also uses the shared
TUN checkpoint to retire the saved native owner before allocation. See
[PF policy](PF.md) for setup, record ownership and crash-recovery constraints.
`SKIP_ROUTING_SETUP=YES` instead leaves interception and routing policy with the
administrator, including exemption of the daemon's upstream DNS traffic. Effective UID is reduced
while pumping; fixed read-only PF children use the setup user through inherited
saved credentials, without changing the parent's identity. It is restored for
cleanup; setup, packet, privilege-restoration and
close failures remain independent. Windows provider selection is configured by
the service. Remaining PF and native runtime profiles are tracked in the
[implementation status](../../IMPLEMENTATION_STATUS.md).

## Resource bounds

Each source allocates one concrete backend owner at construction. Packet,
flow, upstream and operation buffers retain separate bounds.

Defaults allow 16 clients, 128 live requests and 4 MiB of shared payload storage.
Each connection has bounded RX/TX state. Gateway retains one source input and
at most 16 resolver mappings. The helper pump reuses one 65535-byte input slab
and one 65535-byte output slab, with one pending TUN write. Application-flow
sources use their separate `FlowLimits`. Gateway-owned DNS frames zeroize.

Partial input, callback and request deadlines remain tied to their original
operation. Canceling a waiter preserves its cursor. Source loss never substitutes
a connection or replays exposed payload. The service publishes the six official
DNS counters through STATISTICS; queue/write counters do not acknowledge delivery.

See [service configuration](../../apps/gnunet-service-dns/README.md) for Windows
provider selection, creation/borrow policy and administrator routing, and
[monitor/redirector tools](../dns-tools-std/README.md) for executable interfaces.
