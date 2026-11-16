# DNS interception host and helper transport

The host composes official DNS client IPC, the bounded interception engine,
DNSSTUB and an explicit packet source. Shared code owns packet decisions and framing;
platform modules own child processes, pipes, devices and routing controls.

## Interfaces and framing

`Server` owns accepted client connections, ACL checks, credentials and partial
frame cursors. Each client has at most one outstanding callback and decision.
`Gateway` owns the server, `PacketSource` and a shared `Upstream` profile with 16 socket slots, the core DNS byte bound and
four numeric exit entries.
`PacketSource::helper` adopts an original process/pipe owner;
`PacketSource::device` adopts an already configured `AsyncTun`. Windows
`PacketSource::capture` adopts the original upstream-port lease and opens its
WinDivert filter. `Gateway::with_upstream` retains that same configured stub. Resolver
admission failure drops its query without fabricating a DNS answer.

`Helper::spawn` launches the configured absolute executable with six official
arguments: interface, IPv6 address, IPv6 prefix, IPv4 address, IPv4 mask and the
skip-routing flag. Standard input/output use MQ214 and TUN_PI/raw-IP framing.
There is no helper setup acknowledgement or TUN-written acknowledgement.
Process creation and local pipe writes establish neither fact.

## Native packet devices

Native devices feed normalized raw IP into the same interception engine. Receive
allocations transfer into the zeroizing packet owner without another packet
copy. The core's raw output encoder shares reply construction with its helper
envelope encoder. A native write retains one original effect, device write ID,
byte extent and absolute deadline; canceled waits preserve that operation.

Gateway reports distinguish helper pipe acceptance from native whole-packet
submission. `source_retirement` retains either the original process exit or
native device loss/close. Device-close receipts are captured during synchronous
shutdown, including `into_report`; helper processes still require exit polling.
A void Wintun close does not acknowledge final kernel interface removal.

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
old reply. The shared core builds the checksummed reply, and capture injects it
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

Unless `SKIP_ROUTING_SETUP` is enabled, fixed-purpose `ip`, `iptables` and
`ip6tables` commands install mark 136708149, routing table 53 and priority 1053.
The helper owns a root-only locked `/run/gnunet-dns-rust.lock`, refuses preexisting
policy state, tags its mangle rules, installs routes before marks and checks
selectors before removal. It conditionally restores captured `rp_filter`
values. Concurrent administrator changes can leave explicit cleanup uncertainty;
use dedicated network policy or a network namespace.

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

Each packet source allocates one concrete backend owner at construction.
Packet and operation buffers retain their separate bounds.

Defaults allow 16 clients, 128 live requests and 4 MiB of shared payload storage.
Each connection has bounded RX/TX state. Gateway retains one helper input and
at most 16 resolver mappings. Helper reuses one 65535-byte input slab and one
65535-byte output slab, with one pending TUN write. Gateway-owned frames zeroize.

Partial input, callback and request deadlines remain tied to their original
operation. Canceling a waiter preserves its cursor. Source loss never substitutes
a connection or replays exposed payload. The service publishes the six official
DNS counters through STATISTICS; queue/write counters do not acknowledge delivery.

See [service configuration](../../apps/gnunet-service-dns/README.md) for Windows
provider selection, creation/borrow policy and administrator routing, and
[monitor/redirector tools](../dns-tools-std/README.md) for executable interfaces.
