# TUN host API

This adapter owns qualified Linux TUN, macOS utun, FreeBSD TUN or Windows
Wintun packet sources. An explicitly launched Linux VPN helper exposes its
original packet pipes through the same caller-driven packet contract. Packet
engines remain independent of native handles and service policy. The optional
helper uses official type185 framing.

Windows adoption, event waiting, native administration and address observations
are described in the [Windows interface](WINDOWS.md). The Unix provisioning and
routing interfaces are described below.

## Device ownership and provisioning

`OwnedTun::from_fd(OwnedFd, Limits)` consumes a caller-owned descriptor and checks
kernel evidence. Linux uses TUNGETIFF and refuses TAP/VNET_HDR framing;
macOS verifies SOCK_DGRAM, the connected utun controller ID, IFNAME, normal header
flags and interface index. Arbitrary sockets/files cannot qualify through
the public API. A failed adoption closes that consumed descriptor and preserves
the original OS error. Successful adoption sets O_NONBLOCK and FD_CLOEXEC.
FreeBSD requires a character device accepting `TUNGIFHEAD`, an enabled family
header, and the actual `TUNGIFNAME`/interface index; TAP and ambiguous legacy
link headers are refused.

`OwnedTun::open_linux(name, packet_information, limits)` opens `/dev/net/tun` and
executes TUNSETIFF. `None` uses kernel naming; `packet_information` explicitly
chooses Linux PI or IFF_NO_PI. `OwnedTun::open_utun(unit, limits)` opens and connects
the macOS kernel control; `None` chooses a free unit and Some(n) requests
utunN. Native capability/permission failures return their errno. They do not configure addresses, MTU, link state or routes.

`OwnedTun::open_freebsd_exclusive(name, limits)` exclusively creates a new TUN.
`None` requests kernel allocation. A canonical `tunN` requests that exact clone
unit; other names create a fresh clone and rename it with `SIOCSIFNAME`. An
occupied requested name/unit fails instead of adopting or reconfiguring it.
The descriptor is opened using its original devfs unit, with `TUN_IFHEAD` enabled,
and the actual name/index are verified before publication. The caller must
serialize interface administration and device access throughout its ownership.
The fresh interface is assigned the process FIB selected before creation so
injected packets use that table. No address, MTU or route is set here.

On kernels implementing `TUNSTRANSIENT`, verified transient mode places interface
deletion on final FD close. FreeBSD 14 returns native ENOTTY for that request;
the same freshly created interface then retains one control socket, exact
name/index and verified native correlation marker for explicit close-then-
`SIOCIFDESTROY` cleanup. Its [recovery selector](RECOVERY.md) supports physical
reacquisition after a durably checkpointed owner exits.
Independent duplicated
FDs must close before a manually managed owner: native destruction can wait for
open users, and a Rust deadline cannot preempt that syscall. Failed setup closes
the FD before attempting interface destruction.

`OwnedTun::open_freebsd_recoverable(name, checkpoint, limits)` durably records
allocation intent and full identity before packet publication. Startup retires
its saved original device before allocating another. A complete kernel marker
also resolves an allocation intent that crashed before selector checkpointing;
unmarked or ambiguous intents remain fenced. The original checkpoint
lock follows `DeviceHandle` transfers and explicit close; Drop leaves debt for
startup recovery. Managed transient devices also retain checkpoint ownership
until kernel removal is observed. See [checkpoint and failure contracts](RECOVERY.md).

`OwnedTun::open_freebsd_existing(name, limits)` opens an existing `tunN` and enables
`TUN_IFHEAD`. Observed name/index replacement is refused. This API owns packet
access only; the existing interface's administrative lifetime stays with its
caller. Persistent interfaces can survive close even when native link/address
state is cleared.

`into_handle()` retires the old Epoch/effect authority and transfers a
`DeviceHandle` containing the FD and any separate interface cleanup responsibility.
`OwnedTun::from_handle` requalifies that same owner with a new epoch.
`DeviceHandle::try_into_fd` extracts the FD only when no separate cleanup lease
is attached; refusal returns `IntoFdError`, whose `into_handle` recovers the owner
unchanged. Tokens never keep the FD alive.

Explicit `close` performs one FD close, followed by any owned interface
cleanup. It never retries a descriptor number that could have been reused.
An `io::Error` containing `DeviceCleanupError` retains descriptor and interface
failures separately. `InterfaceCleanupError` retains the original control socket,
name/index and native cause; its explicit `retry` checks identity before another
destruction attempt. A detected replacement is refused. Already-observed absence
settles interface cleanup without claiming that a destroy syscall ran. If both
setup and cleanup fail, `DeviceSetupError` preserves both errors. Drop releases packet and control descriptors without attempting a potentially
waiting interface destruction. A persistent FreeBSD 14 interface therefore
requires explicit close; dropping that owner or crashing can leave the interface
for operator/recovery cleanup. Driver-managed transient interfaces follow final
FD close. Use explicit close to observe or recover cleanup failures. Dropping a retained cleanup error abandons that
cleanup responsibility without retrying it. Surrounding destructor fallbacks call
`AsyncTun::defer_interface_cleanup` before transport close. On persistent
interfaces, close then returns a pending-cleanup error containing the original
lease without running a destroy ioctl; it never reports successful removal.

Existing duplicates, persistent Linux devices and external changes to native
framing or administration remain the caller's responsibility. Closing one FD
does not prove every interface reference or route has disappeared. Native
lifecycle qualification remains in [open work](../../IMPLEMENTATION_STATUS.md).

## Packet I/O

Move the owner into `AsyncTun::new` on the caller's existing Tokio runtime. The
adapter registers the original source, creates no runtime, and retains one immutable
queued output packet and one bounded read scratch buffer. Each poll performs at
most one native packet read/write attempt. The scratch capacity is maximum raw IP plus
native prefix plus one extra byte, so oversized input cannot masquerade as a
complete admitted packet.

`AsyncTun::try_new` returns the original owner on setup refusal, so the caller
can correct runtime preparation and retry or close it explicitly. The runtime
must enable I/O and time. Neither constructor creates a runtime or worker.

- Linux raw-IP mode carries no prefix. Linux PI has the four-byte prefix;
  nonzero flags (including kernel truncation) are explicitly rejected, while the
  ethertype is decoded in network order.
- macOS utun uses a four-byte network-order address family: 2 for IPv4 and 30 for
  IPv6. Optional extended header flags are rejected during device qualification.
- FreeBSD TUN uses a four-byte network-order family: 2 for IPv4 and 28 for IPv6.
  Its maximum complete raw packet is 65535 bytes, matching the kernel's `TUNMRU`.
- Windows Wintun carries complete raw IP with no prefix, up to 65535 bytes.
- `Received::bytes()` is one complete raw IP packet; `native_bytes()` retains the
  exact original native frame. Version/header/declared total length are checked.
  IPv6 jumbograms are unsupported. IP/transport checksums and peer authenticity
  are not inferred; the pure VPN packet engine performs its own validation.

`queue(raw, original_until)` fallibly reserves exactly one immutable packet and
returns an original WriteId containing its exact Epoch. Queue pressure returns
WouldBlock before admitting any new packet. `write(wait_until)` / `poll_write`
settle that original packet. Written means a complete device write or Wintun
send-ring submission, without downstream IP processing or remote receipt evidence. Actual WouldBlock retains it and admits no native bytes. EINTR also retains it. A positive short write (or zero write) closes the original FD before reporting
Loss; its suffix is never sent as a new packet or replayed on another device. The ShortWrite cause preserves actual/expected native byte counts and original
pending WriteId; the resulting packet outcome is unknown.

`cancel(&write_id)` removes only the original still-retained packet and reports
Unsent. Since a partial write synchronously retires the FD, every retained packet
has admitted zero bytes. The original finite queue deadline reports Unsent with
Deadline (or ReadEvent::WriteExpired when reads are being driven), independently
of a caller's one wait deadline. Dropping pending read/write futures preserves
all original owner state. Explicit source loss and close include the pending id;
new devices always get new opaque Epoch identity, even if their names/fd numbers
match. Returned observations/packets are caller-owned and may outlive retirement.

## Native address and route execution

`plan(Action, original_until)` creates one non-Clone original effect without
changing the OS. On Unix, `apply(effect)` performs MTU, IFF_UP, IPv4 address/netmask
and IPv6 address assignment ioctls after checking the original descriptor's
name/index. Linux IPv6 uses the AF_INET6 SIOCSIFADDR/in6_ifreq ABI; macOS uses
SIOCAIFADDR_IN6/in6_aliasreq with an exact prefix mask and native infinite address
lifetimes. A successful address ioctl does not claim DAD completed or that the
interface is up; link-up is a separate explicit action. Address and mask changes
remain separate actions, so a later error cannot hide an earlier successful call. NativeApplied only follows a successful native ioctl return and reports
late completion timing separately.
FreeBSD uses its own `ifreq` flags pair and `in6_aliasreq` including the native
`vhid` field. An independent C probe checks these layouts and ioctl values against
the running FreeBSD host's installed headers during native tests.

For a `Route { gateway: None, .. }` effect, call `OwnedTun::route(effect)` or
`AsyncTun::route(effect)`. The returned `NativeRoute` owns one native control
socket and one immutable original request; construction/registration does not
submit the mutation. Poll it or call `drive(wait_until)` until a terminal
`RouteProgress::Complete`. Linux uses NETLINK_ROUTE RTM_NEWROUTE/RTM_DELROUTE with
REQUEST|ACK, main-table static unicast link-scope routes and the original output
interface index. Adds use CREATE|EXCL rather than overwriting an existing route.
FreeBSD uses native NETLINK_ROUTE with the same exclusive-add protocol,
its native IPv6 family and UNIVERSE scope. The OS Netlink kernel module must be
available; CI enables it during VM setup before ordinary-user tests.
The actual interface FIB is captured at device qualification and included
explicitly as RTA_TABLE in every
mutation and query, including FIB 0. Later process `setfib()` calls cannot redirect
that generation's route operations. This selects control operations only; callers
must keep packet-socket FIB selection consistent with their network policy.
macOS uses RTM_ADD/RTM_DELETE on PF_ROUTE, with an AF_LINK interface gateway,
IFP, exact netmask and explicit RTF_IFSCOPE/native interface index. Both IPv4 and
IPv6 interface-route add/remove are implemented. Destination host bits must be
zero for the requested prefix; no destination is silently normalized.

`RouteProgress::Submitted` means only that the complete original request was
written. `RouteOutcome::KernelAck(Ok(()))` requires a correlated kernel
reply. KernelAck(Err) preserves the kernel rejection errno. Linux and FreeBSD
check the real kernel sender, original sequence, type and echoed request header.
Native FreeBSD positive ACK/DONE errno and Linux negative errno are decoded
separately. macOS checks the native reply PID/sequence/type/interface/destination/netmask and
RTF_DONE for success. The control sequence does not recycle within this process,
including across device owners. Unrelated kernel messages are consumed under a
fixed count bound, without becoming completion of this effect.

WouldBlock and EINTR retain the original unsent request. A positive partial write
closes the original control socket and never resumes/replays a suffix. A native
write error is retained on the transaction while a correlated kernel reply may
still arrive; it is also included in the terminal completion. Timeout, source
retirement, reply truncation/overrun, cancellation or unmatched-message exhaustion
after exposure reports Uncertain, never fake installation/rejection. Cancellation
before a mutation write reports Unsent. The exact EffectId/Epoch/action/interface
routing table/FIB and original deadline remain in RouteCompletion, along with any independent
control-socket close error. Dropped drive futures retain the socket/request;
dropping the transaction owner abandons observation and does not undo an OS change.

Resource bounds per route owner are one request (under512 bytes), a4096-byte RX
buffer, one original timer, one outstanding control socket and at most65 consumed
unrelated datagrams before an uncertain terminal outcome. Explicit socket buffer
requests are16KiB receive/4KiB send; the kernel may adjust these to native minima
or accounting rules. Each poll makes at most one mutation write or ACK receive. No background task, route subprocess, automatic retry, delete-on-timeout or
rollback is constructed. Kernel calls themselves cannot be preempted by dropping
an async future; late syscall completion remains an observation.

Gateway routes (`gateway: Some`), policy-routing tables/rules, forwarding/NAT
firewall policy, address deletion and automatic network
rollback are outside this VPN/EXIT interface-setup scope and remain explicitly
unsupported/unimplemented. The caller may still use the clearly labelled
`effect.report(actual_result)` external port; that creates Reported, never
NativeApplied or KernelAck. CallerReported is not the native executor.

## Read-only IPv6 readiness observation

After the explicit IPv6 address action, use
`OwnedTun::watch_ipv6(address, prefix, original_until, options)` or the same
`AsyncTun` method. The returned `Ipv6Watch` retains the exact verified original
Epoch/name/ifindex/address/prefix and finite absolute deadline. It retains no TUN
descriptor and does not extend that device's lifetime. Constructor success means
the read-only query socket was opened, not that the address exists or DAD
completed. `poll` and `drive(wait_until)` perform the reads; dropped drive
futures preserve the original query/deadline. No background task is spawned.

`Ipv6Progress::Observed` includes its immutable original target, completion time,
state and exact native flags. States distinguish `Tentative`, `DadFailed`,
`Ready`, `Detached` (BSD), `Missing` and an explicit actual `PrefixMismatch`. Ready means the exact tuple was present and had no tentative, duplicate or
detached flag at the native query. It proves neither link-up, route success,
remote reachability nor future availability. Monitoring continues after Ready,
DadFailed and Missing so a later disappearance is observable. Call
`cancel()` when startup has consumed the readiness sample, or continue until the
same original deadline; there is no unbounded implicit subscription.

Linux sends only a read-only `RTM_GETADDR` IPv6 REQUEST|DUMP on a private connected
NETLINK_ROUTE socket. A sample is emitted only after the matching multipart
`NLMSG_DONE` with no error/interruption/overrun/truncation. Each matching
RTM_NEWADDR is checked for exact ifindex, local address (IFA_LOCAL when provided,
otherwise IFA_ADDRESS), prefix and IFA_FLAGS (overriding the legacy flags byte). IFA_F_DADFAILED means DadFailed; TENTATIVE or OPTIMISTIC means Tentative. Missing
requires a complete successful dump, never a partial query or arbitrary errno. A missing exact prefix with the address present is PrefixMismatch. Interrupted
or inconsistent dumps are terminal explicit errors, without automatic replay. Each new periodic read-only query gets a non-recycling sequence. No address or
route mutation request is constructed.

macOS and FreeBSD share one bounded observation flow. Each opens one AF_INET6
datagram query socket and uses its platform's address-specific
`SIOCGIFNETMASK_IN6`, `SIOCGIFAFLAG_IN6`, then `SIOCGIFNETMASK_IN6` again on the
original name and exact sockaddr_in6 address/scope. Masks must be contiguous and
stable over this bounded group. DUPLICATED means DadFailed; TENTATIVE means
Tentative (also OPTIMISTIC on macOS); DETACHED is explicit. Actual address-specific
EADDRNOTAVAIL means Missing; other kernel errors retain their errno.

Darwin uses libc's SDK `in6_ifreq`. Its GETNETMASK constant is the
SDK `_IOWR('i',37,in6_ifreq)`, derived by replacing only the command byte of the
pinned libc `_IOWR('i',73,in6_ifreq)` flags constant, since libc omits that netmask
name. FreeBSD has a separate `in6_ifreq` layout with the full aligned native
union extent and its own command values/flag masks. Its native tests compile
against the installed headers to check the layout and command values. A separate
read-only loopback test checks prefix, flags and address absence; it is not TUN
device qualification.

`Ipv6Progress::Complete` distinguishes the original `Deadline`, `SourceRetired`,
explicit `Cancelled`, or real `Error`, retaining the most recent genuine sample
and an independent query-FD close error. Epoch retirement is checked on
every driven poll. Original name/index disappearance or replacement also retires
the observer; it never silently binds old authority to a new device. A periodic
wake checks an idle or stalled query's source within the configured interval
while being driven. Control calls cannot be preempted mid-syscall; any result
arriving after the original deadline is rejected as Deadline. A concurrent
external administrator can change an address immediately after a sample or
between non-atomic native reads; these are time-local observations, and exclusive
configuration ownership remains the caller's responsibility.

Each watcher has one query socket, two original timers and one retained sample. Linux additionally retains one24-byte immutable query and32768-byte RX buffer;
default per-dump limits are64 datagrams and262144 bytes. Callers may choose at
most256 datagrams/1048576 bytes; exceeding either reports an error. Kernel socket
buffer requests are65536 RX/4096 TX (native accounting may adjust them). Sampling
interval is explicit1ms..1s, default50ms. A Linux poll performs at most one
send/receive plus bounded parsing; a BSD sample uses at most three address
ioctls. Interface-name/index lookups are read-only and bounded. Positive short
query writes close the observer; no suffix is resent. Cancel/drop closes only
that original query socket, with no address removal or network policy changes.

## Read-only administration snapshots and route queries

`OwnedTun::snapshot(original_until, options)` and the `AsyncTun` method
return a privately constructed `NativeSnapshot`. The Unix getters below and
[Windows getters](WINDOWS.md#read-only-observations) retain their native meanings.
Construction never turns configuration into native evidence. `SnapshotOptions`
selects IPv4 and IPv6 observations; default options query link state only.
`link_mtu()` retains the actual native link value. `ip_mtu(version)` returns the
applicable limit for a requested family: the shared Unix link MTU or the actual
Windows IP-interface MTU. None means not requested, without an availability claim.
Address and DAD readiness remain separate native facts.

Unix verifies the original device before and between actual getters. An IPv6-only
scope uses an AF_INET6 control socket for link MTU/flags and skips IPv4 getters.
Unrequested IPv4 fields are `NotRequested`. Actual native absence remains
`Ipv4Observation::Absent { errno }`; a zero address remains Present. Other errors
retain their actual classification. The receipt keeps its original epoch,
interface, scope, deadline and query times. This group is not an atomic restore
image. `AdminFailure` preserves SourceRetired, Deadline, Kernel and independent
control-socket close failures. Successful snapshots also expose any close errno.

`OwnedTun::query_route(destination, prefix, gateway, original_until)` and the
`AsyncTun` method return one independently owned `RouteQuery`. The requested
network must already be canonical; gateway family must match. This query retains
the original Epoch/Info/table/destination/prefix/gateway/deadline and query socket,
without borrowing or keeping the TUN descriptor alive. `poll`, `drive(wait_until)`
and `cancel` use its original identity. A canceled waiting future preserves the
original request and deadline. Cancellation closes only that original read-only
query socket. No fresh source, hidden worker, retry, rollback or delete is created.

The private `RouteQueryCompletion` binds the result to its immutable target,
query submission, complete native reply evidence, observation time and independent
write/close errno. Its fields cannot be publicly assembled or transplanted onto a
new device Epoch. Outcomes are `Exact(RouteRecord)`, `Absent`,
`Different(RouteRecord)` and `Unknown(RouteQueryProblem)`. RouteRecord is also
privately constructed and exposes destination/prefix/OIF/gateway/direct
semantics/flags and applicable Netlink table/type/scope/protocol/priority fields. An Exact receipt is a time-local kernel observation only. It grants neither
ownership of an existing route nor permission to delete it. RTPROT_STATIC alone
is also never ownership evidence.

Linux sends only RTM_GETROUTE REQUEST|DUMP for the destination family and examines
the complete main-table inventory. The netlink sender must be the kernel,
and the original sequence must finish with a successful non-interrupted multipart
NLMSG_DONE. Absence requires that complete query and no requested exact network/
prefix key. An ordinary broader/default route cannot stand in for that key. Exactly one candidate must also match the original OIF, desired gateway,
RTN_UNICAST, main table, and expected LINK scope for direct routes (UNIVERSE for
IP-gateway routes). Source-specific/TOS, multipath, next-hop indirection,
non-default IPv6 preference and unsupported route styles are not promoted to
Exact. Duplicate matching keys produce Unknown Ambiguous rather than selecting
the first route. The RTPROT/priority remain visible; existing kernel
connected routes can be verified without being claimed as ours. No policy-routing
rules, alternate tables or remote packet delivery are verified by this narrow Get.

FreeBSD uses the same bounded complete-dump flow for the generation's captured
interface FIB. An explicit RTA_TABLE distinguishes FIB 0 from an all-FIB dump. Native
RTA_RTFLAGS supplies path flags separately from rtmsg flags; exact matching also
requires UNICAST, UNIVERSE scope, the original interface and the requested gateway
semantics without reject/blackhole flags. Missing path flags, multipath, unknown
styles, explicit weights and expiring routes cannot become Exact. Kernel next-hop
identifiers are metadata when complete interface/gateway fields accompany them.
The native DONE can have flags zero; records still require MULTI. Installed native
headers are checked independently during FreeBSD tests.

macOS sends RTM_GET with the original interface scope/index, destination,
mask and interface sockaddr. It validates the native reply version/type/PID/
sequence and RTF_DONE or errno. A correlated ESRCH echo of the exact original
query is Absent with its errno retained. A successful reply must return the exact
canonical destination, contiguous prefix, original interface and desired direct
AF_LINK or IP gateway semantics, with usable non-reject/non-blackhole route flags. A broader-prefix/default fallback or another OIF/gateway is Different. Compact
native masks use SDK offsets and four-byte routing-sockaddr alignment; host masks
and IPv6 scope handling are checked. Scope recovery is explicit and only accepts
the original interface zone. Native Get reply loss, truncation or malformed data
is Unknown. Mac native source fields are exposed as native flags, without
inventing Linux table/type metadata.

`Submitted`/Whole means only the read-only request entered the kernel. A native
write errno is retained while the same original query waits for its correlated
reply/deadline; this handles synchronous BSD errors that also produce native
error replies. No write is retried. Positive short writes close the query and
never send a suffix. Source retirement, deadline, explicit cancellation,
truncation/overrun, inventory bounds and kernel errors yield Unknown. Each query
retains one bounded native request (under512 bytes), one32768-byte RX buffer,
at most128 received datagrams/1048576 bytes, two timers and one native control
socket. Each poll performs at most one query send/receive plus bounded parsing
and read-only source checks. Idle/stalled queries wake for source checking at
most100ms while driven; no private task is spawned. Query and mutation requests
share the existing non-recycling process sequence domain to avoid internal PID/
sequence collisions. Original errors and scope are not completed by another job.

For Add returning EEXIST, the caller may explicitly perform this Get on
the same original epoch and require Exact for its intended tuple. EEXIST, local
Get writing, Different, an unrelated route or Unknown never become success. The
caller separately decides whether to borrow a matching existing route or continue
its own original provisioning work. A query on a replacement epoch cannot settle
an old exposed/uncertain route operation. This adapter neither auto-adopts an
existing route nor removes a mismatching/unowned one.

All these getters are snapshots over a bounded group, not permanent or atomic
original-state/restore authority. External administrators can change configuration
immediately afterward or between native reads. Original descriptor Epoch prevents
rebinding after this owner closes/transfers the source, including name/ifindex
reuse. Native name/index checks detect observed replacement; the OS does not
supply a portable incarnation counter that proves absence of an unobserved
external delete/recreate with identical name/index during live ownership. Safe
exclusive/adopted-device policy and reconciliation of such uncertainty belong to
the caller, rather than being hidden behind a successful snapshot. Existing
foreign duplicated FDs/persistent devices remain explicitly caller-owned facts.

The VPN coordinator confirmed snapshots, existing IPv6 DAD observation and exact
route Get are the minimal required ports for this step. Address removal/restoration
and generalized host policy remain unimplemented here; no new Action or automatic
cleanup policy was added. Existing typed apply/route actions remain unchanged.

## References

The existing single internal
controlled Unix-datagram-FD model checks packet boundaries, original write/cancel,
epoch retirement, external report classification and rejection of a socket
by the public adoption path. Its private test constructor is explicitly **not**
evidence of TUN device qualification. Central compilation/review
remains required before any concrete authorized native configuration checks.

Primary interface references:

- Pinned GNUnet commit `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`,
  `src/service/vpn/gnunet-helper-vpn.c` and `src/include/gnunet_tun_lib.h`.
- [Linux TUN driver documentation](https://docs.kernel.org/networking/tuntap.html)
  and [Linux UAPI if_tun.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h).
- Local Apple SDK `net/if_utun.h`, `sys/kern_control.h`, `sys/sys_domain.h`,
  `net/if.h`, `sys/socket.h` and `sys/sockio.h`; exact C struct layout and ioctl
  constants are supplied by the pinned libc bindings rather than surrogate ABI.
- [Apple XNU utun implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if_utun.c)
  for network-order AF framing, and
  [kernel-control implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_control.c)
  for the original connected controller address.

Additional configuration primaries: local SDK `netinet6/in6_var.h`, `net/route.h`,
`net/if_dl.h` and the route(4) manual; Linux UAPI in6_ifreq/rtnetlink/netlink
headers, [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html),
[Netlink ACK documentation](https://docs.kernel.org/userspace-api/netlink/intro.html)
and [Apple route reply handling](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/rtsock.c).
FreeBSD uses installed `netlink/netlink.h` and `netlink/route/route.h`, the
[route encoder and handlers](https://github.com/freebsd/freebsd-src/blob/releng/14.5/sys/netlink/route/rt.c)
and [ACK/DONE writer](https://github.com/freebsd/freebsd-src/blob/releng/14.5/sys/netlink/netlink_message_writer.c).
The native error and route-field conventions are also checked against releng/15.1.
Device lifetime uses installed `sys/sockio.h` and `net/if_tun.h`, the
[FreeBSD clone owner](https://github.com/freebsd/freebsd-src/blob/releng/14.5/sys/net/if_clone.c),
[interface rename](https://github.com/freebsd/freebsd-src/blob/releng/14.5/sys/net/if.c)
and [transient TUN lifecycle](https://github.com/freebsd/freebsd-src/blob/releng/15.1/sys/net/if_tuntap.c).

## Linux VPN helper

`helper::Link` owns one child, stdin/stdout/stderr and a distinct pipe
Epoch. Its public spawn input uses the official five arguments. It cannot be
passed to `OwnedTun::from_fd`, and its epoch is not a TUN ownership or helper
ready ACK. A bounded read-only kernel snapshot binds the observed interface
index and state. Exact route and IPv6 readiness queries reuse the same native
observers with that original epoch; these grant no administrative authority. Only the helper process creates/configures the interface. An original C helper
can be selected in the default no-MTU-override profile. The explicit
GNUNET_VPN_HELPER_MTU override belongs only to the Rust helper.

There is one pre-reserved immutable output frame and one bounded input frame. Every stdout partial frame has a first-byte native deadline; every stdin output
retains its original queue deadline and accepted prefix. Positive partial
stream writes are continued on the same frame and are never requeued with a new
identity. Zero-exposure expiry is Unsent; loss after exposure retains both the
original IO cause and the exact WriteId helper-prefix observation. A whole frame
accepted by helper stdin does not prove a TUN write or IP delivery.

Stop closes the original pipes and requests the original child stop. The caller
must retain and await `reap` to obtain the wait result. Drop does not claim
reap. Kill, nonblocking wait, final wait and stderr-read errors remain independent. Stderr keeps at most4096 bytes plus the count of observed discarded bytes;
it is not parsed as errno or a ready message. After wait, a finite final read
quantum records whether EOF was seen, without calling an unobserved tail
a full drain. The adapter never creates an async runtime or detached task.
