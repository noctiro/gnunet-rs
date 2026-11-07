# Standard Rust VPN SERVICE

`gnunet-service-vpn` consumes shared SERVICE `-c/-d/-h/-L/-l/-v`,
selected Logger and the standard SERVICE configuration loader. An explicit
configuration error remains an error; absent default user configuration still
loads installed defaults. Post-configuration testing skew uses the same
selected SharedClock authority. No PROGRAM Prepared object, scheduler task,
private protocol or hidden runtime is fabricated.

Early startup retains the original activation/parent-control descriptors and
optional uniquely transferred TUN FD before unrelated descriptor allocation. Its original decimal/alias/open-descriptor/CLOEXEC qualification is retained. Parent-control notices are deferred to selected diagnostics. Explicit daemon
split occurs before account lookup, runtime, new listeners, native TUN, route,
CADET/REGEX client or worker. The parent drops its original TUN, activation
and parent-control owners before waiting on the child status pipe. EOF,
initialization failure and failed status IO are not ready; the parent does not
wait for a live daemon's eventual exit. Only the service child refreshes Logger
PID; selected files and original descriptors are not reopened or rediscovered.

The service prepares adopted listeners/new TCP before configured USERNAME and
initgroups. New Unix endpoints finish only under the target account. The same `[vpn] UNIX_MATCH_UID/GID` (absent false) controls new parent/socket
permissions and kernel credential admission; existing inodes are not
chowned. Standard OPTION_NONE selects Immediate shutdown, with explicit shared
Soft policy retained. Native TUN qualification/opening and all providers
occur after identity transition. A single current-thread runtime directly polls
the original SERVICE, Resolver, TUN, CADET and REGEX owners.

Readiness preserves the existing startup requirement: original TUN
configuration/route/DAD receipts must be ready, the CADET MQ attached,
and the READY stdout line completely accepted and flushed. Only then is the
unique ChildReady writer consumed. A TUN allocation, CreateQueued, diagnostic
message or clock-compatible replacement source cannot substitute for readiness. Remote exit/IP reachability remains explicitly unasserted. Later source loss
does not emit another initial-ready byte.

The official `[vpn]` keys read here are `IFNAME`, `IPV4ADDR`, `IPV4MASK`,
`IPV6ADDR`, `IPV6PREFIX`, `MAX_MAPPING` and `MAX_TUNNELS`, plus shared SERVICE
listener/ACL/identity/lifetime keys. Defaults match pinned v0.29.1:
`vpn-gnunet`, `10.11.10.1`, `255.255.0.0`, `1234::1`, prefix32, and200
mapping/tunnel slots. The configured `[vpn]` `VIRTDNS` and `VIRTDNS6` keys belong
to the surrounding DNS configuration and are not consumed by active C VPN's
configuration handler either.

`[vpn-rust] TUN_MODE=fresh` is the default. On Linux this launches the actual
`gnunet-helper-vpn` selected by `Configuration::suid_binary_path`, after USERNAME
has been applied. The independently installed Rust helper must actually have the
OS privileges needed to create/configure the interface (for example an
administrator-installed SUID executable); this application does not manufacture
capabilities or silently fall back to running the whole daemon as root. The
helper accepts the official five arguments and exchanges type185 frames with the
Linux PI prefix. An original C helper can be selected for the default profile. The Rust helper creates the new nonpersistent TUN exclusively; a preexisting
named interface is not adopted by this default path.

The official helper protocol has no ready or TUN-write acknowledgement. The
service observes the kernel interface index, link state, address/netmask,
exact routes and IPv6 DAD before ChildReady, separately from the original child
and pipe lifetime. These observations do not establish that the child owns that
interface. Whole stdin frame acceptance is reported as HelperSubmitted and is
not a claim of kernel packet injection, peer processing or downstream delivery. A positive partial frame is retained unchanged; cancellation/expiry/source loss
keeps the accepted-prefix fact and original failure instead of Unsent.

The default helper profile does not assume or override the kernel MTU. It reads
MTU and checks the enabled-family minimum and packet buffer cap. Explicit
`[vpn-rust] MTU` is a Rust-helper profile: it passes
`GNUNET_VPN_HELPER_MTU`, which the Rust helper strictly parses and applies before
dropping privilege, and requires exact readback. The C helper does not understand
this override. `HELPER_INPUT_TIMEOUT` (default5s) fixes the original native cap
from the first byte of each incomplete helper stdout frame. It is never renewed
by partial progress. The original configuration deadline also covers helper
qualification.

On macOS fresh mode retains the direct native utun path and requires the selected
identity to have the necessary privileges. It does not pretend the Linux helper
exists on Darwin. `IFNAME` must be an utunN. There is no native/privileged
fallback after a helper failure.

`TUN_MODE=preopened` still requires `GNUNET_VPN_TUN_FD` to designate a uniquely
transferred kernel TUN/utun descriptor. It is verified after USERNAME and
must already match the native plan. Arbitrary files, sockets and helper pipes do
not qualify as this descriptor. The service does not rewrite an externally
provided device. Its framing mode comes from the kernel descriptor;
the official helper transport always uses its mandatory Linux PI prefix.

Every normal error or stop after helper admission closes the original pipe
source, requests that same child stop and awaits its OS wait result before
Resolver retirement and the final report. Kill and wait failures are retained
independently. Drop is only a physical stop attempt and never a reap proof. There is no artificial socket timeout that declares a still-owned process reaped.

Direct native provisioning retains the original configure deadline across native
MTU/address/link ioctls, route ACKs/reconciliation and DAD. An EEXIST route reply
requires an exact query. A queued request, completed local write or TUN
allocation is insufficient for readiness. The first `READY vpn` line is emitted
only after the original TUN plan is ready and the CADET IPC MQ is
attached. It explicitly states that remote exit reachability is unasserted. Application accepts begin after this readiness gate. A permanent startup failure
or timeout closes every source and keeps the original failure.

Internet flows use official REGEX searches by default. `[vpn-rust]
EXIT_DISCOVERY=regex` selects the caller-driven native client at the existing
`[regex]` SERVICE endpoint; no Search MQ exists until a flow needs it. `READY` therefore says `automatic-regex=on-demand-client`, not that a REGEX service
has attached or an exit was found. All searches share the foreground's existing
Resolver and exact clock Arc. They run inside the same direct caller-polled service loop,
with no new hidden worker, DHT implementation or private search protocol.

Each bounded search retains the original VPN discovery/flow generation. Actual
REGEX request enqueue precedes pure admission; a whole local write is separate
from an RESULT. Only an original result with matching job, MQ epoch
and ordinal supplies a peer. The search then closes its original MQ before the
pure discovery retires. A result discovers a peer; CADET endpoint/credit/KX
checks still apply. The peer AF assignment comes from the explicit
`PEER_AF_PROFILE` configuration, never from inferred byte lengths or a supposed
authentication property of REGEX. The official search has no transport selector.

Defaults are16 simultaneous search MQs,10 seconds to send,30 seconds to receive a
first result and60 seconds per original job. Configure `REGEX_SEARCHES`,
`REGEX_SEND_TIMEOUT`, `REGEX_FIRST_RESULT_TIMEOUT`, `REGEX_SEARCH_TIMEOUT` and
`REGEX_IO_SLICE_BYTES` to change these bounded local policies. Deadline order and
zero IO/slot resources are rejected at configuration time. A separate original
native Instant hard limit prevents logical clock regression from keeping a job
alive indefinitely. Timeout, EOF and native failure are inconclusive;
there is no invented wire DONE, no proof that no matching exit exists, and no
attached search replay. A closing or stale flow cancels the exact old search. Table capacity produces an explicit original refusal without blocking other
searches, application MQs or the shared Resolver.

`EXIT_DISCOVERY=configured` instead selects explicit fixed policies. `CONFIGURED_EXITS` is a semicolon-separated list of entries:

```
PEER  prefix|any  tcp|udp|icmp|icmp6|any  first-last  native|linux|darwin
```

`PEER` accepts the official52-character GNUnet identity or64 hex digits. Up to64
ordered entries select the first matching destination network, transport and
port. The AF profile describes the peer endpoint's platform wire AF
assignment. An empty list is valid for named SERVICE redirects; Internet flows
then fail with a configured provider miss. Configured selection is not
reported as an automatic REGEX result. Named peer SERVICE requests do not need
Internet exit discovery in either mode. `PEER_AF_PROFILE` supplies their default
profile and REGEX-discovered peers' explicitly selected profile;
`IPC_AF_PROFILE` supplies the local VPN IPC source profile (both default native). No stopped DHT/UDP communicator/GNS branch is consulted.

Shared resource defaults are8 local MQs,32 request debts per MQ,256 shared
request rows,200 leases and200 flows. All flows share16 packets of2048 bytes and4
surplus packets of65575 bytes; the process does not allocate maximum packet
vectors per possible channel. `[vpn-rust]` overrides are `MAX_CLIENTS`,
`REQUESTS_PER_CLIENT`, `REQUEST_SLOTS`, `PACKET_SLOTS`, `PACKET_SLOT_BYTES`,
`LARGE_PACKET_SLOTS`, `LARGE_PACKET_BYTES`, and `PACKET_BYTES`. Payload backing is
fallibly allocated and capped at64MiB; other metadata/source capacities are
explicitly checked. Actual incoming envelopes and the single immutable native
TX per port remain owned until writing or source loss. The native CADET carrier
has its actual64348-byte application limit; no private fragmentation is added.

Other local knobs are `MTU` (direct native default1280; helper default observes
the native value), `ENABLE_IPV4`, `ENABLE_IPV6` (both true),
`IDLE_TIMEOUT`, `IPC_INPUT_TIMEOUT`, `IPC_SEND_TIMEOUT`,
`PEER_INPUT_TIMEOUT`, `TUN_SEND_TIMEOUT`, `CADET_SEND_TIMEOUT`,
`CONFIGURE_TIMEOUT`, `ADDRESS_WATCH_TIMEOUT`, `STARTUP_TIMEOUT`,
`SHUTDOWN_GRACE`, `MAINTENANCE_INTERVAL`, `IO_SLICE_BYTES`, and
`CADET_IO_SLICE_BYTES`. Every deadline is finite, nonzero and representable. The initial DAD budget is never extended by tentative observations. Subsequent
bounded IPv6 samples must remain ready; source/address loss retires the
original flows instead of pretending the previous sample remains proof.

`STOPPED vpn` retains IPC/CADET/TUN source metadata, original write
exposure/pending IDs, unconfirmed native-control count, route/flow/buffer debt and
REGEX original reports/pending jobs. The new `take_cleanup_errors` transfers
coordinator, IPC, prior-TUN, control-close and final-TUN-close error objects in
separate fields once, without changing the permanent closed latch, epochs,
reports, route state or uncertainty counters. Empty error slots never reopen a
source. The earlier single-failure getter is not used as a complete cleanup result.

All diagnostics use the shared Reporter with severity-stable site IDs,
permanent failure latch and registered original task waker. Each callback class
checks failed before the next new Resolver/Coordinator/REGEX admission. Logging
failure takes the normal clock-free original close path. Actual terminal IPC
CleanupFailed stops new admission; ControlFailed only comes from the existing
control_failed shutdown branches, and TunLost only after that original device
was physically retired. These source failures retain their typed errors
and fence the next normal class. Recoverable BackendRetry/BackendLost and their
original retry/clock/deadline behavior remain unchanged. There is no per-packet
error-log queue; independent retained failures are limited by the original fixed
source/client/control cleanup set after the first terminal fault.

REGEX closes before VPN; VPN closes every original IPC/CADET/TUN/control source
before original Resolver disconnect, even when another close fails. Normal,
error, construction refusal and dropped-future guards preserve owned causes
and independent cleanup. Same-stage independent causes keep both objects rather
than formatting/dropping the later one. Final output errors and unresolved
original debt remain distinct. No cleanup requires another successful canonical
clock sample. The original coordinator algorithms for owned versus borrowed
routes, DAD, partial writes, fixed native hard limits, uncertain outcomes and
receive_done remain unchanged. No Unknown is replayed or called delivery.

This is the production foreground source candidate for native ports. It is not a full GNUnet completeness or new interoperability acceptance claim. The example is input text,
not evidence that a device or route was created. Earlier unavailable-IPC or
own-peer EXIT/DNS profiles are not relabeled as this new standard SERVICE entry passing. Actual privileged TUN forwarding and complete GNUnet-node interoperability remain separate qualification work.
