# Rust EXIT daemon foreground

`gnunet-daemon-exit` is the PROGRAM/CADET daemon corresponding to the active
v0.29.1 `src/service/exit/gnunet-daemon-exit.c`. It consumes the real
`gnunet-exit-host::runtime::Driver`; it does not invent a service IPC protocol. It has no local service listener.

The process composes the shared VPN packet/official wire base, whole-packet TUN
adapters, native route and IPv6 DAD owners, and core TCP/UDP service selection.
It preserves both `(hash, TCP)` and `(hash, UDP)` targets while opening each
CADET hash once. Duplicate `(hash, protocol)` configuration is rejected.

## Startup and configuration

The first operation captures original inherited descriptors and parent control. A parent may explicitly transfer one genuine already open TUN using the decimal
`GNUNET_EXIT_TUN_FD` environment hint and `TUN_MODE=preopened`. The parent must
transfer exclusive ownership; it must not independently close/reuse that number
inside the child. The hint is consumed before configuration/runtime creation. Aliases with the shared listener/control declarations are rejected before
ownership transfer. `OwnedTun::from_fd` later performs native device
qualification; an arbitrary pipe/socket cannot masquerade as a TUN.

There is no listener bind phase. Nonempty inherited listener/readiness sets are
closed as failed startup and explicitly refused, rather than announcing an
invented AcceptRegistered/bound phase. The normal shared parent-control stream
and installed SIGINT/SIGTERM handlers remain supported; EOF is not a synthetic
shutdown signal.

Shared PROGRAM supplies source option/config/log ordering, `GNUNET_ARGS`, normal
`-c/-h/-v/-l/-L`, testing skew and scheduled SPEEDUP. No positional argument is
accepted. The normal reference NLS-disabled build profile is explicit. A positive
PROGRAM return from failed log setup is not treated as permission to start. `[exit] USERNAME` and the common fallback are resolved/applied with the actual
shared group/GID/UID semantics before runtime or providers. Linux fresh mode
starts the privileged `gnunet-helper-exit` afterwards, selected through
`Configuration::suid_binary_path`; the daemon itself need not retain TUN/admin
capabilities. Installation must provide the helper's OS privilege. No key
file is read. All runtime/Resolver/REGEX/native diagnostics use the PROGRAM's
selected Logger through the shared Reporter, including its permanent failure
latch and registered task wake. Log failure stops new admission and preserves
original cleanup/results.

One current-thread PROGRAM task owns one shared Resolver broker and the one
CADET application MQ. Foreground loops poll the Resolver and EXIT owner fairly;
there are no per-peer threads, detached tasks or ambient `getaddrinfo` calls.

Official keys consumed from `[exit]` are `ENABLE_IPV4`, `ENABLE_IPV6`,
`EXIT_IPV4`, `EXIT_IPV6`, `IPV4ADDR`, `IPV4MASK`, `IPV6ADDR`, `IPV6PREFIX`,
`TUN_IFNAME`, `EXIT_DNS`, `DNS_RESOLVER`, and shared `USERNAME`. Exit capability
implies the corresponding enabled TUN family. IPv4 masks must be contiguous;
the pinned official IPv6 configuration rejects prefixes127 and128.

Sections ending in `.gnunet.` use the official `TCP_REDIRECTS` and
`UDP_REDIRECTS` lists: `local_port:hostname:remote_port` separated by spaces or
semicolons. `localhost4`/`localhost6` mean the configured TUN address. Numeric
addresses and bracketed IPv6 literals are accepted; other names use actual
shared Resolver type4/5 callbacks with an original finite query deadline. A
returned enabled-family address is selected, then the original remaining query
is explicitly cancelled. Failed lookup is not converted to an endpoint. Service
hashes use the official SHA512 name descriptor with the first two hash bytes
replaced by the big-endian local port. At most256 mappings are retained.

`[exit-rust]` contains local resource/provisioning controls, not private wire:

- `TUN_MODE=none|preopened|fresh|direct`. By default an enabled IP family uses
  fresh mode, and disabled IP families use the genuine DNS-only none profile.
  Non-DNS ports require a packet source and an enabled family. On Linux fresh
  uses the official six-argument helper; direct retains explicit native creation
  under the selected identity. Preopened still consumes the unique kernel
  descriptor and uses native administration. Fresh/direct reject a transferred
  descriptor. None creates no TUN/route/helper operation.
- `LINUX_TUN_PI` selects Linux raw-IP/TUN_PI framing. `UTUN_UNIT` selects macOS
  utun; the original kernel-qualified interface name/index remain authoritative.
  If `TUN_IFNAME` is supplied it must equal the name.
- Direct native `MTU` defaults1400. Helper default observes kernel MTU
  and does not assume1400 or override the original C helper. An explicit MTU uses
  the shared Rust-only `GNUNET_VPN_HELPER_MTU` setting; it must satisfy the family
  minimum and the official65527 raw-byte frame cap, and requires exact native
  readback. Original C helpers do not understand this override.
- Linux helper accepts `(TUN, physical-egress-or-minus, IPv6-or-minus, prefix,
  IPv4-or-minus, mask)`, emits/consumes type185 plus original Linux PI, and has no
  ready or TUN-write ACK. Default helper profile is compatible with the original
  C packet/CLI contract. `HELPER_INPUT_TIMEOUT` defaults5s from the first stdout
  frame byte and never renews on partial progress. Source/write tokens and every
  accepted prefix stay on the original pipes.
- `[exit] EXIT_IFNAME` supplies the physical egress interface. The config's
  `%` disable value is translated to the helper CLI `-` marker. Requested Linux
  forwarding/IPv4 masquerading is performed by the privileged Rust helper before
  its new TUN becomes observable; setup subprocess/OS failures cause a
  nonzero exit with bounded original diagnostics. Neither a successful spawn nor
  the kernel interface snapshot is called a forwarding/NAT ACK. Global forwarding
  values and masquerading rules are not silently deleted or restored on shutdown,
  consistent with the public C profile's persistent administrative side effects.
- `ROUTES` is at most32 semicolon-separated explicit interface route intents,
  `numeric/prefix` or `numeric/prefix@gateway`. These use native route
  transactions, never an external `route_applied` report. Only the original
  correlated `KernelAck(Ok)` is installation. In helper mode, service-side
  administration is read-only: requested extra routes must already have actual
  exact kernel observations; they are not sent as fabricated route-add receipts. EEXIST/rejection, timeout,
  uncertainty and close failures remain failures. A late successful ACK
  still creates a cleanup obligation. Preexisting/uncertain additions are never
  blindly deleted as though this daemon created them.
- Internet authorization and REGEX announcements share the official
  `EXIT_RANGE_IPV4_POLICY` / `EXIT_RANGE_IPV6_POLICY` from `[exit]`. Each enabled
  Internet family requires its policy key. The normal public `exit.conf` is read
  through shared PROGRAM configuration; there is no implicit policy-file key.
  Empty/all-excluded sets authorize no Internet target and open no REGEX MQ.
  `POLICY` and `DEFAULT_ALLOW` are rejected product configuration keys; there is
  no old-policy migration or fallback authorization source. Pure Rust users may
  still explicitly choose the core's `InternetRules::Ordered` API.
- `REGEX_POLICY_RULES` defaults512 total parsed IPv4+IPv6 rows (maximum4096).
  Expressions are measured before exact allocation and capped by the official
  ANNOUNCE frame. Actual generated policy sets include every configured rule,
  including zero-network entries, with the shared prefix bound to the whole
  union. TCP/UDP share its port set; family-correct ICMP uses query port zero.
  Named service redirects and DNS retain their independent configured gates.
- `REGEX_FRAME_BYTES` defaults65535; `REGEX_IO_SLICE_BYTES` defaults that frame
  bound. `REGEX_SEND_TIMEOUT` defaults10s, `REGEX_JOB_LIFETIME`6h and
  `REGEX_RECONNECT_DELAY`1s, all finite. Native jobs retain original deadlines;
  renewal or post-loss reconnect creates a new logged job/generation after the
  old physical source ends. Official service refresh is30minutes, compression4
  for IPv4 and8 for IPv6. Local Submitted records only whole IPC writes.
- `DNS_RESOLVER_PORT` defaults53 and `DNS_RETRY` defaults1s. The official
  `DNS_RESOLVER` must be a numeric address. Real DNS UDP sockets/jobs remain
  independently bounded, with source/id/question validation in Driver.
- Finite original bounds: `CONFIGURE_TIMEOUT`10s, `DAD_TIMEOUT`10s,
  `ADDRESS_WATCH_LIFETIME`60s, `SERVICE_LOOKUP_TIMEOUT`10s,
  `STARTUP_TIMEOUT`30s for CADET port writes and required local REGEX
  submissions, `SHUTDOWN_GRACE`5s.
  A DAD observer reaching its original finite lifetime closes; continued running
  creates a new native observer. It never resets the retired query or invents a
  Ready callback. Actual tentative/duplicate/missing/detached/prefix mismatch
  while serving stops forwarding and enters cleanup.
- Core controls: `MAX_FLOWS`, `MAX_PROCESSING_RECEIPTS`, `MAX_OUTPUT_FRAMES`,
  `MAX_OUTPUT_BYTES`, `PACKET_BYTES`, `PEER_BYTES`, `DNS_BYTES`,
  `ENTROPY_DRAWS`, `IDLE`, `INPUT_LIFETIME`, `QUARANTINE`.
- Native controls: `MAX_CADET_PORTS`, `MAX_CADET_CHANNELS`, `MAX_INNER_FRAMES`,
  `MAX_DNS_JOBS`, `MAX_DNS_QUESTIONS`, `IO_GRACE`, `FIRST_INPUT`, `TUN_INPUT`.
  Channel×inner capacity must fit the processing-debt table.
- Shared clients: `CADET_FRAME_BYTES`, `CADET_IO_SLICE_BYTES`,
  `CADET_PAYLOAD_BYTES`, `CADET_SEND_CREDIT`, `RESOLVER_FRAME_BYTES`,
  `RESOLVER_IO_SLICE_BYTES`, `RESOLVER_QUEUE`. Existing native owners validate
  frame and slot capacities. Resolver slots/name storage are fixed128/256.
  `PEER_AF_PROFILE=native|linux|darwin` explicitly selects the official numeric
  peer AF ABI without adding any negotiation wire.

The two example configurations are inputs for a later explicitly executed
integration run. They do not start dependencies. DNS-only needs a CADET
service and a configured UDP DNS endpoint; its public discovery publisher
also uses the configured PILS and DHT services. No TUN is required. Named remote
service hosts additionally need the configured GNUnet Resolver. A direct or preopened native run requires the selected identity's native
administrative privileges. Linux fresh instead needs the privileged helper
installation. macOS keeps its explicit direct utun path and has no invented Linux
helper. Disabled egress setup is an explicit operator-managed profile; no native
snapshot proves external forwarding, NAT or remote reachability.

## Readiness and retirement

READY is emitted only after successful required native interface configuration,
Ready DAD observation, every requested original route ACK, and complete
CADET PORT_OPEN writes on the current MQ. It reports exact port count, verified
interface, IPv4 ioctl/IPv6 observation facts, explicit route ACK count and literal
DNS configuration and local REGEX operation counters. At most two original REGEX
MQs use the same existing Resolver/RuntimeClock. They are enabled only after
TUN/address/DAD readiness and written CADET ports. Every drive pass checks
current TUN source and port state before polling announcements; known loss
physically cancels their old jobs before renewed readiness can start new ones. READY waits for whole local ANNOUNCE writes when nonempty Internet policies need
them, with `advertisement_ack=none` and remote reachability unasserted. There is no
wire ANNOUNCE acknowledgement; local writes do not prove REGEX service acceptance,
DHT publication, remote eligibility or Internet forwarding. The new integration
source path remains subject to native and official interoperability acceptance.

With `EXIT_DNS=YES`, a separate bounded owner signs the standard112-byte DNS
advertisement through the PILS identity, verifies the returned signature
with the shared PT advertisement codec, and submits one DHT type10 PUT under
SHA512("dns"). It uses the same Resolver and clock. The original DNS CADET port
must be fully announced on its current source before this owner performs IO. The normal settings select node-wide `[PILS] PROFILE` once and pass it to this
owner's PILS client. The default `reference029` (alias `reference-0.29.1`)
and official conditional `deterministic` profile remain explicit alternatives;
`lsd0014-text` is a separate textual interpretation, with no C interoperability
claim. Invalid selections fail before native setup; there is no verification
fallback. This choice is independent of `PEER_AF_PROFILE` and leaves each
original advertisement's signer binding, deadline and result debt intact. An initial or refreshed advertisement has one original operation deadline across
identity, signing, DHT connection and PUT. Fresh publication intents normally
refresh every15minutes with a checked3hour public expiration.

A transient advertisement dependency failure retires that exact operation and
keeps its cause/terminal outcome. After finite backoff, only a current real
port and verified identity may create an independent new expiry/signature/PUT. Unknown old PUTs are not replayed, and existing DNS forwarding remains available. A completed local PUT write proves no remote publication. Already exposed public
advertisements cannot be withdrawn here; they retain their signed expiration. READY and STOPPED report these local facts separately from forwarding readiness.

On ordinary signal/error exit, the DNS advertisement owner first stops its
original signature and PUT sources and drains retained terminal notices. Then both original REGEX announcement MQs and retry timers
are physically cancelled without clock/Resolver/ACK waits before the observer is
cancelled. Each ending receipt and final operation counters remain explicit;
remote DHT entry expiry is not claimed. Then only routes actually
ACKed as created by this daemon are deleted through the original TUN, and
shutdown uses one original finite global native target. Then Driver retires
original flows/channels/ports/MQ/TUN/DNS owners and settles its original partial
write and outer receive_done debts from physical outcomes. Logical clock,
route cleanup, driver cleanup, Resolver cleanup and output failures are retained
independently before the original operation error is returned.

A PROGRAM scheduler clock failure can cancel the task before it polls again. Its drop guard still independently cancels both REGEX jobs and synchronously
closes the Driver, IPv6 observer and Resolver without a clock sample. Interrupted native route/DAD owners emit their
cancel/uncertainty receipts. No async kernel route deletion is claimed on
that cancellation path: unremoved ACKed route intents are reported explicitly. Closing a fresh nonpersistent TUN removes its interface; a persistent preopened
interface can retain configuration/routes and requires explicit operator
reconciliation. No previous interface state or preexisting route ownership is
invented. The same applies to an uncertain exposed route add without its ACK.

Scoped Driver delegates in `runtime/admin.rs` cover plan, ioctl apply,
route transaction and native IPv6 observation. A read-only
`tun_source_current()` predicate additionally reports the original epoch's known
physical liveness; it proves no address/route readiness. These APIs cannot expose,
swap or rebind the descriptor and do not acknowledge a core packet/flow. Existing
CADET/DNS/whole-packet ownership logic is unchanged. The foreground owns official REGEX Internet announcements through the real
configured REGEX service. DNS DHT advertisement uses its independent actual
PILS/DHT clients; no replacement service, worker or private protocol is created. An operational REGEX backend and native forwarding remain separate
deployment and interoperability requirements. Native-client
ending receipts expose known local outcomes; an OS close errno not exposed by the
shared CLIENT interface is not invented as a successful cleanup receipt.

## Original helper and terminal ownership

The original PROGRAM future remains outside the scheduler task through shared
`foreground::run`. Scheduler/clock/Logger/parent errors set the same stop gate;
that same future closes its original sources and awaits the helper wait. No replacement child, future, source, flow or deadline is minted for cleanup. Helper pipe whole acceptance and complete helper RX frames have independent
`helper_submitted`/`helper_received` counters; native `tun_written`/`tun_read`
remain native descriptor facts. Neither counter asserts IP delivery.

Constructor refusal returns Parts, including an already-started helper,
for same-owner close and wait. Unexpected packet-source loss moves that owner
into retained retirement storage; it is not dropped before wait. Zero-exposure
frame cancellation is Unsent, while a positive partial frame requires original
source close and retains its exact write id/prefix as unknown exposure. The
shared helper guard runs before canonical clock/Resolver work.

`Shutdown.quiescent` is only the core IO-debt state after close attempts. Actual
helper wait, Resolver physical drop, owned independent causes and final output
are obtained separately before normal completion. The final error retains typed
native/REGEX/core facts and helper report even for a sole Logger failure. One
first-stop native grace is reused for all retirement turns; OS child wait
is never declared complete by that grace or by Drop.

Normal EXIT helper stop sends TERM only through the original Child after an
unreaped-state check, allowing the Rust helper to stop and actually wait
its active setup command. The parent then obtains the original helper wait. This does not turn an external C helper's exit status into proof that its
internal subprocesses joined. Both helper profiles disable implicit Tokio
kill-on-drop; a previous ECHILD/unknown wait error cannot leave an implicit PID
signal armed. VPN's explicit normally authorized KILL policy is preserved. An exceptional dropped owner only attempts its authorized stop and reports no
reap/descendant/global-configuration completion.
