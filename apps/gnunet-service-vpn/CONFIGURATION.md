# VPN service configuration and device contracts

`gnunet-service-vpn` consumes shared SERVICE `-c/-d/-h/-L/-l/-v`,
selected Logger and the standard SERVICE configuration loader. An explicit
configuration error remains an error; absent default user configuration still
loads installed defaults. Post-configuration testing skew uses the same
selected SharedClock authority. No PROGRAM Prepared object, scheduler task,
private protocol or hidden runtime is fabricated.

## Startup and identity

On Unix, early startup retains the original activation/parent-control descriptors and
optional uniquely transferred TUN FD before unrelated descriptor allocation. Its original decimal/alias/open-descriptor/CLOEXEC qualification is retained. Parent-control notices are deferred to selected diagnostics. Explicit daemon
split occurs before account lookup, runtime, new listeners, native TUN, route,
CADET/REGEX client or worker. The parent drops its original TUN, activation
and parent-control owners before waiting on the child status pipe. EOF,
initialization failure and failed status IO are not ready; the parent does not
wait for a live daemon's eventual exit. Only the service child refreshes Logger
PID; selected files and original descriptors are not reopened or rediscovered.

On Unix, the service prepares adopted listeners/new TCP before configured USERNAME and
initgroups. New Unix endpoints finish only under the target account. The same `[vpn] UNIX_MATCH_UID/GID` (absent false) controls new parent/socket
permissions and kernel credential admission; existing inodes are not
chowned. Standard OPTION_NONE selects Immediate shutdown, with explicit shared
Soft policy retained. Native TUN qualification/opening and all providers
occur after identity transition. A single current-thread runtime directly polls
the original SERVICE, Resolver, TUN, CADET and REGEX owners.

Readiness preserves the existing startup requirement: original TUN
configuration/route/DAD receipts must be ready, the CADET MQ attached,
and the READY stdout line completely accepted and flushed. Only then is the
unique readiness writer acknowledged. The Windows notification uses the original
managed parent pipe; its wait cannot extend the initial startup deadline. A TUN allocation, CreateQueued, diagnostic
message or clock-compatible replacement source cannot substitute for readiness. Remote exit/IP reachability remains explicitly unasserted. Later source loss
does not emit another initial-ready byte.

## Configuration keys

The official `[vpn]` keys read here are `IFNAME`, `IPV4ADDR`, `IPV4MASK`,
`IPV6ADDR`, `IPV6PREFIX`, `MAX_MAPPING` and `MAX_TUNNELS`, plus shared SERVICE
listener/ACL/identity/lifetime keys. Defaults match pinned v0.29.1:
`vpn-gnunet`, `10.11.10.1`, `255.255.0.0`, `1234::1`, prefix32, and200
mapping/tunnel slots. The configured `[vpn]` `VIRTDNS` and `VIRTDNS6` keys belong
to the surrounding DNS configuration and are not consumed by active C VPN's
configuration handler either.

## Device selection

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

On FreeBSD fresh mode records a private recovery checkpoint before creating a
TUN and renaming it to `[vpn] IFNAME`. `[vpn-rust] TUN_RECOVERY_FILE` defaults to
`$GNUNET_DATA_HOME/vpn/tun-recovery`. The original checkpoint lock is held through
native device lifetime and cleanup. Startup retires the exact previously saved
owner before another allocation; unresolved allocation intents block recreation.
An occupied name is refused. Checkpoint selection is rejected in preopened mode
and on other platforms. Native creation still requires the selected identity's
privileges. Packet framing, route FIB and IPv6 readiness use FreeBSD backends;
see the [TUN ownership contract](../../adapters/tun-std/API.md#device-ownership-and-provisioning).

### Windows Wintun

`TUN_MODE=fresh` creates a new adapter through an explicitly selected official
Wintun provider. `TUN_MODE=existing` opens `[vpn] IFNAME` and verifies the desired
configuration without rewriting it. Unix FD inheritance is unavailable here.
Names may contain Unicode. Fresh-device qualification rechecks the actual
native alias; existing-device selection retains the native open result and its
qualified GUID/LUID/index. Creation/open errors do not select an alternative device.

`WINTUN_DLL` is required and must expand to an absolute path. The operator must
trust that official Wintun DLL, its dependencies and ABI: loading it executes
native code. The service performs no download, provider search or driver install
preparation. Actual adapter creation can provision Wintun's native resources.
`WINTUN_RING_BYTES` selects a power-of-two size from 131072 through 67108864
bytes per ring, default 4194304. Packet and flow storage remain separately bounded.

An unexpected packet failure ends the old session and retains its original
adapter. The service retires original route/query observers and drains old
flows, packet effects and discovery jobs before admitting a fresh packet epoch.
It then checks the existing interface, MTUs, address/mask, exact routes and DAD
without replaying configuration. CADET and local IPC keep their independent
owners; allocation requires the newly verified route state.

If the retained packet handle cannot start, the service tries a freshly opened
handle only on the exact original GUID/LUID/index/compartment. The original
creator remains owned, superseded handles close, and old route responsibility
survives. This handle refresh does not rewrite configuration or release the
original route scope; configuration and DAD are verified again.

One `CONFIGURE_TIMEOUT` target covers draining, restart attempts, retry backoff
and verification. Restart failures retry from 100ms up to 1s; short-lived
admissions retain the same target. Positive native packet I/O or one second
admitted without an observed loss ends that episode. The quiet interval is a
retry policy, not a delivery receipt. Stop releases retained recovery ownership;
diagnostics keep bounded first/latest causes.

When a complete native table reports the old interface missing, its retained
adapter closes before physical reopen. Complete bounded interface and forwarding
tables must establish absence of the original LUID and its routes. This sealed,
epoch-bound observation settles only the old route scope; native getter errors,
remaining rows and LUID reuse preserve uncertainty. A failed later reopen still
retains the actual old-scope observation and independent error.

The exact provider-name/GUID/compartment selector may reopen a reappearing
interface with newly qualified LUID/index. The coordinator retires the old core
source only after jobs, flows and packet effects quiesce. The new device is
borrowed and needs valid externally prepared configuration and fresh route/DAD
verification. No old packet, address-row selection or deletion authority moves
to it. All phases keep the same outage deadline. A native observer or control
failure probes actual interface absence before selecting this recovery path;
invalid configuration on a present interface remains a failure.

For a missing device originally created in `fresh` mode, selected-provider
NotFound also permits automatic recreation. A complete old-scope observation and
vacant alias/GUID are required. Creation uses a private provider name and restores
the configured alias through the new GUID's NetCon object. Conflicts and native
errors preserve failure; no other interface is renamed or adopted. The new scope
gets new configuration and route jobs before route/DAD readiness. Existing-mode
devices remain borrowed and are never recreated. The original outage target
covers creation and provisioning as well as reopen.

Owned route cleanup authority survives same-adapter session replacement;
borrowed routes remain borrowed. Wintun's void release calls do not independently
prove that kernel routes disappeared. Failed or interrupted deletion remains
explicit route debt.

Windows verifies configured USERNAME against the current native identity;
it does not perform a Unix account transition. Normal detached re-exec, managed
console detachment, original activation and parent readiness use the shared
Windows startup layer. New local endpoints use `LOCAL_ACCESS=owner` by default;
`group` and `everyone` are explicit alternatives. This selects a native endpoint
ACL, not a Unix peer-credential result. `UNIX_MATCH_UID/GID=YES` is rejected on
Windows. Inherited listeners retain the creator's security responsibility.

Only enabled IP families have native MTU actions and snapshot queries. The
other family remains untouched; every MTU action has a separate original receipt.
Interface configuration, route queries and DAD use the
[shared Wintun contracts](../../adapters/tun-std/WINDOWS.md). Native synchronous
calls can complete after the initial deadline; their actual results retain late
classification. They are not interrupted or replayed by a timer.

### Unix descriptor adoption

`TUN_MODE=preopened` still requires `GNUNET_VPN_TUN_FD` to designate a uniquely
transferred kernel TUN/utun descriptor. It is verified after USERNAME and
must already match the native plan. Arbitrary files, sockets and helper pipes do
not qualify as this descriptor. The service does not rewrite an externally
provided device. Its framing mode comes from the kernel descriptor;
the official helper transport always uses its mandatory Linux PI prefix.

## Shutdown and native ownership

Every normal error or stop after helper admission closes the original pipe
source, requests that same child stop and awaits its OS wait result before
Resolver retirement and the final report. Kill and wait failures are retained
independently. Drop is only a physical stop attempt and never a reap proof. There is no artificial socket timeout that declares a still-owned process reaped.

Direct native provisioning retains the original configure deadline across native
MTU/address/link calls, native route results/reconciliation and DAD. An EEXIST route reply
requires an exact query. A queued request, completed local write or TUN
allocation is insufficient for readiness. The first `READY vpn` line is emitted
only after the original TUN plan is ready and the CADET IPC MQ is
attached. It explicitly states that remote exit reachability is unasserted. Application accepts begin after this readiness gate. A permanent startup failure
or timeout closes every source and keeps the original failure.

## Exit discovery

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
PEER  prefix|any  tcp|udp|icmp|icmp6|any  first-last  native|linux|darwin|freebsd|windows
```

`PEER` accepts the official52-character GNUnet identity or64 hex digits. Up to64
ordered entries select the first matching destination network, transport and
port. The AF profile describes the peer endpoint's platform wire AF
assignment. An empty list is valid for named SERVICE redirects; Internet flows
then fail with a configured provider miss. Configured selection is not
reported as an automatic REGEX result. Named peer SERVICE requests do not need
Internet exit discovery in either mode. `PEER_AF_PROFILE` supplies their default
profile and REGEX-discovered peers' explicitly selected profile;
`IPC_AF_PROFILE` supplies the local VPN IPC source profile (both default native).
Native profiles select the actual Linux, macOS, FreeBSD or Windows address-family
values. The peer profile describes its C endpoint independently of the local
platform.

## Resource bounds and scheduling

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

## Diagnostics and cleanup

`STOPPED vpn` reports actual IPC/CADET/TUN source metadata, write exposure,
pending IDs, unconfirmed native-control count, route/flow/buffer debt and REGEX
jobs. `take_cleanup_errors` transfers each independently owned close error once;
reading errors cannot reopen a retired source or clear its uncertainty.

The shared Reporter keeps a permanent failure latch and the original task waker.
A terminal source or logging failure stops new admission and takes the native
close path. Typed causes remain separate. Recoverable backend failures retain
their original retry bounds; they do not replay retired payloads. Retained errors
are bounded by the fixed source/client/control cleanup inventory.

Shutdown closes REGEX, then VPN's original IPC/CADET/TUN/control sources, then
Resolver. Another close failure cannot skip a source. Independent same-stage
failures retain both error objects. Output errors and unresolved effect debt
remain distinct; cleanup requires no successful logical-clock sample. Unknown
outcomes are never treated as delivery or permission to replay.
