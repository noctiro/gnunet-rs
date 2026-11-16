# PF interception policy

The macOS/FreeBSD helper installs DNS policy into the dedicated
`gnunet-rs/dns` anchor. Routing and socket-group matching use the system
[pf.conf interface](https://man.freebsd.org/cgi/man.cgi?query=pf.conf).

## Administrator configuration

PF must be enabled. Its first filter rule must delegate this anchor, after any
normalization rules and before other filter decisions:

```pf
anchor "gnunet-rs/dns"
```

Fresh installation requires an empty anchor without nested anchors. The helper reserves
`/var/run/gnunet-dns-rust-pf.lock` with a root-only original-file lock before
opening an interface. Saved policy is recovered first. Foreign rules, damaged
records or a replaced lease prevent another installation.

Set `[dns] SKIP_ROUTING_SETUP=NO` to use this backend. `YES` leaves routing with
the administrator. Daemon and helper must retain equal real/effective groups;
this binds the upstream-DNS exemption to the group that owns daemon sockets.
Deploy the daemon under a dedicated group: traffic from every socket owned by
that group bypasses interception.

## Rule scope

Four generation-labeled rules route outgoing IPv4/IPv6 UDP destination-port 53
to the original TUN name and permit incoming UDP source-port 53 replies from that
interface. The daemon's socket group is exempt. IPv6 link-local source traffic
is excluded. Rules use `no state`; they create no persistent PF flow state.

The official helper envelope carries raw IP bytes and TUN_PI without the
original interface's scope. Injecting a reply through a different TUN does not
restore that scope. Supporting link-local flows requires a capture/reinjection
backend that retains the native zone; removing the rule exclusion alone cannot
supply it.

The root ruleset, skip settings and PF enable ownership remain with the
administrator. Existing-state handling is platform-specific as described below;
broader platform limits remain in
[implementation status](../../IMPLEMENTATION_STATUS.md).

## Interface coverage

All interfaces with assigned IPv4/IPv6 addresses must be visible to PF and have
filtering enabled, including loopback and currently down interfaces. PF's `skip`
setting bypasses anchor evaluation. Remove it from the required interfaces in
the administrator's PF configuration before starting automatic interception.

The helper compares the native address snapshot with the complete
`pfctl -v -s Interfaces` listing before device allocation, before policy mutation
and before successful installation. The final check also requires the actual
new TUN name. A missing or skipped required interface refuses admission; failure
after an attempted load retains owned-policy cleanup debt. Unrelated interface
groups or drivers without assigned addresses need not be enabled.

The listing uses the control executor's 32 KiB output bound, at most 4096 rows and
borrowed names, sorted once for duplicate detection and native-name lookup.
Empty, malformed, duplicate, unknown-format or truncated output cannot certify
coverage. Each check includes enumeration and parsing in its original
three-second allowance; final installation checks also share the original state
retirement deadline. Runtime verification uses the same complete coverage check.

## Runtime policy observation

Automatic interception retains the native address scope used for startup state
retirement: interface names, indices and scoped socket addresses, sorted and
deduplicated within the native snapshot bounds. Final installation must observe
the same scope. Down/up flag changes alone do not revoke it; down interfaces
were already included in state selection. Added, removed or rebound addresses
require a new startup state sweep rather than adopting an older sweep.

While pumping, the helper checks PF enablement, the root delegation, exact
canonical anchor rules, absence of child anchors, the original lease and native
interface coverage. One cycle begins five seconds after the preceding successful
observation. All five fixed queries and native checks share one three-second
allowance fixed before waiting. A delayed poll cannot reset that allowance;
probes never overlap or accumulate a backlog. Output remains bounded to 32 KiB
per query, with only one original control child active at a time.

Packet processing remains under the reduced effective UID. On macOS and FreeBSD,
each fixed trusted control child selects the effective user captured during
privileged setup, using its inherited real/saved credentials before exec. The
parent does not regain privilege to poll the monitor. Group IDs remain unchanged,
and command input contains no packet payload. Stop, pipe deadlines and observation
failure fence subsequent packet admission. A canceled probe leaves its original
child and lease in the controller for retirement before policy cleanup.

Observation failure or changed policy, coverage or address scope ends the pump.
Normal cleanup removes only the original verified rules; foreign or uncertain
policy retains its existing journal obligation. No live policy is rewritten or
automatically adopted. A failed read-only probe reports its original failure
before waiting for child retirement, so that wait cannot extend packet admission.
Cleanup then performs the executor's bounded original-child stop and reap.

These periodic observations do not lock PF or native interfaces. Packets can be
processed between a change and detection, and transient changes entirely between
observations may be missed. Index/name reuse with the same observed address is
not proof of uninterrupted physical identity. Concurrent administrator changes
remain outside an atomic interception guarantee.

## Existing DNS states on FreeBSD

After the owned rules are loaded, startup reads numeric FreeBSD 14 `pfctl -vv -s
states` records. It selects locally originated outbound UDP destination-port 53
flows against the native assigned-address snapshot, including addresses on down
interfaces. NAT's stack-side endpoints determine origin and destination. Inbound,
forwarded, TCP, other-port and IPv6 link-local-source flows are excluded.

Each target uses the original nonzero state ID and creator ID through
[`pfctl -k id`](https://man.freebsd.org/cgi/man.cgi?manpath=FreeBSD+14.0-RELEASE&query=pfctl&sektion=8).
No host wildcard or global state flush is used. An independent full-table
readback checks those original IDs regardless of their later flow predicate.
Unknown, duplicate, truncated or wildcard target identities refuse the snapshot
before any kill is admitted. Native command success alone is not absence proof.

The state table does not carry the original socket group. Cached DNS state for
the dedicated daemon group can therefore also be removed; new traffic retains
the rule's group exemption. This is startup state retirement; runtime observations
stop the pump when its recorded address scope changes.

Parsing streams through one bounded 2048-byte line and retains at most 4096 target
IDs; unrelated records are discarded without accumulating the state table.
Each command retains its original three-second bound. One ten-second allowance
also spans interface observation, selection, all kills, readback and final owned
policy and interface verification. Cancellation retains the original child and
lease; partial retirement never becomes a successful installation. Retired kernel
state is not recreated during policy cleanup.

## Existing DNS states on macOS

The helper uses the separate [native PF state owner](../native-std/PF.md) after
loading its canonical rules. This uses an explicit `/dev/pf` descriptor and the
guarded 64-bit Darwin ABI, rather than a host-wide `pfctl -k` operation. A complete
bounded native table selects local-source UDP destination-port 53 flows from
their stack-side endpoints. Exact selectors include both full addresses, both
ports and the original PF interface name. Equivalent PF records for one DNS
flow share one selector; every original state/creator ID remains in readback.

Darwin has no state-ID or direction comparator in this deletion interface.
Matching new state for that same DNS flow can also be removed, including cached
daemon-group state. Ordinary remote-origin replies/forwarding and other ports
or protocols remain outside the selector scope. Caller-controlled administrative
scope changes must remain excluded; this is startup retirement.

Native calls, selection, readback and final rule/interface checks share the
original ten-second allowance. A full native buffer is treated as a potentially
truncated prefix and grown within fixed limits before any kill. Failed or late
work retains cleanup debt and cannot admit an installed policy. Synchronous
kernel calls cannot be interrupted, and an error can follow an actual state
removal. The native error retains attempted/completed command counts without
interpreting the kernel's truncated eight-bit killed-state count as absence.

## Installation and retirement

Rule control runs only the fixed root-owned `/sbin/pfctl` utility. Inputs contain validated
interface names, numeric addresses/groups and a fresh random owner label.
The subprocess has a cleared environment, fixed arguments, bounded input/output
and one original three-second deadline. A canceled wait retains that command,
its byte cursors and exit authority. Setup stop retires it before policy cleanup.
A failed wait prevents PID-based signaling or waiting against a replacement.
Each control command inherits a duplicate of the original lease descriptor.
Its shared file lock fences startup while that command survives the helper;
recovery cannot race an earlier command that can still change PF policy.

The parser's canonical rule output is captured before mutation, with optimization
disabled. The installed rules must match that output and retain the delegation.
Attempted writes remain cleanup debt even if their command fails or times out.
Before removal, the helper checks the original lease, exact canonical rules,
owner labels and absence of child anchors. Observed changes leave uncertain
policy intact. Cleanup flushes only this anchor's rules and confirms emptiness.

Control-command retirement, policy cleanup, privilege restoration and TUN close
retain independent failures. The helper removes policy before closing its TUN.
Dropping the helper future cannot acknowledge asynchronous policy cleanup;
normal callers drive it through native stop and completion.

## Crash recovery

Before the first mutating command, the locked lease file stores and synchronizes
one `GNPFDNS1` private record containing the random generation label and exact
canonical rules. Its rule payload is bounded to 32 KiB. A SHA-256 checksum detects
damaged or torn records; it does not authenticate a privileged writer. The lease
name is synchronized before policy admission. Existing records are not replaced.

Startup reads that original file before allocating a TUN. An empty anchor permits
record retirement. Otherwise every rule must match the saved canonical output
and owner label, with no child anchors, before cleanup can flush the rules.
Confirmed emptiness precedes truncating and synchronizing the record. A command,
observation or synchronization failure keeps the retirement obligation; startup
cannot publish a new policy. Cancellation retains both the command owner and
saved policy. Unjournaled or changed residue requires administrator recovery.

FreeBSD additionally uses the shared [TUN recovery checkpoint](../tun-std/RECOVERY.md)
at `/var/run/gnunet-dns-rust/IFNAME.tun`, in a root-only directory. The saved
physical device is retired before another allocation, including when routing is
managed externally. Normal close clears its checkpoint only after native cleanup.
Allocation intents without a qualified native marker remain unresolved. Keep
the same administrative scope and finish existing policy cleanup before changing
between automatic and administrator-managed routing.

Concurrent administrator changes cannot be made atomic through the command
interface. Native PF/device operation and crash profiles require runtime
qualification; the private pipe tests do not perform PF or device operations.
