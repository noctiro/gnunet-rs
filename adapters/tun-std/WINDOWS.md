# Windows TUN interface

The shared packet reactor uses the [native Wintun provider](../native-std/WINTUN.md)
and the same packet, epoch, cancellation and deadline types as Unix devices.

## Adoption and ownership

`OwnedTun::from_wintun(Session, Limits)` consumes an explicitly created native
session and qualifies its original GUID/LUID/index and network compartment. It never loads a DLL or
creates a device implicitly. A later thread-compartment change is refused. Provider trust and administrative provisioning
belong to the caller. Qualification failure closes the consumed session.

`into_wintun` transfers the original session and permanently retires the old
epoch. Re-adoption qualifies a fresh epoch. Explicit close ends the original
session and closes the adapter once. Wintun's void release functions supply no
separate kernel-removal result. The provider's exact DLL mapping stays pinned
until process termination because its orphan-cleanup callbacks have no public
join API; the original Rust loader reference still closes normally.

## Explicit recovery

`try_from_wintun` returns the original native session when qualification fails;
`AsyncTun::try_new` returns the original qualified owner when registration fails.
The entered runtime must enable I/O and time. The ordinary constructors retain
their consuming-close behavior on returned setup errors.

Unexpected native packet failures end the session and retire the original read
wait, packet epoch and queued write. `Loss::recovery` then owns the original
adapter without keeping its old rings or packets. `retire_wintun_session` requests
this transition explicitly. Explicit close and allocation-failure teardown release
the adapter instead. A retained recovery owner must be restarted, transferred or
closed; `release_wintun_recovery` releases it while preserving the loss diagnostics.
The installed VPN and EXIT services consume it for bounded session recovery and
recheck configuration before renewed forwarding readiness. Diagnostic history
retains no adapter ownership.

`WintunRecovery::restart` checks the original interface, starts the same ring
capacity and registers a new packet epoch. Refusal identifies Start, Qualify or
Register and returns the original adapter for explicit retry or release. The
original epoch never becomes current. Packet bytes, old operation deadlines and
address/route mutations are not replayed. The original IPv4 row selector is kept
only for exact read-only observations; link, routes and DAD must be checked anew.
A missing or replaced original interface remains an error. An explicit native
selector reopen is a distinct operation with a new owner and borrowed provenance.

`refresh_scope` opens a fresh packet handle on the exact retained native scope,
then starts and registers a fresh packet epoch. The original creator remains
owned through the replacement's lifetime; old ports and packet epochs stay
retired. It preserves original route responsibility and the exact IPv4 observation
selector, and performs no configuration replay. Reopen, Start, Qualify and Register
refusals retain the actual owner/stage. The installed services try this after an
original-handle start failure, under the same outage target and stop gates.
Fresh link, MTU, route and DAD observations still precede forwarding readiness.
A changed GUID, LUID, index or compartment refuses same-scope continuation.

VPN adoption treats restarted sessions as existing configuration to verify,
including when the retained adapter was originally created by this process.
Creation/removal responsibility stays with that original native adapter. VPN's
explicit coordinator recovery additionally retains its original owned route
scope through old-flow retirement and fresh read-only verification. It does not
convert owned debt into a borrowed scope or claim route removal from a void
provider release. EXIT's
`replace_tun` accepts an explicitly prepared replacement only after its old
packet source and helper retirement; CADET, DNS and original flow deadlines are
preserved while stale TUN writes remain retired.

## Physical reopen

`retire_missing_wintun` reads a complete bounded interface table before retiring
a live packet owner as InterfaceMissing. A reused LUID or native query failure
is not missing-interface proof. This lets an observer failure select physical
recovery without treating a duplicate or invalid address on a live interface
as device replacement.

`WintunRecovery::detach_missing` releases the original adapter only after its
physical identity is missing. It retains the exact provider, provider-name/GUID/
compartment selector, old identity and packet profile as `WintunReopen`. The old
creator closes before a new adapter opens; its void release still proves no
kernel cleanup.

After original mutation jobs quiesce, `observe_scope` reads complete bounded
interface and IPv4/IPv6 forwarding tables and rechecks the old identity. Remaining
routes, reused LUIDs, capacity limits and getter errors preserve uncertainty.
A sealed `WintunScopeRetirement` binds actual absence to the retired packet
epoch. It is a historical observation, not a lock or replacement-readiness
receipt. Later attempts retain that fact rather than interpreting the new
interface's routes as old effects. The caller serializes administration across
this boundary. See [native route-query semantics](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardentry2).

`open` reopens only the selected logical GUID as borrowed, qualifies its actual
LUID/index and starts a fresh packet epoch. Old address-row selection and
mutation ownership do not transfer. The replacement needs fresh address, MTU,
route and DAD verification. Failures return the physical recovery intent and
actual stage; provisional borrowed sessions close. Native calls keep one caller
deadline, including late-return refusal. No DLL search occurs.

`open_or_recreate` permits fresh creation only after an actual selected-provider
NotFound and only with the original creator's sealed recipe. Alias/GUID conflicts,
identity changes and permission errors do not trigger creation. A reopened source
remains borrowed; a created source carries fresh provisioning responsibility.
The installed VPN and EXIT services settle the old scope only from its sealed
absence observation, then configure a created replacement or verify a borrowed
one. Both require fresh route/DAD checks. Native device qualification remains in
[open work](../../IMPLEMENTATION_STATUS.md).

Creation, alias restoration, session startup, qualification and registration
refusals retain at most one actual provisional creator. Retries finish that owner
instead of creating another device. Stop releases the retained owner; its void
close does not settle kernel-removal uncertainty.

## Whole-packet reactor

`AsyncTun::new` duplicates the session's original read event and registers one
native thread-pool wait. The duplicate belongs to the registration; Wintun's
original event is neither reset nor closed. Registration retires before session
release. Callback metadata has independent lifetime, and callbacks disassociate
before invoking caller wake code so reentrant retirement cannot join itself.
Wakes are coalesced to one notifier and one pending wake per registration.

Each poll attempts at most one native packet operation. Input is copied from
one complete receive-ring loan, which is always released. Oversized packets
are discarded and reported as rejected input. The packet bound is 65535 bytes.

A full send ring admits no bytes. The original immutable packet and deadline
remain queued, with one reusable 1ms timer as the capacity retry hint. No busy polling or
background packet task is created. Written records whole-packet provider-ring
submission. It does not prove transmission or remote processing. Dropping a
borrowed future preserves its original owner, registration and pending packet.

## Administrative effects

`plan` allocates an original action tied to this epoch and finite deadline.
`apply` performs actual IP Helper operations through a qualified `InterfacePort`:

- `IpMtu { version, bytes }` updates one explicitly selected IP-family row.
  Each family has its own original effect and actual completion. A later failure
  leaves earlier receipts intact; no automatic rollback or replay occurs.
- Link changes request administrative up/down and grant no operational readiness.
- IPv4 address assignment creates an explicit /32 row. A separate contiguous
  netmask action updates the last address actually created by this owner.
  Existing rows are neither silently adopted nor deleted.
- IPv6 assignment creates the explicit address/prefix without requesting
  optimistic DAD. Creation success grants no address-readiness result.

`route` prepares a single caller-driven operation without mutation. Polling
checks the original source/deadline and performs the native create/delete once.
`RouteSubmission::NativeCall` records entry into the synchronous native path;
`RouteOutcome::NativeReturn` preserves its result separately from a Unix socket
ACK. A native qualification error can precede mutation. Cancellation before
polling is Unsent. The job retains no session, adapter or DLL.

Native calls are synchronous. A timer cannot preempt them or undo changes.
Their actual results retain Late classification when the original deadline
passes during the call. Errors never become synthetic acceptance receipts.

## Read-only observations

`snapshot(until, SnapshotOptions)` queries actual interface status and the
explicitly requested IP-family rows. Default options request link state only.
`link_mtu()` retains the actual IF_ROW2 link value; `ip_mtu(version)` reports the
requested family's IP MTU. IPv4 and IPv6 values may differ. An unrequested family
is not queried or treated as absent; errors for a requested family remain errors.
IPv4 address/netmask selection runs only when IPv4 was requested. Unix `flags()` is None;
`windows_status()` retains the native status pair. Administrative up/down is
separate from operational readiness. Before this owner creates an address,
zero rows is Unassigned and multiple rows is Ambiguous. After creation, the
snapshot queries that original selected row. Native errors remain errors.
Getters form a time-local group rather than an atomic restoration image.

`watch_ipv6` samples the exact original address/prefix and actual native DAD
state. Preferred, Tentative, Duplicate, Deprecated, Invalid and unknown states
remain distinct. A prefix mismatch is explicit. Address absence requires an
exact-address query and requalification of the original interface/family.
Windows DAD states are not represented as Unix address flags.

`query_route` performs one exact canonical destination/prefix/next-hop lookup.
The record uses fields returned by the native getter, rather than copying the
request into an observation. Protocol and origin remain Windows values;
Unix route flags and Netlink type/scope are absent. Native loopback routes
remain unsupported for forwarding-route matching, even when their next hop is
unspecified. Missing-key evidence retains
the actual native status only after the original interface/family are qualified.
A synchronous native return has separate submission and evidence variants.
The query retains no packet device and grants no mutation or cleanup authority.

Watchers retain identity and retirement metadata rather than device ownership.
They use the shared finite sampling interval and original deadline. Cancellation
and Drop release observation state without changing addresses or routes.
