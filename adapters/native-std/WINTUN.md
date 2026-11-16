# Windows Wintun boundary

`gnunet_native::wintun` owns the native Wintun DLL, adapter and bounded packet
session. It provides original-interface IP Helper observations and explicit
administrative calls. Packet I/O carries raw IP bytes without GNUnet or private
encapsulation. The [shared TUN reactor](../tun-std/WINDOWS.md) integrates these
owners with VPN/EXIT packet sources.

## Provider and lifetime

`unsafe Driver::load(absolute_dll_path)` requires caller trust in the selected
official DLL, its dependencies and ABI. The shared native loader limits dependency
lookup to the selected DLL directory and System32. The boundary performs no
download, search for an alternative provider, global logger change or driver
installation during loading. `Driver::create` is a separate administrative effect
and may provision the driver's native resources.

A typed export table and its original loader reference stay alive through every
adapter and session. Before any device or session export runs, the exact loaded
module is pinned until process termination. Wintun queues
[orphan-cleanup work](https://git.zx2c4.com/wintun/tree/api/adapter.c)
from create, open and close without exposing a join operation. The process pin
keeps those callbacks and their module storage valid after the last Rust owner
releases its loader reference; it does not report cleanup completion. Replacing
the selected provider requires a process restart. Export-resolution or pin
failure attempts the original loader release once; `LoadFailure` retains an
independent release error when that also fails. Owners remain on their loading
thread.

`Driver::create` selects a new adapter; `Driver::open` opens an explicit existing
name. Both capture the kernel GUID, LUID and index before returning. Later
`InterfacePort` operations match those original values; aliases are display metadata.
Requested GUIDs do not replace actual observations. Failed qualification closes
its original provider adapter rather than returning an unqualified owner.

`Adapter::start` consumes the original adapter. A start failure returns it through
`StartError::into_parts`. `Session` ends before the adapter closes, and the DLL
outlives both. Created and opened adapters retain distinct removal responsibility.
The native end/close functions return void: returning from those invocations does
not create an independent kernel-removal acknowledgement. Global driver deletion
is outside this ownership boundary.

The provider owns orphan-device discovery and cleanup. An adapter name, requested
GUID or saved LUID does not grant a new Rust owner deletion rights after a crash.
An explicit open observes the actual surviving interface and remains borrowed;
it does not inherit the former creator's removal responsibility.

## Session restart and explicit reopen

`Session::end` ends its rings and returns the same adapter. The adapter and its
administrative ports retain their original identity and removal responsibility.
Read-event registrations must retire before ending that session. Session and
adapter release use separate linear owners so every Drop path preserves this
order. `SessionKind` distinguishes a first successful session from a restarted
session on that adapter owner; neither state establishes address readiness.

`Adapter::reopen_retained` refreshes a packet handle only while provider name,
GUID, LUID, index and compartment still match the original scope. Old
administration ports retire permanently. The new packet handle is opened;
`Adapter::origin` continues to report the retained creation lifetime. An original
creator stays in one unique root owner, released after the final packet handle
and session. Repeated refresh closes superseded packet handles and does not
build an ownership chain. An opened adapter never acquires another creator.
Refusal returns the original owner; provisional opened handles close. This is
same-scope continuity, not interface-absence proof or configuration readiness.

`Adapter::selector` copies the original provider name, observed GUID and network
compartment without querying a failed interface. Wintun's provider name is its
`DEVPKEY_Wintun_Name`, which can differ from the mutable IP Helper display alias.
`Driver::reopen` uses that provider name and verifies the actual GUID and
compartment. It returns an opened owner with freshly qualified LUID/index, grants
no former creator's removal responsibility, and never falls back to creation.

`create_exclusive` checks the complete native interface table and provider name
before creation. The caller serializes native administration across that check
and creation; the observation is not a reservation against another administrator.

`Adapter::recreation` preserves a recipe only from the real creator, including
across retained-handle refresh. After exact old-scope retirement, `Recreation`
checks alias/GUID vacancy, creates under a random private provider name and
verifies the requested GUID and compartment. `Identity::rename` selects that
new GUID's NetCon object, scans bounded connection metadata for collisions, and
restores the configured alias without moving another connection. COM references
and property allocations release on their original thread before the apartment.
Errors return any qualified provisional creator; `Recreation::finish` resumes
alias restoration on that same owner. Void provider close remains distinct from
observed kernel removal. The original finite deadline covers these native calls.
See the [NetCon rename contract](https://learn.microsoft.com/en-us/windows/win32/api/netcon/nf-netcon-inetconnection-rename)
and [SDK interface layouts](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/NetCon.h).
Missing, renamed or reused provider names retain their actual errors. The selector
is local selection data and does not preserve an old physical or packet epoch.

## Packet I/O and waits

`RingCapacity` admits powers of two from 128 KiB through 64 MiB per ring. Each
session owns receive and send rings. `MAX_PACKET_BYTES` is 65535; application
packet/work pools remain separately bounded by their caller.

`Session::receive` attempts one packet and releases its original native loan on
every path. A complete packet is copied into caller-owned storage. Insufficient
capacity returns `Receive::Discarded` without exposing truncated data. Empty
is a distinct normal ring result. Native corruption/termination errors retain
their actual OS error. Received bytes have no checksum or peer-authentication
claim.

`Session::send` allocates, initializes and submits one complete native loan before
returning. No native packet pointer escapes. `SendStatus::Full` admits nothing;
`Queued` records local provider-ring submission, without transmission or remote
processing credit. The caller retains its logical operation and retry policy.

`read_event` borrows the original session-owned event, preventing session closure
while that borrow lives. Its recipient must not reset or close it.
`receive_ready` makes only a zero-timeout event observation. The boundary creates
no polling task, worker or async wait: the upper reactor must register its own
original wait and retry the actual receive. A signaled event is not a packet.

## Interface administration

`Adapter::port` clones a qualified `InterfacePort`. This retains the original
identity, original network compartment and a retirement fence, never a session,
adapter handle or DLL. A later thread-compartment change is refused.
Adapter Drop retires every port before closing the provider handle. A later
interface with matching display metadata cannot reactivate a retired port.


`interface` reports the original GUID/LUID/index, native alias, MTU and raw
administrative/operational states. `ip_interface` reports family-specific MTU,
metric, connected state and configured DAD transmissions. Names never select
later operations. `set_mtu` first reads and preserves other family settings;
IPv4 SitePrefixLength follows the documented zero requirement.

`set_link_up` requests administrative state without treating it as operational
readiness. Address creation, prefix update and deletion use the original LUID.
Creation does not request optimistic DAD. `address` returns the actual DAD state,
prefix, lifetimes and source-selection flag; creation success cannot stand in
for preferred-address observation. `find_address` distinguishes exact-address
absence only after rechecking the original interface and its native IP family.
`ipv4_addresses` reports zero, one or multiple rows without inventing a primary
address. It processes at most 8192 system-wide rows and releases the original
SDK table on every successful-allocation path.

Routes require a canonical destination, valid prefix and same-family gateway.
An absent gateway requests an interface route. Link-local IPv6 scope comes from
the qualified interface index. Route metrics are offsets, separate from interface
metrics. `create_route`, `route` and `delete_route` preserve native result codes;
existing/absent entries are not converted into successful mutations.
`find_route` qualifies the original interface/family before reporting absence.
Returned route fields come from the actual getter, including destination,
next hop, interface, protocol, origin, loopback status and metric offset.
An unspecified next hop alone does not distinguish local-host and forwarding
routes; native loopback status remains separate.

The caller authorizes and serializes administration, including exclusion of
concurrent interface replacement around index-based native calls. Snapshots,
LUIDs and route values grant no cleanup or restart authority. These operations
are synchronous native effects and may block; an async deadline cannot be called
a canceled device or administrative operation.

## Native API references

The binding follows the [official Wintun public API](https://git.zx2c4.com/wintun/tree/api/wintun.h)
and its [provider documentation](https://git.zx2c4.com/wintun/about/).
IP Helper behavior follows the Microsoft contracts for
[interface changes](https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry),
[address creation and DAD](https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry)
and [route creation](https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2)
and [lookup](https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getipforwardentry2).

The native [route row contract](https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2)
keeps loopback state separate from an unspecified on-link next hop.
