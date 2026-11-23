# Windows WFP callouts

This `no_std` kernel leaf implements the WDK boundary for original UDP DNS
flows, buffered device I/O, native injection, receive authorization, and registration.
The driver boundary shares fixed identifiers with the service's FWPM adapter.

## Driver startup

`image.rs` exports the WDM `DriverEntry`. It prepares the secure packet and
maintenance devices, the original nonpaged runtime and a separate kernel-only
file that pins the driver against unload. The first authenticated START
validates the complete descriptor list and retains the original user sockets
before initializing WFP. Capture starts only after policy preparation and a
final check of the same file and policy. START holds the passive lifecycle
control through that commit. BFE loss can still revoke the policy independently.

## Native ownership

Prepare pinned nonpaged state and both family-specific transport handles
before publishing callbacks. Register the DATAGRAM_DATA and endpoint-closure
callouts before the ALE_FLOW_ESTABLISHED callouts. The ALE discovery callback reserves a generation in
the state before associating it with the same-family datagram callout. The
original flow-delete callback returns that generation to the arena. An existing
flow without a context can attach after recovery when DATAGRAM_DATA supplies
the original flow, endpoint and compartment and WFP accepts the association.
Copying an outbound DNS body does not grant ownership of the original packet.

Deployment provisions the static driver provider and six callouts outside
the driver's dynamic engine. The driver installs the inbound guards, outbound
discovery and capture filters, and UDP endpoint closure filters in one
transaction. Classification trusts the original installed native IDs. Service-file
startup enables capture only after that transaction and the original
upstream socket reservations are live. [WFP object ownership](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)

## Native retirement

Revoke capture and reply authority, then remove the discovery, capture and
endpoint closure filters. Wait for original submissions, request original flow
removal, and observe the native flow-delete callbacks. A pending removal retains
the flow context for deletion and denies traffic through that context. Submitted
injections keep their own completion callbacks. Keep the inbound guard filters
while unregistering their callouts. While the filters remain installed, WFP
applies its default block action to the unregistered guard callouts. Successful native
unregistration ends callout entry, and handle destruction waits for pending
native injections. The driver then removes the inbound guards and releases
their original owners.
[Callout driver unload](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/unloading-a-callout-driver)
[Unregistered callout actions](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutunregisterbyid0)
[Injection handle destruction](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsinjectionhandledestroy0)

After the data service closes its file, use the [maintenance client](../../../adapters/wfp-dns-std/README.md#driver-maintenance)
to advance retirement and enter the passive native wait. Once callbacks,
packets, upstream handles and namespace links have retired, the maintenance
IRP releases the kernel-only anchor. Close the maintenance file before
requesting SCM unload. After anchor release, the protected native maintenance
device admits exclusive read-only observation of the fixed terminal record.
The data device and DOS links remain retired. A restarted operator can obtain
and close a fresh observation file before asking SCM to stop. Windows calls
the fixed `DriverUnload` after file and IRP cutoff. It deletes the original
WDM devices and frees their driver state.
[WDM unload environment](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/unload-routine-environment)

Losing the current BFE policy revokes the file's capture and reply authority.
The file observes that loss through device I/O and can drain original queued
completions after STOP. After it closes, a protected packet CREATE advances
passive retirement of the old generation. The driver retains original callbacks,
injections and upstream custody until their native retirement. A canceled
FWPM session permits retiring its old filter identities while the original
engine handle still needs its own close result. The next file starts capture
against newly registered callouts and committed filters. The stable driver
keeps its BFE subscription and unload anchor throughout recovery.
After a failed START, the original file retains its recorded failure. A
protected new CREATE can start recovery after that file's cleanup. It can
publish a fresh generation only after the original native owners retire.
[BFE state notifications](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpmk/nf-fwpmk-fwpmbfestatesubscribechanges0)

## Local device

The control device uses an exclusive, buffered I/O object with a System-only
default ACL. It accepts one file generation with read and write access. The
driver references an unnamed service event from the original user process and
signals it for capture and completion records. Drain both queues after a wake.
START carries the original IFS socket handles and their observed ALE
endpoint identities. The driver opens its own kernel handles before enabling
capture and excludes those endpoints during association and capture. STOP
revokes capture and releases those handles while keeping already submitted
operations readable through their actual completions.

A READ returns the original DNS query and opaque token. A WRITE submits a
response or revokes the token. Revocation can veto a pending reply while
preserving the native completion and any already-observed receive verdict.
The driver retains all route facts. Queued, expired and stale generations
cannot submit responses.

The capture callback reserves nonpaged storage before copying the UDP body.
It makes both the token and the copy available before absorbing the original
datagram. Queue, native copy and read custody share one fixed bound. A refused
capture leaves the packet to normal WFP classification. File cleanup revokes
the session and frees unconsumed captures. Native operations accepted before
cleanup still retire through their actual callbacks.

A WRITE acknowledgement records native submission. A separate buffered
control returns the original NBL status and receive-gate observation. Packet,
MDL and NBL resources remain owned until native completion. Socket delivery
requires its own observation.

## Receive authority

The UDP `ALE_ENDPOINT_CLOSURE` callbacks revoke every bound flow for the
original endpoint handle, including multiple remote flows of an unconnected
socket. The original flow-delete callback still retires each native flow
association. Already-submitted injections retain their own completion debt.
[ALE endpoint lifecycle](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management)

Flow discovery opens a bounded closure observation before extracting native
flow facts. A recent close for the same endpoint or an overwritten observation
window refuses the association before native submission. The original flow
reservation retains its generation through the SDK call and gains capture
authority after success while the endpoint remains open. If closure wins during
the call, the associated context stays owned until its native delete callback.
[Native flow association](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0)

Only a single-buffer datagram injected by a live original handle can consume
an original request's one receive authorization. The receive callback verifies
the live session, flow context, expiration, exact addresses and ports, routing
compartment, local interface LUID and native interface indices. In both
directions the original flow context is required. A reported native flow handle
or transport endpoint handle must match the association. A flagged zero handle
refuses admission. Outbound capture requires the native transport endpoint.
The LUID comes from the original `DATAGRAM_DATA` classification. Capture
requires that value before absorbing a datagram. The receive gate refuses a
changed LUID even when the interface and subinterface indices match. The
inbound classification supplies its own route facts. A link-local remote needs
an outbound zone matching the classified interface. Any separately reported
inbound arrival interface must agree. Site-local remotes remain outside capture
because a link index cannot establish the site zone. Injection history alone
cannot authorize a re-injected clone. Foreign datagrams continue ordinary WFP
policy. LUID and index comparison still leaves equality under identifier reuse,
and socket delivery requires its own observation.
[IPv4 classification fields](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_datagram_data_v4_)
· [IPv6 classification fields](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_datagram_data_v6_)
· [Classification metadata](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer)
· [Transport receive injection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsinjecttransportreceiveasync0)
· [Windows IPv6 zones](https://learn.microsoft.com/en-us/windows/win32/winsock/link-local-and-site-local-addresses-2)
· [Interface identifier lifetime](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nf-ndis-ndisiffreenetluidindex)

Use `FWP_ACTION_CALLOUT_UNKNOWN` for the receive guard. It permits forward
classification via `CONTINUE` and a veto via `BLOCK`. The SDK treats any
non-permit result from a terminating callout as a block. A veto clears the
action-write right. An already denied hard verdict does not consume the
original authorization. [WFP callout actions](https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0)

## Build

The [WDK build tool](../../../tools/wdk-bindgen/README.md#build-the-driver)
generates target-specific bindings and builds an unsigned x64 or ARM64 driver image. The
[native backend contract](../../../adapters/dns-service-std/NATIVE_BACKENDS.md)
tracks signed Windows qualification.

## Package preparation

The generated [primitive driver INF](package/gnunet-wfp-driver.inf.in) registers
`GNUnetDnsIntercept` as a demand-start WDM kernel service. The build tool stages
the INF and matching driver image together in its `package/` output. Each INF
targets only its image's architecture. Generate
and sign `gnunet-wfp-driver.cat` for that exact pair. The deployment must check
for Windows build 19041 or newer before installation.
`ExAllocatePool2` sets this runtime floor. Install and start through the
[operator commands](../../../adapters/wfp-dns-std/README.md#operator-commands).
[Primitive drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/creating-a-primitive-driver)

Use `cargo xtask stage-node --wfp-package DIR` to include the signed package in
a matching Windows node prefix. The staged INF, image and catalog retain their
original bytes. Windows applies the driver signing policy during deployment.
[Native node staging](../../../tools/xtask/node/README.md#peer-connections-and-platform-components)

Provision the persistent WFP objects before starting the driver. Save the
installation receipt for verification and removal. When removing the driver,
stop the data service, retire the original driver resources and close the
maintenance file before requesting SCM stop. Remove the persistent metadata
with its original receipt. [Operator commands](../../../adapters/wfp-dns-std/README.md#operator-commands)
