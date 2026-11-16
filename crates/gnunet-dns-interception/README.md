# DNS interception core

The core implements official DNS interception phases independently of native
IPC, packet devices and DNSSTUB. The default feature provides checked
DNS_HELPER/TUN_PI framing; `alloc` enables the bounded phase owner.

## Interfaces and packet flow

`Engine` receives validated IPv4/IPv6 UDP port-53 queries from a caller-owned
source. It advances request monitoring, pre-resolution, resolution,
post-resolution, response monitoring and output. Each phase freezes eligible
client allocations, visiting the most recently connected client first.
Monitoring cannot replace packets. A pre-resolution answer terminates remaining
providers; a rewritten query continues through the resolver.

`prepare_client` builds official IPC callbacks. `prepare_helper` builds a
checksummed reply with the official helper envelope. `prepare_packet` builds the
same raw IP/UDP reply for native packet devices. Both packet paths share one
encoder and the same output ownership rules. No platform framing enters client
IPC or DNS data.

Unknown old request identifiers are ignored; a wrong client or current output is
refused. Official INIT has no acknowledgement, and REPLY has no added credit or
cancellation extension. TCP interception and fragment reassembly remain outside
the supported packet layouts.

## Ownership and errors

Client, source, request, resolver and output tokens bind the caller's `Instance`,
allocation, row and checked serial. Only the official opaque eight-byte request
identifier enters IPC. A source loss does not discharge an application callback.
Rejecting prepared output invalidates that attempt before another can be minted.

Queue admission, positive local exposure, complete local writes, physical source
retirement, resolver cancellation and expiry are separate inputs. A helper pipe
write and a native packet submission establish different transport facts;
neither acknowledges remote delivery. DNSSTUB responses must match transaction
ID, opcode and questions. These checks do not establish DNSSEC authentication.

## Resource bounds

Client/request directories have explicit limits. Phase membership uses a bitmap
for at most 64 clients and an allocation high-water mark. Payloads share an
actual-capacity budget and zeroize on replacement or retirement. Smaller updates
reuse allocation; growth must fit while the previous allocation remains held.
Directory and allocator overhead are separate from the payload-byte bound.

The core creates no socket, resolver, process, task, clock or filesystem owner.
The [native host](../../adapters/dns-service-std/README.md) supplies those ports.
