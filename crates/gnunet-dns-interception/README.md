# DNS interception core

The core implements official DNS interception phases over DNS datagram bodies,
independently of native sockets, packet devices, helper processes and DNSSTUB.
The default build provides the borrowed `Query` validator and `FixedEngine`,
which uses caller-owned payload storage. The `alloc` feature adds `Engine` with
heap storage. Both expose the same source, client, request and effect contracts.

## Interfaces and DNS flow

`Query::decode` checks a complete DNS query header and the official IPC ceiling
of 65519 bytes. It borrows the original body without allocation and does not
validate questions, records or DNSSEC. The native host validates its transport;
endpoint, IPv6 scope and reply-route ownership remain outside this core.

`Engine::intercept` accepts that typed query from the original attached source.
It advances request monitoring, pre-resolution, resolution, post-resolution,
response monitoring and output. Each phase freezes eligible client allocations,
visiting the most recently connected client first. Monitoring cannot replace
bodies. A pre-resolution answer skips remaining providers; a rewritten query
continues through the resolver.

`prepare_client` encodes the official IPC callback. `prepare_source` returns a
`PreparedReply` borrowing the retained DNS response bytes and its immutable
`Effect`. Native encoding can read `dns()` without an intermediate payload copy;
the borrow ends before the engine admits, rejects or retires the effect.
IP/UDP checksums, helper envelopes and native socket send limits belong to the
[native host](../../adapters/dns-service-std/README.md).

Unknown old request identifiers are ignored; a wrong client or current output is
refused. Official INIT has no acknowledgement, and REPLY has no added credit or
cancellation extension. DNSSTUB responses must match transaction ID, opcode and
questions; these checks do not establish DNSSEC authentication.

## Ownership and errors

Capabilities bind the caller's `Instance`, allocation, row and checked serial.
Only the official opaque eight-byte request identifier enters IPC. Two engines
sharing an allocation domain still cannot exchange sources or effects. Rejecting
prepared output invalidates that attempt before another can be minted.

Queue admission, positive local exposure, complete local output, physical source
retirement, resolver cancellation and expiry are separate inputs. `written`
records the native owner's completed output observation, not remote delivery.
`source_stopped` settles one output only after its actual native operation stops;
it neither closes the source nor retires another request. Physical source loss
does not discharge an application callback or resolver debt.

## Resource bounds

Client/request directories have explicit limits. Phase membership uses a bitmap
for at most 64 clients and a serial high-water mark. `FixedEngine::with_storage`
reserves one equal-sized lane per request in the supplied arena. A resize never
moves another request. The allocating engine instead shares a capacity budget
between active requests. Smaller updates reuse the allocation; growth must fit
while the previous allocation remains held. Both erase replaced and retired
payloads. Native transports can choose a smaller limit than the shared IPC ceiling.

The core creates no socket, resolver, process, task, clock or filesystem owner.
