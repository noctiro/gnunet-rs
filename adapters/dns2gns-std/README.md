# DNS2GNS ordinary gateway host

`Runtime` binds the configured IPv4 and IPv6 UDP listeners independently and
retains each address or error. Windows sockets disable ICMP-induced connection
resets before bind. Isolated native receive errors keep the original listener;
per-family counts and first causes remain bounded in the report. The PROGRAM supplies the original shared
clock, configuration and GNS/IDENTITY/VPN CLIENT sources; no Resolver or detached
task is created here.

## Public interface

Each bounded slot owns its original query future through full-name routing,
ordinary DNS only after `NotGns`, optional VPN allocation, and the reply on the
original listener. On Linux, FreeBSD, macOS and Windows, wildcard listeners retain
the local address and ingress from each datagram. Replies use that address and
carry the original zone for link-local IPv6. The listener discards datagrams
with missing or conflicting packet information. Every phase uses the original
finite canonical and native query targets. VPN reply TTL is capped by both the
original GNS expiration and requested lease target. Allocation, cancellation and close do not prove remote
forwarding or lease revocation. Unsupported GNS records may produce a normal
zero-answer DNS reply, with source-record, skipped and packed counts kept apart.

Call the native guard before canonical/provider work. After permanent Stop call
`begin_close` and keep polling `poll_close` on the same owner. `into_report`
physically drops any unobserved remainder and records it as unresolved; neither
Drop nor an observation timeout grants quiescence. Reports contain metadata and
original errors, never question names, packets or record bodies.

The packet profile projects A, AAAA, canonical DNS-wire CNAME and VPN
allocations. It validates upstream source, original request token, wire
ID, response/question fields and label case semantics before restoring the
client ID. The current common UDP packet budget is at most 65507 bytes, and the
independent encoded GNS-record budget defaults to 65535 bytes. Opaque VPN service
identifiers use the latter budget rather than a DNS-name length restriction. Temporary input/IDNA work and the original GNS frame are released before their
next asynchronous phase when an owned query or projection replaces them.

Endpoint metadata is shared; each client obtains a fallible provider
copy and its own Instance/operations. This does not clone live I/O or native
operation authority. The public with-TLD recursion limit is 128. Connection
retries retain each source's first owned error and bounded counts alongside
terminal cleanup observations.
