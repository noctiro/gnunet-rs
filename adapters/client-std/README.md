# Shared CLIENT host adapter

This adapter owns Unix/TCP endpoint selection, caller-shared live configuration,
retained connection attempts, bounded address probes and explicit Resolver ports. It adds no service protocol and never constructs a broker, a STATISTICS owner,
a native-DNS fallback or a background task. The caller drives one shared process
Resolver and supplies its typed resolution context and canonical clock.

`EndpointSource` samples configuration at logical MQ creation. `Endpoint` keeps
that MQ selection; `ConnectionAttempt` retains the original socket/DNS/timer work
across canceled wait futures. Connected bytes use runtime `Connection`, whose
optional generic lease drops before the exact original socket. The broker's
lookup drain implements that lower-level lease. PortError preserves the original
resolution/time cause and terminal attempts retain it on repeated polls.

AddressLookup::poll_socket_addr observes the same original callback with the full
native SocketAddr, preserving IPv6 scope/flow information through the TCP
probe. CLIENT replaces only the service port. IP-only Resolver ports use the
default single-callback lift with scope/flow zero; no extra lookup, acknowledgement,
lease or native effect is created. A source that supplies native metadata must
not silently discard it through its IP-only observation method.

Protocol frames, partial framing cursors, acknowledgement credits, peer epochs,
request cancellation and retry policy remain in domain owners. Socket readiness
never reports transferred bytes or application success. `official-client` exposes
this layer in the SDK; `official-ipc` additionally enables the STATISTICS host.
