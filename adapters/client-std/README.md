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

## Native endpoints

Windows `UNIXPATH` attempts use the runtime's AF_UNIX stream adapter, with the
same attempt guard, cancellation owner and official path-shortening rule. Socket
names require valid UTF-8 and native sun_path bounds; general Windows WTF-8
filenames are not silently substituted. Connecting grants no peer identity or
application acknowledgement. See the [local stream contract](../service-runtime/README.md#local-streams)
for ownership and remaining Windows listener/credential qualification.

## Service presence

`presence::test` follows the pinned official weak synchronous observation on
Unix and Windows. ARM-managed `UNIXPATH` uses existence without connecting;
Windows queries native reparse-node attributes. Other existing local endpoints
are connected and immediately closed. Refusal/missing nodes fall through to the
configured TCP test. Loopback TCP uses bind evidence; other configured hostnames
are assumed up without DNS or a connection. No result authenticates a service,
proves application readiness or acknowledges a request. This synchronous probe
has the same potential to block during connect as its official counterpart.
