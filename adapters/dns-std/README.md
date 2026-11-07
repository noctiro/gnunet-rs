# Caller-driven GNUnet DNSSTUB UDP host

The `gnunet-dnsstub-host` package owns nonblocking IPv4/IPv6 UDP sockets
for the pure `gnunet-dnsstub` owner. Enable the SDK's optional `official-dns`
feature to use `gnunet::dns_host`. Construction and configuration do no network
I/O. `resolve` copies bytes and draws unbiased OS entropy; `drive` opens sockets
and performs sends and receives inside an I/O/time-enabled Tokio runtime.

Each slot retains at most two family-specific sockets. IPv6 sockets use
`IPV6_V6ONLY`. Sending uses one nonblocking syscall and reports its actual
result; any error leaves the already scheduled retry active. Receive storage is
the explicit maximum plus one byte, so an oversized packet is discarded rather
than delivered as silently truncated data. Read and due-send priorities alternate
across drive calls, preventing either a receive backlog or zero retry interval
from starving the other direction.

Callbacks receive borrowed `UnverifiedDatagram` data and a restricted controller. The controller can add servers, change retry, resolve, cancel or stop. It cannot
recursively drive the owner. `Admission.evicted` explicitly represents a replaced
consumer's failure. Stop closes sockets immediately, including inside a
callback; cancellation keeps them for reuse. Dropping a drive future keeps the
original request, socket owners and absolute retry schedule. Dropping the owner
closes every socket.

A drive deadline limits how long the caller waits; it is not a DNS request
deadline and never manufactures a result. The raw stub does not check DNS ID,
QR, questions, names or DNSSEC. Configured-source replies may repeat, and retries
continue until cancel or stop. The resolver above this layer must validate its
response and manage its original deadline.

`cargo test -p gnunet-dnsstub-host --locked --offline` runs local IPv4/IPv6
UDP lifecycle, filter, cache, cancellation, fairness, oversize and syscall-error
tests. The receive-error generation test explicitly injects that error into the
cache owner; it does not claim the kernel produced the error.
