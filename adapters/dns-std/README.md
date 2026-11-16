# Caller-driven GNUnet DNSSTUB UDP host

The `gnunet-dnsstub-host` package owns nonblocking IPv4/IPv6 UDP sockets
for the pure `gnunet-dnsstub` owner. Host query buffers use its explicit heap
profile, avoiding maximum-packet pool temporaries on the native stack; the
allocation-free inline core profile remains available for embedded callers. Enable the SDK's optional `official-dns`
feature to use `gnunet::dns_host`. Construction and configuration do no network
I/O. `resolve` copies bytes and draws unbiased OS entropy; `drive` opens sockets
and performs sends and receives inside an I/O/time-enabled Tokio runtime.

Each slot retains at most two family-specific sockets. IPv6 sockets use
`IPV6_V6ONLY`; Windows sockets select exclusive address use and disable ICMP-induced connection resets before
bind. Isolated receive errors emit `ReceiveRejected` with the original cause,
retaining the same socket generation, requests and retry schedule. Fatal receive
errors emit `ReceiveFailed` and invalidate only that generation. Sending uses one nonblocking syscall and reports its actual
result; any error leaves the already scheduled retry active. Receive storage is
the explicit maximum plus one byte, so oversized data is never delivered as silently truncated data. Winsock
`WSAEMSGSIZE` is reported as an isolated receive rejection without a known sender. Read and due-send priorities alternate
across drive calls, preventing either a receive backlog or zero retry interval
from starving the other direction.

Callbacks receive borrowed `UnverifiedDatagram` data and a restricted controller. The controller can add servers, change retry, resolve, cancel or stop. It cannot
recursively drive the owner. `Admission.evicted` explicitly represents a replaced
consumer's failure. Stop releases cached socket references, including inside a
callback; cancellation keeps them for reuse. Dropping a drive future keeps the
original request, socket owners and absolute retry schedule. Dropping the owner
releases its socket references.

## Capture-port reservations

`reserve_sockets` binds every configured slot for one family before queries are
admitted; it sends no packet. The returned `SocketReservations` lease retains
the original sockets independently of stub cancellation, stop or drop.
`belongs_to` checks the original socket objects and live core generations.
Keep the lease until every capture filter exempting those ports is closed.

A reserved stub never replaces a failed socket or opens another family. Fatal
socket loss invalidates the lease's match while keeping the bound port occupied;
the capture owner must stop before admitting further queries. Startup binding
failure stops the partially prepared stub. Ordinary lazy stubs retain their
existing retry and socket replacement behavior.

## Response and deadline contracts

A drive deadline limits how long the caller waits; it is not a DNS request
deadline and never manufactures a result. The raw stub does not check DNS ID,
QR, questions, names or DNSSEC. Configured-source replies may repeat, and retries
continue until cancel or stop. The resolver above this layer must validate its
response and manage its original deadline.

`cargo test -p gnunet-dnsstub-host --locked --offline` runs local IPv4/IPv6
UDP lifecycle, filter, cache, cancellation, fairness, oversize and syscall-error
tests. The receive-error generation test explicitly injects that error into the
cache owner; it does not claim the kernel produced the error.
