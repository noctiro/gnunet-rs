# Official VPN allocation client

`Client` is a bounded caller-driven native IPC client for the pinned official
GNUnet v0.29.1 VPN service. It shares the existing CLIENT endpoint selection,
clock, framed IO and Resolver ports. It creates no background task or service. An explicit `AfProfile` describes the service's C AF constants. Wire IDs are
opaque eight-byte values echoed exactly and never reused within a client.

`internet` and `service` encode official redirects. Lease expiration is distinct
from the finite local response deadline. Only a matching USE_IP frame
produces `Outcome::Allocation`; None is allocation failure. A successful
allocation does not assert a connected exit, packet forwarding, kernel routes
or remote application delivery.

Cancellation suppresses local results. The official protocol has no CANCEL or
revoke message. Unwritten requests are removed. A partially written original
frame finishes on the same MQ under a fixed hard deadline, or that MQ closes;
no suffix moves to another connection. Local Unknown means a lease may exist. Loss settles old operations without replay. New connections serve only explicit
new intents. Drop closes original IO. Controlled local IPC checks do not qualify
TUN devices, host configuration or a full official VPN/EXIT peer flow.
