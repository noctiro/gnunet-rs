# Official VPN allocation client

`Client` is a bounded caller-driven native IPC client for the pinned official
GNUnet v0.29.1 VPN service. It shares the existing CLIENT endpoint selection,
clock, framed IO and Resolver ports. It creates no background task or service.
An explicit `AfProfile` describes the service's C AF constants. Wire IDs are
opaque eight-byte values echoed exactly and never reused within a client.

## Construction

The caller supplies the endpoint and shared clock/Resolver through
`EndpointSource`. Select the service's actual AF profile, including when the
client and service run on different platforms:

```rust
use gnunet_vpn_client_host::{AfProfile, Client, EndpointSource, Error, Instance, Limits};

fn client<'a>(instance: &'a mut Instance, source: EndpointSource, af: AfProfile)
    -> Result<Client<'a>, Error>
{
    Client::new(instance, source, af, Limits::default())
}
```

Drive I/O in the caller's Tokio I/O/time context. An unattached idle client
starts no connection. Cancelling its last unissued operation retires the
original connector.

## Allocation and deadlines

`internet` and `service` encode official redirects. Lease expiration is distinct
from the finite local response deadline. Only a matching USE_IP frame
produces `Outcome::Allocation`; None is allocation failure. A successful
allocation does not assert a connected exit, packet forwarding, kernel routes
or remote application delivery.

Admission fixes canonical and independent native response bounds before
encoding. `next_deadline` exposes the absolute boundary;
`next_native_deadline` exposes the original monotonic target. The driver checks
native bounds before clock access, connection progress, I/O and reply dispatch.
Containing owners poll `poll_native_guard` before their own clock waits. This
guard arms the original native wakeup and dispatches local retirement facts
without sampling the canonical source.

## Cancellation and retirement

Cancellation suppresses local results. The official protocol has no CANCEL or
revoke message. Unwritten requests are removed. A partially written original
frame finishes on the same MQ under a fixed native grace, or that MQ closes.
Cancellation samples no canonical time. Grace starts at the earlier of
cancellation and the original response hard target, with the original absolute
response expiry plus grace as a separate ceiling. Repeated cancellation cannot
renew either target. No suffix moves to another connection. Local Unknown means
a lease may exist. Loss settles old operations without replay. New connections
serve only explicit new intents. Drop closes original I/O.

Native device and official peer qualification follow
[implementation status](../../IMPLEMENTATION_STATUS.md).
