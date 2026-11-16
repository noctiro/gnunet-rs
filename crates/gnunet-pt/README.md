# PT protocol core

This crate implements GNUnet DNS translation and DNS-over-CADET state machines.
Packet and advertisement codecs work without allocation; the `alloc` feature
adds the bounded business owner. The [native host](../../adapters/pt-std/)
connects it to DNS, VPN, DHT and CADET clients.

## Public interfaces

- `packet` validates DNS packets and transforms selected A/AAAA records.
- `exit` verifies signed advertisements and encodes CADET DNS messages 193/194.
- `core::Core` retains original DNS callbacks, allocation jobs, discovery tokens,
  channels, attempts, deadlines and reply-write obligations.

Create one caller-owned identity domain and configure explicit resource limits:

```rust
use gnunet_pt::{Error, core::{Core, Instance, Limits}, packet::Families};

fn main() -> Result<(), Error> {
    let instance = Instance::new();
    let _core = Core::new(&instance, Limits::default(), Families {
        ipv4: true,
        ipv6: true,
    })?;
    Ok(())
}
```

An attachment represents an observed native DNS connection. Callers supply its
packets and original finite deadlines, execute `Work` through the native ports
and correlate completion using the returned opaque tokens. Source replacement
retires old requests even when service IDs repeat.

`Core::next_wakeup(now)` includes future request/discovery/exit deadlines and
fixed channel-retry targets. Already due work remains available through
`next_work`; an old target cannot hide a later wakeup. Prepared DNS decisions
precede new allocation, channel or query work.

## DNS translation

POST scans answer, authority and additional sections. Each selected A/AAAA record
requires an original same-family VPN allocation. Admission reserves both input
and full reply capacity before exposing allocation work; refusal creates no job.
Results fill reserved replacement slots. Final transformation runs once and
validates all compression aliases before exposing an immutable answer. A failed
allocation or invalid transformation drops the original callback.

Rewritten native replies use zero TTLs, clear AD and preserve unrelated bytes.
The pure `packet::rewrite` API instead clamps TTLs to the remaining VPN lease.
Original input is immutable. Existing RRSIG bytes cannot authenticate changed
RRsets. Queued output retains its memory until the original write or source loss.

## DNS exit discovery

Signed advertisements use official purpose 11 and bind expiration to the peer.
Discovery uses SHA512("dns"), DHT block type 10, replication 1, options 1 and an
empty extended query. CADET uses SHA512("exit-dns"). Each channel has unique DNS
IDs, bounded attempts, response correlation and explicit send/receive credit.

PRE admission reserves the original query plus one buffer large enough for both
the encoded query and the configured maximum DNS reply. Query transmission,
channel replacement and reply acceptance reuse this reservation. A valid reply
needs no allocation or extra payload budget. The reservation is released only by
the original reply write or DNS-source retirement; cancellation alone retains it.

The host owns actual lookups, connections, native hard deadlines and cleanup.
VPN/EXIT own address leases, forwarding, devices and routes. Protocol compatibility
and release acceptance follow the [central contract](../../spec/gnunet/compatibility.md).
