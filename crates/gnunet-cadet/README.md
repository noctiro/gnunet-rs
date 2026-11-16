# CADET protocol owners

Allocation-free `no_std` owners implement the official application IPC, local
service and reliable peer channels. Callers supply tables, buffers, clocks and
physical I/O. The [native adapter](../../adapters/cadet-std/) composes them with
sockets, authenticated tunnels, discovery and routing.

## Application client

`client::Client` uses caller-owned port and channel slots. `Instance`, `Epoch`,
`Port`, `Channel`, `Transmit` and `Delivery` tokens identify their original owner;
wire channel integers never replace that authority.

Prepare writes into caller storage, retain those bytes immutably, report actual
physical exposure, then report the complete original write. Only a service ACK
grants send credit. Receive completion requires the original single-use Delivery.
Physical loss retires channels and retains logical listening ports for explicit
reannouncement. Application data is never replayed automatically.

## Service lifecycle

Explicit Destroy releases the application's raw channel number while the
original peer channel can still drain. A replacement uses a new typed slot and
generation. An active duplicate is a conflict. Original immutable output or an
unissued remote-close notification for that number temporarily refuses a new
CREATE with WouldBlock. Destroy may cancel only an unissued notification; a
later failure cannot issue an old raw Destroy for the replacement endpoint.

`Service::retire_ingress` fences an original lost MQ before its previously
accepted Destroy drains finish. It rejects new commands, revokes ports and
closes other channel work. Existing drain effects keep their original owners;
new client output and remote opens are not admitted. The native owner enforces
the original finite drain bounds, stops physical I/O and eventually calls detach.
Detachment preserves original pending-output and exposure facts. No clock,
socket or replacement source is created by these transitions.

## Peer channels and send selection

`peer::ChannelOwner` uses caller send/receive buffers for OPEN proof, wrapping
message numbers, ordering, selective ACKs, application credit and original-message
retransmission. Its tunnel port supplies authenticated input and retains
immutable output through physical settlement. Peer acceptance is separate from
remote application delivery.

`Service::next_send_where` considers each ready channel's oldest unadmitted
payload, applies caller eligibility and preserves global order among candidates.
`send_admitted` checks that queued head again. The four existing TX records avoid
an additional queue. A head copied to its peer owner remains in that reliable
FIFO; later window slots can admit subsequent payloads. One full peer window
does not block unrelated ready channels.

## Diagnostic drops

`CADET_DROP_CADET_MESSAGE` applies to the original application channel. The
client retains its immutable transmit token; there is no service ACK or replay
across source loss. One opaque two-byte selector replaces the previous value;
zero clears it and unknown channels are ignored. The next matching peer
plaintext is discarded before encryption or CORE queueing. Selector bytes match
the encoded peer header directly, without byte-order reinterpretation. Local
loopback and unrelated packets do not consume it.

`Emission::Dropped`, Sent and physical failure remain separate. Exposed attempts
cannot become diagnostic drops. Reliable DATA/OPEN retain their original MID and
payload for bounded retry; dropped ACK/OPEN_ACK/DESTROY consume only the selected
control attempt. See [open work](../../IMPLEMENTATION_STATUS.md) for remaining
fault-injection and interoperability qualification.
