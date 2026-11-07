# CADET protocol owners

`client::Client` implements the official CADET application IPC state machine
using caller-owned port/channel slots. It is `no_std`, allocation-free and
independent of sockets, scheduling or Resolver services. `Instance`, `Epoch`,
`Port`, `Channel`, `Transmit` and `Delivery` tokens identify their original owner;
wire channel integers never replace that authority.

Prepare writes into caller output, retain those bytes immutably, report actual
physical exposure, then report the complete original write. Only a service
ACK grants send credit. A received packet requires its original single-use
`Delivery` when calling receive_done. Physical loss retires all channels and
retains logical listening ports for reannouncement; application data is never
replayed automatically.

The service releases an application's raw channel number on explicit Destroy,
including while that original peer channel drains. The C API can immediately
reuse the number. The old typed peer owner, accepted sends and close receipts
keep their original slot and generation until retirement; they never
become the replacement endpoint. An active duplicate remains a conflict. Original immutable application output or an unissued remote-close notification
for the same number temporarily blocks a new CREATE with `WouldBlock`, using the
native adapter's existing retained-input retry. Explicit Destroy may cancel only
an unissued notification. A later peer failure during a locally requested drain
cannot queue an old raw Destroy for the replacement.

The service source cases cover raw-number reuse before original open/peer-close
retirement, original ACK/expiry/failure settlement, and frozen output pressure. They are source cases, separate from normal C/Rust interoperability acceptance.

`peer::ChannelOwner` implements reliable peer-channel endpoints using caller
send/receive buffers: OPEN proof, wrapping message numbers, ordering, selective
ACKs, application receive credit and original-message retransmission. Its tunnel
port must supply authenticated input and retain immutable output through
physical settlement. Peer acceptance does not mean remote application delivery.

`Service::next_send_where` considers only each ready channel's oldest
unadmitted payload before applying its caller's eligibility predicate, then
preserves the original global order among those candidates. The existing four
TX records supply this check without a new queue or metadata allocation. `send_admitted` independently checks that queued head again. A head already
copied to its peer owner stays in that owner's reliable FIFO; another
window slot can admit the following payload without serializing every
channel to one outstanding packet. A full peer window on one channel cannot
hold unrelated ready channels. Pure source cases use Service/ChannelOwner
transitions, original DATA/MIDs and ACK inputs to check the one-slot blocked case
and the two-slot pipeline; their caller emission observations are not native
writes, tunnel authentication or interoperability acceptance. No historical
normal-run failure is attributed to this defect without new runtime evidence.

The native application adapter is `gnunet-cadet-host`. The independent
peer-facing CADET service, encrypted tunnels and discovery/routing remain
incomplete; the pure channel engine alone supplies none of those operations.

The standard `CADET_DROP_CADET_MESSAGE` diagnostic request is accepted on the
ordinary application MQ for its original channel. The pure/native client API
retains its original immutable transmit token and has no service ACK or replay
across source loss. One bounded opaque two-byte selector replaces the previous
selector; zero clears it, unknown channels are ignored, and the next matching
peer plaintext is discarded before encryption or CORE queueing. The fixed
C daemon compares these bytes directly against the encoded peer header; they are
preserved without a host/network-order reinterpretation. Local loopback traffic
and unrelated channels/packet types do not consume it.

An explicit `Emission::Dropped` is separate from `Sent` and physical failure;
exposed attempts cannot be relabeled dropped. Reliable DATA/OPEN retain their
original MID/payload and bounded retry; dropped ACK/OPEN_ACK/DESTROY consume only
the selected original control attempt. Node reports diagnostic drops
separately from physical writes and peer acceptance. This source path has no
runtime, fault-injection or official interoperability acceptance yet.
