# Direct GNUnet peer

`gnunet-direct-peer` runs one provisioned CORE peer over the original reliable
TCP queue. The adapter binds the expected remote and local signing identities
to the authenticated communicator queue. Direct TRANSPORT validation and FLOW
use the official wire format. CORE then runs CAKE and delivers confirmed
application records. The `gnunet` facade exposes `direct_peer` with its
`direct-peer` feature.

## Configure the carrier

Construct `Peer` with the local TRANSPORT signing key, the matching CORE
identity, the expected peer, direct link limits and exclusive buffer storage.
Set the original CORE frame limit independently of the outbound BOX limit.
Reserve one frame buffer and coverage bitmap per inbound reassembly, plus one
outbound fragment BOX. `Peer` defaults to four simultaneous reassemblies.
At least one receive lane must fit the maximum logical frame. Other lanes
can be smaller. Incoming originals use the smallest available lane that fits.
`DiscoveryBuffers` separates the retained canonical HELLO bytes from parsing
scratch. Configure its frame, address byte and address count limits together.
Use it as the `Transport` port of the
[firmware TCP driver](../gnunet-tcp-communicator-core/README.md#firmware-host).
The TCP local identity must also match. A replacement connection constructs a
new peer and FLOW scope. The application implements `Application` to observe
association confirmation, consume complete messages synchronously and offer
its current original send.

## Drive I/O and retirement

Drive the TCP owner on socket readiness, application output and the earliest
absolute or elapsed timer. Validation expiry drops CORE keys and any original
retained frame. FLOW accounts for actual TCP admission and retains receive
credit until the original upper frame retires. A full receive slot can drop
excess CORE frames while continuing to process later TRANSPORT controls.
The application send callback reports local admission of the full original,
after the final fragment when fragmented. Ciphertext and physical delivery
remain owned by TCP. Advisory fragment ACKs use bounded storage and do not
block reassembly when that storage fills.

## Discover peer addresses

`Application::discovered` receives the configured peer's accepted HELLO address
set and its signed expiration. The normal GNUnet HELLO signature covers only
metadata. The peer's own authenticated CORE DATA also binds the address bytes
to that sender. Withdrawal and expiration each carry the corresponding signed
expiration so a caller retaining candidates across carriers can order them.
Callbacks borrow the canonical NUL-delimited bytes for their duration. `received` still
delivers the original authenticated CORE application frames, including HELLO.

## Protocol scope

`Application::routed` receives typed LEARN and BOX envelopes from the
validated carrier. The embedding owns DV verification, replay, and forwarding.
`Application::reachability` reports the current TRANSPORT validation lease
independently of CORE confirmation. `routing_offer` supplies an original DV
frame and can request a native write receipt for its final span.
Backchannels and NAT burst belong to the TRANSPORT engine.
[TRANSPORT](../gnunet-transport/README.md) · [CORE profile](../gnunet-core/README.md#version-and-profile)
