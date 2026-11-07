# UDP packet and session core

This `no_std`, unsafe-free crate implements the explicit GNUnet v0.29.1 UDP
packet fields and packet authentication. Its default feature set needs no heap. The `alloc` feature adds bounded sender master ownership, immutable prepared
packets with burned BOX sequence numbers, receiver KID windows and explicit
replay-store admission. Randomness and monotonic time come from callers.

The interoperability profile follows the unchanged official source
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`, including its KID formula:
HKDF-Extract(salt=BE32(sequence), IKM=master), then HKDF-Expand with
`gnunet-communicator-udp-kid`. LSD0007 instead describes an expand-only KID
formula. No wire negotiation or fallback is invented for that discrepancy.

Initial KX uses Elligator KEM 0x0022, a 48-byte prefix, a 104-byte confirmation,
a purpose33 signature over the complete 112-byte transcript, and AES-256-GCM
with empty AAD. BOX has a 48-byte prefix. Ordinary rekey uses KEM 0x0020 and the
official 36-byte type1462 message. ACK is the exact 72-byte type1460 message. Padding uses type1461 and caller-provided entropy. All cryptographic
algorithms are shared with `gnunet-session-crypto`; production uses no C FFI.

`Receiver::initial` authenticates before calling `ReplayStore`. Its trait is a
required gate, not an implementation of durable persistence. The finite unit
store only proves trait behavior. A backend must bind local identity,
remote sender and monotonic time in its own namespace, persist atomically with
an exclusive writer fence, and keep ambiguous outcomes quiescent until resolved. Neither the unit store nor the normal C packet helper proves that requirement. The fixed C verifier authenticates purpose33 but does not itself implement the
persistent monotonic-time gate required by LSD0007.

The `udp_packet_oracle` example is a finite component observer using public
fixture seeds A=[3;32], B=[5;32], ordinary official TEST type0/counter messages,
entropy for KEM/padding, and public metadata only. Open verifies the
three packets, both ACKs, authenticated metadata and fixture padding extents.

The packet component profile covers initial exchanges, BOX/rekey packets and
malformed authenticated fields. It checks C structure layouts separately from
packet authentication. Stored vectors and component observers do not identify
the current normal daemon or its runtime ownership behavior.

This evidence establishes packet components only. Native UDP sockets, IPv4/IPv6
MTU behavior, transport IPC/backchannel lifecycle, PILS identity ownership, NAT,
durable replay persistence, scheduler/resource teardown and complete UDP or Node
interoperability remain separate required work.

BOX preparation prefers the newest usable ACK-confirmed master. A retained
sender can therefore recover after a peer loses volatile receive keys and
accepts a fresh initial exchange, without first spending stale older credit. Original sealed packets keep their key/sequence and old grants are not refunded
or revoked. This is an internal selection policy: official formats, KIDs,
CMAC/AEAD checks and per-master sequence/byte limits remain unchanged. It differs
from the selected C source's oldest-first scheduling and requires independent
C peer qualification; matching that internal order is not a wire requirement.
