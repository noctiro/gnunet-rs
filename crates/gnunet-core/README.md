# CORE peer protocol

This crate implements a pure, allocation-free GNUnet v0.29.1 CAKE peer owner. It uses the existing Rust DHKEM/KDF/AEAD primitives. Time, entropy, identity and
caller buffers are explicit; no socket, runtime, database or libgnunet backend
is part of the production dependency graph.

The peer owner implements InitiatorHello, ResponderHello, InitiatorDone and
explicit encrypted confirmation; ordered transcript hashing; retained identical
flight retransmission; application records and key updates; per-epoch anti-replay
windows; authenticated activity, heartbeat probes and loss. It keeps an old
confirmed association usable while a new responder handshake is unconfirmed. Abandoning an unconfirmed exchange also retires its keys, so a late old ACK cannot
confirm a newer flight. Speculative receive ratchets are committed only after
authentication; invalid future-epoch input cannot reset an existing replay window.

`record::Sender` and `Receiver` are directional mechanisms. A caller constructing
them directly owns key authorization. `session::Session` performs the handshake
checks before installing keys and authorizes application send/delivery only after
explicit confirmation. Returned bytes are encoded frames, not proof of transport
admission, remote processing or durability. The host must retain immutable frames
and partial I/O across cancellation and return TRANSPORT receive credit
only after handling the original input.

## Version and profile

The implementation targets source revision
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165` and
[LSD0012](https://lsd.gnunet.org/lsd0012/). The source/header wire profile has
144/48/84/36-byte InitiatorHello/ResponderHello/InitiatorDone/record prefixes in
the normal 64-bit reference build. Handshake ABI padding participates in the
source's transcript; encoding writes it explicitly rather than casting Rust
objects. The source's native 32-bit-word hash comparison and heartbeat flags also
need an explicit word-order profile. Other source-native ABI/platform profiles
remain unverified; this crate does not silently claim portable C struct layout.

The application-record associated data, sequence masking, key schedule and
Finished checkpoints follow the pinned implementation. Do not add private tags,
headers or negotiation fields to repair a draft/source discrepancy. The actual
host must also respect the outer TRANSPORT IPC envelope's smaller payload budget
before generating a record or reserving service credit.

## Acceptance boundary

Production Rust regression tests cover full handshakes, both application
directions, duplicate/lost flights, invalid authentication, transactional replay
state, retained old associations, resource refusal, clock rollback, heartbeat
loss and abandoned-exchange identity. `cake-observer` is a test-only executable
that exposes this owner to unchanged official C CORE/application processes.

The crate is a peer engine. A complete Rust CORE daemon, application IPC/client
registry, monitoring/service composition, PILS lifecycle integration, and an
independent full Rust TRANSPORT/node still require implementation and acceptance. Rust-to-Rust tests or isolated CAKE/C CORE observations do not certify those
missing service layers or full GNUnet interoperability.
