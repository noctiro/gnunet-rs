# TCP session design

The encrypted reliable underlay uses the official TCP communicator format.
TRANSPORT owns HELLO/contact validation; the TCP handshake adds no HELLO field.
PILS supplies immutable identity keys and PEERSTORE supplies three replay-time
operations. Hosts provide NAT, listeners, Resolver, statistics and service IPC.

## Records

| Record | Encoding and authentication |
| --- | --- |
| Initial | 32-byte Elligator KEM0x0022 representative plus 136 encrypted bytes: sender32/signature64/monotime8/challenge32 |
| ACK | 140 bytes: header4/sender32/signature64/monotime8/challenge32; CTR encrypted, no ratcheting HMAC |
| BOX1451 | Header4/MAC32/payload; size is payload length, not total extent |
| REKEY1450 | 140 bytes: header4/MAC32/ordinary KEM0x0020 encapsulation32/signature64/monotime8 |
| FINISH1452 | Authenticated fixed control record |

Purpose31 signs 144 bytes containing both peers, representative, monotime and
challenge. Purpose39 authenticates the role-specific challenge ACK. Purpose32
signs 112 bytes containing both peers and rekey encapsulation. Admission checks
identity, target and original handshake/replay context.

BOX HMAC-SHA512 covers its payload and is truncated to 32 bytes. After admission,
the sole 64-byte MAC key is replaced and erased through SHA512 ratcheting.
FINISH/REKEY authenticate their fixed struct with MAC zeroed. Initial and rekey
KEMs are distinct and cannot be substituted for each other.

## Stream and state ownership

A `Session` owns one bounded physical chain with separate replay-operation tokens,
ACK registration, backpressure, immutable partial output, rekey and closing state.
Identity keys cannot change behind an admitted session. `Registry` issues
instance/generation-bound admission so copied metadata cannot create or retire
another session.

Cipher state persists across reads/writes. Decoding stops at each record boundary;
a REKEY switches context before subsequent ciphertext is decrypted. Authentication
failure erases accumulated plaintext and closes that decoder. Capacity refusal
precedes sender mutation. Borrowed authenticated bytes cannot escape into the next
mutable decode operation.

## Cancellation and close

Once a BOX is admitted its ordered bytes drain, or the native owner terminates
the whole stream and reports loss. Canceling a wait preserves work; it does not
rewind nonce/MAC state or promise that a message was unsent.

Graceful finish drains earlier output, stages one FINISH and retains its first
close bound. Repeated close is idempotent and refuses new sends. Late service
callbacks retire their original leases without reopening the session. Native
shutdown owns sockets, replay handles, queues and provider retirement separately.

## Native composition

The [runtime host](../../adapters/tcp-runtime-std/README.md) multiplexes shared
service links and supervises immutable-key generations above the pure engine.
