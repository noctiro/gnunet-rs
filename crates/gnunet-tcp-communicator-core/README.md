# TCP communicator core

An allocation-free `no_std` implementation of GNUnet v0.29.1 TCP sessions and
service-message formats. The facade exposes the pure API as `gnunet::tcp` and
the optional native host as `gnunet::tcp_host` through `official-tcp`.

## Public interfaces

| Interface | Responsibility |
| --- | --- |
| `Session` | Handshake, challenge ACK, ratcheting HMAC, AES256-CTR, REKEY, BOX and authenticated FINISH |
| `Registry` | Unique admission and generation-bound session ownership |
| `Identity::from_keys` | Immutable borrowing of one complete identity key pair |
| Caller ports | Buffers, replay operations, signed monotime and completion leases |

Logical absolute time and signed persistent monotime are separate inputs.
Replacing the current PILS identity cannot change an admitted session's
handshake, ACK or rekey identity.

## Replay and cancellation

Replay checks scan the original iterator to END before a final store, including
empty history. The host serializes peer/key scans and commits and retains a write
barrier after callback cancellation. Storage failure closes the affected peer.

Once `send` stages a BOX, its MAC step belongs to the ordered stream. Canceling a
wait retains that work. Graceful `finish` drains admitted records and emits one
FINISH under a fixed five-second target. Repeated close does not renew the target
or admit new sends. An abort physically closes the stream, reports `native_lost`
and retires the original service and write completions.

## Native composition and reference

The [runtime host](../../adapters/tcp-runtime-std/README.md) multiplexes sessions
and shared services. The [communicator application](../../apps/gnunet-communicator-tcp/README.md)
owns executable configuration and startup. Tokio is a host/test dependency;
the pure crate has no runtime dependency.

See [session design](DESIGN.md), [reference differences](UPSTREAM.md) and
[reference tools](tools/README.md).
