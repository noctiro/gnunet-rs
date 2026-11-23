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
| `firmware::Driver` | One original stream, synchronous durable replay, clock and local TRANSPORT queue |

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

## Firmware host

Give `firmware::Driver` an already connected or accepted nonblocking stream,
its caller-owned buffers, a clock with trusted absolute time and cryptographic
entropy, a durable replay backend and a local TRANSPORT queue owner. Use
`firmware::REPLAY_OPERATIONS` as the session's replay-operation limit. If
construction fails, the driver returns the original stream to its caller.
The driver handles at most one original service effect or socket turn at a time.
Replay reservations settle before socket I/O and before ordinary queue work.
Keep driving while a turn advances work, and after errors until retirement.
Use the reported socket interest, logical deadline and native stop deadline
when arranging the next wake. Local TRANSPORT output also wakes its original
driver. A successful queue send continuation means ciphertext admission.
`Outgoing::ObserveNative` also reports when the socket has accepted the
complete original BOX. One observation may be pending per driver while
ordinary output continues. The callback reports the native write turn's
elapsed time, or an error if the connection retires before acceptance.
`WaitStream` allows the firmware to wait on the original socket through the
driver. Cap that wait at the earliest TCP or upper-layer deadline.

The board must qualify its storage backend before reporting durable replay
updates or signed-time range reservations. Session and timestamp state do not
require an allocator. Use the
[shared TRANSPORT protocol](../gnunet-transport/README.md) for validation and
flow handling behind the queue.

## Native composition and reference

The [runtime host](../../adapters/tcp-runtime-std/README.md) multiplexes sessions
and shared services. The [communicator application](../../apps/gnunet-communicator-tcp/README.md)
owns executable configuration and startup. Tokio is a host/test dependency;
the pure crate has no runtime dependency.

See [session design](DESIGN.md), [reference differences](UPSTREAM.md) and
[reference tools](tools/README.md).
