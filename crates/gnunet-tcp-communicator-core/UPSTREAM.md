# TCP reference behavior

These source observations refer to GNUnet v0.29.1
`gnunet-communicator-tcp.c`. They describe C control flow, not runtime results.
Rust preserves valid wire behavior while refusing uninitialized state and
retaining distinct operation and listener capabilities.

## Parsing and replay storage

- `proto_read_kx:3279` treats cumulative input length 36 as a NAT probe without
  checking its MessageHeader type or size. A 168-byte initial KX split after
  36 bytes can enter this branch. It leaves local `tc` uninitialized before
  `:3351` reads `tc.challenge`. Rust parsing must validate the frame before selecting
  this path.
- `handshake_monotime_store_cb:2995` advances `handshake_ack_monotime_get`
  instead of `handshake_monotime_get`; the malformed/stale branches at
  `:3034/:3047` also use the wrong context. Rust retains separate typed
  operation capabilities and never substitutes a foreign or null context.
- `proto_read_kx:3303..3318` calls `decrypt_and_check_tc` on a zero-initialized
  Queue before assigning `target` from `tc.sender`. The timestamp query at
  `:3112..3117` therefore passes a zero peer to `peerstore_api.c:894..895`.
- `rekey_monotime_cb`, `handshake_ack_monotime_cb` and `handshake_monotime_cb`
  return on `record == NULL` before creating an initial timestamp record.
  Storage occurs while processing an existing record, so an empty database
  follows a different path from the documented replay-persistence intent.

The Elligator scalar-zero case is rejected before calling the normal libsodium
helper. Invalid helper preconditions are not replayed as C negative tests.

## Authentication and native ownership

`try_handle_plaintext:2124..2231` verifies an ACK's claimed sender signature,
local intended receiver and source challenge, but does not compare its sender
with `queue.target`. `wire::verify_ack` returns the signature-bound sender;
queue admission remains a separate owner decision.

The C listener pauses after EMFILE/ENFILE until a queue closes, but
`create_proto_queue` does not attach the accepting ListenTask/listen socket to
its new queue. The rearm branch in `queue_destroy` may therefore lack the
listener identity. The Rust host retains the original listener capability.

## Ordered output and close

`mq_send:2792..2800` ratchets `out_hmac` when plaintext is enqueued, whereas
`mq_cancel:2840..2847` only clears `pwrite_off`. Forgetting the admitted BOX can
make later records fail authentication. The Rust interface has no per-message
cancellation after BOX admission. Dropping a polling wait retains its bytes.

Graceful close also differs from C's `queue_finish` overwrite/repeated-MAC
behavior: an already staged BOX keeps its original plaintext and cipher order,
and one FINISH follows native drain. TRANSPORT loss retires old callback
metadata while retaining the healthy stream's ciphertext and plaintext; those
callbacks never move to a replacement source.

To abort, physically close the native owner, report `native_lost` and settle
the original write, service and receive-completion obligations. Terminal state
suppresses new records and continuations without claiming written bytes became
unsent. Already issued write leases retain their backing buffers until their
completion is reported.
