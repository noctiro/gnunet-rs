# GNUnet TCP communicator core

This allocation-free `no_std` package implements the fixed GNUnet v0.29.1 TCP session and its service-message formats. `gnunet::tcp` exposes the pure API; `official-tcp` additionally exposes the Unix host as `gnunet::tcp_host`. Production code uses independent Rust cryptography and official wire fields.

`Session` owns the 168-byte Elligator initial exchange, purpose31/39 signatures, role-specific challenge ACK, truncated and ratcheting HMAC, persistent AES256-CTR streams, byte/time REKEY, BOX and authenticated FINISH. Logical absolute time can regress; the signed persistent monotime is a separate caller input. Caller-owned buffers, replay-operation credit, completion leases, generation identity and cleanup remain explicit. `Registry` issues a unique non-Copy Admission so copied metadata cannot create a second session or retire another live owner. `Identity::from_keys` immutably borrows one complete original key pair. Replacing a current PILS identity cannot change an existing session's next handshake, ACK or rekey operation. The former mutable current-key interface has been removed.

The separate process-level communicator host shares one TRANSPORT/PEERSTORE pair across independently owned physical sessions. Its one-session Driver facade uses the same manager. The host retains sockets and partial I/O across canceled waits, copies bounded IPC output before releasing its producer, rotates runnable effects, and retains overlapping original PEERSTORE operations across rekeys. It retains TRANSPORT queue identity and role when its local MQ is replaced. A complete communicator process still needs process-wide configuration/listeners, Resolver/NAT integration, interface scanning, reversal, shared lifecycle/CLI and persisted-clock storage. CORE application encryption and the other communicator implementations remain separate work.

The frozen candidate has finite normal C component comparisons and unchanged normal C peer observations with bidirectional traffic, rekeys and SQLite timestamp records. Those receipts bind the implementation inputs; fresh proof of the integrated workspace is pending. Failed explorations and the known upstream Peerstore monitor-disconnect defect remain recorded in `SOURCE_FINDINGS.md` and the integration audit. No whole TRANSPORT, CORE or util completion is claimed.

See [session design](DESIGN.md), [source differences](SOURCE_FINDINGS.md) and
[reference verifier](tools/TCP_VERIFIER.md). Tokio is a host test/example
dependency; the pure crate has no runtime dependency.

Replay checking scans each original iterator to its END before one final store, including initially empty history. It does not write while the SQLite serial iterator remains live. The host serializes each peer/key scan and commit through the store result and retains a write barrier after callback cancellation. Backend failure is distinct from successful END; failed storage closes the peer. The official wire encoding is unchanged, while this Rust internal strategy deliberately avoids the fixed C record/replace/NEXT self-feeding behavior. Historical component receipts retain their original behavior scope and are not automatically promoted to this implementation.

Graceful close preserves the original staged BOX and ciphertext until they drain,
then emits one ordinary authenticated FINISH. Repeated `finish` calls neither
ratchet again nor renew the fixed five-second target; new sends are refused and
late replay/queue-registration callbacks cannot reopen the closing session. The
old send wait receives no invented success continuation. This internal ordering
avoids the fixed C `queue_finish` overwrite/repeated-ratchet quirk while using
the same wire record. A failed/expired carrier still closes physically. It does
not identify the record behind the historical normal Bob retirement warning. There is no single-message cancellation after `send` stages a BOX: that MAC
step belongs to the ordered stream. The unused broken `cancel_send` API was
removed. Dropping a polling wait keeps original work; `finish` explicitly drains
admitted records before closing. To abort transmission, the native owner
must close that physical stream and notify `native_lost`, then drive its original
service/completion cleanup. Already-issued writes keep their genuine result and
already-written bytes remain written; no continuation success, MAC rollback or
replacement stream is invented.
