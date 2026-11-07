# Source-reading findings requiring explicit owner policy

These observations are anchored to the unchanged v0.29.1 `gnunet-communicator-tcp.c` inventory hash. None is credited as an executed normal-C daemon regression. Dangerous C uninitialized/invalid-context paths are not deliberately exercised.

- `proto_read_kx:3279` treats cumulative input length36 as a NAT probe without checking its MessageHeader type/size. A168-byte ordinary initial KX split after36bytes can enter this branch. The branch never initializes local `tc`, but `:3351` later reads `tc.challenge` into challenge_received. Safe future parsing must not copy this uninitialized behavior; source-version discrepancy policy is pending. No36byte-fragment normal C test is run.
- `handshake_monotime_store_cb:2995` calls iteration_next on handshake_ack_monotime_get instead of handshake_monotime_get; malformed/stale branches `:3034/:3047` also use the wrong context. Those can be absent or belong to a different concurrent operation. The Rust owner must retain distinct typed operation capabilities rather than pretend success or use a foreign/null context. Source-policy review remains pending.
- `proto_read_kx:3303..3318` constructs a zero-initialized Queue and calls decrypt_and_check_tc before assigning target from tc.sender. `decrypt_and_check_tc:3112..3117` starts handshake timestamp iteration with queue.target, and `peerstore_api.c:894..895` immediately copies that peer into the request. Thus this inbound query is source-bound to the zero identity before target assignment. No claim about experimental database results is made.
- Each of rekey_monotime_cb, handshake_ack_monotime_cb and handshake_monotime_cb returns when `record==NULL` before creating an initial timestamp record. Store occurs only while processing an existing record. The intended documentation of replay persistence differs from this empty-database control flow. This is a source observation, not measured persistence behavior yet.
- `try_handle_plaintext:2124..2231` ACK verification checks its claimed sender's signature, local intended receiver and the source challenge, but does not compare the claimed sender with queue.target. Current wire::verify_ack intentionally documents that exact boundary and returns its signature-bound sender, without queue admission. Any additional future equality policy must be explicit.
- `mq_send:2792..2800` ratchets out_hmac while plaintext is enqueued, whereas `mq_cancel:2840..2847` only clears pwrite_off. That omission can make later records fail authentication. The unused analogous Rust per-message cancel_send API has been removed; a live ordered stream cannot forget that admitted BOX. Existing physical native-loss retirement handles an abort without a MAC rewind or silent cancelled-payload drain.
- Source listen_cb pauses EMFILE/ENFILE until a queue closes, but create_proto_queue does not attach the accepting ListenTask/listen_sock to the new protoqueue. queue_destroy's rearm branch therefore may lack the relevant listener identity. Do not silently drop the listener capability in the Rust host; finite-resource evidence/policy remains pending.

The Elligator scalar-zero case is rejected before calling the normal libsodium
helper. Invalid helper inputs are distinct from normal daemon negative cases;
Rust rejects the scalar safely without replaying an invalid C precondition.

The current safe graceful-close ordering intentionally differs from the C
`queue_finish` overwrite/repeated-MAC behavior: an already-staged BOX retains
its original plaintext and cipher order, and one FINISH follows native drain.
The current interface has no per-message cancellation after BOX admission.
Source search found the removed `cancel_send` method had only one pure-test
caller and no production host caller. The production TRANSPORT-loss path
retires old callback metadata while retaining the healthy core's original
ciphertext/plaintext and never replays that callback on a new source. Dropping
a polling wait also retains its original bytes. Graceful `finish` explicitly
drains already-admitted records; callers requiring an abort must physically
close the native owner, report `native_lost`, and drive the same original
write/service/receive-completion cleanup. This terminal path suppresses new
records/continuations and never claims already-written bytes became unsent.
Already-issued write leases still own their completion before close may
release their backing buffers. No new cancellation abstraction or private wire
field is necessary. A source case checks that terminal lifecycle instead of
requiring a later peer Authentication failure from the omitted MAC step.
