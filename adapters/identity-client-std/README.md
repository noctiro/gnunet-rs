# Official native IDENTITY client

`gnunet-identity-client-host` implements the active v0.29.1 local IDENTITY API on
shared CLIENT endpoint selection and retained `Framed` I/O. This crate creates no
Resolver, worker, background task, entropy source, key file, or daemon. All I/O is
caller-driven through `poll` or `drive`. Construction only allocates bounded
metadata and registers the explicit source clock listener.

## supported operations

- `Client::monitor(&Instance, source, Limits)` sends START (624), exposes
  UPDATE events (626), and marks `initialized` only on the initial-list
  END record. Current egos are borrowed through `egos` / `ego`. Rename preserves
  an ego token; deletion or physical source loss revokes it.
- `Client::new` is an operations-only original MQ and allocates no ego cache.
  `create`, `create_generated`, `rename`, and `delete` send CREATE (629), RENAME
  (630), and DELETE (631). The ordered RESULT_CODE (625) completes an
  operation. The local token never enters wire. A code0 result is the service's
  success response; it does not itself prove disk durability. The pinned C
  service can send its response before a later disk write.
- `create` imports an explicitly owned opaque `SecretKey`; `create_generated`
  invokes the caller's explicit cryptographic `Entropy` provider. Successful
  creation returns the original key ownership only in its original completion.
  `SecretKey::anonymous` is the official published anonymous constant; it neither
  reads nor writes a key file.
- `Lookup::exact` and `Lookup::by_suffix` own separate, explicit one-shot MQs.
  Their requests are LOOKUP (632) and LOOKUP_BY_SUFFIX (633). A found ego
  arrives in an UPDATE; a miss is the RESULT_CODE(200), not an END.
  Results freeze and physically stop that exact lookup MQ before publication.
  Exact comparison is case-insensitive and suffix comparison is case-sensitive
  in the pinned service; the client sends the original names unmodified.

The active pinned header, client API, service handlers, and message registry do
**not** contain get-default or set-default operations. Older prose mentioning
`GNUNET_IDENTITY_get` and the service's internal default-name file do not provide
such a wire command. No627/628/default API or synthetic acknowledgement is added.

## Original source, cancellation, and results

One stable caller-owned `Instance` supports bounded dynamic client/lookup owners. Atomic checked allocation IDs never recycle; they are private Rust metadata. Each attachment creates an `Epoch`. Ego/operation tokens bind the exact
original owner and source, and do not become valid on a reused slot, same-named
ego, or replacement MQ. No key hash is used as a public identity token.

Each submitted operation has a finite original absolute `until` in the canonical
source clock's microseconds and an original native-time bound. It is not renewed
by callbacks, wait cancellation, clock rollback, or reconnect. `drive`'s optional
Tokio deadline is observation-only. `Queued`, positive `Activity`, whole
`Written`, and actual `Completed` are separate facts. Sending the full frame
locally is never interpreted as a mutation/lookup result.

`cancel` removes zero-written originals where physically possible. Already
exposed originals keep immutable partial suffixes and their FIFO tombstones. Late results retire that original tombstone with `LocalReason::Cancelled` rather
than completing a different operation. The first finite retirement grace is not
extended by repeated cancellation. If it cannot settle, the client physically
stops that MQ and retires every affected original with its exposure. There is no official wire CANCEL, and cancellation does not revoke an operation
already seen by the service. Original unsent operations are reported as Unsent;
exposed loss/timeouts remain ambiguous and are never automatically replayed.

On loss the monitor immediately wipes its live ego secrets and revokes
all old ego handles. With `Limits::reconnect` enabled, only a fresh START/snapshot
is rebuilt after the original completion/ego-retirement observations drain. Old CREATE/RENAME/DELETE/LOOKUP frames are never replayed. With it disabled,
`reconnect` is explicit. Clock/Resolver port refusals stop physical I/O and need
`recover_ports`; explicit permanent close cannot be recovered.

`close` and Drop stop the native owner without reading a clock. The shared
CLIENT transport has no separate close-errno receipt; this API reports the known
preceding I/O/port/protocol cause and native owner retirement without inventing a
kernel acknowledgement or remote cancellation result. Local outcomes/ego
retirement observations remain drainable after explicit close.

## Memory and sensitive ownership

All frame buffers use shared zeroizing `OwnedFrame`/RX storage. Imported/generated
keys use `gnunet_identity::SecretKey`, which erases on drop and has no ordinary
Clone/Hash/Serialize. `Identity`, `EgoView`, `Outcome`, and all event formatting
redact private material. `Identity::secret` borrows an opaque owner; explicit
secret exposure/duplication/public-key derivation is a conscious caller action. No private key appears in automatic logs, a JSON representation, an operation
identifier, or a diagnostic generation.

Limits are explicit and validated before connection:

| Resource | Default | Bound |
|---|---:|---|
| Pending operations, tombstones, undelivered completions |32|fixed allocated rows|
| Monitored egos |1024|fixed allocated rows; none for operations-only/lookup|
| Name bytes |1024|per retained name, no final NUL|
| Original outbound immutable bytes |256KiB|logical pending plus physical queue|
| Physical output queue |1frame|complete original frame retained through write|
| Native RX frame |65535bytes|one current retained frame|
| Native syscall quantum |65535bytes|caller-configurable nonzero|
| Initial START through END |30s|native finite bound per attachment|
| Exposed cancellation/timeout retirement |5s|first native deadline, never renewed|

Cache lookup is a bounded linear constant-time-key comparison scan; names are
copied once per UPDATE. The wire has no stable ego identifier besides the key,
so same-key aliases inherit the pinned C client's same-key rename ambiguity. Returned snapshots/creation material transferred to callers are caller-owned;
they are outside the retained client cache budget. A name/frame/cache allocation
or protocol refusal stops the original MQ rather than retaining a permanent head
frame, faking an END, or misassigning a FIFO result.

## Checks

Its
key-shaped fields are published synthetic mocks, never passed to cryptographic
generation, public-key derivation, hashing or a C service. The model checks
START/initialization, create/rename/delete response ordering, zero/partial
cancellation, source loss/no replay/new ego scope, exact lookup, suffix miss and
immediate physical retirement on an admission-clock fault. An exposed request's
retirement is capped by its original native deadline plus grace, including a
late poll/cancel. Provider failure discovered during admission closes and
invalidates the source before returning its original error; one bounded loss
observation remains available before another admission. This is not production crypto, private-key-file or C interoperability proof.
