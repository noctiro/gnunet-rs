# Official caller-driven NAMECACHE client

`gnunet-namecache-client-host` implements the active v0.29.1 local NAMECACHE API
on shared CLIENT endpoint selection, the caller's canonical RuntimeClock and
retained Framed I/O. Construction reserves finite metadata and a clock listener;
it does not open a socket, Resolver, key file, network search, thread or task.

## operations and validation

`Client::lookup(query, until)`, `cache(block, until)` and `delete(query, until)`
produce the LOOKUP_BLOCK, BLOCK_CACHE and BLOCK_DELETE requests. Every
response is matched to its original BE32 RID, operation kind, actually
attached source epoch and complete original request write. Native Queued,
positive-byte Activity, whole Written and Completed are separate events. No private INIT, ACK, CANCEL, request identifier or extra stream terminator is
added. Unknown/canceled/duplicate RIDs are consumed and ignored as in the C API.

A lookup with outer expiration0 is the official actual-miss sentinel, including
when it carries an ignored tail. This is separate from timeout, EOF, resource
failure, malformed data and signature failure. A nonzero-expiration response is
accepted only after `gnunet_namecache::verify_lookup` validates:

- the complete encrypted block framing and official carried-key signature;
- the exact original query against the block's derived public-key hash;
- signed inner expiration equal to the original response expiration.

Only then is the ciphertext copied once into the returned owned `Block`. Its
constructor is private. It provides bytes, original query and expiration without
decrypting or exposing a zone secret. The signature proves the carried key's
signature, not authority for a caller's zone/label or authenticated transport. Expiry filtering belongs to the consumer; the reference cache may return blocks
pending its periodic expiration. This client does not add current-time expiry
filtering or invent an authenticated naming result.

`cache` checks the complete block signature before submitting its immutable
ciphertext frame. Outer expiration0 matches the official C producer; the active
service ignores that outer field and obtains expiry from the block. Cache and
delete outcomes preserve the signed32-bit result, including unknown
positive/negative values. A local write is no service success or fsync proof.

## Bounded ownership and cancellation

One caller-owned `Instance` supports multiple dynamic clients without leaked
storage or a per-operation lifetime borrow of a mutable registry. Native epoch
and operation tokens use checked unique local allocation IDs and exact owner
identity; they never enter wire. Official RIDs start at0 and increase without
reuse across this client's replacement MQs. After UINT32_MAX, new admissions
return Overflow; live originals still drain and an explicit new Client can use a
new source/owner. No delayed reply can become a new operation by slot reuse.

Each operation has an original finite absolute response deadline in the shared
source's microseconds and a corresponding original native-time bound. A canceled
`drive` future preserves all physical read/write cursors and accounting. Its
optional Tokio deadline is only a caller observation budget; it never renews or
cancels an operation. Clock rollback cannot extend the original native bound.

`cancel` removes originals that have no written bytes when physically possible. A partial original retains its immutable suffix on that same MQ, under the first
finite native retirement grace. Once wholly written, it completes locally with
its exposure; its never-reused late RID is ignored. Unlike IDENTITY's
FIFO-only wire, NAMECACHE needs no pending response tombstone after whole write. Repeated cancellation does not extend the first retirement bound. First drain
is capped at `min(native-now, original-hard) + grace`, so a late poll cannot
renew an already expired original. A suffix that
cannot drain before the hard bound causes source retirement and local
outcomes for every affected original. There is no remote cancellation receipt,
cache rollback, or promise that an exposed cache/delete did not commit.

On EOF or native/protocol/clock/Resolver failure the physical source stops
before local loss observations. Every unfinished original ends with its actual
Unsent/Partial/Written exposure. No lookup, cache or delete is automatically
replayed. A
malformed known response, wrong operation kind, wrong query, or invalid signature
stops that MQ and never exposes the block as a lookup result.

A clock refusal during public lookup/cache/delete admission also immediately
stops the existing physical source before returning the admission error. One
bounded original loss record remains for the next poll before any new admission;
its original pending operations receive local source-loss outcomes. No later
drive call is needed to prevent further physical I/O.

`close` and Drop stop the original physical owner without sampling the clock. Known I/O/port/protocol causes are retained. The shared CLIENT close port has no
independent close-errno/remote-revocation receipt, and this API invents neither. Local completions remain drainable after close.

## Memory policy

| Resource | Default | Ownership |
|---|---:|---|
| Live requests/drains/undelivered completions |32|fixed preallocated metadata rows|
| Total outbound pending/physical immutable bytes |256KiB|allocated on request admission|
| Complete encrypted block |63KiB|official public API maximum; exact wire codec remains broader|
| Native complete RX frame |65535bytes|one retained input frame|
| Physical output queue |1frame|original bytes retained through full write|
| Native syscall quantum |65535bytes|explicit configurable nonzero limit|
| Partial suffix retirement grace |5s|first native hard deadline|

The client does not preallocate a large payload per request/peer. Response buffers
are bounded by one input frame and one fallible owned block copy, transferred to
the caller. Unknown RID bodies incur no block signature verification. Source
bytes, frame size, and block limits reject admissions before exposure; permanent
input/resource errors stop the source rather than parking a head frame forever
or faking a miss. Pending results are bounded by the same operation rows.

## Checks

No private-key file was read or hashed. `tests/native.rs` includes only the
existing explicitly public `edkey_ascii-block.bin` ciphertext and query fixture,
never private_input or key files. It checks RID response reordering,
signature-validated lookup/cache, expire0 miss, raw statuses, zero/partial cancel,
late RID suppression, unknown cache loss/no replay, source replacement and
ciphertext-tamper refusal. A separate public-cipher Unix profile exercised this
production client against an unmodified official C service with SQLite, and an
official C API client against the Rust memory service. The latter also
observed a miss after an owned Rust service restart. These profiles do not
establish private-key crypto, whole GNS or whole-project conformance.

`Client::poll_native_guard` checks/arms original native operation/control/drain
bounds before an enclosing canonical-clock wait. It performs no socket IO,
logical sampling, decoding or cryptographic work. It can return prior admission
loss, an already settled completion or a native expiry result; local Unsent and
Unknown outcomes remain distinct from service results. Ordinary poll shares the
same logic, and its pinned native timer is reused when only the wake target
changes.

The configurable complete-block ceiling reaches the wire limit65519;
the default remains the declared C API value budget63KiB. This distinction
allows a legitimate63KiB plaintext GNS set plus112-byte header and optional
16-byte tag when explicitly configured. The active C CACHE implementation sends
and stores the full block without applying that conservative header constant.
