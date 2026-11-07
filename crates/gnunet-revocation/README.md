# Official revocation certificates and work

This independent noalloc port follows GNUnet v0.29.1,
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`, revocation.h,
revocation_api.c, gnunet-service-revocation.c and gnsrecord_pow.c.

The complete current certificate is372 public bytes: timestamp8, informational
TTL8,32BE64 nonces, typed public key36 and signature64. Both current blindable
key families use the same width. Decoding validates framing/type only. Its
signature binds purpose3, original timestamp and typed public key; the TTL and
nonce set are not signed. No private key, key file, entropy or storage is opened. External signers can use the exact52-byte signing_message region.

IPC preserves official types636..639, key/proof length words and complete
frames. Application requests have no wire RID/CANCEL. REVOKE is also the actual
peer flood frame. Both replies preserve rawBE32, including unknown values. The pinned daemon replies REVOKE0 on acceptance and1 on failure, despite
its opposite header comment; query0 means known revoked and1 still valid. Local
queue/write cannot produce either service result.

Verification reuses the existing BLOCK revocation implementation. Signature and
strict nonce order are checked once against immutable original bytes. Each
Verification::step performs at most one existing Argon2id13/t3/m1024KiB/p1 hash
with salt GnsRevocationPow in explicit caller-owned1MiB memory. Score/lifetime
are available only after all32 hashes; TTL remains informational, and
the existing clock/FOREVER behavior is preserved. The synchronous BLOCK plugin
uses this same stepper and completes it in its existing call.

Miner retains a fixed public certificate and32 best distinct candidate nonces,
with an explicit starting counter, finite target and no wrap. It keeps the best
scores rather than reproducing C's lossy first-replacement array strategy;
the final wire nonces are sorted numerically. One call performs at most one real
hash, and refused scratch cannot consume a candidate. All caller scheduling,
cancellation, total work limits, timestamp/lifetime rechecks and signer
ownership remain explicit. A mined certificate is not a verified signature or
service/persistence result.

`Miner::resume` continues candidates from the same standard372-byte public
artifact. It recomputes each distinct carried nonce using at most one actual
hash per step before generating new candidates; repeated zero/empty slots count
as one candidate, never32 trusted work results. No saved score or private C
calculation state is imported. The timestamp, typed public key and signature stay
original; only the informational TTL and unsigned nonce slots are mutable.

The format carries neither discarded search history nor a counter. Fresh search
starts above max(the explicit start floor, all carried nonces); callers may supply
the prior `search_after()` observation to avoid repeating rejected counters. The count in `progress()` covers hashes in this new owner, including restored
candidates. No historical count is inferred. Counter exhaustion is explicit and
never wraps, including a carried nonce of u64::MAX. A fully recomputed candidate
set can finish at that bound without trying another counter.

`checkpoint()` exposes only another structural public Certificate. During
restoration it retains the whole original candidate pool, including candidates
not yet rehashed. Afterwards it retains the current best pool; empty
positions repeat one candidate instead of fabricating additional distinct work. Only `certificate()` after the target is reached exposes completed sorted
mining work, still without asserting current lifetime or service acceptance.

Native client/SERVICE, marked durable inventory, CORE/SETU and ordinary CLI are
composed by the existing host/application layers. Their existence does not
establish REVOCATION or whole-GNUnet acceptance.
