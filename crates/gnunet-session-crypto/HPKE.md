# Official HPKE contexts, pinned GNUnet v0.29.1

This workspace module builds on the independently implemented session primitives.
It supplies the actual
X25519/standard-SHA256/ChaCha20Poly1305 context chain and explicit private-key
codec operations. It does not replace a missing upstream mode with a private
construction. All 28 public functions implemented in `crypto_hpke.c` are listed
with exact compiler-derived header signatures and source anchors in
`hpke-inventory.json`; that inventory is separate from acceptance credit.

## Complete source boundaries

The fixed source is `src/lib/util/crypto_hpke.c` (1109 lines), with
`src/include/gnunet_crypto_lib.h:373..490,2279..2773,5078..5233`, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. The complete file, public declarations,
normal-C build configuration and selected libraries are hashed by the verifier.
Internal functions are labeled_extract, labeled_expand, the static
GNUNET_CRYPTO_hpke_labeled_extract_and_expand, kem_encaps_norand,
verify_psk_inputs, key_schedule, increment_seq and compute_nonce.

The header declares Base0, PSK1, Auth2 and AuthPSK3. Both setup2 implementations
only handle Base and PSK; the other modes return SYSERR before key scheduling.
Their sender-authentication key arguments are not read in these supported modes.
Rust represents all four declarations, accepts Base/PSK and returns Unsupported
for Auth/AuthPSK. These are matching rejection semantics, not complete RFC auth
support. There is no public upstream Export function: key_schedule derives a
32-byte `exporter_secret` field and no other source consumer uses it. The Rust
context allows an immutable borrow of that opaque Prk, which already provides
standard HKDF expansion. It does not add an absent RFC Export label/operation.

The source has KEM0020 and Elligator0022. Ordinary X25519 setup accepts only0020;
distinct typed Elligator setup accepts only0022. It reuses the existing special
scalar/representative KEM, not an ordinary-public-key cast. Upstream key_schedule
hardcodes the context suite `HPKE || 0020 || 0001 || 0003`, even on its Elligator
branch. The new context operations preserve that GNUnet behavior while the KEM
itself retains `KEM || 0022` and exact representative32 || recipient-public32.
This is not a new RFC suite or a change to TCP/UDP wire/one-shot defaults. There
is no HPKE GCM/KDF suite selector in this pinned public context API; its AEAD is
always IETF ChaCha20Poly1305, key32, nonce12 and tag16. Other suites remain out of
this API; the separate UDP-GCM primitive does not extend this HPKE suite selector.

An unknown KEM in the C Base/PSK branch can reach key_schedule with an
uninitialized shared secret. No invalid-KEM normal-C experiment is performed.
Rust's typed selector rejects unknown values; it never forges successful state.

## Key schedule and owned state

The selected existing KEM supplies an opaque shared_secret32: raw X25519 uses
`KEM0020` and enc32||pkR32; Elligator uses `KEM0022` and the original representative,
including its two mapping-ignored high bits, followed by pkR32. The same schedule
performs:

* `psk_id_hash = LabeledExtract(empty, psk_id_hash, psk_id)`;
* `info_hash = LabeledExtract(empty, info_hash, info)`;
* context = one mode byte || hash32 || hash32;
* secret = LabeledExtract(shared_secret as salt, secret, psk);
* key32, base_nonce12 and exporter32 = LabeledExpand(secret, key/base_nonce/exp,
  context, the respective length).

All labels include `HPKE-v1` and the fixed10-byte suite and use BE16 output
lengths. No extra NUL, framing, private domain, hash substitution or implicit
RNG is inserted. PSK and identifier must either both be empty or both nonempty;
Base requires empty inputs and PSK mode requires both nonempty. No artificial
minimum PSK length is imposed. Binary info/PSK/ID bytes, including embedded NUL,
are retained exactly.

Parameters borrow the caller's inputs and expose no Debug implementation.
Context contains no borrowed caller secret: key and exporter become owned,
erased values. Hash/context and temporary secrets are erased owners. Context,
all previous secret owners and the scalar provide neither Clone nor Debug.
The stored nonce and sequence are public state, not secret key buffers. No
allocation, OS RNG, C FFI, clock or network is added to production code.

The public C context fields allow arbitrary key dumps and rollback. Rust uses
an opaque owner with role/sequence/sequence_be/nonce getters and borrowed
exporter. It has no cloning, rollback or state-import operation. This is an
explicit safe API decomposition, not C ABI or arbitrary public-struct mutation
equivalence. Existing caller-owned key bytes remain caller-owned; the explicit
private codec outputs secret material whose owner must erase it. No claim is
made about all compiler register/spill copies or unobservable post-drop bytes.

## Operation and failure semantics

C seal checks Sender role and open checks Receiver role before writing output.
The unified Rust Context follows these checks. Setup results are returned only
after every derivation succeeds; failed partial C output state is never imported.
The random Base sender setup draws exactly32 bytes through an explicit Entropy
argument, distinct from the64-byte IKM used by the existing private-key creation
API. Fallible entropy refusal leaves caller output unchanged and no context.

C stores ctx.seq as network-order u64 memory bytes. Rust stores a host integer,
returns its BE64 representation explicitly and XORs those bytes into the last8
bytes of base_nonce12. Successful operations advance one; failed authentication
retains the same sequence and can be retried correctly. C increments after the
cipher call. Sequence MAX-1 succeeds and advances to MAX; at MAX a cryptographic
operation can write data and subsequently report SYSERR. Rust never returns
those failed bytes as valid output: exhausted seal erases its target range and
refuses; open authenticates first, then erases plaintext and refuses if its
successful-authentication sequence cannot advance. A bad tag at MAX remains an
authentication refusal. The C and Rust boolean result and sequence are compared;
C failed-output contents are intentionally not compared as valid ciphertext or
plaintext. Normal-C limit-open tests generate a valid sequenceMAX input with
libsodium and the public C context fields, rather than consume a failed seal's
output as a valid message.

The production owner exposes no sequence setter. Finite exhaustion tests set
Rust private state inside its cfg(test) module, while the normal C caller sets
the already public C field to matching BE values. This is a declared test-state
initialization seam, not an extra public protocol or a claim of performing 2^64
messages. NBO carries255/256 and2^32, MAX-1/MAX are checked as operations.

Seal/open offer separate-buffer and in-place operations. Ciphertext is
payload||tag16, with untouched unused caller capacity. Capacity, role and basic
framing refusals are atomic; authentication failure erases only the plaintext
range. No hidden capacity truncation occurs. Existing AEAD preflight proves
payload counter and length bounds without allocating huge buffers.

The C one-shot seal writes enc32 before ciphertext, but returns only the
ciphertext length in ct_len_p. The Rust OneshotLengths contains both
`total_written` and `c_reported_ciphertext_len`; the normal C observations check
this explicitly for empty and nonempty payloads. One-shot open requires the
complete enc32+tag16 minimum. C's shorter-than-enc unsigned-underflow path is not
executed; Rust refuses it safely before parsing or decrypting. Zero-capacity
and resource refusals are Rust storage contracts, not invented C wire messages.

The Elligator context entry points are `sender_setup2_elligator`,
`receiver_setup2_elligator` and `sender_setup2_elligator_random`. The deterministic
sender takes an `elligator::Secret` and explicit tweak; the random sender uses the
existing explicit entropy and nonzero attempt budget. Base and PSK are supported;
Auth variants and wrong typed selectors fail before KEM/entropy. Mode/PSK rules,
labeled input lengths and fixed expansion-context lengths are preflighted before
KEM work. Real representability/DH failures still return their KEM error.
No raw-PRK context import, state cloning or implicit random source is added.

## Checks

This Elligator context extension was source-reviewed and formatted only. Its two
context/refusal regression sources are prepared for compilation, not executed.
The prior0020 verifier receipts below do not qualify0022 contexts or normal-C
interoperability for these new operations. The new source comparison uses HEAD
`14698f19848af867f48a04521e274abd55972075`, `crypto_hpke.c:449..580,615..653`;
its fixed schedule suite remains explicit above.

The portable verifier is `tools/hpke_verify.py`; it copies the production sources
into a fresh output, renders Cargo.toml.in for the explicit repository, and
keeps all target files and generated fixtures outside the workspace. It checks
exact dependency/feature equality with the workspace manifest and rejects changed
or new registry identities relative to the integrated package. HPKE itself adds
no registry dependency; the separate GCM module's dependencies are documented in
DEPENDENCIES.md. The normal
dependency graph excludes std/alloc features and the production library
compiles for thumbv6m. Existing14 secret trait refusals plus one positive control
are re-executed; Context Clone/Debug, exporter lifetime and consumed-key reuse
get four extra exact-code compile failures and a positive borrow control.

The source-bound verifier executes 24 unit tests (10 baseline,8 contexts and6 GCM),
7 independent primitive public-API tests and2 existing scalar docs. The two
normal-library HPKE/primitive oracles, together with the separate GCM oracle,
remain ignored in default tests and receive no default
passing credit. Each new helper-O0/O2 normal-C run independently compared171
rows, and each accepted90 Rust ciphertexts using the unchanged
public HPKE open APIs. Both helper profiles link the same normal library;
they do not constitute separately optimized C library builds. Actual C random
sender/one-shot rows may differ between runs. They are checked by Rust
receiver setup/decryption rather than expecting deterministic encapsulations.

Six negative controls mutate captured C key, nonce, exporter, sequence or
ciphertext fields, or remove a row. Every one must execute and fail the named
Rust comparator test; compiler failures and zero selected tests do not count.
Original source, normal libraries, production sources, tools, manifests and
locks are hashed before/after. This proof is not a CORE/TRANSPORT handshake,
network daemon or full-GNUnet conformance claim. Function and lifecycle coverage
must be reviewed separately;171 is an observed row count, not a requirement
count. All inventory verification fields remain null until full owner acceptance.
Normal setup2 observations pass valid non-NULL authentication keys in all modes,
including the source-defined Auth refusals and Base/PSK ignored-key behavior.
