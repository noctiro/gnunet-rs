# GNUnet Paillier scalarproduct

This is the distinct installed Paillier peer profile in GNUnet v0.29.1, not
the default ECC protocol. The default feature set exposes the fixed-capacity
checked arithmetic only. `alloc` adds bounded original Alice/Bob sessions,
matched private vectors and official peer-frame ownership. No OS, FFI, task,
socket, global RNG or implicit key generation is used.

Alice's `can_drain_peer_input` exposes only the reply-continuation phase where
an earlier copied ciphertext chunk can still be in cooperative decryption. The native owner may retain the next already received original Bob
multipart frame across a subsequent channel close, with its source and
original bounds. This phase owes no Alice output. It does not mean the full
reply was copied: every retained tail still passes the ordinary profile,
count, ciphertext and arithmetic checks, followed by the existing
can_finish_locally/product and IPC-write gates. No new peer receive,
ACK, key or session may be created after that physical retirement. Bob's
handoff condition and normal failure/cancellation remain unchanged.

The arithmetic uses the actual `gnunet-paillier` jobs. With `S=2^682`, Alice
encrypts `S+a`. Bob chooses independent uniform Fisher-Yates permutations `p/q`
and fresh signed32 masks `r`, then sends the standard two square sums and the
interleaved original ciphertext columns:

- `s=E(sum((r+b)^2))`, `s'=E(sum(r^2))`;
- `Kp=E(2S+a[p]-r[p]-b[p])`, `Kq=E(2S+a[q]-r[q])`.

Alice actually decrypts these fields and computes
`(D(s)-D(s')+sum((D(Kq)-2S)^2)-sum((D(Kp)-2S)^2))/2`. The two `sum(a^2)` terms cancel exactly. Division must be exact; missing fields,
invalid residues, out-of-profile magnitudes and overflow fail the original
operation. A full signed256-bit result is encoded as the standard separate
sign and positive `GCRYMPI_FMT_STD` magnitude, including a necessary leading
zero octet. The ECC bounded-i32 result is not used.

The selected arithmetic profile retains the C producer's signed-i64 coefficients
and signed32 masks. It supports every MIN endpoint without signed overflow or
the C `-INT32_MIN` undefined expression. It does not claim stronger input privacy
than that mask profile, a zero-knowledge proof of Bob's inputs, or a platform
side-channel assessment. At most2^20 rows bounds all sums below2^151 and the
product magnitude by `rows*2^126`, below the checked256-bit arithmetic capacity.

`MatchedVector` adopts the original allocations, rejects duplicate keys,
filters zero coefficients, and sorts the sixteen native-u32 words in the
explicit `HashOrder::{Little,Big}` profile. Only the keys enter SETI. Actual
DEL_LOCAL callbacks remove entries; original DONE and the remaining
key count seal the snapshot. The native caller must derive that count from its
original remaining keys, not trust the C DONE `current_size` field, which the
reference producer does not assign. Original values are never reloaded from mutable native state.

Alice owns an `Rc<KeyPair>` for the original key snapshot. Bob pins the
original modulus from the Session frame. Neither key rotation nor
reconnect rebinds existing work. Callbacks carry a stable `Binding` with an
instance and non-reused generation; the same wire session hash never revives
an old channel or SETI callback. The authenticated peer/channel/epoch
and SETI handle must be mapped to that binding by the native owner.

Bob requires both original SETI DONE and the exact received Alice
ciphertext count. These are separate facts; local client input count is never
substituted. Entropy is explicit and each advance is bounded; the original
deadline covers channel setup, SETI, all arithmetic and outgoing frames without
renewal. Public modulus validation and fixed-width gcd/division/inversion are
finite indivisible calls; neither OS calls nor those boundaries are claimed
preemptible. Initial bounded sorting and final snapshot compaction are finite
admission/callback operations.

Every official output is immutable and original. `admit_output` moves a counted
allocation into a non-cloneable `Frame`; `complete_output` consumes that exact
frame and its original Written/Unsent/Lost classification. Written means the
whole original frame reached its original local MQ, never a peer ACK. Bob's
final `reply_handed_off` records that exact local C-visible completion, not
Alice's computed result. Alice's computed product is independent of its later
native client output. Cancellation erases jobs, coefficients, masks, scratch and
unadmitted output while retaining admitted frame debts. Quiescence never
ignores those debts. A later source loss remains separate from an already known
computed product/local handoff; original native errors must also be retained by
the native owner, beyond this core's pure error classification.

The frame ceiling is the CADET64348 bytes. At that ceiling Alice uses124
ciphertexts/frame, Bob's first reply61 pairs plus the two sums, and subsequent
replies62 pairs. A smaller configured frame remains explicit. Buffers reserve
input extents and per-frame extents, not `max_rows*max_frame`. Every Vec capacity, fixed session state, original key snapshot, admitted frame
and caller-reported additional native buffer is counted against the per-session
retained-byte budget. Extra native copies must be charged before admission. Allocator bookkeeping and process-wide shared resources are not an RSS claim;
the eventual native service must additionally enforce its total session budget. Independent maximum rows/bytes/work/deadline settings need not all be reachable
simultaneously. There is no silent eviction, private wire or algorithm fallback.

The fixed reference source has observable inconsistencies that this code does
not reproduce: multipart Alice copies the first column into both columns; Bob's
SETI-DONE branch tests local client count where the following comment describes
received CADET count. The Rust decoder and
session preserve the two columns and both original completion facts.

Native SETI/CADET service integration, explicit normal
Paillier profile selection, whole daemon resource accounting, source
retirement/client responses, the confirmed complete-response/local-computation
retirement window, and two-direction C/runtime acceptance remain. An arithmetic product or source-present module alone does not finish this
profile or the complete GNUnet implementation.

The fresh local-retirement API is a source increment beyond the compilation
baseline above and awaits its own selected static integration. `intersection_key`
borrows initial SETI population keys by index in O(1). `can_finish_locally` is
true only for already-owned complete original reply data after SETI DONE,
or an known final computation/handoff. It does not prove a source close
or a valid product. After validating the entire original outer packet and
physically retiring every old source/receipt, the native owner may call
`retire_peer_for_local_work` once. Alice keeps actually decrypting/checking the
owned data under the unchanged original deadline; Bob keeps only his local
handoff fact. Source cause is retained independently. No old IO/ACK or new key,
clock target, source epoch, protocol DONE or result is generated by retirement. Normal native integration and
its full outer-tail/receipt/physical-retirement conditions still require the
separate host increment and acceptance.
