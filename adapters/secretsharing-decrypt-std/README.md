# Native original-share decryption

`gnunet-secretsharing-decrypt-host` is an caller-driven781 implementation
using the native PILS client and shared threshold math. Threshold one uses
a verified local quorum without constructing a CONSENSUS client. Higher
thresholds keep the existing CONSENSUS client and cooperative workflow. General multi-peer Generate780, qualified DKG and general fair-encryption
production remain separate required capabilities; the ordinary service has a
separate singleton780 generator. The ordinary SERVICE binary composes this
owner through `gnunet-secretsharing-host` for existing-share781 decryption and
actual782 output. This package provides no media/storage/key-file access and
does not establish whole SS completion.

Sources coherently snapshot configured PILS/CONSENSUS endpoints on the same
Clock/Resolver, then freeze selected endpoints. Request adopts exactly one
zeroizing781 frame with its original start/deadline, ciphertext, share and
explicit native-index ABI. There is no Data/Source/secret Clone or pointer
layout compatibility layer. Original caller/native input copies remain their
own owners' separate erasure responsibility.

After PILS identity is observed, its peer must match share.my_peer. The original epoch/peer and current HELLO validity are checked before normal
work and again after every fallible provider boundary. All native/canonical
hard targets remain clamped to the original parent/request deadline, never
renewed by source retries, proof work or partial IO. A dropped observation
future preserves original cursors; explicit close permanently stops every
constructed source before cancelling/erasing secret mathematical work. No reconnect or
unknown contribution/signature replay is implicit.

The pipeline performs c1/public-key/sigma subgroup membership, original
peer/index uniqueness and threshold checks, then proves sigma=g^my_share. PartialProver draws bounded OS entropy, erasing partial output on a real
provider failure and retaining the original getrandom error independently from
the pure math refusal. UnsignedPartial is signed by the PILS
KeyTarget::Exact operation for purpose23. The returned operation, signer,
announcement epoch and signature are checked before that proof can contribute. Both local and
remote872/type0 values use the same sealed PartialVerifier; no flag or custom
verified-partial constructor substitutes for cryptographic verification.

For threshold one, the original share can contain one or several participants. All its original peers, indices, sigma values, public key and local secret are
still checked. The PILS identity must match the original local share,
and the local purpose23 signature and sealed PartialVerifier are both retained. The one genuine VerifiedPartial moves with that same checked Roster into the
existing CombineJob. In particular, public-key interpolation must still match:
a malformed threshold-one share with sigma_local != public_key cannot produce
plaintext. No Consensus constructor, JOIN, Insert, CONCLUDE or525 is used or
inferred. The local path prepares its proof early but waits until the original
absolute start before combination/result release, under the unchanged parent/
request hard deadline and original PILS epoch/identity lifetime. It uses the
existing guarded PILS connect/poll APIs with those same targets before actual
native IO, including after a fallible provider boundary.

For thresholds above one, as in fixed C, the original CONSENSUS session
identifier is SHA512 of exact
ciphertext256, and JOIN preserves original peer order/start/deadline. The
original Insert and Conclude are retained independently through whole writes. Normal CONSENSUS filters locally submitted values, so the verified local
partial remains locally owned and is not labelled a remote523 observation. It can contribute to the eventual original quorum only when its Insert
whole-write and the original real525 were observed. A local write is never a
remote acceptance or DKG qualification receipt.

Incoming invalid, duplicate, unrelated-peer, wrong-cipher or false-proof values
are rejected while a distinct verified quorum may still form. Resource,
entropy, time or source failures are not converted into negative proofs. At
most one original native523 and one proof verifier are held; no bulk incoming
proof queue is created. One finite math turn and the native sources are
fairly interleaved; the async convenience observation yields to its parent.

The cooperative path requires original525 after its whole Conclude. That path's required distinct valid partials, or threshold one's genuine local
partial, plus unchanged roster/index/sigma/cipher associations and successful
CombineJob produce Done(Plaintext). Combine adopts the same checked Roster
without clone/reconstruction/self-reference; the original allocation is counted
once. The original public-key interpolation check and same-cipher threshold
algorithm are shared with the pure math package. A real525 with too few valid
partials is a Roster error, not a fabricated plaintext. This intentionally does
not copy C's FIXME insufficient-peer success or original-index array bug.

Report retains original signing operation/completion/lost-source cause,
whole local contribution receipt, raw native retry errors, original ciphertext
and timing/threshold fields, actual525, rejection/verified counts, independent
entropy failure and original physical-close IDs/idle postcondition. If the
PILS API cannot expose a partial signing cursor, a missing result is explicitly
unknown; it is never guessed Unsent. Actual primary errors are returned while
independent source/cleanup facts remain available for take_report. Only explicit
close sets cancelled. Original source loss/EOF cannot count as525. `local_threshold_one` records only the selected path, not proof completion:
verified/completed are stage facts. On that path contribution stays None,
conclude_written/consensus_done stay false, and consensus_loss stays None because
no such source was constructed. Physical PILS close and idle still gate
the normal service's plaintext output.

Limits separately bound the request frame, participants and
math work/entropy, child native buffers and a conservative owner reservation. The checked participant vector reserves the original peer count. The
local path reserves only one VerifiedPartial, no Consensus peer vector, selected
PILS endpoint storage only and no unused Consensus child buffer ceiling. Its
owned connect guard/start waiter are separately charged. The cooperative path
keeps its original peer/partial reservation. Received proofs are processed
singly. The reservation counts fixed owner storage, selected endpoint storage, child configured ceilings, one held input
frame and original roster/partial capacities once as ownership moves. Child
ceilings can conservatively overlap shared Arc storage; this is not an exact
RSS measurement, allocator bound, constant-time theorem or performance claim.

Native SERVICE IPC dispatch/782 output and normal service registration are
production paths. Only Decrypt::Done after physical source retirement
can enter the same secure136-byte782 queue; partial and whole writes remain
separate facts. The separate singleton780 generator can produce real783;
general multi-peer780/qualified DKG remains unfinished.

The prior owner passed selected offline native/Linux and architecture checks. Actual C interoperability, source/fault/platform/resource acceptance
and general SS completion remain unverified.
