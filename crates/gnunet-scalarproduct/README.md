# GNUnet scalarproduct default ECC core

`gnunet-scalarproduct` is a no_std core behind the explicit `alloc` feature. It implements Edwards25519 Alice blinding, Bob aggregation, unblinding and
incremental bounded discrete logarithms using the existing Dalek/crypto crates. It contains no FFI, socket, entropy fallback, task, persistence or native worker.

Use an explicit HashOrder matching the peer C ABI. The official hash comparator
compares native u32 words from the end; raw-byte ordering is different. Vector
admission rejects duplicate keys even if one value is zero, retains the all-zero
key, excludes zero coefficients from SETI, then seals the matched vector
on original SETI Done. Signed MIN is safe in Rust; fixed C call sites assert on
that value, so this does not claim C accepts MIN.

The Computation owner keeps one immutable original native effect. Admit before
native I/O and complete only the original whole-write or physical-close
receipt. No local write proves remote liveness, processing, or Alice's result. Bind the original local CADET channel before completing Connect as Written. Original Delivery, SETI operation, epoch/channel and cancellation ownership do
not migrate to a new source. Failed unfinished setup must physically retire its
locally-created native resources before its terminal Unsent/Lost receipt. On
failure/cancel the host stops old I/O, retires any admitted action and drains
cleanup; effect=None alone never means stopped. The host retains original
native causes and original hard/cancellation bounds independently.

Default outgoing chunk size is 128 pairs, within CADET capacity (1005
pairs). The fixed C Alice capacity macro divides by one point although the
producer sends two points; this core does not repeat that oversized-frame bug. All dynamic memory uses fallible reservation and charges Vec capacity;
source ownership/capacity accounting is not an RSS or measured performance
claim. The DLOG default is inclusive +/-1048576 with memory 1024. Construction,
heap ordering and searching advance in explicit finite work units. There is no
fake zero result or unbounded DLOG scan, and this is not a constant-time claim. Secrets/partial entropy and owned coefficient storage are explicitly wiped;
compiler registers/allocator process residue are not claimed to be audited.

Only original SETI DONE over the sealed empty matched vector establishes
successful empty-intersection completion. Alice returns the exact mathematical
zero as normal IPC649 status2/range0/product_length0; the official C client
initializes an MPI zero for that response. Bob returns status2 with no product,
preserving the responder role. No identity point, peer frame, DLOG result or
peer/write ACK is synthesized. Local ClientResult still requires its original
whole write, and all original SETI/channel/port cleanup debt remains due. Foreign/early DONE, source loss before DONE, cancellation and deadlines retain
their failure paths. A post-DONE physical source retirement may preserve the
already established zero through the existing local-work API and keeps its
independent cleanup cause.

The fixed C ECC services do not correctly complete their own empty-intersection
peer workflow: Alice sends no cryptodata for an empty set, while Bob's DONE
branch compares the local client count. This change interoperates with the
public C result consumer; it does not claim empty-profile interoperability with
those broken C peer services. Nonempty input-point validation and encryption remain unchanged. Canonical identity aggregate columns flow through ordinary unblinding and
bounded DLOG, including a genuine zero result from a nonempty intersection. The complete original SETI DONE, final receive/write receipts and cleanup are
still required. The fixed C peer's scalar-multiplication primitive rejects an
identity G aggregate; no successful C-peer result is claimed for that profile. An identity H column follows its separate addition path and is not covered by
that specific reference failure. Rust preserves the group arithmetic
and official point encoding. A normal nonempty result retains exact MPI STD
magnitude/range fields. Nonempty Bob success remains its local last
aggregate-send completion, not a fabricated Alice product. Native default-ECC SETI/CADET/IPC composition and ordinary Alice/Bob service
entrypoints are integrated with selected compiler checks. Paillier session and
native service profiles remain separate work. This core grants no whole SCALARPRODUCT or interoperability
completion credit.

A multi-message CADET outer packet remains owned by the host through every
inner message. Completion::Processed is legal only for ReceiveDone and records
local processing of a non-final inner message, never a wire ACK/write. The host
retains the original outer Delivery and byte offset; only after the final inner
message does SDK.receive_done run and its whole native write complete
the final action as Written. Cancellation physically closes that original input.

After SETI Done and complete owned final Bob payload, Alice's remaining
bounded DLOG is local work. `can_finish_locally` is only a core data-readiness
fact; it does not validate an outer CADET tail or close anything. After the host
validates that complete original tail, physically retires the original peer IO
and preserves each original write/input receipt, `retire_peer_for_local_work`
may keep that local work under the original hard/cancel bounds. It also covers
the same final input's pending ACK/result tail and Bob's last-written
aggregate. A pending final ReceiveDone accepts only its exact original actual
Written/Lost/Unsent receipt; Processed/Retired cannot fake a final ACK. A retired
input never causes a later old-source ACK. Source causes remain independent of
the mathematical result. Missing inputs, incomplete aggregates, unknown
last writes, failed SETI and cancellation keep their ordinary failure behavior. This is a pure API forward: native outer-tail/physical-retirement integration is
separate, and the new source cases remain unexecuted.

The final-input local-work forward and its new source cases also passed selected
macOS/GNU Linux compilation and thumbv6m allocated compilation.

The empty-intersection forward above changes only the real-DONE zero branch,
its existing role/cancel source case and documentation. It provides no new native, cryptographic, mixed-peer or performance credit.

The nonempty identity-column forward removes only the final Bob aggregate
refusal. It adds no new wire message, zero shortcut, algorithm fallback or
resource policy. Source cases use the same full two-party multipart computation
path for a lone identity G column, a lone identity H column and two identity
columns with an exact zero product. Source preparation/compilation and actual
crypto/native interoperability remain separately qualified.
