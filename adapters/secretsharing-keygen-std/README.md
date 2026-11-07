# SecretSharing generation stages

This adapter owns the official780 intent and its two-round native generation
flow: commitment production, own/remote reveal validation and final aggregation. Generally usable FAIR remains obstructed by the original fixed response width. It adds no
private message, complaint round, reduced roster or replacement proof profile.

`Sources::new` snapshots PILS/CONSENSUS endpoints with their common clock. `Request::from_frame` preserves the original request. Normalization adds the
local identity when absent, sorts the original roster, rejects duplicate
identities, and validates the threshold and complete original-roster reveal
extent before key search. Local polynomial indices remain unchanged thereafter.

`Round1` uses bounded existing Paillier and polynomial jobs, owns each exclusive
stage in one data-bearing enum, and obtains the purpose21 signature from
PILS. The returned signature is verified before standard CONSENSUS INSERT. Original signing and INSERT identities remain outside the transient math state,
so delayed write observations retain their original association. A whole write
is recorded as a write, never an acknowledgement or successful DKG.

Incoming commitments must pass shape, roster, signature and public-modulus
checks before occupying a row. The first complete valid row is retained;
subsequent messages cannot revoke it. Invalid-first input does not poison the
row. There is no separate signed-digest or permanent-exclusion allocation. Remote523 claiming the local identity cannot establish the own row: only the
local signing/INSERT path does that. Official purpose21/22 regions do not
contain SID, so authentication alone cannot prove same-session equivocation. The reference C Round1 overwrites its row; Rust retains one complete owner rather
than depending on the order of conflicting statements. Neither establishes an
order-independent Byzantine agreement rule absent from the original protocol.

Round1 completion requires real525, the original whole INSERT and CONCLUDE,
sufficient checked commitments and the original local row. Its first CONSENSUS
source retires, then `CompletedRound1` moves the unique `Transcript` and sealed
`SigningSession` together. The same PILS client, identity, branded
operation and completion remain live across this handoff. Failure/cancel/drop
retire whichever original sources remain owned. Polynomial and Paillier private
owners have no Clone/Debug and are erased on drop. A Round1 transcript alone is
not a final share.

`round2::Round2` consumes that handoff and opens the second original CONSENSUS
source immediately, using the unchanged SID/midpoint/deadline. Its own producer,
remote validator and source work alternate; PILS observations precede normal
work. Both contribution origins use the same validation kernel and temporary
borrowed context. Every original recipient's polynomial value is checked, even
when its Round1 key is missing; missing keys prevent final selection. Available
keys drive exact FAIR equations and local decryption/recovery/scalar matching.

Own reveal signing uses the original still-current identity. Matched actual
SIGN whole-write and signature completion must refer to its branded operation;
foreign completions do not turn the original missing result into a known one. The exact signed bytes undergo the same validator before standard INSERT. Only that matched whole INSERT receipt admits the own contribution and
allows CONCLUDE. Remote523 claiming the local peer cannot substitute for it. `ContributionEvidence` preserves either remote523 or own signing and
insertion facts; local callbacks and processing acknowledgements are not invented.

A held remote validation job does not suppress original TX: the CONSENSUS client
can advance guarded transmission without reading a second element or allocating
an extra observation queue. A valid early523 requires the original whole JOIN;
only525 additionally requires the original whole CONCLUDE. Actual source loss,
partial-write and provider faults retain their original causes.

Only actual525, original whole JOIN/CONCLUDE and physical source closure can
construct `LocalTranscript` and its private `ClosedSource` facts. The persistent
PILS session is physically retired before that transfer as well. `finalize::Finalization`
consumes that owner, releases unused Round1 secrets, selects complete rows in
original-index order, and moves each scalar/coefficient allocation into the
existing bounded `AggregateJob`. Actual source observations accompany the result. No public boolean or arbitrary caller-selected list can construct this closed
receiver result.

`Finalized` preserves the original roster, threshold, local index and per-dealer
disposition. It can encode the standard783 response directly through the common
wire writer without temporary column vectors or another private-share buffer. A ready count below the threshold, an absent local row and an empty ready set
are end-of-round results. The local nonmember sentinel is the ready count;
selected original indices are not renumbered. A usable decryption `Roster`
still requires its separate strict admission. Equation checks are not promoted
into a general FAIR knowledge/range certificate.

`own::OwnRevealBuilder` consumes the unique Round1 transcript and constructs
every original reveal slot through the existing owned Horner evaluation and
checked FAIR attempt. Original keys, indices, degree and whole bounds are
retained. The constructor preflights the complete carrier extent and actual
simultaneous capacities before allocating one public reveal buffer; it draws
no entropy and creates no source. Missing recipient keys or an unrepresentable
response are refusals, not zero-filled proofs or smaller rosters. `PreparedReveal` exposes the exact purpose22 signing region. Signature attachment
verifies the original peer and bytes before transferring `SignedOwnReveal`. This is a mathematical/signature-checked payload; it grants no PILS SIGN,
whole INSERT, remote523 or source-completion credit. The complete native owner
still needs persistent PILS/session composition and standard submission.

`Generation` composes these owners and finalization under one original whole
bound and reservation. `Generation::from_pils` adopts an already observed idle
client without reopening it. Its constructor does no native IO or SIGN and
closes its owned client on refusal. The normal service uses this entry after
identity routing; its existing singleton path remains available. Normal
multi-participant requests run this flow and preserve failures,
including an unrepresentable FAIR response. They are not blanket-refused by an
unsupported-profile placeholder. This source path does not establish generally
usable FAIR or unchanged-C full generation interoperability.

All stages preserve the original absolute deadline and native hard bound. Exclusive math states move secret owners without cloning; source retirement is
independent of those transitions. Capacity accounting follows Vec spare
capacity and retained observation frames across handoff. It is an explicit
reservation, not measured RSS or a performance claim. Original failed-write
reports remain charged for pending-table/payload capacity until those
facts are transferred or dropped.
