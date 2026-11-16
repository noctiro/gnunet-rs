# GNUnet CONVERSATION core

This pure Rust package implements the conditional official Conversation Line /
Channel protocol, independently of audio devices and native scheduling. Default
builds expose the borrowed wire/types only; `alloc` enables the bounded
Session state machine and caller-key signature operations. It does not start a
service, access keys, invoke a worker, or select an audio backend.

## Lines and authenticated calls

Each local IPC gets its own exclusive Instance/Session. Opaque IDs
retain and compare the nonzero-sized original Instance reference; equal
serials or unifiable Rust lifetimes cannot cross Line ownership. This uses no
unsafe pointer dereference, entropy or global counter and prints no address. A Line registers
an exact CADET port or makes one ordinary outgoing call. Incoming channels bind
the registered port/source and network peer. Per-Line CIDs are opaque
round-trip values; high bits grant no authority. Incoming CIDs are monotonic and
never reused; exhaustion is explicit. Outgoing CID0 follows the ordinary C role.

Outgoing734 imports the original typed Ego private key into the existing
zeroizing IDENTITY owner, signs RingInfo112/purpose20 with the PKEY or
EdDSA implementation, and retains only the public740 frame. Incoming740 checks
exact key36/signature68/type equality, Line port, original local peer
identity and a live finite expiration before Ring735. The network peer may be
different from the authenticated caller Ego. Fixed C obtains its own peer via
`GNUNET_CRYPTO_get_peer_identity`; a native Rust owner may use PILS, but
must retain/check its original epoch. No configured peer or peers[0] substitutes.

A healthy identity change on that same verified observer updates the Line in
place. Each incoming channel retains its original local RingInfo target, so a
late old invitation is checked against that channel's context. New
channels capture the newly observed peer. Registered port intent, branded calls,
frozen frames, admitted effects and original deadlines are retained.
`rebind_identity` requires the same observer epoch. Physical observer replacement
uses `replace_identity_source`: the host first pauses I/O on actual observer loss,
then verifies a later branded epoch of that same original client. This changes
neither a call's signature target nor its independently held CADET source, bytes
or deadlines. A new socket or numeric generation alone supplies no authority.

## Controls and media

Actual742 is required for outgoing PickedUp738. Local PickUp732 changes the
callee state and queues the real742; local queue admission does not imply a
whole write. Hangup741, suspend743, resume744 and opaque audio745/739 use the
original Channel and separate local/remote suspension flags. Invalid directions
and phases fail without partial admission; stale local CIDs are ignored. Suspended incoming audio is consumed without delivery. No media playback,
codec/device negotiation, remote delivery or human acceptance is claimed.

## Effects and retirement

All physical effects retain their original IDs, bytes, deadlines and source
owners. Written means a complete local operation. Lost preserves an
independent error/exposure classification. Per-call cancellation revokes new
submission. The host can remove a provably unwritten frame or drain an already
exposed prefix using `effect_drain_allowed`, on the original stream and within
both the original effect and call-close bounds. Whole-Line cancellation permits
no such drain. An unsafe peer drain requires actual source retirement before
settling its outcome. Original peer effects never replay; an exposed effect is
never relabeled Unsent. EOF remains source loss and a local HangUp notification;
it cannot become remote pickup or remote HangUp741. Final CallReport requires
Channel disappearance and all original debts, including notification.

`transport_lost` ends calls on a physically retired CADET source while retaining
the local Line and logical listening intent. It can preserve one admitted local
frame on its existing IPC. `restore_port` requires that original source's pending
OpenPort outcome to be settled and a trusted whole announcement on a replacement
source; it restores no old call. `source_lost` retains terminal Line shutdown
semantics when its listening source is permanently lost.

[Retirement](src/session/retirement.rs) preserves the first call failure and
queues one standard local HangUp for an announced call ended by setup, output
or source failure. Queue pressure parks that notice without failing unrelated
calls. Its output deadline is clamped to the original close bound, including
after channel disappearance; it never obtains a fresh retirement allowance.
A missed mandatory notice or a failed uncancelled client frame requires the
native owner to close the shared IPC. Canceling a provably unsubmitted
frame alone does not imply IPC failure. Expected cancellation of an unwritten
frame is not a call failure. Queued local Ring/control frames preserve FIFO, so
a CID is introduced before its failure HangUp. Local notices do not set the peer-HangUp
observation, and unverified incoming channels do not announce a CID.

The native owner maps one outer CADET delivery to its validated inner
frames. Completion::Processed is permitted only for ReceiveDone of a nonfinal
inner; the original outer remains physically held and no ACK is claimed. Only
receive_done transmit completion for the final inner is Written.

## Scheduling and resource bounds

Metadata is fallibly reserved once at the configured finite maxima; frames
allocate only when their capacities fit the remaining retained budget. Retirement slots are separately reserved. Defaults are32 calls,128 normal
effects,1MiB queued frame capacity,2MiB retained capacity, frame64348, one-day
ringing,10s original output intent and30s original close grace. These limits
cover core-owned retained capacities, not allocator overhead, caller/native
buffers, crypto stack/registers or total RSS. Native parents retain their own
original global hard deadline. Ongoing connected calls have no invented wire
expiration; the ringing signature expiration applies to call setup.

Call IDs use slot+nonreused serial lookup; exact Effect IDs use binary search. The bounded EffectScan freezes a serial fence per round and checks only the
requested candidate budget. Independent channel owners can progress around a
slow channel. Original local IPC output and each Channel's native operations
retain FIFO order. Input credit has its own per-Channel FIFO, independent of
outgoing audio credit, and CloseChannel depends on both; each ReceiveDone
additionally depends on its corresponding
ClientFrame terminal. End waits for state/I/O before resetting, avoiding
an idle scheduling loop. The old `effect()` accessor is a simple oldest-item
view, not a fair multi-channel scheduler.

Current-source C peer, device and recovery qualification is tracked in
[implementation status](../../IMPLEMENTATION_STATUS.md).
