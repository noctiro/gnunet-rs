# gnunet-conversation-client-host

Caller-driven original Conversation IPC, using the existing CLIENT and Framed
owners and the official borrowed codec. It has no service-core dependency,
implicit GNS lookup, device, key discovery, Resolver task or worker. Constructors
require an entered Tokio IO/time runtime and the caller's explicit endpoint and
original `Bounds`. A constructor opens no connection itself.

`Line::register` freezes one731 at the selected port. `Line::call` freezes one734
with the selected network target, port and borrowed original IDENTITY ego key. The key is different from a network peer identity. That one private frame is
zeroizing, has no Debug and is never replayed after attachment. All selected
endpoint snapshots are fixed; pre-attachment native retries retain the same
original bounds and initializer. Source loss physically retires that Line and
returns its original Loss.

`poll_progress` / `drive` return attachment, retry, original partial/whole
write receipts and735/738/733/736/737/739 notifications. Whole Register/Call
write proves only a local write; no registration ACK, remote readiness, ring
receipt, pickup or media-delivery receipt is invented. Ring public keys are
supported typed PKEY/EDKEY values reported by the selected service. The SDK has
no signed RingInfo context and makes no independent ringing-signature claim.

A registered phone may explicitly consume that retired Line with `reregister`
after observing its Loss and stopping old media/returning every Audio lease. Only EOF/IO or the stream retirement forced by a real733 racing a partial
old control permits this; explicit close, whole/input/control expiry and
protocol/clock refusal do not. Once an original731 has written whole, this
established fact survives new registration-only attempts: an expired finite
replacement init/write phase may be retired and replaced within the same whole
lifetime, without calls/input/control being replayed. The replacement has a new
Domain/Epoch and contains only731 for the same fixed endpoint/port. Old calls, controls and audio are never replayed. Until731
has really written whole, its initial/write targets remain unchanged across
attempts; afterward each finite registration phase stays capped by the original
whole lifetime. Old capacities are released before replacement allocation. The caller retains the old loss facts and supplies fair retry waits and current
identity/source policy; the SDK creates no recovery task or readiness ACK.

`Call` and `Operation` retain an per-Line Arc identity. Call state is
bound to the original attachment and incoming/outgoing role, independently of
CID bits. Observed raw CID bytes are echoed exactly, including the fixed C raw
copy convention. A registered Line can retain multiple calls within `calls`. Ended, write-debt-free calls can be `release`d; their CIDs stay in bounded history
and are never reassigned to a new token on that MQ. No outgoing CID is guessed:
before the first actual738 or733, cancel the outgoing Line with `close()`.

`pick_up`, `hang_up`, `suspend`, `resume` and `audio` return original operations. They enqueue immutable frames in Line FIFO order, with targets fixed at
admission. Local pickup whole-write permits local media and is recorded separately
from remote pickup. Local/remote suspension flags are independent. Backpressure returns an resource refusal without truncating, replacing
or replaying caller audio. HangUp is a protocol action behind earlier admitted
writes; `close()` is immediate physical cancellation of the original MQ.

Reads and writes receive alternating bounded poll opportunities after the
initializer truly wrote. A blocked write does not hide incoming HangUp. Actual
733 suppresses only provably unwritten pending work for that call, yielding
original `Unsent` receipts. If an affected original frame is already partial,
the shared MQ is physically stopped before exposing the notification; its real
unknown exposure and the separate call fact survive in the pending original
`Loss`. A subsequent `close()` returns that same loss before any Cancelled cause.

Owned `Audio` has borrowed byte/capacity access, no Clone/intoVec and only Send
constituents. It can be transferred to a caller-selected device thread without
copying its payload. Each observation retains a per-Line Arc quota lease until
Drop; Vec capacity and count remain charged. Payload storage is erased
before lease return. Quota exhaustion pauses input through backpressure,
while the write class and original whole deadline remain live. Drop takes the
original waker under the small quota lock and wakes after unlocking; RawWaker
clone/drop also occur outside the lock. No lock crosses await, native syscall,
provider or device work. Caller-created copies are outside SDK memory accounting.

`Bounds` is one finite original whole-Line canonical/native lifetime. Initial
attachment-through731/734, every write and each first-byte-through-complete-frame
target are additionally finite and capped by it. Activity and canceled observer
futures renew none of them. The partial-input alarm ends at complete
framing, rather than after a slow audio consumer. The caller explicitly drives
its shared Resolver and signal/output guards and physically closes on them.

Every failure physically retires the original source before `Lost`. Loss keeps
the initializer, all pending original partial/whole facts, call snapshots,
original targets and outstanding audio quota. Loss-time collection uses tables
reserved before IO, with no new fallible allocation or clock sample. A quota
snapshot of None means unknown debt after lock refusal, never zero. If an
admission-time clock refusal stops the source, the admission reports Closed and
the exact retained cause is available via `retirement`, `poll_progress` or
`close`. Drop is a physical safety net; explicit close is needed to receive its
original report. No EOF is turned into a notification or successful hangup.

Defaults:32 retained calls,65536 CID history entries,64 pending originals,
65535B local frames,64344B audio,1MiB pending frame capacities,8 outstanding
audio observations/524280B,4MiB SDK retained budget and65535B syscall quantum. Initial/write/partial timeouts are30s/10s/15s, capped by caller Bounds. Limits
are validated before attachment; metadata is finite, payloads grow on demand. Incoming audio readiness conservatively reserves room for one complete maximum
frame within its quota; custom byte limits need not permit all count maxima at
once. Exhaustion is explicit, with no historical CID or live call eviction. Accounting includes table, pending-frame, framing, bound storage and
outstanding Audio capacities. Shared CLIENT port/clock internals, allocator/OS
overhead and arbitrary caller copies are separate; no RSS claim is made.

This source candidate was formatted and source-reviewed only. Normal tools and devices
must explicitly compose these owners with their own selected identity/GNS/media
sources and independent cleanup.
