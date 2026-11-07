# gnunet-messenger

A normal PROGRAM entry for the existing Rust Messenger API and official native
Messenger service. It selects the common PROGRAM options, Logger and one shared
clock/Resolver context; it does not start a private daemon or generate an ego.

## Caller interface

- `-e/--ego IDENTITY`: look up an existing IDENTITY ego. As in the pinned CLI,
  an absent named ego selects the fixed anonymous identity with a warning.
- `-r/--room ROOMKEY`: hash the supplied room-name bytes using the official
  room-key construction; otherwise use OS entropy for the public room ID.
- `-d/--door PEERIDENTITY`: enter through that decoded peer; otherwise open.
- `-S/--secret SECRET`: exact Base32GNS 64-byte local record secret. With no
  option, the official handle default is 64 zero bytes. This is a local encrypted
  record input, never a substitute for message MACs, signatures or membership.
- `-p/--private`: each stdin chunk has an immutable snapshot of active
  room members and is sent through the private-message API for each one.
- `-s/--silence`: omit received content. `-R/--request` follows signed original
  predecessor hashes through GET requests and authorized cached history.
- `-t/--talk`: binary TALK on the all-zero discourse, with an one-second
  KEEP_ALIVE subscription; output contains other received TALK bytes only.
  `-R` has no effect in TALK mode, matching the pinned branch.
- `-P/--public`: set the official room public bit and disable automatic epochs.

Ordinary text input follows the pinned maximum 57344-byte read, strips a final
LF and applies first-NUL string semantics. TALK retains every read byte. All
active body kinds have user-visible descriptions; file URI, ticket, invitation,
tag and public identifier fields are rendered without logging keys/ciphertexts. Rendering is not a byte-for-byte copy of the C terminal layout.

The pinned C anonymous branch accidentally ignores `-S`; this implementation
honors an explicitly selected secret for both anonymous and named identities.

## Original operations and shutdown

The API mints an owner-bound immutable `Deadline` before each original caller
intent. Native hard and logical expiry are reused while awaiting capacity,
recipient keys or an epoch; admitted operations are never reissued to fabricate
success. Local admission, local whole-write and core completion/echo have
separate accounting. None is a remote delivery acknowledgement.

SIGINT, SIGTERM, stdin EOF, parent control, selected-Logger failure, Resolver
failure and source loss retain the original API owner. A fixed cleanup budget
quiesces new automatic room initialization/epoch/renewal work, while existing
work remains live. Normal exit attempts LEAVE, CLOSE and DESTROY;
DESTROY is accepted only from its whole-write report. Expiry or failure
physically closes that same source and retains original unsubmitted/partial
jobs and independent native/record/domain/Resolver/Logger errors. Eligible
temporary connection loss restores logical OPEN/door intent through new actual
sources and JOIN. Old SEND/STORE operations retain their failure/exposure
and are not resubmitted. Current name/subscription controls are newly signed
after the new JOIN; record watches bind that current source.

The same unique stdin owner remains observable during recovery after a real
first JOIN. Actual EOF/error is processed before a loss can start recovery, and
Stop/EOF closes an unjoined recovery owner without claiming DESTROY was written. Input received while disconnected is explicitly reported unsent and erased,
with one warning per outage and no offline queue or old recipient binding. Before the first JOIN, original input backpressure remains. Pending
caller deadlines do not renew; established membership follows the existing chat
task until Stop. Diagnostics have fixed detail capacities and omitted counts. Selected strict macOS/Linux API and command checks pass for this successor;
runtime remains unverified.

The shared PROGRAM foreground helper retains the same product future if its
scheduler fails, signals the same stop latch, and lets that future perform
cleanup. Instance-branded native tickets are consumed within their original
lexical scope; final static reports retain diagnostic metadata and owned
errors, not forged quiescence receipts.

## Bounded resources and explicit profiles

`[messenger-rust]` accepts:

| Key | Default | Allowed |
| --- | --- | --- |
| PROFILE | native 255-byte original profile | `little-255`, `big-255`, or absent/native |
| OPERATION_SECONDS | 30 | 1..3600 |
| CLEANUP_SECONDS | 5 | 1..60 |
| RECORD_WINDOW_SECONDS | 86400 | 30..604800 |
| MESSAGES | 2048 | 16..65536 |
| STATE_BYTES | 67108864 | 1048576..268435456 |

The profile is an explicit homogeneous original-producer contract, including
body and ABI order, not negotiated authentication. A missing original layout
fails explicitly. The record monitor is one finite observation window, with no
silent renewal, source retagging or replay after expiry.

One 57344-byte zeroizing stdin slab is shared across private recipients. Native,
core, history, displayed-message, requested-message and pending-operation tables
all have finite bounds. `STATE_BYTES` is an aggregate ceiling, not an eager
allocation. The CLI owns stdin exclusively: zero-timeout readiness polling with
a 25ms bounded cadence precedes each bounded synchronous read. No detached
reader/task or inherited descriptor flag mutation survives exit. Stdin/stdout
regular-file and terminal syscalls can block in the OS and are not claimed to be
hard-deadline preemptible.

This package is a source implementation, not an interoperability or execution
receipt.
