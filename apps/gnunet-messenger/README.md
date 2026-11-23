# gnunet-messenger

A native PROGRAM entry for the Rust Messenger API and official Messenger IPC
on Linux, macOS, FreeBSD and Windows. It selects the common PROGRAM options,
Logger and one shared clock/Resolver context. The configured services must
already be running; the command does not generate an ego.

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

For example, with endpoints configured in `gnunet.conf` and an existing ego:

```sh
gnunet-messenger -c gnunet.conf --ego alice --room team
```

Omit `--ego` for the fixed anonymous identity. `--public` selects the official
public-room bit; `--talk` selects binary stdin/stdout rather than text rendering.

## Original operations and shutdown

An immutable startup deadline covers Resolver construction, optional IDENTITY
lookup and the first JOIN. Native startup, parent control and stop subscriptions
use the shared PROGRAM layer on every supported platform.

The API mints an owner-bound immutable `Deadline` before each original caller
intent. Native hard and logical expiry are reused while awaiting capacity,
recipient keys or an epoch; admitted operations are never reissued to fabricate
success. Local admission, local whole-write and core completion/echo have
separate accounting. None is a remote delivery acknowledgement.

Native stop signals, stdin EOF, parent control, selected-Logger failure, Resolver
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
task until Stop. Diagnostics have fixed detail capacities and omitted counts.

The shared PROGRAM foreground helper retains the same product future if its
scheduler fails, signals the same stop latch, and lets that future perform
cleanup. Instance-branded native tickets are consumed within their original
lexical scope; final static reports retain diagnostic metadata and owned
errors, not forged quiescence receipts.

## Bounded resources and explicit profiles

`[messenger] MESSENGER_GROUP_KEYS` defaults to `YES` and controls automatic
GROUP proposals in private rooms. Set it to `NO` to disable initiation.

`[messenger-rust]` accepts:

| Key | Default | Allowed |
| --- | --- | --- |
| PROFILE | native 255-byte original profile | `little-255`, `big-255`, or absent/native |
| OPERATION_SECONDS | 30 | 1..3600 |
| CLEANUP_SECONDS | 5 | 1..60 |
| RECORD_WINDOW_SECONDS | 86400 | 30..604800 |
| MESSAGES | 2048 | 16..65536 |
| STATE_BYTES | 67108864 | 1048576..268435456 |
| OUTPUT_BYTES | 1048576 | 65536..16777216 |

The profile is an explicit homogeneous original-producer contract, including
body and ABI order, not negotiated authentication. A missing original layout
fails explicitly. The record monitor is one finite observation window, with no
silent renewal, source retagging or replay after expiry.

One 57344-byte zeroizing stdin slab is shared across private recipients. Native,
core, history, displayed-message, requested-message and pending-operation tables
all have finite bounds. `STATE_BYTES` limits client state. `OUTPUT_BYTES` limits
queued payload bytes and each staged row; at most `MESSAGES` rows are queued.
Capacity exhaustion fails explicitly without truncation. Buffers grow on demand
and erase consumed content. Native I/O uses the shared [binary ports](../../adapters/program-std/BINARY_IO.md):
one original reader and writer, each with one pending native request. Stdin
readiness is observed before admission where the platform supports it; shared
descriptor flags are preserved. TALK bytes bypass text conversion.

Display counts advance only after actual native write counts cross the frozen
row boundary. Output admission is separate from write, flush and close results.
Normal shutdown drains admitted rows under the same fixed cleanup deadline;
failure fences new output. Outstanding input/output requests retain their
original transfer and native close observations. Windows requests cancellation
of the original input worker without treating the request as completion. A
blocked native write can outlive the deadline and remains explicitly unresolved.

## Code layout

`session.rs` owns the lexical API and cleanup scopes. `session/scheduling.rs`
composes PROGRAM, Resolver and stop owners; `lookup.rs` handles IDENTITY,
`admission.rs` submits room operations, `events.rs` handles protocol progress,
and `state.rs`/`alarm.rs` retain bounded state and original deadlines.
`output/render.rs` formats frozen rows, `writer.rs` owns bounded native output,
and `report.rs` preserves independent lifecycle failures.
