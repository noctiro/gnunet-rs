# Conversation command

`gnunet-conversation -e NAME [-p LINE]` uses the normal PROGRAM configuration,
logging, shared clock, Resolver and signal sources. The IDENTITY exact
lookup selects a supported typed ego; its private key is owned and zeroized by
the original source/SDK frames. There is no private-key argument or key-file
fallback. `LINE` defaults to `[conversation].LINE`, then to the explicit local
default `1`. Its UTF-8 bytes, excluding a NUL terminator, use the official SHA512
port mapping.

The command waits for the IDENTITY initial directory and a verified PILS
identity using node-wide `[PILS] PROFILE`, defaulting to `reference029`. An optional `[conversation-command-rust] PILS_PROFILE` must agree with an
explicit node choice. The selected type reaches the PILS client;
failed verification never changes the profile. A changed/deleted ego or replaced
PILS MQ ends the original phone. A healthy peer change on the same verified MQ
updates future `/address` output while preserving original SDK calls, intents
and bytes. Fresh verified announcements may extend that announcement's lifetime;
they do not extend original call or write bounds. The caller ego and network
peer are distinct identities. Native terminal runtime qualification remains
separate from the service's selected identity profile.

Interactive commands:

| Command | Actual action |
| --- | --- |
| `/address` | Format the standard version1 PHONE record using the observed PILS peer and selected line port, then print NAMESTORE publication guidance. It does not publish. |
| `/call FULL_NAME` | Use the ordinary full-name GNS API, including direct zTLD, configured mappings and IDENTITY suffix lookup, requesting PHONE104. A currently usable version1 record starts an original outgoing SDK Line with the selected ego. |
| `/accept [#N]` | Enqueue local pickup for an incoming Ring735. An omitted number is accepted only when there is one suitable call. |
| `/suspend` | Enqueue local suspension of the active call and immediately stop its local media pipes. |
| `/resume [#N]` | Enqueue resume for the selected locally suspended call, suspending a different active call first. |
| `/cancel [#N]` | Cancel the current full-name query locally, or enqueue hangup for a selected call. An outgoing call whose CID has not been observed is canceled by closing its original MQ. |
| `/status` | Show the bounded current call table and its actual/local states. |
| `/quit`, stdin EOF | End the interactive session and independently retire its original owners. |
| `/help [TOPIC]` | Show the command summary. |

UI numbers address retained original opaque Call handles. They do not authorize
another Line/Epoch or derive a peer CID. Multiple incoming calls and one outgoing
call are supported within the combined table cap. There is one active local
media owner. Actual whole pickup/resume receipts also settle races between two
earlier queued activation commands: the previously active call receives a real
suspend intent rather than silently becoming unreachable.

Only PickedUp738 or a complete original local pickup732 permits media. Register731 written locally is not readiness or a peer acknowledgement. The
normal SDK retains partial writes, raw CID observations, source losses and
original FIFO ownership. After a recoverable registered-phone loss the command
retires only that phone's old calls, intents and audio, then waits for its actual
media children to stop/reap and their cleanup report before calling the SDK's
explicit registration recovery. Independently owned outgoing media is unchanged. The same logical phone, selected identity/PILS source, port and whole lifetime
remain; only a new731 is sent after a bounded100ms wait. First-unwritten731 phase
targets are retained. Once established, a replacement registration-only phase
may expire and be retired for another finite attempt within that same whole
lifetime. Old receipts/causes stay in the bounded diagnostics; whole registration
remains a local write. Explicit close, whole/input/control expiry or
identity/protocol failure cannot revive it. Outgoing calls are never redialed, and old controls or
audio are not replayed. GNS/IDENTITY source failure or EOF is not a negative
lookup or a successful hangup. A zero-record GNS result remains distinct
from source failure.

## Rust helper installation

The command explicitly owns two independent Rust helper children:
`gnunet-helper-audio-record` and `gnunet-helper-audio-playback`. It reuses the
existing `gnunet-arm-spawn-helper` process wrapper and `OriginalChild` registry;
it neither starts ARM nor uses ARM RPC. These three executables must come from
the corresponding Rust installation. For an executable in `PREFIX/bin`, default
helpers are `PREFIX/lib/gnunet/libexec/NAME`. Otherwise they are siblings of the
current executable, including a normal Cargo output directory. The three
absolute path overrides below support explicit alternate Rust installation
layouts. There is no PATH or official C-helper fallback.

Both audio helpers receive no arguments. The recorder writes standard730
frames containing Ogg/Opus bytes. Playback consumes standard730 on stdin and
has no Ready, ACK or data stream on stdout. The parent handles partial headers
and bodies, and keeps the helper730, Ogg-page and Opus-packet boundaries
independent. Recorded compressed bytes may be split into original SDK audio
frames of at most64344 data bytes, preserving their byte order. Incoming SDK
Audio owners retain their original RAII quota until the complete helper frame
has been written or that explicit media owner is stopped. Payloads are not
copied into a second playback queue or converted into raw PCM by the command.

Cancellation/suspension first closes the original parent pipes and clears their
retained audio. TERM is sent only to unreaped OriginalChild capabilities,
then KILL at half the fixed shutdown grace if needed. An consuming wait
is required before another media pair starts. Real exit status, signal syscall
success/error, partial cursors and unreaped debt remain in bounded diagnostics. An abnormal owner drop makes one clock-free kill/nonblocking-reap attempt and
retains any remaining debt; it does not manufacture a completed cleanup. A
child spawn, write, exit0 or complete live Ogg EOF is not evidence that hardware
is ready, a remote party heard audio, or an EOS was generated on SIGTERM.

## bounds

The section `[conversation-command-rust]` accepts:

| Setting | Default |
| --- | --- |
| `SESSION_LIFETIME` / `--timeout` | 1 day |
| `STARTUP_TIMEOUT` | 30 seconds for the original ego/PILS startup |
| `CALL_LIFETIME` | 1 day, clamped to the original whole session |
| `CONTROL_TIMEOUT` | 10 seconds |
| `SHUTDOWN_GRACE` | 5 seconds, a separate physical cleanup budget |
| `MAX_CALLS` | 32 combined current calls, configurable1–1024 |
| `MAX_EGOS` | 1024, configurable1–65536 |
| `COMMAND_BYTES` | 4096 |
| `OUTPUT_BYTES` | 1 MiB |
| `PLAYBACK_FRAMES` | 8 observed audio owners |
| `PENDING_FRAMES` | 64 original native frames per Line |
| `AUDIO_OUTPUT_BYTES` | 1 MiB of queued original native frames per Line |
| `NATIVE_RETAINED_BYTES` | 4 MiB per SDK Line |
| `HELPER_RECORD`, `HELPER_PLAYBACK`, `HELPER_LAUNCHER` | Absolute Rust helper paths described above |

All durations are finite. Each `/call` captures its canonical/native target
before GNS and reuses it through the original outgoing Line. Signals, Logger,
clock and Resolver failure are checked before further normal native work. Each control retains its first intent target during local backpressure. Helper
first-byte and queued-write budgets are fixed and capped by the original media
call's whole bound. Synchronous environment/descriptor preparation is followed
by the same whole-bound check before each child spawn; a blocking OS call
itself cannot be preempted. Physical cleanup does not require a healthy expired
business clock or Resolver.

Input/output queues, table rows, original SDK byte capacities and child counts
are bounded independently. The selected maximum counts are not a guarantee
that all maximum payloads fit simultaneously. Exhaustion is an explicit error,
without eviction/replay or invented service completion. Diagnostics retain the
first/latest SDK retirements and media sessions plus counts, rather than an
unbounded history. These budgets cover the owned CLI/SDK observations; caller
copies, kernel pipes and independent helper/provider memory are not a process
RSS claim.

Terminal descriptors are duplicated, use reactor readiness for pipes/TTYs, and
restore jointly captured original open-file flags on close, including when
stdin/stdout share an open-file description. Regular-file terminal IO and
synchronous selected logging can block in the OS and cannot be forcibly
preempted by the protocol hard bound. Untrusted displayed names/messages are
escaped; binary audio and private keys are never formatted.

Both service generations actually accepted the complete
Register731; the PHONE value stayed identical and all18 original processes
exited and were reaped without cleanup errors. Original Cancelled/Closed Line
causes remain recorded separately from physical cleanup.

This selected result covers registration recovery. New incoming calls after
recovery, answered calls, media/device operation, cancellation under load,
unchanged C Conversation peer cryptography and full platform/resource/performance
qualification remain open. A clean interactive exit means original local owners
retired; it does not assert that a call was answered or heard.
