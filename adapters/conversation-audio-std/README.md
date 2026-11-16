# Conversation media owner

`gnunet-conversation-audio-host` supplies the blocking media functions
used by the two explicit Rust helper processes. `record(Limits)` opens the
selected native capture provider, encodes Float32LE 48 kHz mono
40 ms blocks with libopus VOIP, and emits standard Conversation audio type 730
messages containing an Ogg Opus byte stream. `playback(Limits)` receives those
messages, validates and reconstructs Ogg pages/packets in Rust, decodes actual
Opus packets, applies pre-skip, signed header gain and end trimming, and submits
Float32LE PCM to the standard playback provider. No GNUnet C library/helper or
raw-PCM substitute supplies this implementation.

The selected recording profile uses 1920 samples, a 1024-byte encoded-packet
cap, loss-percentage 1, in-band FEC 1, complexity 10 and voice signal. The real
OpusHead and OpusTags occupy independent pages; each audio packet advances the
48 kHz granule by 1920. The playback profile supports mono/stereo mapping family
0, including fragmented packets, multiple packets per page and continued tags. It does not implement multichannel mapping families, diagnostic raw-Ogg/WAV
environment modes, a GStreamer provider, device selection or codec substitution.

The 730 frame, Ogg page and Opus packet boundaries are independent. Input is
incremental and finite: maximum whole helper frame 65535 bytes, Ogg page 65307,
assembled packet/tags 262144 and capture-prefix resynchronization 65536 by default. Major byte/sample buffers use fallible growth with actual-capacity checks. The
finite retained reservation includes those maxima, PCM, codec-state reservation
and bounded metadata; it is not a process RSS limit. Native codec state sizes are
queried before creation; requested Pulse buffers are finite, while library/server
internal allocation and blocking latency remain provider properties.

Capture-prefix corruption may resynchronize within its explicit budget. A CRC
mismatch is a error. Sequence gaps discard unavailable packet fragments and
retain lost-page/unrecoverable-packet observations; this owner does not synthesize
silence or pretend missing samples were decoded. New BOS with a new serial can
replace a live stream without EOS, as normal recording termination requires. Actual EOS trims only decoded samples. Partial 730/page/packet EOF fails;
complete live EOF can drain successfully while retaining an unterminated-stream
observation. Local drain is not human-hearing or remote-delivery proof.

## Native providers

The scoped `native` module separates libopus, library loading and audio devices.
Unix uses PulseAudio simple; Windows uses shared-mode WASAPI on the default
communications endpoint, with system sample-rate/channel conversion. Windows
buffers remain borrowed from the original engine until release; capture packet
tails survive a helper read boundary. Silent packets produce zero PCM and
`capture_discontinuities` counts native flags without inventing missing samples.
Rendering starts after its first buffer submission and drain waits for the
original queue before stopping. Device invalidation is returned, with no silent
replacement. See Microsoft's [WASAPI contract](https://learn.microsoft.com/en-us/windows/win32/coreaudio/wasapi).

Windows loads `libopus-0.dll` or `opus.dll` beside the installed helper, using an
absolute path and the shared native library owner. It does not search the current
working directory. The helper owns an STA COM reference; service and engine
references release before its event and apartment. Unix retains its standard
libopus/PulseAudio library candidates. Missing libraries, permissions and device
failures preserve native codes, with HRESULT distinct from Win32 I/O errors.
Owned Rust PCM/compressed buffers erase on release. The rest of the crate denies
unsafe code.

## Process ownership

These functions deliberately block and belong only in independent helper
processes. The normal caller owns the original call/source identity, pipes,
backpressure, deadlines, signal termination and wait/reap. There is no
helper Ready/ACK protocol and no hidden SDK worker/thread. A blocked native read,
write or drain cannot be preempted by these functions; the parent can terminate
and reap the explicit process. SIGTERM has its normal process action and does
not promise a final EOS. After a failure, playback attempts a flush and
retains an independent cleanup failure alongside the original cause.

## Compatibility

GNUnet v0.29.1 `meson.build` selects the record source for its
default playback target. The official selected `gst` profile chooses the playback source and
also carries Ogg/Opus inside 730, so it remains a possible unmodified official
producer/consumer profile. Native device and C↔Rust qualification remain in
[implementation status](../../IMPLEMENTATION_STATUS.md).
