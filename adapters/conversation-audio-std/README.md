# Conversation media owner

`gnunet-conversation-audio-host` supplies the blocking media functions
used by the two explicit Rust helper processes. `record(Limits)` opens the
standard PulseAudio simple capture provider, encodes Float32LE 48 kHz mono
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

The scoped `native` module binds only public POSIX loader, libopus and PulseAudio
simple APIs. The rest of the crate denies unsafe code. Missing libraries, symbols,
device permission, codec and native I/O refusals preserve provider codes
or bounded original loader diagnostics. Native handles have matching RAII free/
destroy owners; owned Rust PCM/compressed buffers erase on release. No installed
library or audio device is probed during source preparation.

These functions deliberately block and belong only in independent helper
processes. The normal caller owns the original call/source identity, pipes,
backpressure, deadlines, signal termination and wait/reap. There is no
helper Ready/ACK protocol and no hidden SDK worker/thread. A blocked native read,
write or drain cannot be preempted by these functions; the parent can terminate
and reap the explicit process. SIGTERM has its normal process action and does
not promise a final EOS. After a failure, playback attempts a flush and
retains an independent cleanup failure alongside the original cause.

Fixed GNUnet v0.29.1 `meson.build` erroneously selects the record source for its
default playback target; this Rust playback does not copy that build defect. The official selected `gst` profile chooses the correct playback source and
also carries Ogg/Opus inside 730, so it remains a possible unmodified official
producer/consumer profile for later authorized acceptance. Neither profile has
been built or exercised for this implementation. Source preparation and pure case
source are not audio/device, interoperability, latency or performance evidence.
