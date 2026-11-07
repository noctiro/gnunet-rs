# Explicit Conversation audio helpers

Package `gnunet-helper-audio-command` installs two Rust binaries:

- `gnunet-helper-audio-record`: no arguments, stdin unused, stdout only complete
  standard type-730 frames carrying Ogg Opus bytes from microphone capture.
- `gnunet-helper-audio-playback`: no arguments, reads type-730 stdin frames and
  plays decoded audio; stdout carries no control or data messages.

Both use `gnunet-conversation-audio-host` and the selected Unix PulseAudio simple
plus libopus provider. They do not invoke the official GNUnet helpers, search a
replacement producer or accept private control messages. No argument is a device
name, private key or codec command. Extra arguments exit 2; provider,
framing, checksum, codec or I/O failure exits 1 with an audio-byte-free stderr
cause. Playback can exit 0 after complete-boundary EOF and drain; exit 0
is not a Ready, remote acknowledgement or proof that somebody heard the audio. Record is continuous until error or parent termination.

The parent normal Conversation caller must bind each owned process and pipe to
its Call/Epoch, preserve partial pipe writes, and terminate/wait/reap the
original process before reusing media ownership. There is no startup Ready/ACK. The 4-byte 730 header is BE16 total size followed by BE16 type 730; its payload
is opaque Ogg stream bytes. Helper-frame boundaries do not define Ogg-page or
Opus-packet boundaries. Ordinary SIGTERM ends the process without an EOS promise;
blocking provider calls require parent timeout and TERM/KILL/reap bounds.

The helpers require available standard Opus and PulseAudio simple dynamic
libraries and the user's permitted PulseAudio device/session at execution. No dependency installation, library load, device access, recording, playback,
build or runtime validation was performed while preparing these sources.
