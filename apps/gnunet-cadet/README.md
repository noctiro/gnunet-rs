# gnunet-cadet

This standard PROGRAM exposes the existing CADET client as a binary pipe
and echo tool. Its Cargo package is `gnunet-cadet-command` and the binary is
`gnunet-cadet`, keeping the existing pure package name independent.

- `gnunet-cadet PEER [PORT]` opens an outbound channel; PORT defaults to `default`.
- `gnunet-cadet -o PORT` listens for one incoming channel and withdraws the port
  after selecting it. Additional incoming channels are actually destroyed.
- `-e` selects a periodic echo client or, with `-o`, an echo listener.

PEER is the official52-character GNUnet identity. The exact non-NUL port-name
bytes (up to4096, including a legal empty name) are hashed using the existing
GNUnet SHA-512 primitive, without a terminator/private domain. Each data
message has the official four-byte header and `CADET_CLI` type1059. Incoming
strings may contain multiple complete such messages; their payloads remain in
order. No new handshake or private frame is introduced. Existing inspection
commands remain available through `gnunet-cli cadet peers|tunnels|paths`.

Standard PROGRAM `-c/-L/-l/-h/-v`, testing clock selection and selected
Logger/Reporter are reused. The configured `cadet` CLIENT and the process Resolver
share the same live configuration and RuntimeClock Arc. Source loss
permanently closes this allocation: old channels, partial frames, credit or
uncertain payloads are never replayed into a replacement epoch.

One caller-owned stdin handle, stdout handle, channel, port and received frame
loan remain inside the retained original PROGRAM future. There is no reader
thread, detached task, fd ownership duplication or shared-OFD flag change. Stdin
uses readiness and at most60000 bytes per chunk. Stdout uses unbuffered
writes of at most512 bytes, preserving its original partial cursor; readiness is
not treated as a completed write. Inactive/backpressured polls use bounded wake
cadence. These synchronous OS syscalls, including regular-file/device IO, cannot
be forcibly interrupted by an async timer; the program does not claim otherwise.

A received original outer Delivery is acknowledged exactly once, after all its
stdout payload writes (or original echo sends) finish locally. Mere frame
ownership/drop is not receive_done. Every outbound admission retains its original
Transmit until the matching Written event. Credit means local service send
credit; neither enqueueing nor whole IPC write proves peer receipt/application
processing. Binary payloads only reach stdout or the original echo path. Logger,
Debug and reports contain lengths, tokens, epochs and exposure metadata.

`[cadet-cli] CHUNK_BYTES` is1..60000 (default60000), `IO_BYTES` is1..65535
(default8192, with stdout additionally capped512), `OPERATION_SECONDS` is1..3600
(default30), and `CLEANUP_SECONDS` is1..60 (default5). Initial connection, each
original submitted/held send, first-positive partial frame, received processing
loan and echo intent have fixed native/logical targets. Retrying local admission
or waiting for credit does not renew them. Idle listening/pipe sessions have no
invented overall expiry. Echo probes are serialized with the public one-second
spacing; their measured RTT is diagnostic, not an authentication receipt.

EOF, Ctrl-C and parent stop use one original native cleanup grace. New stdin and
probe work stop, while existing frames/output/receive_done and ordered port/channel
destruction may finish on the same source. Then the client closes before
Resolver disconnect/Drop. Fatal source, clock, logger or IO failure physically
closes the same owner and retains exposure/held-byte facts. No timeout is
reported as a whole write or remote destruction. Native, stdin, stdout, Resolver,
close and selected Logger failures remain independent in the owned final error,
including a Logger-only failure. Product construction failures also retire the
same process Resolver. No private key file or service algorithm is part of this
app.
