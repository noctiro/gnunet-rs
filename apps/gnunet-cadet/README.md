# gnunet-cadet

Exposes CADET binary streams, echo and management queries on Linux, macOS,
FreeBSD and Windows. Its package is `gnunet-cadet-command` and its binary is
`gnunet-cadet`.

## Invocation and protocol

```sh
gnunet-cadet -c gnunet.conf PEER PORT
gnunet-cadet -c gnunet.conf --open-port PORT
gnunet-cadet -c gnunet.conf --echo PEER PORT
gnunet-cadet -c gnunet.conf --peers
gnunet-cadet -c gnunet.conf --tunnels
gnunet-cadet -c gnunet.conf --peer PEER
```

`PEER [PORT]` opens an outbound channel; PORT defaults to `default`. `-o PORT`
listens for one channel and withdraws the port after selecting it. Additional
incoming channels are destroyed. `-e` selects periodic echo or an echo listener.
Standard PROGRAM options select configuration, logging, help and version.

`-P` lists peers, `-T` lists tunnels, and `-p PEER` lists paths to the selected
peer. Each query writes the official text rows and completes when it receives
the matching END from the configured CADET service. `-C CONNECTION_ID` is
unavailable in the selected official service.

PEER is the official 52-character identity. Non-NUL port-name bytes, up to 4096
including an empty name, use the existing GNUnet SHA-512 primitive without a
terminator or private domain. Data retains the official four-byte header and
`CADET_CLI` type 1059. Multiple complete inner messages retain their order.
Peer and port selection grant no independent authentication proof.

## Ownership and flow control

The [scope](src/run/scheduling.rs) captures initial operation bounds and native
stop subscriptions before constructing the process Resolver. Fresh client
startup handles inherited resources before other native owners. One retained
PROGRAM future owns the original channel, port, TX, RX loan and stdio owners.
The CADET client and Resolver share one LiveConfiguration and RuntimeClock.
Source loss closes this allocation; no uncertain payload moves to a new epoch.

A received outer Delivery is acknowledged once, after its actual stdout writes
or echo sends finish locally. Dropping a frame never calls receive_done.
Outbound admissions retain their original Transmit until matching Written.
Service send credit and whole IPC writes remain separate from remote
application-delivery proof. Payload content reaches only stdout or echo;
diagnostics contain bounded lengths, tokens, epochs and exposure metadata.

## Native I/O and retirement

[Stdio](src/stdio.rs) lazily captures each original binary route only when its
role needs it. Each route has one bounded worker and at most one native call.
Stdin readiness avoids an idle pipe read; stdout writes at most 512 bytes.
Canceled waits retain their original work, and temporary non-writing errors
back off without changing the cursor or deadline. Shared file flags, console
modes and process standard routes remain unchanged.

EOF and native/parent stop halt new stdin and probe work. Existing output,
receive completion and ordered channel/port teardown share one original native
cleanup deadline. The client closes before [stdio retirement](src/stdio/retirement.rs);
actual late output counts update the original RX metadata without issuing an ACK
on a closed client. Late input is counted as unsubmitted and never sent.

On Windows, retirement can request cancellation of the original outstanding read
on its retained worker thread. A request proves no completion. Only the actual
native canceled result and close receipt establish read retirement; the report
keeps cancellation separate from byte counts. Writes are never canceled or
replayed. A driver that cannot finish before the bound leaves its original
worker and receipts in the failure. Native close is not a thread-join or
remote-delivery receipt. The original Resolver is then disconnected independently.

## Resource settings

Configure service endpoints through ordinary `[cadet]` and `[resolver]` settings.
These `[cadet-cli]` limits are local policy:

| Key | Default | Range |
| --- | ---: | --- |
| CHUNK_BYTES | 60000 | 1–60000 |
| IO_BYTES | 8192 | 1–65535; stdout additionally caps each write at 512 |
| OPERATION_SECONDS | 30 | 1–3600 |
| CLEANUP_SECONDS | 5 | 1–60 |

Connection setup, submitted or held sends, partial frames, received processing
loans and echo intents have fixed native/logical bounds. Admission retries and
credit waits never renew them. Idle sessions have no invented overall expiry.
Management queries use one `OPERATION_SECONDS` budget through the final END.
Echo probes use one-second spacing; RTT is diagnostic. Native, stdin, stdout,
Resolver, cleanup and Logger errors retain independent causes and known prefixes.
See [open work](../../IMPLEMENTATION_STATUS.md) for remaining qualification.
