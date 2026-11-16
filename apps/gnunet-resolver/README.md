# gnunet-resolver

Prints forward or reverse results from the shared GNUnet Resolver API. Linux,
macOS, FreeBSD and Windows use the same query, callback and output lifecycle.
The package is `gnunet-resolver-command`; its binary is `gnunet-resolver`.

## Invocation and configuration

```sh
gnunet-resolver -c gnunet.conf hostname
gnunet-resolver -c gnunet.conf --reverse 127.0.0.1
```

Forward output contains numeric IPv4/IPv6 addresses, one per line. Reverse input
is a numeric IP without a port or scope extension; output retains returned
hostname bytes or the API's numeric fallback. No argument is a no-op, matching
the official tool. Standard PROGRAM `-c/-L/-l/-h/-v` select configuration and
diagnostics. Configure the `[resolver]` endpoint through ordinary configuration.

`[resolver-cli] MAX_RESULTS` defaults to 4096 (1–65536).
`MAX_OUTPUT_BYTES` defaults to 16777216 (1–67108864). Result and output exhaustion
are errors; rows are never silently truncated.

## Query and callback ownership

The [scope composition](src/run/scheduling.rs) constructs one original command
budget and native stop subscription before the Resolver. One LiveConfiguration,
RuntimeClock, Broker, Query and uniquely owned Driver remain inside the retained
foreground future. Forward uses `ip_get(Family::Any)`; reverse uses
`hostname_get(..., true)`. Standard local/numeric API paths keep their callback
semantics. The command adds no DNS lookup backend or private IPC protocol.

Every Delivery must match the original Query token. Its value is copied into one
bounded line before returning the lease, so output backpressure never retains a
borrowed callback across a Driver poll. Forward port-zero values use bare
numeric addresses. Reverse bytes receive no lossy text conversion. Result
content goes only to stdout, never diagnostics or terminal metadata.

## Native output and cancellation

[Output](src/output.rs) uses the shared capacity-one native binary I/O owner.
One worker owns a duplicate of the original stdout route and at most one
512-byte write. The command retains one line, at most 65536 bytes including its
newline. Canceled completion waits retain the original transfer rather than
submitting its bytes again. Interrupted or would-block writes back off without
advancing the cursor or renewing the deadline. Shared file status flags and
process standard routes remain unchanged.

Resolver construction, retries, callbacks and output work share one original
five-second native/logical budget. Native guards precede canonical and Driver
polling. Fresh client startup handles inherited resources before other native
owners; shared subscriptions retain original parent control and native stop
sources. Stop cancels the original query and admits no further output transfers.
Fatal source, clock, output or Logger failures also stop new work.

[Output retirement](src/output/retirement.rs) closes admission and observes only
the original write, flush and close for one fixed second. It uses native time
independently of the canonical clock and Resolver. A blocked kernel call remains
owned by its original worker; timeout does not establish kernel cancellation.
An unresolved receipt remains in the returned failure. Written counts include
only actual native results, including a result first observed during retirement.

## Completion and errors

Actual END, non-END completion, cancellation, missing terminal callback, source
loss and physical cleanup remain separate facts. A Lost/Unavailable event fences
the original query before another Driver poll; no replacement MQ replays it.
The original Query is dropped before Driver disconnect, then output retires.
Independent cancel, Driver, I/O, output-close and Logger errors remain available
with bounded callback/output metadata. Already written prefixes survive failure.
Neither stream closure nor missing terminal data becomes a successful DNS END.
See [open work](../../IMPLEMENTATION_STATUS.md) for remaining qualification.
