# gnunet-nse

`gnunet-nse` prints the first estimate from the configured official NSE service.
`-m/--monitor` continues until native stop or a configured finite monitor target.
The Rust package is named `gnunet-nse-command` to distinguish the protocol crate.

## Usage and configuration

```sh
gnunet-nse -c gnunet.conf
gnunet-nse -c gnunet.conf --monitor
```

Shared PROGRAM configuration, logging, help and version options apply; positional
arguments are rejected. [nse-client.conf](nse-client.conf) documents local client
budgets. The first-result budget defaults to 60 seconds. `[nse]` selects the
actual local/TCP endpoint; this command performs no PoW or private-key work.

Output contains the server UTC timestamp, `#peers=2^logestimate`,
`ld(#peers)=logestimate` and deviation, with six decimal places. NaN/inf remain
statistical observations rather than verified peer counts.

## Native lifetime

The command captures startup inheritance first and uses shared native parent and
stop control on Unix and Windows. Its selected Logger and shared clock drive
business/connection diagnostics; estimate lines remain stdout.

A fixed-size output worker handles native text or exact redirected bytes.
Network deadlines and stop observation remain live during output backpressure.
PROGRAM cancellation retains the original write for independent bounded
retirement, including actual transfer and flush/close errors. A deadline cannot
force-cancel a blocked kernel call or roll back exposed bytes.

Success requires a complete real estimate line. An explicit finite monitor target
succeeds after complete output; incomplete output or runtime failure yields 1,
and preparation errors yield 2. Source, output, logging and Resolver cleanup
retain separate causes. See the [native API](../../adapters/nse-client-std/) for
framing, retry, cancellation and resource contracts.
