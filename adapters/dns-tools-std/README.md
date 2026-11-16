# DNS monitoring and redirection

`gnunet-dns-monitor` and `gnunet-dns-redirector` share PROGRAM configuration,
DNS client IPC, Resolver scheduling and native parent/stop control on Linux,
macOS, Windows and FreeBSD. They require a running DNS interception service.

## Commands and configuration

Monitor accepts `-i/--inbound-only`, `-o/--outbound-only` and `-v/--verbose`.
It displays validated question and record data, escapes terminal control bytes,
and forwards each original callback. By default it observes queries and responses.

Redirector accepts `-4/--ipv4`, `-6/--ipv6` and `-v/--verbose`.
It subscribes to post-resolution callbacks and replaces only answer-section
A/AAAA addresses of the correct width. Header flags, TTLs, compression pointers
and unrelated records retain their original bytes. Unchanged or malformed
packets are forwarded. Rewriting an address does not establish DNSSEC validity.

Both use standard PROGRAM options, including `-c/--config`, help, version and
logging. `--socket PATH` selects an explicit local stream endpoint. Otherwise
the shared configuration selects the service endpoint, including TCP.

```sh
gnunet-dns-monitor -c node.conf --duration-ms 30000
gnunet-dns-redirector -c node.conf --ipv4 192.0.2.10 --max-packets 10
```

Additional limits are `--duration-ms` (default 300000, maximum 86400000),
`--max-packets` (default 0, duration only), `--max-entries` (maximum 16384) and
`--io-slice-bytes` (1–65535). The client retains at most 64 callbacks and 4 MiB
of source data. Packet parsing and replacement reuse fixed-capacity buffers.

## Ownership and shutdown

Option preparation, foreground scheduling, native control and callback handling
live in separate modules. The selected Reporter is shared with the caller's
PROGRAM scheduler; output failure permanently stops new reply admission.

Callback admission, whole local writes, timeout drops and source loss are
separate observations. Stop closes the original client before disconnecting
its Resolver. A packet limit allows a five-second reply drain within the
original total deadline. Reconnection resubscribes on a new source and never
replays replies or reuses old callback tokens.

Standard output remains synchronous; these network deadlines cannot preempt
an operating-system output call. Utility success does not establish interception
installation or delivery beyond the local IPC connection.
