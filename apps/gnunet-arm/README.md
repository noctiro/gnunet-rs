# Official ARM CLI

This application implements the v0.29.1 `gnunet-arm` command options and control
phases using the Rust ARM client/monitor and shared native process owner.

```sh
cargo build -p gnunet-arm-cli -p gnunet-arm-host --bins --locked
target/debug/gnunet-arm --help
target/debug/gnunet-arm -c /path/to/owned.conf -I
```

The helper binary is built alongside the CLI for the explicit local-start port. The default installation layout and remaining native profiles still need full
acceptance. Runtime service endpoints and commands use official configuration;
there is no private wire or new GNU option.

The existing phase order, source result codes, cancellation, LIST/monitor output,
quiet, timeout, entry signals and local startup/restart remain in the same State
and byte-preserving option parser. Those sources and their private pure models
are unchanged by the selected-logging integration.

The normal entry selects the shared `Logger::setup_routed` policy and
`Reporter`. `-L/-l`, GNUNET_FORCE_LOGFILE, GNUNET_FORCE_LOG and GNUNET_LOG use the
same public selection implementation as PROGRAM. Nonempty forced logfile takes
precedence over -l. Shared timestamp/component/PID/severity formatting, rotation
and filters are used; no ad-hoc two-level warning filter or second file sink
remains. Native warning/path bytes are passed through `message_bytes`, without
UTF8 replacement or interpretation as a format string. Ordinary State stdout
and explicit business stderr remain literal status streams, separate from logs.

Immediate help/version/parser results precede logger/file/runtime setup. Normal
configuration and arm.CONFIG fallback are retained. The selected SharedClock
(including the existing configured testing skew) is shared by original control,
monitor, Resolver and logging owners; an embedding invocation with a different
Resolver clock is refused before native admission. CLI generic locale/catalog
and scheduled time-speedup behavior are separate remaining PROGRAM integration
work.

`runtime::run` consumes `Invocation { config, options, ports, diagnostics }`;
`diagnostics::Selection` owns one selected Logger/clock and is cloned only for
that same command. This makes the original scope explicit rather than silently
opening logging inside run. The standalone main is the consumer. Initial
control/monitor failures which the source leaves as nonfatal business return
codes are retained as owned `InitialErrors` (`take_initial_errors`) and do not
rewrite State.ret. If accompanied by another error, they are included in the
combined returned failure, including an independent logging failure.

A failed Reporter permanently fences the next native/provider poll and wakes
its original task. Normal/error completion cancels only the original
OperationId and disconnects the same control/monitor MQs. Future-drop guards
also close those owners; a fallible control disconnect is retained in the
selected command's cleanup slot. No started service is killed or synthetically
reaped: the caller's original ChildRegistry remains the owner. Native error,
callback/clock failure, output failure, cancellation, control disconnect,
Resolver disconnect and first Logger error remain independent causes. Failed
status writes are not replayed from the beginning during cleanup; their original
buffers are cleared immediately after each attempt and their capacity reused.

The source -d condition is unchanged. Deletion diagnostics go to the selected
Logger, and an already failed logging gate does not start new deletion work.

The source C's unsafe second-format-string behavior is replaced by literal Rust
output. Defined-safe native comparisons and the Rust-only percent-name regression
remain separate. `tools/verify.py` freshly builds the CLI and existing helper,
checks full workspace lint/dependency settings and records process exits,
frames and bytes; all local fixtures use owned temporary paths.

The malformed relative-time error path in the pinned C implementation reads an
uninitialized local. Fresh argv comparisons therefore use32 defined-safe
profiles; four malformed-time-containing profiles are excluded conservatively. Rust rejects invalid values in a separate safety regression. Earlier36-profile
receipts remain historical and their malformed C paths receive no conformance
credit.
