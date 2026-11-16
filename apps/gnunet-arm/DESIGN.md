# ARM CLI design

## Module responsibilities

- `options.rs` binds ARM metadata and values to shared PROGRAM/GETOPT parsing,
  help, diagnostics and literal-space `GNUNET_ARGS` handling. Native values use
  the shared lossless local-string boundary.
- `state.rs` owns command phases, source result handling and remaining flags.
  `state/output.rs` owns catalog rendering, byte buffers and permanent output
  failure. Neither module discovers sockets, processes or native libraries.
- `locale.rs` retains one explicit PROGRAM translation backend and case context;
  parsing, configuration, output and diagnostics share that selection.
- `runtime.rs` composes the state with ARM control/monitor hosts, Resolver and the
  selected diagnostics/clock. `runtime/signals.rs` owns native stop subscriptions;
  `runtime/files.rs` implements explicit deletion.
- `diagnostics.rs` binds PROGRAM logging and the original shared clock to one
  invocation. The binary is a thin argument/exit adapter.

## Operation ordering

The reducer orders stop/restart, start, init, list and monitor phases. Request
callbacks preserve official result codes and the STOPPING/EOF distinction.
Monitor has its own MQ and callback authority; its failure cannot fabricate a
successful LIST. Output remains borrowed or staged only for synchronous reporting.

A drive cancellation preserves physical I/O and operation state. Shutdown cancels
original callback authority before disconnecting owners. Neither path implicitly
kills a locally launched ARM process. The embedding caller owns the child registry
and must retain launch resources needed by admitted startup work.

## Native boundary

Unix selects the fresh-exec helper and original signal/descriptor policy. Windows
uses the same ARM client/monitor state over native CLIENT transport and the shared
Windows child/bootstrap producer. Native paths preserve UTF-16 code units, including
isolated surrogates. Path arguments are structured; PREFIX/OPTIONS use the GNUnet
fragment grammar. Windows console termination and Unix scheduler signals are
selected inside the signal adapter.

Explicit `--delete` uses the configured paths and never traverses link or Windows
reparse-point targets. Windows clears the readonly attribute of ordinary owned
entries without changing their DACL. The caller must exclude concurrent namespace
mutation while administering those directories.

## Logging and time

An invocation carries the selected Logger/Reporter and shared clock. Control,
monitor, Resolver and logs use that same clock source. The standalone entry
shares PROGRAM's bounded speedup owner and logical timeout subscriptions;
embedded runs leave scheduler selection with the caller. A mismatched Resolver clock
is refused before native admission. Logger failures remain independent of
business status and physical cleanup errors. Immediate option output precedes
logger, file and runtime setup. Catalog/format errors retain their original
cause and permanently retire output; consuming that error does not clear the
failure gate. Failed output prevents new delete work while original native
owners still close normally.

The official kill-request catalog msgid escapes a second-pass reason placeholder
as `%%s`. Lookup retains that exact msgid; one safe render binds the reason and
service name to typed argument positions. Native argument bytes never
become a second format string. Literal list status labels and relative-time units
remain literal, matching the source's catalog boundaries.

The [host ownership contract](../../adapters/arm-std/API.md) defines local launch
and cancellation. Repository-wide open behavior is tracked in
[implementation status](../../IMPLEMENTATION_STATUS.md).
