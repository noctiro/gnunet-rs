# Binary I/O

The optional `binary-io` feature provides `binary_io::Input` and `Output` for
raw file or redirected standard-stream bytes on Unix and Windows. Protocol and
record state remain in the application. The adapter owns blocking native I/O,
bounded scratch and completion receipts.

## Requests and memory

Construct a port from an owned `File`, a path, or captured stdin/stdout. Opening
paths and capturing standard streams are synchronous native operations. New
output files receive private native permissions; truncating an existing file
preserves its permissions or ACL.

Each port has one worker, a 128 KiB requested stack and one initialized,
zeroizing scratch buffer. The selected buffer capacity must be 1–65,536 bytes.
`begin` admits exactly one nonempty bounded read or write; another request is
refused until that completion is consumed. Output bytes are copied into this
same scratch before admission. Each request makes one native read/write call
and returns its actual byte count or error.

`complete().await` observes the admitted request. Canceling that wait keeps the
same receiver with the port; another wait does not resubmit work. A successful
read borrows only its reported bytes. An I/O error does not prove the absence
of partial native effects; retry policy belongs to the caller.

## Standard streams

`Input::stdin` and `Output::stdout` retain owned duplicates of the original
native routes. They do not change shared Unix file-status flags or acquire
Rust's global buffered stream locks. Redirected binary bytes are preserved
without Unicode or newline conversion. Coordinate all readers/writers and
capture stdin before any buffered reads. Console encoding and input modes
remain native OS behavior; use redirection for a binary backup.

`Input::stdin_ready` observes the original route without consuming bytes or
changing flags. Coordinate that observation and capture with other route users.
It can avoid a pending read on an idle pipe, but is not a preemption guarantee
for console, file or device operations.

`Output::stdout_text` uses the same bounded worker for native text routes.
Windows console chunks must contain complete valid UTF-8 and are written as
Unicode; file and pipe routes preserve exact bytes, including partial suffixes.
Select chunk boundaries accordingly. Raw `stdout` keeps binary semantics.

## Retirement and cancellation

`retire` closes admission and returns a `Retirement` owner. An already admitted
native call continues with its original file and buffer. `poll_closed` observes
the actual output flush and single consuming native close attempt, preserving
their independent errors and monotonic completion instant. It also retains the
outstanding transfer; `take_transfer` consumes that result and any successful
read bytes exactly once. Debug output excludes buffer contents.

On Windows, `Retirement::request_read_cancel` targets only the original retained
input worker after admission closes. `ERROR_NOT_FOUND` permits another bounded
request for that same not-yet-issued read. Request success is independent from
`Transfer::read_cancelled`, the actual operation result, and its close receipt.
A normal read can still win the race. This API rejects output retirement; no
write or replacement thread is canceled.

A close receipt does not prove a thread join. `worker_finished` separately
observes thread completion without waiting. Flush and close are not filesystem
durability or downstream-delivery barriers. Dropping a port or retirement owner
never waits for a blocked syscall, forces cancellation or reports success.

Keep retirement ownership outside a cancellable operation. Applications select
their own finite cleanup deadline and retain unobserved receipts, late results
and native errors when that deadline expires. Repeated waiting must not renew
the original deadline or replay the transfer.

`settle` observes a fixed array of retired owners under one caller-anchored
native deadline. It requires a Tokio time driver. `RetiredSet` keeps each original
transfer, flush, close and wait failure separately; a missing port has no receipt.
Windows cancellation requests target retained input workers only. The collector
never submits another transfer or cancels writes. Deadline expiry preserves
unresolved original owners rather than manufacturing completion.

## File layout

- `binary_io.rs`: public ports, original transfer and retirement observations.
- `binary_io/owner.rs`: request admission, reusable scratch and worker handoff.
- `binary_io/worker.rs`: unique file/text-route execution and native flush/close.
- `binary_io/retirement.rs`: shared finite collection of original native receipts.
- `binary_io/tests.rs`: real pipe cancellation, retirement and binary bytes.
