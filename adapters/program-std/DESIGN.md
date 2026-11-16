# PROGRAM design

## Modules

- GETOPT owns option tables, native argument bytes, permutation and once-only cleaners.
- Configuration observers route diagnostics synchronously through the selected logger.
- Logger owns policy, append/rotation files, callbacks, source metadata and formatting.
- Locale uses the selected trusted native gettext provider.
- SharedClock exposes one canonical authority and separate subscriptions.
- Scoped execution owns bounded tasks and original generation-bound task IDs.
- DAEMON registration snapshots a launch before reserving scheduler capacity.

## Ownership

Preparation returns either a main capability or an early option-processing result.
A positive parse index alone cannot grant main authority after logging failure.
Callbacks observe borrowed configuration without retaining a logger or a mutable
guard across async work. Local diagnostic observation overrides the persistent
observer for that operation, avoiding duplicate output.

Logger files and process stderr are separate resources. Process locale/stderr
installation requires its native capability; dropping an ordinary logger cannot
claim to restore process-global state. Normal resource errors are typed results.
A fail-stop is limited to a broken declared native invariant.

Windows process stderr delegates handle ownership to the native adapter. Win32
stderr and UCRT fd2 receive independent duplicates; temporary CRT standard-slot
allocation preserves the native input/output table. Installation errors retain
their partial-state phase. The Unix descriptor backend remains separate; the
shared logger does not own a process standard handle.

Wall-clock sampling is separate from calendar conversion, so each log timestamp
converts only its final offset-adjusted value. Calendar conversion has separate
POSIX and Windows backends with shared date assembly. Windows uses wide native
formatting and preserves conversion failures
through an owned error chain. Log-directory preparation uses native path rules;
shared diagnostics retain the original IO error domain instead of interpreting
every platform's error number as Unix errno.
Windows opens a log file directly first and creates parents only for a missing
path before one retry. A successful open needs no directory metadata permission.

Logging BRE has separate POSIX and Windows backends. The Windows grammar and
bounded boolean machine are safe Rust; native character properties and collation
belong to the native adapter. Parsed syntax uses an arena and is discarded after
instruction compilation. Ordinary rules omit captures; backreferences retain
distinct compact capture histories. Explicit work/state limits bound both paths,
and exhaustion propagates as an error. No callbacks or locale changes run inside
matching. See the [BRE contract](NATIVE-CONTRACT.md#windows-regular-expressions).

Tasks are polled by the caller. Stop/Drop retires pending work outside bookkeeping
borrows; original TaskIds cannot cancel a replacement run. Clock/Resolver startup
and cleanup belong to that execution scope.

The single-thread Reporter shares the selected logger/clock, retains its first
failure and wakes the waiting task. Taking an error does not clear its failure
latch. Applications own their bounded shutdown after reporting failure.

See [public interfaces](API.md), [native contracts](NATIVE-CONTRACT.md) and
[locale binding](NATIVE-CONTRACT.md#configuration-locale-binding).

## Bounded command output

[`output`](src/output.rs) keeps encoding and domain errors on the command thread.
The native layer captures an original stdout/stderr handle; PROGRAM owns a
capacity-one I/O channel, a reusable 64 KiB buffer, a stop/deadline supervisor and
one blocking writer. UTF-8 packets preserve scalar boundaries; binary packets
retain bytes. Each native call checks the original packet deadline and retirement
flag. A call admitted before retirement can finish after waiting stops; no further
write or flush is admitted afterward. The failed owner retains that original job
or its unresolved receipt. Runtime teardown follows Tokio's explicit
[background shutdown contract](https://docs.rs/tokio/1.54.1/tokio/runtime/struct.Runtime.html#method.shutdown_background).

`Control` binds the command's immutable work deadline and one separately selected
cleanup grace. Row encoders must flush before counting an emitted row. Snapshots
separate buffered, submitted, positively written, flushed and discarded bytes;
flush is neither a downstream reader acknowledgement nor a durability barrier.
Unsubmitted partial records are discarded after domain failure, and diagnostics
use a separate original stderr owner. The application decides when it can exit;
dropping an owner never certifies cancellation of a blocking OS operation.
