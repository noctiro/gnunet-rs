# ARM native launch policy

## Shared process layer

ARM-self delegates creation and original-child ownership to
[service-runtime](../service-runtime/PROCESS.md), and Windows bootstrap to
[service-startup](../service-startup/README.md). The ARM adapter supplies command
configuration, finite limits and official client outcomes.

## Platform command boundaries

`launch/plan.rs` resolves configuration and libexec paths. Unix preserves the
source textual command grammar and fresh-exec helper contract in `launch/unix.rs`.
The helper restores inherited signal/stdio state before target exec.

Windows `launch/windows.rs` supplies an explicit image, environment/cwd, standard
streams and bootstrap to the existing native producer. Native binary/configuration
paths become literal `OsString` arguments; only PREFIX and OPTIONS are command
fragments. The shared argument composer also serves the normal ARM SERVICE.
No Windows path is round-tripped through the Unix escaping grammar.

## Bootstrap lifetime

Windows reserves bounded observation and driver storage before process admission.
The launcher owns each pending bootstrap; the operation holds only its immutable
completion observation. Cancellation closes callback authority without dropping
the original child's startup channel. `settle_startups` completes remaining handshakes without waiting for a live
process to exit. Explicit child draining continues both bootstrap and original
exit observations. Dropping the launcher closes unfinished local
endpoints without implicitly terminating or waiting for a child.

Native lookup/decoding failures encountered through CONFIGURATION's optional
variable-lookup interface are retained and returned by synchronous planning.
Explicit snapshots never change ambient PATH, environment or cwd.
