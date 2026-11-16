# gnunet-uri

Run the configured default action for one `gnunet://SUBSYSTEM/PAYLOAD` URI on
Linux, macOS, FreeBSD and Windows.

## Usage

```sh
gnunet-uri [-c CONFIG] URI
```

Standard PROGRAM supplies configuration, logging, help and version options.
`[uri] SUBSYSTEM` selects a trusted executable and configured arguments. The
complete URI follows as one literal argument. URI and QR use the same selection;
configured NAMESTORE `-u` consumes the URI directly, without an inserted `--`.

## Configuration

See [handler configuration](CONFIGURATION.md) for command parsing, native paths,
resource limits and stop grace. Handler stdio is redirected to null; QR uses
inherited stdio. Windows launches the selected application directly without an
implicit command interpreter.

## Lifetime and errors

The [shared dispatcher](../../adapters/uri-std/README.md) retains the original
child across canceled observation futures. Native stop and parent control begin
bounded retirement; parent EOF alone is not stop. Spawn, exit, stop requests and
cleanup are separate observations. Exit0 confirms process completion, not a
GNUnet service acknowledgement. An unreaped original child remains a failure.
