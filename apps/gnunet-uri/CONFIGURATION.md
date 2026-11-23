# URI handler configuration

## Handler selection

`[uri] SUBSYSTEM` contains an executable and fixed arguments using the shared
GNUnet command tokenizer. Double-quoted groups retain all literal spaces. Backslash escapes the next byte,
including inside quotes; escape native path backslashes or use Windows forward
slashes. Unbalanced quotes and trailing escapes fail. Shell expansion, URI
tokenization and percent decoding are not performed. A configured
command may include an argument separator when its own grammar requires one.

```ini
[namestore]
URI_IMPORT_EGO = my-zone

[uri]
gns = gnunet-namestore -e 1a -u
```

The handler imports into the local IDENTITY ego `my-zone` with a one-year
expiration. An explicit `-z my-zone` also selects the ego. Set the option in
the configuration loaded by the handler. If the handler needs a non-default
configuration file, include `-c CONFIG` in its command.
Windows paths containing spaces must be quoted inside the configured command.
Bare Windows executable names resolve through an immutable PATH/cwd snapshot;
explicit paths use that snapshot's native root/drive rules. Creation passes an
explicit application name to CreateProcessW. A batch file cannot implicitly
invoke cmd.exe. Explicitly configuring a command interpreter grants its own
command-language semantics and should not be used for untrusted URI input.

URI scheme matching is ASCII case-insensitive; configuration owns subsystem
matching. NUL is rejected. Unix native bytes are preserved. Windows arguments
use the shared lossless UTF-16 adapter; malformed local byte encodings fail
rather than undergoing replacement.

## Resource limits

| `[uri-rust]` key | Default | Maximum |
| --- | --- | --- |
| `MAX_URI_BYTES` | 65536 | 1048576 |
| `MAX_HANDLER_BYTES` | 4096 | 65536 |
| `MAX_HANDLER_ARGS` | 256 | 4096 |
| `STOP_GRACE` | 5 seconds | 1 hour |

Counts and grace must be positive. The argument limit includes the configured
executable, before the final URI. Native command-line/environment limits remain
additional platform constraints. Ordinary URI has no added whole-operation
limit; QR supplies a fixed original scan-and-dispatch deadline.
