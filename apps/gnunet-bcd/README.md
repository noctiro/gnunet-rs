# gnunet-bcd

Serve GNS business-card forms and generate PDF cards or QR PNGs on Linux, macOS,
FreeBSD and Windows. Rendering uses a fixed escaped template with selected native
TeX Live pdflatex and Ghostscript executables.

## Usage and routes

```sh
gnunet-bcd [-c CONFIG] [-p PORT]
```

Standard PROGRAM provides configuration, logging, help and version options.
The default port is 8888. Numeric BIND_TO selects the listener; IPv6 explicitly
admits dual-stack operation. Startup creates the HTTP listener; tools run only
for rendering requests.

| GET route | Behavior |
| --- | --- |
| `/`, `/full` | Simple/full contact forms |
| `/submit/simple`, `/submit/full` | Validate typed GNS zone key and generate a card |

Presence of `gnspng` selects QR PNG conversion regardless of its value. HEAD
serves simple-form headers without rendering. Other methods return 501, unknown
GET routes 404 and malformed typed forms 400. Missing tools and failed rendering
return 500; PDF-only requests do not require Ghostscript. Attachments are
`gns-business-card.pdf` (`application/pdf`) or `gns-qr-code.png` (`image/png`).

## Configuration

[Configuration](CONFIGURATION.md) selects absolute tool paths, private temporary
storage and finite connection, memory, work and deadline bounds. Windows starts
executables directly with original process handles; Unix uses the shared native
spawn helper. Tools are not installed or downloaded by the server.

## Shutdown and ownership

Native stop subscriptions and original parent control stop admission and drain
independent jobs. Original process exit, artifact observations and temporary-name
cleanup remain separate. Jobs retain their quota during unresolved retirement.
A lost wait right or failed original-directory cleanup produces failure and keeps
the unconfirmed path in diagnostics. [Host contracts](../../adapters/bcd-std/README.md)
describe application resource bounds and native blocking boundaries.
