# QR configuration

## Native providers

`[qr-rust] LIBPNG` selects a libpng1.6 provider; `LIBZBAR` selects a ZBar provider.
Explicit paths must be absolute. Windows requires LIBZBAR for both inputs and
LIBPNG for PNG input. Libraries, dependencies, exports and loader context are
trusted local configuration, never selected by a decoded symbol.

```ini
[qr-rust]
LIBPNG = C:\GNUnet\providers\libpng16.dll
LIBZBAR = C:\GNUnet\providers\zbar.dll
```

These paths illustrate an operator-owned provider layout. No provider is
installed or downloaded by the command. Unix omitted paths select the standard
platform library basenames with NOW/LOCAL loading.

## Inputs and bounds

`--png FILE` uses lossless native path decoding. `--device DEVICE` selects an
opaque native ZBar device identifier; otherwise `DEVICE` supplies it. Unix
camera default is `/dev/video0`; Windows requires explicit selection. Device
identifiers admit at most 4096 non-NUL bytes. `--no-display` overrides `DISPLAY`,
which defaults to YES.

| `[qr-rust]` key | Default |
| --- | --- |
| `INPUT_BYTES` | 16777216 |
| `MAX_WIDTH`, `MAX_HEIGHT` | 8192 |
| `MAX_PIXELS` | 16777216 |
| `SYMBOL_BYTES` | 65536 |
| `CAMERA_POLL_MS` | 25 |
| `CAMERA_WIDTH`, `CAMERA_HEIGHT` | 640, 480 |
| `TOTAL_TIMEOUT` | 5 minutes |

`--timeout` overrides TOTAL_TIMEOUT; it must be positive, finite and at most one
day. Provider limit maxima are defined by [Limits](../../adapters/qr-std/src/types.rs).
The same whole deadline covers decoding and handler dispatch. Shared
[URI limits and stop grace](../gnunet-uri/CONFIGURATION.md) also apply.
