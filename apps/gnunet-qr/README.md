# gnunet-qr

Decode a QR/barcode from a PNG or selected camera and dispatch its original URI
through the shared configured GNUnet handler on Linux, macOS, FreeBSD and Windows.

## Usage

```sh
gnunet-qr [-c CONFIG] --png FILE
gnunet-qr [-c CONFIG] --device DEVICE [--no-display]
```

Select one input. Standard PROGRAM supplies configuration, logging, help and
version options. The decoder returns bounded original symbol bytes; the shared
[URI selector](../../adapters/uri-std/README.md) validates them before launching a
handler. Handler stdio is inherited. Decoded URI/pixel buffers are not logged.

## Configuration

[QR configuration](CONFIGURATION.md) selects trusted native libraries, device,
display and memory/time bounds. Windows requires explicit absolute libpng/ZBar
DLL paths and an explicit device when using camera input. Unix may select the
standard provider basenames through its trusted loader context.

## Ownership and cancellation

One original deadline covers file/device acquisition, decoding and handler exit.
The nonthreaded camera is retired before handler admission. Native stop and
parent control retain independent camera and child cleanup failures. Provider
absence, decode failure or no symbol is an error. Synchronous native calls remain
blocking boundaries; [provider contracts](../../adapters/qr-std/README.md) describe
buffer, callback and library lifetimes.
