# Native QR and barcode providers

This Unix adapter uses standard libpng1.6 simplified read and public libzbar
scanner/processor APIs through one confined POSIX loader module. It never calls
a GNUnet C library. No additional registry crate, decoder subprocess, private
wire, fake symbol, downloaded provider or silent fallback is introduced. The provider/device must be available in the deployment. Unsupported
camera/display/platform and missing exported API return failures.

`scan_png` borrows complete bounded encoded input, checks decoded dimensions,
decodes grayscale+alpha, strips alpha in place, then gives the Y800 image
to ZBar. This preserves the fixed producer's alpha-strip intent rather than
compositing transparent code pixels on a new background. The first symbol
is copied with its public exact length and raw symbology. It is not URI authority;
the ordinary shared URI selector must validate it before handler admission. `Symbol` has no Debug/Display of its bytes.

`Camera` selects an device, requests dimensions and optional native display,
and uses a nonthreaded processor on the calling thread. Each `step` has a finite
1..100ms native poll interval. Real image callback dimensions are checked; native
camera size requests are advisory and can be ignored by the device. Result-set
references obtained from processor_get_results are released exactly once after
copying. Callback registration is retired before its stable original owner drops. Explicit clock-free close attempts deactivation/display close and always destroys
the same processor, retaining both independent fallible cleanup return values. A void destroy does not prove hardware/driver work has completed.

Defaults: encoded PNG16MiB, width/height8192, pixel count16MiB,
symbol65536 bytes, camera poll25ms, requested camera640x480. PNG's in-place GA
staging retains at most twice the configured pixel count in bytes; grayscale is
compacted without another pixel buffer. Encoded, GA and symbol allocations check
Vec capacities against their explicit bounds. Maxima are256MiB encoded,
32768 per dimension,256MiB pixels and1MiB symbol. Small loader/API/native owners
are additional fixed-count metadata. This is not a whole-process RSS or opaque
provider allocation bound. A camera can allocate internally before reporting its
dimensions. Synchronous loader/decoder/device/close calls are not claimed
preemptible; the caller's original guard runs around each acquisition/native
operation, including loader attempts and symbol lookup.

Only provider.rs permits standard native unsafe. The API/opaque handles retain
their original library owner. libpng simplified reads handle their own C error
jumps; no Rust stack frame is crossed by a manually installed longjmp callback. All non-provider layers are safe Rust.
