# Native QR and barcode providers

Bounded PNG decoding and nonthreaded camera scanning through public libpng1.6
and ZBar APIs. The adapter uses the [shared native loader](../native-std/API.md#native-library-references);
its dependencies are standard codecs rather than GNUnet C services.

## Interfaces and provider trust

`unsafe scan_png(libraries, input, limits, before_native)` borrows complete encoded
input. `unsafe Camera::open(library, device, display, limits, before_native)` owns
one original processor. Callers trust the selected provider code, dependencies,
public C ABI and loader context. Explicit libraries use absolute paths. Unix
None selects standard basename search; Windows requires explicit DLL paths.
Native error sources, including bounded POSIX loader diagnostics, are retained.

`Symbol` owns bounded exact bytes and the actual symbology. It has no payload
Debug/Display implementation and grants no URI or source authentication. The
consumer validates URI selection before admitting a handler.

## Image and camera ownership

PNG dimensions are checked before allocating grayscale+alpha storage. Alpha is
stripped in place before a Y800 image is scanned; a new background is not
composited. Original native image loans and API owners retain their library
reference until the matching destruction/free call.

Camera uses a nonthreaded processor on the caller's thread. Each step has a finite
1–100 ms native poll interval. Requested dimensions are advisory; actual callback
dimensions are checked. Result-set references are released after copying. Callback
registration is retired before its stable original observation owner drops.

Explicit clock-free camera close attempts deactivation and display close, then
always destroys the original processor. Independent fallible results remain in
`Cleanup`; a void destroy supplies no separate kernel/device-idle receipt.

## Resource and cancellation bounds

[Limits](src/types.rs) bound encoded input, dimensions, pixels, symbol bytes and
camera polling. PNG staging retains at most two bytes per admitted pixel and
compacts grayscale without another image allocation. Provider objects add a fixed
count of native owners. Opaque provider allocations and kernel buffers are
outside the application's byte budget.

The original caller guard brackets acquisition, loader attempts, symbol lookup
and native operations. It never renews deadlines. Synchronous loader, decoder,
device and close calls cannot be interrupted inside the call. Libpng simplified
reads contain their own C error jumps; no Rust longjmp callback is installed.
