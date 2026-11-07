# gnunet-qr

Normal PROGRAM frontdoor for one scanned GNUnet URI. `--png FILE` selects
bounded regular PNG input; otherwise the camera profile selects
`--device DEVICE` or `[qr-rust] DEVICE` (default `/dev/video0`). `--no-display`
disables the optional native window. Standard PROGRAM configuration/logging,
GNUNET_ARGS and help/version apply. `--timeout DURATION` overrides the finite
total lifetime. Provider absence or unsupported camera/display is an error. The camera is physically retired before a configured URI handler can start.

The first QR/barcode symbol feeds `gnunet-uri-host::Settings::from_qr_uri`
and the same retained Dispatcher used by the ordinary URI PROGRAM. Only trusted
configuration is tokenized; original URI bytes form one final argument. There
is no automatically inserted `--`, shell, extra service, self-RPC, fake decode,
authentication claim or generated key. The handler inherits standard stdio. Real child exit0 is required; partial work, timeout, cancellation, cleanup error
or unknown child status cannot become success. Handler output belongs to the
configured child, not a new buffered protocol in this app.

The inherited parent control is captured at the unique first executable entry,
using the existing SERVICE-startup ownership boundary before Logger/runtime/FD
users. The narrow private capture function is the only app unsafe allowance;
standard native provider calls are isolated in qr-std/provider.rs. Unexpected
inherited listeners are explicitly retired and refused. POSIX signals are
additional stop sources, not substitutes for a transferred ParentControl.

One original canonical/native target is captured before image/provider work and
is reused through child dispatch. Actual regular input is opened nonblocking
before fstat, so a FIFO is refused without waiting for a writer. Encoded reads
and owned capacities are bounded; metadata/read changes do not renew the
target. Native device calls, filesystem and child spawn can still block in the
OS; no hard preemption or complete provider memory bound is claimed. Cancellation
retains original causes and independently attempts camera and child cleanup. Undrained child wait debt is an explicit failure. No hidden task or decoder worker
is spawned by this app (the ZBar processor is requested nonthreaded).

`[qr-rust]` keys INPUT_BYTES, MAX_WIDTH, MAX_HEIGHT, MAX_PIXELS, SYMBOL_BYTES,
CAMERA_POLL_MS, CAMERA_WIDTH, CAMERA_HEIGHT match qr-std's explicit limits. DEVICE selects raw native device bytes; DISPLAY defaultsYES; TOTAL_TIMEOUT
defaults5minutes, positive/max1day. Image/device names cap4096 bytes with no NUL. The shared `[uri-rust]` limits and STOP_GRACE apply to handler selection/cleanup. Native provider internals and inherited child stdio are not charged as owned
image buffers. URI/pixel/symbol contents are never Debug-formatted by this app.

The fixed active GNUnet build installs this public utility conditionally when
ZBar is available; PNG is additionally a selected PNG profile. Source presence
here does not prove installed providers, successful scanning/camera operation,
handler behavior, interoperability, or full GNUnet completion.
