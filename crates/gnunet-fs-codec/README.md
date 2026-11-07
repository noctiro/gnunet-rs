# Metadata zlib codec capabilities

This package implements `gnunet-fs::metadata` codec traits in pure Rust using
the pinned `miniz_oxide` provider. It has no C zlib, libgnunet, file or network
backend.

The default `Inflate` capability owns inline decoder state and borrows caller
output. It verifies the zlib header, complete member and Adler32, rejects
trailing bytes and unprovided dictionaries, and distinguishes output exhaustion
from incomplete input. Each invocation resets the prior stream state, including
after failure. Its `Progress` reports output bytes; the metadata envelope
core additionally checks that this equals its declared decompressed size. Raw DEFLATE and gzip are not metadata zlib streams.

`Compressor` exists only with the explicit `alloc` feature. Construction performs
heap allocations for miniz's boxed state; this capability must not be
advertised as allocation-free. The caller owns and reuses the codec object. Each call resets that existing state and emits one complete zlib member into
caller output. Compression level9 does not require byte identity with C zlib. No codec operation silently selects a C implementation or an unavailable
capability.

Both providers treat output as scratch on failure. They never receive or write
outside the caller-supplied slice, but its written prefix is not a validated
artifact after an error. The metadata core applies its separate wipe/validation
and final-output atomicity policies.

The tests distinguish default-feature inflation of independent stored/fixed
fixtures from allocation-enabled compression roundtrips and reset/retry
checks. Those Rust tests are not official C interoperability receipts, physical
MCU memory measurements or a complete FS/Node acceptance claim.
