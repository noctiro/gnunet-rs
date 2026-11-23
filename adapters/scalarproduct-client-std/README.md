# Native SCALARPRODUCT caller

`gnunet-scalarproduct-client-host` owns one original computation MQ using the
installed official scalarproduct IPC. `Role::Alice` selects the ordinary
`scalarproduct-alice` section and `Role::Bob` selects `scalarproduct-bob`. ECC/Paillier service implementation is selected by configuration; the caller
adds no private negotiation, alternative frame or computation implementation.

## Public interface

Construct `Client::new(source, role, encoded_elements, limits, original_bounds)`
inside an entered Tokio runtime with IO/time enabled. The caller drives its
explicit Resolver. Elements are exact72-byte public key64/signed-BEi64
records; the wire Element helper produces them. Empty vectors and duplicate
keys are rejected. Input order and zeros are preserved. The vector
capacity and temporary uniqueness-index capacity are checked against an
explicit budget before native ownership is created.

The vector is adopted without an extra SDK copy. Only one encoded initial or
multipart frame is queued at a time. Original contained/total counts and role
select the standard640/641/642/643 frames. The immutable cursor advances only
on that original frame's whole write. The original vector allocation is
released after its last whole write. Local Written/input-complete receipts are
not service processing acknowledgements.

There is one physical epoch. Socket attempts may retry before attachment
within the same original bounds. After attachment, source loss, EOF, errors or
explicit close retire that original MQ without replaying input. Close is
clock-free. Dropping a progress future retains the same owner. The caller
receives a complete response before sending more input. Success requires all
original input frames to have written. A service failure may arrive sooner.
Retirement receipts retain actual byte counts for late writes and invalid or
partial response frames.

Response retains the exact raw status, independent signed range and original
GCRYMPI_FMT_STD product bytes. Only status2 is success; this SDK does not turn
any other word or local write into success. The SDK does not parse MPI values,
compute a scalar product, verify cryptography or authenticate the selected
service's mathematics. The raw response remains available through `as_wire`.

## Limits

Limits separately bound vector/count, frame, exact result and syscall sizes. The original source/operation deadline is immutable. Initial, each queued
frame and partial-response targets are finite native/canonical bounds clamped
to it, never renewed by partial progress. The caller may use the clock-free
native fence during unrelated waits. These finite storage profiles do not
constitute an exact RSS or performance measurement.

See the [computation services](../../apps/gnunet-service-scalarproduct/README.md)
for ECC and Paillier selection and the [implementation status](../../IMPLEMENTATION_STATUS.md)
for pending interoperability qualification.
