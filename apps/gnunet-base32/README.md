# Base32 command

`gnunet-base32` encodes raw stdin using the canonical GNUnet Crockford alphabet.
`gnunet-base32 -d` decodes stdin to raw stdout. Help and version exit before
acquiring conversion I/O. Linux, macOS, FreeBSD and Windows share the same codec
and streaming conversion loop.

## Byte format

Output has no added newline or terminator. Decoding accepts lowercase and the
O/I/L/U aliases supported by the [record codec](../../crates/gnunet-gnsrecord/).
It rejects whitespace, `=` and invalid trailing lengths. Empty input succeeds.
Valid encoded lengths modulo 8 are 0, 2, 4, 5 and 7; unused final low bits follow
the official codec. A single invalid character is rejected.

```sh
printf hello | gnunet-base32
printf D1JPRV3F | gnunet-base32 -d
```

## Streaming and private spool

Fixed input/output arrays retain at most seven carried input bytes. Encoding
writes complete groups incrementally. Decoding validates the entire input
before writing stdout, storing decoded groups in a private disk spool rather
than accumulating them in memory. The spool is created only for the first
nonempty decoded group.

The shared native filesystem adapter creates a private directory and file
relative to retained directory handles. Unix uses owner-only permissions;
Windows uses a protected current-user DACL with trusted administrative access.
Windows removes the original file link with [POSIX disposition](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex).
The original file identity and link count are checked. Its name and empty
parent directory are removed before conversion continues; the original open
file remains until validation, rewind and bounded output finish. No file path
is reopened. Unconfirmed or replaced entries are never deleted by guessed path.
Temporary storage follows the native temporary-directory selection.

Spool storage grows with decoded input and can fail. File operations remain
synchronous; cancellation cannot interrupt a kernel filesystem call. Cleanup
preserves independent namespace and consuming file-close errors. No durability
or secure-erasure guarantee is provided.

## Native I/O and cancellation

Unix duplicates and registers original pipe/terminal descriptors, retaining and
restoring their shared nonblocking flags. Regular files use bounded synchronous
I/O; unregistrable character devices use nonblocking I/O with a retry timer.
Independent flag changes are reported rather than overwritten.

Windows uses capacity-one binary workers without Unicode or newline conversion.
A canceled wait retains the original request. Shutdown ends admission and
observes pending transfers, flush and close under one three-second bound.
Read cancellation targets only the original input worker; it does not cancel
writes or prove that a pending native operation has finished.

Unix SIGINT/SIGTERM and Windows console termination cancel conversion. Malformed
decode exposes no stdout prefix; a later output error or cancellation can leave
valid output partially written.

## Exit status

Statuses are 0 for success/help/version, 1 for options/setup, 2 for stdin,
3 for malformed input, 4 for stdout, 5 for spool errors and 6 for cleanup-only
failure. Handled Unix cancellation returns 128 plus the signal; Windows native
termination returns 130. Diagnostics retain original and cleanup causes.
