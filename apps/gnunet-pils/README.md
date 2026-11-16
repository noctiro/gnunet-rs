# gnunet-pils

Observe the public local peer identity from GNUnet PILS on Linux, macOS, FreeBSD
and Windows.

## Configuration and examples

The selected configuration supplies `[pils] UNIXPATH` or its TCP endpoint.

```sh
gnunet-pils -c gnunet.conf --once
gnunet-pils -c gnunet.conf --duration-ms 60000
```

`--once/-1` prints one verified 52-character identity and exits after flushing.
Continuous mode prints each observation within the finite duration. Standard
PROGRAM options select logging, help and version. See the
[shared command reference](../../adapters/peer-tools-std/README.md) for endpoint
overrides and explicit signature profiles.

## Ownership and results

The command reads public service announcements without loading a private key.
A connection is not an identity observation. Original parent/native stop and
logging failures retire the same client and Resolver; a finite canceled action
cannot claim an output result. Stdout and cleanup failures affect the exit code.
