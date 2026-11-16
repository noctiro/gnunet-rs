# GNUnet HELLO and PILS commands

This adapter implements the installed `gnunet-hello` and `gnunet-pils` commands
on Linux, macOS, FreeBSD and Windows through the official PILS and PEERSTORE
clients. Public identity and signatures come from the selected services.

## Process interface

`run(tool, startup)` consumes a fresh-process `ClientStartup` and returns the
actual process exit code. The executable captures inheritance before creating
configuration, logging or runtime owners. Errors before diagnostic selection
remain in `Result`; selected-Logger failures return a failure exit code.

One PROGRAM task owns the selected Reporter, original native stop subscriptions,
clients and explicitly driven Resolver. Export/signing, import and iteration
have separate modules. Normal exit and cancellation retire the original clients
before Resolver disconnect. Rejected or canceled tasks preserve independent
cleanup failures in one bounded shared slot per owner.

## Commands

`gnunet-pils --once` prints one verified 52-character public peer identity and
exits after its output flush. Without `--once`, it prints each observation,
including metadata refreshes, within the configured finite duration. Attachment
alone is not an identity result. Canceling a single-identity or export action before its output
completes fails; continuous observation can stop between complete outputs.

`gnunet-hello` requires exactly one action:

- `--export-hello/-e` prints the current public announcement as a canonical
  `gnunet://hello/` URL. `--binary/-b` selects the complete HELLO_URI frame.
- `--expiration/-E TIME` with export submits the original address snapshot for
  PILS purpose-7 signing under the exact observed identity. Output requires the
  matching verified signature, operation, physical epoch and current signer.
  Source loss does not replay the signing request.
- `--import-hello/-i` validates URL or binary stdin and drives PEERSTORE
  `hello_add`: exact-peer scan, newer-record comparison and, when necessary, one
  original REPLACE followed by STORE_RESULT. Output distinguishes an actual
  store from an existing newer record. Cancellation cannot retract a store.
- `--dump-hellos/-D` iterates the official HELLO namespace, verifies each record's
  peer/profile binding and grants one-record credit. It displays escaped public
  addresses and signature coverage. Successful ITERATE_END completes the list;
  a partial prefix does not. Stop uses the original iterator and a fixed grace.

## Configuration and examples

```sh
gnunet-pils -c gnunet.conf --once
gnunet-hello -c gnunet.conf --export-hello --binary > hello.bin
gnunet-hello -c gnunet.conf --import-hello < hello.bin
```

Standard PROGRAM options select configuration, logging, help and version.
Endpoints come from `[pils]` and `[peerstore]`, or explicit `--pils-socket` and
`--peerstore-socket` local paths. Windows paths use the native AF_UNIX transport.
`--duration-ms` accepts 1..86400000, defaulting to 30000 for HELLO and 300000 for
PILS. `--io-slice-bytes` accepts 1..65535.

The default signature profile follows `[PILS] PROFILE`, or `reference029` when
absent. `--profile reference029|reference-0.29.1|deterministic` explicitly selects
another endpoint's profile. Invalid selections fail without fallback.
No private-key setting is required by either command.

## I/O and resource contracts

PILS retains at most two operations; PEERSTORE uses four operation rows and
256 KiB source/output budgets. HELLO address storage is bounded to 65423 bytes
and 1024 addresses. Binary messages are capped at 65535 bytes; text input/output
uses the codec's checked URL bound, including worst-case escaping. Input grows
from 4096 bytes only as needed, with a separate oversize sentinel. Import uses
one original zeroizing input and, for URLs, one bounded canonical message.

Stdin and stdout use synchronous standard handles in bounded chunks. Their
flags remain unchanged and no blocking worker is introduced. A synchronous
call can outlast its deadline; post-call checks classify that late return as a
failure. Accepted stdio bytes do not prove kernel exposure. Explicit output
flush is a separately guarded operation. Drop performs no extra flush or native
I/O; it retains the accepted-byte count when explicit flush was unconfirmed.
Ordinary Rust/OS stdio buffering still applies.

Diagnostics use the selected Logger. Its failure fences subsequent source and
I/O work; action, client, Resolver and unconfirmed-output facts remain separate.
The default HELLO signature authenticates metadata, with address coverage
reported separately by the [HELLO codec](../../crates/gnunet-hello/README.md).
Runtime qualification remains in the central
[implementation status](../../IMPLEMENTATION_STATUS.md).
