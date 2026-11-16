# gnunet-scrypt

Offline GNUnet NSE proof mining on Linux, macOS, FreeBSD and Windows. The
historical executable name is retained; the algorithm is GNUnet Argon2id13
(t=3, 1024 KiB, p=1, 64-byte output).

## Usage and configuration

```sh
gnunet-scrypt [-c CONFIG] [-k KEYFILE] [-o PROOFFILE] [-b BITS] [-t DURATION]
```

Standard PROGRAM supplies configuration, help and logging. Omitted `-k` selects
`[PEER] PRIVATE_KEY`; omitted `-o` selects `[NSE] PROOFFILE`. Zero/omitted `-b`
selects `[NSE] WORKBITS`; the selected range is 0–511. Configured zero disables
mining without publishing a proof or printing a found-proof line. Extra operands
are rejected.

`-t/--timeout` delays each unfinished ten-candidate round; it is not a whole
operation timeout. Zero yields immediately; FOREVER waits until stop.
`--total-timeout DURATION` fixes the whole-operation bound before key/store
preparation; zero/FOREVER is unbounded. `--max-hashes COUNT` bounds completed
hashes, with zero unbounded. Hashes, rounds, checkpoints and wakes never renew the
whole bound. Each completed hash yields cooperatively.

## Keys and proof files

The shared PILS loader admits exact private raw32 Ed25519 seed files using native
owner/access, link and stable-read checks. It may create an initially absent key
through private staged publication. Malformed, unreadable or disappearing inputs
do not authorize replacement. The initial secret owner is erased before mining;
only its direct Ed25519 public32 snapshot enters the proof work.

Proof artifacts contain exactly eight native-endian bytes, matching the C
utility's raw8 representation. Hash input is those original8 bytes, the public32
and the existing `gnunet-nse-proof` salt. Missing proof starts at counter0;
malformed, symlinked or short/long proof files fail.

The shared [proof store](../../adapters/nse-std/src/proof.rs) holds the original
private namespace and cooperating-writer lock. Atomic replacement, file sync,
readback and directory synchronization remain distinct observations. Windows
reports the naming barrier as Unavailable; successful file publication does not
imply power-loss durability of the directory entry. Historical C writers do not
honor the Rust lock; callers exclude uncooperative namespace changes.

## Cancellation and persistence

Native stop subscriptions and parent control register before key/store setup and
remain attached through mining. Native file, entropy, hash and stdio calls are
synchronous; stop checks bracket these boundaries. Parent EOF alone is not stop.

The current cursor is checkpointed every 1000 hashes, on a valid candidate and
on stop/error with unsaved progress. Final checkpoint errors remain independent
of the initiating failure. An uncertain publication is never blindly retried or
reset to counter0. Counter MAX is verified once before exhaustion is reported.

A found proof is committed before `Proof of work found: N!` is written. Partial
stdout, a late stop, persistence or logger failure still makes the result fail
while preserving actual progress and publication facts. Progress logging contains
public counters; key bytes are not logged.
