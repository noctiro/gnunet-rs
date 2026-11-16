# gnunet-ecc

Offline GNUnet Ed25519 seed-file inspection and generation, using the shared
PROGRAM configuration and logging interfaces on Linux, macOS, FreeBSD and Windows.
Files contain consecutive raw 32-byte seeds, with no wrapper or side database.

## Commands

| Selection | Behavior |
| --- | --- |
| `-p FILE` | Print public identities as canonical Base32GNS lines |
| `-x FILE` | Print public hexadecimal identities with the `HEX:: ` prefix |
| `-P FILE` | Explicitly print private seeds as Base32GNS |
| `-i [-e COUNT] FILE` | List indexed public identities on stderr; default limit is UINT32_MAX |
| `-g COUNT FILE [PREFIX]` | Generate and publish COUNT seeds, optionally matching a public Base32 prefix |
| `-E` | Print fresh ECDHE examples, including private material and SHA512(X25519) shared values |

Operation precedence is E, i, positive g, x, p, P. Other selections reject unused
operands. The public prefix admits 0–52 symbols and the shared GNUnet Base32
aliases; at most 256 public bits participate. Private seed and encoded scratch
buffers are zeroized when their owners retire. Only `-P` and `-E` print secrets.

```sh
gnunet-ecc -g 2 ./peer.keys
gnunet-ecc -p ./peer.keys
```

## Configuration and bounds

Standard PROGRAM options provide `-c/--config`, `-L/--log` and `-l/--logfile`.
`--timeout DURATION` bounds the whole operation; zero selects `[ecc-rust]
TOTAL_TIMEOUT`, and a final zero/FOREVER is unbounded. `--max-attempts COUNT`
bounds entropy candidates; zero selects `[ecc-rust] MAX_ATTEMPTS`, with a final
zero unbounded. `[ecc-rust] WORK_UNITS` selects the cooperative work budget,
default 32, range 1–65536. Neither bound renews between records, candidates,
publication or output writes. Native stop
subscriptions and original parent control use the shared client startup path.
Filesystem, entropy, crypto and stdio calls remain synchronous native boundaries.

## File ownership and publication

The selected parent must be an existing ordinary directory; final symlinks and
nonregular inputs are refused. Reads retain the original native file and check
its full identity, size and change times against the selected directory entry.
Empty inputs and incomplete raw32 records fail.

Generation requires a process-user namespace without foreign writes. It streams
into an exclusively created private sibling: Unix mode 0600 or a Windows private
DACL. The selected target must be absent or an unchanged empty/raw32 regular
file. After file sync, publication atomically replaces that authorized target or
creates an absent name with a no-clobber hard link. Operations use the held
original directory and file; unsupported native operations retain their error.
The caller excludes concurrent administrative namespace changes. Metadata checks
are observations, not an inter-process compare-and-swap.

Publication admission is retained before the native call. A later failure may
coexist with a visible target; it never authorizes replay or rollback. Temporary
link removal and original writer close are attempted independently of stop/time
checks, with both failures preserved. Cleanup never deletes the published target.
A retained sibling path is diagnostic information, not deletion authority.
Directory synchronization is recorded separately: Windows reports Unavailable,
which is not a durable naming-barrier receipt.

## Module boundaries

[Key operations](src/keys.rs) own cryptographic and output policy.
[Reader](src/keys/reader.rs), [namespace](src/keys/namespace.rs) and
[staging](src/keys/staging.rs) isolate original-object reads, directory selection
and streaming publication over the shared native filesystem adapter.
