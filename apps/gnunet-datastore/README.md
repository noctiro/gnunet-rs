# gnunet-datastore

Dump and insert records through the configured GNUnet DATASTORE service. The
package is `gnunet-datastore-command`; its executable is `gnunet-datastore`.
Linux, macOS, FreeBSD and Windows share the same command and record processing.

## Usage and configuration

```sh
gnunet-datastore -c gnunet.conf --dump --file datastore.backup
gnunet-datastore -c gnunet.conf --insert --file datastore.backup
```

`-d/--dump` writes binary records to stdout and `-i/--insert` reads stdin.
`-f/--file` selects an expanded native filename instead. With both operations,
dump finishes and closes before insert opens the file or reads stdin. Standard
PROGRAM configuration, `-L/-l`, help and version options apply. A configured
DATASTORE service is required; positional arguments are rejected. Use file or
pipe redirection for binary standard streams.

## Backup format and service behavior

The official format begins with exactly 16 bytes `GNUNETDATASTORE1`, without an
extra NUL. Each record contains 92 bytes of network-endian metadata and its value:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | Value size |
| 4 | 4 | Block type |
| 8 | 4 | Priority |
| 12 | 4 | Anonymity |
| 16 | 4 | Replication |
| 20 | 8 | Absolute expiration in microseconds |
| 28 | 64 | Datastore key |

Values are bounded by the IPC maximum of 65,423 bytes. Zero-length values are
valid. Invalid magic, truncated records, excessive lengths and nonadvancing
UIDs fail explicitly. Dump requests ANY records from UID 0, advances to UID + 1
and terminates only on DATA_END. This is a live traversal, not an atomic
snapshot; the official DATA_END marker cannot distinguish some backend errors
from absence. Insert sends each complete validated record once and waits for
its original STATUS; negative status fails. A lost mutation is never replayed
automatically.

## I/O ownership and resource limits

The command uses [shared binary I/O](../../adapters/program-std/BINARY_IO.md)
with a 16 KiB scratch buffer per stream. File and standard-stream transfers run
on their original worker while the foreground continues observing stop,
deadline and Resolver events. File opening retains its synchronous native
blocking contract. New output files are private; existing permissions or ACLs
are preserved. Partial output remains on failure. Flush/close does not imply
an fsync or durable storage.

One DATASTORE request and reply are retained at a time. Dump borrows accepted
value bytes; insert reuses a zeroizing 65,423-byte value buffer and fixed header.
Content and opaque STATUS diagnostics are excluded from logs. Each record has
one 30-second logical and native deadline; progress does not renew it.

Stop or cancellation closes I/O admission without resubmitting an outstanding
transfer. A caller-owned cleanup registry outlives the cancellable PROGRAM
task. Each stream gets one separate one-second retirement deadline. Unobserved
or late transfers, actual flush/close errors, client/Resolver cleanup and logger
errors remain explicit failures. A stopped wait does not prove that an already
admitted native read or write had no effects.

## Source layout

`main.rs` composes PROGRAM; `early.rs` calls shared client startup capture and
`control.rs` subscribes to shared stop signals. `foreground.rs` composes the
operation and cleanup owners; `foreground/driver.rs` drives client, Resolver and
deadline events, `foreground/records.rs` handles backup traversal/insertion and
`foreground/outcome.rs` retains results and diagnostics. `format.rs` encodes
backup records; `stream.rs` owns bounded transfers and their retained cleanup.
