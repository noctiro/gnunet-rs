# gnunet-directory

Inspect local plaintext GNUnet directory artifacts, including downloaded `.gnd`
files. The command streams files through the shared directory, metadata and URI
codecs on Linux, macOS, FreeBSD and Windows.

## Usage

```sh
gnunet-directory [-c CONFIG] [--timeout DURATION] FILE...
```

Standard PROGRAM options supply configuration, logging, help and version output.
Every operand selects a local file. Native filename bytes and Windows UTF-16 code
units pass through the shared lossless argument adapter. Root and entry metadata,
URIs and filenames are escaped for display; binary values report their lengths.
Parsing validates local syntax, not source authenticity or embedded content.

## Configuration and memory

One input segment, one complete record and bounded decompression scratch are
reused across files. The command does not collect the whole artifact or all
entries. `[directory-rust]` controls per-record resources:

| Setting | Default |
| --- | --- |
| `RECORD_BYTES` | 2097152 |
| `CODED_METADATA_BYTES` | 1048576 |
| `PLAIN_METADATA_BYTES` | 8388608 |
| `METADATA_ITEMS` | 4096 |
| `URI_BYTES` | 16384 |
| `TOTAL_TIMEOUT` | Unbounded |

Increasing limits may increase memory use. Metadata field bounds must fit u32;
whole-file parsing retains checked u64 extent/work and platform usize entry bounds.
`--timeout` overrides the configured duration; zero selects configuration, and a
final zero/FOREVER is unbounded. The original canonical and native targets stay
fixed across files, records and output writes.

## Input, cancellation and errors

Public file symlinks may resolve normally. The resulting ordinary file remains
open; full native identity, size and modification/change times are rechecked
against its selected path around reads and at EOF. A changed, truncated, corrupt
or unreadable input fails. Unix nonblocking admission avoids waiting on FIFOs;
Windows admits regular disk files through the native file adapter.

Native stop subscriptions and original parent control share client startup;
parent EOF alone does not request cancellation. Work yields between bounded
units, while filesystem, codec and stdout calls remain synchronous.

A file failure allows other selected files to be inspected. A stop, logger or
stdout failure ends further admission. Already accepted reads, parse progress
and output bytes remain accounted; the first file error, terminal error and
independent final stdout-flush error remain separate. Any selected file failure
makes the process exit nonzero.
