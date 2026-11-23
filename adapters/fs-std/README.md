# FS host

Native files, storage clients, task recovery and peer providers for the GNUnet FS
engine. Public contracts are documented in the [API reference](API.md).

| Area | Main interfaces |
| --- | --- |
| Local content | `Repository`, reusable `Buffers`, descriptor-anchored `OutputDir` |
| Service requests | `ipc::Client`, block lookup, LOC signing, indexing and unindexing |
| Transfers | Authenticated file/range/tree download and full/indexed publication |
| Search | Keyword/namespace sessions, probes and retained observations |
| Durable tasks | Download, publication, search, probe and unindex tasks; bounded catalog worker |
| Providers | DATASTORE, CADET, GAP/CORE and DHT serving/routing |
| Metadata | Shared extraction, keyword preparation and offline inspection |

The `service` feature enables native FS requests; `network` adds publication.
The facade exposes local hosts through `official-fs`, clients through
`official-fs-client` and publication through `official-fs-network`.
Clients, publication, namespace keys, task catalogs, automatic sharing and
download/search/probe/unindex recovery share their Unix and Windows implementation.
Provider integration remains in the
[open platform work](../../IMPLEMENTATION_STATUS.md).

## Native storage

`Repository`, input opening and buffered file/directory encoding and reading
share their content logic on Unix and Windows. The repository separates
[shared admission](src/store/repository.rs) from [native operations](src/store/native.rs).
`Insert` distinguishes new and existing objects and carries `Retention`:
volatile backing or a synchronized file with a `DirectorySync` observation.
The [native directory barrier](../native-std/API.md#anchored-filesystem-operations)
reports the result separately from data-file synchronization. Cleanup errors
retain the completed retention separately.

Anchored plaintext output shares [path validation](src/output/path.rs),
[publication](src/output/observed.rs) and original directory owners on Unix and
Windows. `ReadFile::directory_sync` is present only after real file synchronization
and checked final naming; generic caller writers make no filesystem observation.
Windows output refuses device names, streams and spellings rewritten by Win32.

[Input roots](src/input_tree.rs) share original-handle child opening on Unix
and Windows. Bounded extraction snapshots live in
[input_tree/frame.rs](src/input_tree/frame.rs) and consume native enumeration,
full identities and change fences. Local names remain native; publication
metadata checks protocol encoding separately. Source fingerprints and automatic
sharing catalogs use tagged complete identities. Automatic sharing rechecks the
original catalog before acting on a scan or admitting a publication task.

Built-in extraction uses the same file probe on every host. It recognizes
common MIME signatures, HTML fields, image dimensions, JPEG header comments,
ID3 audio tags and image metadata from TIFF, BigTIFF, Olympus ORF,
Fujifilm RAF, Minolta MRW, Panasonic RW2 and Canon CRW. TIFF-based RAW
identification uses the CR2 header, DNG version and known compression values.
The shared EXIF reader handles standard camera, exposure and GPS fields,
JIS comments, and Canon, Fujifilm and Nikon type 3 MakerNotes. JPEG, EXV sidecars,
TIFF, ORF, PNG, PSD, PSB and JPEG 2000 supply IPTC and XMP. PGF uses metadata
from its embedded image or EXV carrier. GIF, WebP and PDF also supply XMP.
JPEG XL supplies dimensions and orientation, plus XMP and EXIF from plain
and Brotli-compressed boxes.
HEIF and AVIF supply image dimensions, orientation, EXIF and XMP from
primary items and supported tracks. Canon CR3 supplies camera, exposure and
GPS fields from its Canon directories, frame metadata from CTMD tracks and
XMP from its Adobe UUID box.
PDFs supply document information, version, page count and dates
through classic cross-references and structural streams using Flate, LZW,
RunLength, ASCIIHex or ASCII85 filters. Standard security revisions 2–6 use
the implicit empty user or owner password. A locked document contributes
its MIME type.
Positioned reads share one probe budget and avoid scanning page and image payloads.
ID3v1 uses a fixed tail read when applicable. Optional fields must fit the
publication's metadata byte and item limits. The [GNU libextractor provider](../extractor-std/README.md)
can supply additional formats through the original file descriptor.

The [task WAL](src/durable/store.rs) shares bounded framing, recovery and
unknown-write fencing. It uses native entropy, private directories, single-link
files and physical exclusive locks. `Store::directory_sync` reports the actual
root/parent naming barrier separately from synchronized WAL contents.

## Ownership and effects

Operations retain their source, deadline, partial effects and cleanup outcome.
Unknown storage mutations are not automatically replayed. Output uses held
parent descriptors and no-clobber commits. A verified range does not certify
unselected content; a local write does not certify remote delivery.

The [index queue](src/server/index_worker/queue.rs) serializes admission and
closure without retaining senders in capacity waiters. Stopping or losing a
client discards its unsubmitted index work; already queued jobs retain their
original result and settle before the index thread joins. Weak resolution ports
cannot reopen the index or keep it alive after shutdown. FIFO capacity permits
bound queued jobs and prevent new readonly requests from starving waiting
registrations, removals or enumeration.

The shared [operation limit](src/time_limit.rs) retains the original
source-clock target and, for finite operations, one native allowance captured
before clock registration. Progress, block changes and reconnects cannot renew
it; an explicit outer native target can only tighten it. FOREVER remains
unlimited unless an outer native bound was selected. Directory downloads and
full/indexed tree publication pass the same stop target to every child operation.
Durable runs include WAL setup and revalidation; native targets are not persisted.
Search retains one limit across its query graph, reconnects and staged results;
expiry closes the original MQs. Each query keeps its own reconnect backoff. A new
verified result resets that query's backoff and leaves its deadline, seen list
and matched keywords intact. Historical replay and independent completed
probes preserve their own clock observations. After authenticating and admitting
a journaled advertisement, replay seeds the original query's official seen list
with the hash of the complete signed block. Historical hints are evictable so
new results can use the original bounded client capacity. Construction registers
the clock. Native timers are created on first poll. The persistent publication runner shares
one limit across verification, index registrations and PUTs. Synchronous provider work cannot be forcibly interrupted. Actual storage
receipts, partial output and uncertain effects remain independent observations.

See the [CLI guide](../../apps/gnunet-cli/README.md) and
[FS service configuration](../../apps/gnunet-service-fs/README.md).
