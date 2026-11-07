# Automatic sharing

The application implements `gnunet-auto-share` using the existing FS
publication API. It adds no protocol, native service, C FFI, hidden Resolver or
subprocess publisher.

The standard PROGRAM takes exactly one directory and implements the active
`-a/--anonymity`, `-p/--priority`, `-r/--replication`,
`-d/--disable-creation-time`, `-D/--disable-extractor`, and `-V/--verbose`
options. Shared PROGRAM supplies config/help/version/log options, the actual
selected logger, configuration defaults, scheduler and same SharedClock. Defaults match the active publisher: anonymity1, priority365, replication1,
indexed regular files, expiry at UTC Jan1 of current source year+2. Calendar
conversion uses the approved existing `time=0.3.55` dependency, never an implicit
second clock. The one optional configured `[auto-share] USERNAME` is applied
before directory, catalog, runtime worker and native source construction.

Extraction selection is owned configuration passed to that same worker. `[FS] EXTRACTORS` is actually consumed; `--extractors CONFIG` overrides it. `-D` disables format extraction and automatic KSK extras. The exact configured
`-` value disables only the provider and built-in format probes; safe filename
and selected creation-date metadata and their automatic KSK tasks remain enabled. These controls are deliberately separate. Missing EXTRACTORS with no selected
library uses the bounded built-in profile; this is not libextractor's default
plugin list. Select an absolute standard native library with
`[fs-rust] EXTRACTOR_LIBRARY` or `--extractor-library ABSOLUTE-LIBRARY`. Configuration filenames use the ordinary configuration expansion; the command
line library argument is an explicit absolute native path. With that library,
missing EXTRACTORS requests its default plugins; a present configuration string
is passed unchanged to the standard plugin selection. A present non-`-` value
without a selected library fails before the worker starts; it is never silently
ignored. Missing libraries, symbols, callback bounds and observed provider
errors do not fall back to built-in success. Either provider-off selection avoids
resolving or loading an unused library path.

The fixed C path supports this distinction: a nonnull empty metadata object
serializes as a valid 12-byte v2 header. The helper sends that header; scanner
metadata-tail length is then positive, so it inserts safe filename type180 and
derives its KSK. Only the separate CLI disable flag clears the automatic URI in
the final publish inspector. This does not assert that every scanner message has
metadata or that an empty native callback stream proves successful parsing.

Only the existing joined file worker creates, uses and explicitly closes a
provider; the PROGRAM/main/Resolver own no provider, extra worker or subprocess. The original version snapshot, same-File identity checks, metadata/keyword
budgets and original stop/operation bounds remain in force. Native plugin
internal memory and blocking calls are not covered by a Rust RSS or forced
preemption claim. Provider void return with no callback cannot prove that every
plugin parsed successfully; output facts remain metadata and actual
accepted publication tasks. This source increment has not loaded a provider or
run the ordinary command.

A bounded worker builds sorted descriptor-anchored stat snapshots, prepares each
stable top-level file/subdirectory, and rechecks that exact original snapshot
before and after the actual `auto_prepare` call. A changed input cannot be
recorded as the older version. Scans never read plaintext content; preparation
uses the existing indexed/tree/metadata/KSK implementation. Symlinks and
special objects are refused, not followed outside the selected directory. No incomplete scan is treated as a deletion. C and Rust `.auto-share*` private
names are excluded from top-level publication.

Every Prepared content Task, KSK Task, KSK URI/target, and metadata
name/relative object/target/body length/body digest is recorded before any native
submission. Recovery consumes the complete original collection, verifies actual
Task ids and artifacts and strict standard-v2 metadata, and checks all completed
Task states before trusting a completed catalog row. Aggregate task WAL bytes
are checked before opening/allocating the full recovered collection. Content
and all KSK Tasks run serially through FS/DATASTORE sources and their
original replies. A group uses one fixed logical/native operation target. A successful catalog row follows all genuine Task completions; URI output does
not promise network replication or continued remote availability.

Unknown writes, orphan intents, fenced WALs, or failed restoration isolate that
original version/path. A changed input cannot evade this fence by creating
another task. Known safe partial/refused work retries the same Task. No retained raw response projection can mint a NativeResult or authorization. Deleted input stops new work; no network erasure/unindex success is invented.

The new `.auto-share-rust` namespace is a marked, exclusively locked FS-owned
store. Its immutable header binds the canonical watched root's device/inode. Only fresh creation initializes a missing canonical image; an existing
marked directory missing that image fails closed. Dynamic catalog state uses
bounded checksum/generation images with create_new0600, file sync, atomic rename
and parent sync. Failed/uncertain local commits fence the owner. Temporary
cleanup checks the observed inode and never adopts a temporary image as
committed. It assumes the private namespace is not concurrently replaced by a
hostile same-UID writer; separate check+unlink is not an atomic inode-unlink API. There is no C-state import or old-format migration.

`Stop` wakes the original owner. Signals, original parent control, native/source
bounds, selected-log/stdout failure, Resolver failure, and PROGRAM scheduler
failure all retain and drive the SAME publication future through source
retirement and worker shutdown/join. The Resolver disconnects afterward. Independent publication/storage/worker/diagnostic/scheduler/disconnect failures
are retained. Dropping an observation is not reported as cleanup. Synchronous
OS filesystem calls and ordinary bounded stdout writes may block; this code
does not pretend to force-cancel them or mutate inherited OFD flags.

Default bounds are explicit: 1024 historical top-level names, 4096 versions,
65536 scan objects, depth64, 8MiB name workspace, 256MiB input total, 4h maximum
scan spacing, 2s stability, 60s retries, 5min/group, 24h/source allocation,
64GiB logical retained-file quota with 8GiB pre-reservation/version, 64MiB group
plan/recovery-WAL budget and an 8MiB catalog image. Reservations do not allocate
physical disk. Completed/superseded files remain retained and quota-charged;
there is no silent GC of uncertainty. Exhaustion is an explicit error. The
`[auto-share-rust]` resource keys are `ENTRIES`, `VERSIONS`, `FAILURES`,
`SCAN_OBJECTS`, `SCAN_CHILDREN`, `SCAN_DEPTH`, `NAME_BYTES`, `SCAN_NAME_BYTES`,
`STABILITY`, `MIN_SCAN`, `MAX_SCAN`, `RETRY`, `OPERATION_TIMEOUT`,
`SOURCE_LIFETIME`, `RETAINED_BYTES`, `VERSION_RESERVATION`,
`EXTRACT_PROBE_BYTES`, `METADATA_ITEMS`, `METADATA_BYTES`, `KEYWORDS`,
`KEYWORD_BYTES`, `KEYWORD_TASKS`, and `GROUP_PLAN_BYTES`. Durations use the
standard configuration parser and must be positive and finite.

C differences intentionally retained as source facts: MIN_DELAY is one minute
although its comment says one second; the C stat fingerprint overwrites one
array cell and hashes an uninitialized one, which Rust replaces with sorted
typed stamps; C auto-share passes `-d` although the pinned publisher accepts `-E`
for adding dates and no `-d`. Here `-d` actually disables creation metadata. No C private ABI/storage or those internal defects define a new wire protocol.

Existing lower FS paths retain their actual
behavior, including explicit clock-regression errors.
