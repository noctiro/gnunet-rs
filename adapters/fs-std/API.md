# FS host API

## Repository and output

`gnunet-fs-host` connects the official content/directory core to native storage. `BlockSource` and `BlockSink` separate retrieval/storage from encoding and
authentication. `Repository` stores raw ciphertext+tag blocks by query hash,
anchors directory descriptors, refuses object symlinks and commits immutable
objects without replacement. Create its root under an existing parent directory.
The shared repository uses descriptor-relative Unix or original-object Windows
operations. `Insert::{Created,Existing}` carries `Retention`; filesystem inserts
report file synchronization independently of `DirectorySync`. Windows directory
barriers report `Unavailable`. `CleanupAfterCommit` retains the successful
retention and the independent cleanup error. Failed publication or later
identity/barrier checks preserve an uncertain outcome.
Callers serialize stored-object mutation and administrative shard replacement or
removal. Ordinary concurrent immutable insertions use exclusive temporaries and
no-replace publication; the selected root may be renamed without redirecting it.

Reuse `Buffers` across imports and reads. Block/frontier buffers are bounded by
protocol geometry; record/decompression storage grows only when parsing needs it. `publish_directory` reads the prepared layout directly into block-sized buffers,
using logarithmic record lookup rather than allocating the entire directory. `visit_directory` lends authenticated parent entries to a recursive owner. Controlled operations sample cancellation between blocks.

`OutputDir` holds an existing output directory by its original Unix or Windows
handle. It rejects unsafe
relative names and symlink parents, creates private same-directory temporaries,
authenticates the entire file and syncs it before a no-clobber link. Existing
files stay intact. A known final commit and a cleanup failure remain distinct.
`ReadFile::directory_sync` records actual file synchronization and final-name
verification while preserving an unavailable directory barrier separately.
`CommitStage::FileSynchronized` carries that observation for artifact and error
reports. Windows rejects DOS device names, alternate streams and trailing
periods/spaces under its [native naming contract](https://learn.microsoft.com/windows/win32/fileio/naming-a-file).
Native temporary names have eight decimal digits to avoid case
folding and generated DOS short-name aliases; an equal final name is skipped.

`FileIdentity` retains complete platform-tagged fields, including Windows'
128-bit file ID. These observations do not authorize cleanup without the held
original or task-owner proof. Local task event version 3 and catalog format
`FSJCAT02` store complete identities and file/directory synchronization separately;
superseded formats are refused. GNUnet content, URI and IPC formats are unchanged.

The SDK feature is `official-fs`. The local CLI exposes `fs import`, `fs cat`,
`fs export`, `fs ls` and `fs pack`; these operate on the explicitly selected
repository.

## Service client

Enable the host `service` feature (SDK `official-fs-client`) for `ipc::Client`. It runs one FS service operation on a dedicated CLIENT connection: keyword
or D/I block search, LOC signing, index registration/listing and unindexing. Supply an `EndpointSource`, borrowed `Instance`, official `Request`, resource
limits and one absolute deadline from `source.clock()`. Call `drive()` until an
accepted event or terminal result. Received blocks remain encrypted; pass them
to the content reader to authenticate/decrypt their file tree.

The existing generic channel owns native connection selection and framing. Partial reads/writes survive dropped drive futures and observation timeouts. Cancellation closes the dedicated MQ; a partially written index mutation
retains its uncertain outcome. Search reconnection keeps the original query,
deadline and bounded local deduplication set. A newly accepted query-bound
block resets the delay for a future reconnect. The default RecentWindow policy
works around the pinned C service's continuation merge condition; Continued
supports the complete official wire form when the service merges it correctly. Search silence has no completion or not-found meaning. Index acknowledgements
do not assert durable datastore publication.

## Downloads and ranges

`Buffers::download` retrieves each D/I block, authenticates its complete
root-bound file tree and writes through AsyncWrite. It can read/populate a
verified local block cache. One source-clock deadline covers blocks, reconnects,
writer backpressure and flush. Queries reuse a dedicated MQ with a caller-selected
rotation bound; delayed replies are routed by their ciphertext query. Caller
control remains observable during pending source reads, destination writes and
flushes. Continue retains the original future and its partial cursor. Cancel
stops further polling and can leave an accepted prefix or unfinished flush;
reported progress counts only complete chunk deliveries.

Finite transfers also capture one native allowance from the initial remaining
duration before clock registration. A stalled source clock cannot strand a
pending connection, destination write or flush. Block progress and reconnects
retain that allowance. `DownloadOptions::native_deadline` and
`PublishOptions::native_deadline` let enclosing operations pass the same stop
target to child transfers; they can only shorten the child's derived allowance.
Directory download and full/indexed tree publication capture one target before
traversal and pass it through files, generated directories and namespace queries.
Durable runs capture it before WAL setup and keep it through revalidation and
new output. Process-local targets are omitted from manifests; an explicit resumed
run admits a new target from its caller's deadline. Explicit range/unindex native
bounds also only tighten the allowance. FOREVER remains unlimited when no outer
native bound was selected. Synchronous
filesystem and callback work cannot be forcibly preempted, and known native
receipts remain distinct from timeout or cancellation intent.
`OutputDir::download_file` uses the same fd-anchored commit/cleanup path as local
reads. Dropping a whole transfer closes its MQ and removes the private temporary.

`OutputDir::download_resumable` owns the selected filename and uses the GNUnet
partial-file layout. Data blocks occupy their plaintext offsets and index
blocks follow the rounded data extent. The original anchored file is locked,
and each reused block is checked against the expected CHK before use. A complete
existing file can be authenticated from plaintext alone. On success the file is
truncated to its exact plaintext length and synced. `IncompleteOutput` controls
whether a stopped transfer keeps or removes its eligible incomplete output.

`Buffers::download_range_to` retrieves only the selected data leaves and their
necessary index ancestors through the same native lookup and verified cache. Its asynchronous `network::range::RangeSink` borrows each `VerifiedChunk`, with
the original absolute file range, until that chunk's future completes. A sink
can write at those coordinates. `Buffers::download_range` instead concatenates
the selected plaintext at an `AsyncWrite` cursor and flushes once; it does not
create a sparse full-size file or make a durable-output claim. Both APIs are
available with `service`, without requiring publication or server features.

Supply half-open file coordinates and `network::range::Options` containing the
existing `DownloadOptions` plus the original native deadline, captured before
clock/setup work. The same canonical/native bounds cover cache, query, sink
backpressure and finish; neither is renewed for a block. Reversed or out-of-file
ranges are rejected. Existing whole-content admission limits still apply, and
the implementation reuses protocol-sized block buffers and bounded key storage. The ordinary CLI remains an entire-file download interface.

Successful `ReadRange::completion` is `Completion::Verified(VerifiedRange)` after
the selected tree authenticates and the sink accepts every chunk and finishes. This proves the selected range, without certifying unselected leaves or becoming
a `VerifiedFile`. A valid empty selection in a nonempty file returns
`Completion::EmptySelection`, with no authentication proof, source-clock query,
network/cache operation or sink call. Empty content selected as `0..0` still
requires its root block and normal sink completion.

Failures retain authenticated work separately from complete delivered
chunks and bytes. `Report::pending_delivery` identifies the original chunk whose
sink may have written a prefix before error/cancellation. A real `VerifiedRange`
survives a later cache or sink-finish failure; it does not establish output
completion. The original lookup is closed before returning. Dropping an
unfinished transfer also drops that owner, with no zero-output guarantee. Individual synchronous cache or sink calls cannot be forcibly interrupted while
blocked; the original hard bound is checked before subsequent polls.

## Probes

`Buffers::probe` retrieves one canonical data leaf and only its necessary index
path using the same native lookup, deadline and cancellation owner. It returns a
private native `Observed` containing an authenticated `VerifiedRange`, actual
write/work counts, one original bounded reply and accepted elapsed samples. It uses neither cache nor output and never returns a whole-file receipt. Explicit
empty leaf0 authenticates the empty root. `sample_leaf` uses bounded
rejection sampling over all leaves, including a partial tail. This differs
from the pinned C client's floor-based sampling heuristic, without changing the
SEARCH message or introducing internal C probe flags into the protocol.

`search::Session::begin_probe` binds a visible CHK/LOC result to one detached
single-use ticket, preserving its anonymity, loopback choice, signed LOC peer
and original source clock. `Probe::run` produces the private completion;
`finish_probe` consumes it into only that result/revision's observation book and
returns the full original native outcome. Foreign or stale completions are
returned intact. Result IDs carry a private session stamp. Books are allocated
lazily and charged to the retained-state budget; different results can be driven
concurrently without borrowing Session throughout I/O. Rank is `2*successes-trials`
and certainty is trials. An written query reaching its deadline is an
inconclusive trial. Setup deadlines, cancellation and typed errors are separate. These are in-memory observations; replaying a search WAL creates no fresh probe
or availability claim. `forget_probe` only invalidates local accounting after caller drops/stops
its detached future; it does not claim to close another live native owner. The CLI exposes `fs probe <fs-socket> <CHK-or-LOC> [timeout-seconds] [leaf-ordinal]`.

`search::automatic::Automatic` owns the original Session, schedules visible
CHK/LOC results incrementally, and multiplexes bounded original probe futures
fairly with search progress. It uses no hidden task, output/cache or replacement
Resolver. Buffers are allocated lazily and reused. Stop cancels and drains the
original probes and search MQs, preserving each native result and independent
cleanup error. This local scheduling policy does not add FS wire flags.

## Private task storage

`durable::store::Store` owns bounded, checksummed records and one physical
exclusive writer lock. Creation and reopen qualify private directories and
single-link lock/WAL files, using complete native identities. Each mutation
revalidates the original objects and selected directory entries. A registered
directory identity is checked before lock acquisition or recovery. Native entropy
supplies task IDs; no network format or path encoding is inferred from those IDs.

Recovery checks complete record framing and checksums, repairs only a qualified
incomplete tail and refuses complete corruption. Ambiguous appends fence the
original writer. Positional reads preserve its append cursor. These algorithms
are shared on Unix and Windows; native locks, ACLs and file access remain below
the storage layer. Windows lock files are not data channels while locked.

WAL synchronization and naming durability are separate observations.
`Store::directory_sync` retains the combined root/parent barrier: synchronized
only when both barriers actually succeeded, otherwise `Unavailable`. Windows
still synchronizes actual file contents and reports unavailable directory
barriers. Local path serialization preserves native spellings; peer filenames
require valid UTF-8 on Windows before output path validation.
Download, search and probe tasks expose the same observation through
`storage_directory_sync`, independently of output publication receipts.

## Task catalog and probe history

`jobs::catalog` registers original download, search, probe, unindex and prepared-publication
tasks, their random task identities, captured directory identities and bounded
scheduling policies. It reuses the private task WAL and exclusive writer fence. Discovery lists registered intent without pretending a stored status is live. Execution opens the original typed task with its expected directory identity
checked before lock/WAL recovery, then checks the task identity. Download
parents/caches use captured directory FDs; managed graph bindings are checked
against the opened graph. No catalog record can clear a task's native
Unknown, refusal, cancellation or uncertain local append.

`jobs::Worker` multiplexes a bounded set of original run futures with a stable
due heap, one original source-clock timer and a waking stop handle. It creates
no hidden task/Resolver and keeps no unbounded results list: callers receive
each complete typed outcome/failure through `next`. New-result/ACK/file quotas
pause the original owner; safely settled pauses/deadlines may be rescheduled
after an explicit delay. Failures stop that entry's automatic repetition. Tasks sharing a managed graph wait in a local resource queue. Stop or coordinator
failure forbids new dispatch, requests Pause and drains the original native
owners before returning the first coordinator error. A known accepted reply or
Unknown remains in its original typed result even if scheduling later fails. Dropping an undrained worker leaves interrupted task history, never a claimed
settled pause. One exclusive catalog owner controls policy; live multi-process
administration remains separate work.

The CLI exposes `fs jobs-create`, `jobs-add`, `jobs-list`, `jobs-enable` and
`jobs-run`. Each worker run uses a finite dispatch budget and bounded concurrency;
SIGINT/SIGTERM request cooperative drain. Individual job failures are events,
and a coordinator failure exits nonzero after draining. The registry and queue
are Rust-local organization; no GNUnet wire field or retry permission is added.

`probe_task::Task` persists original intent and terminal observations under an
exclusive WAL owner. Each terminal binds the random TaskID, manifest hash and
original Attempt, retains its authenticated-prefix FS frames and keeps
native failure/caller intent/local recording failure independent. Reopen
reauthenticates historical paths; it never reconstructs a native `Observed` or
restores historical success into a fresh Session Book. A private original receipt
can record exactly its original terminal after a local WAL failure, without a
new socket. Abandoning interrupted read-only intent counts no availability trial.

`automatic::Persistence` binds child tasks to immutable original root query
inputs, anonymity/loopback policy, canonical result URI and namespace query
scope. Ephemeral ResultId indexes are never persistent identities. The same
causal probe completes the original Session Book and independent task WAL; a WAL
failure retains both the native result and original recording receipt. Child
tasks are created/opened beneath the original set directory FD. Registration
and history have explicit bounds; no all-result transcript cache is retained. `fs search-probe` exposes this automatic/persistent composition, while
`fs probe-task-*` and the fourth jobs kind expose standalone observation tasks.

## Storage and publication

Enable `network` (SDK `official-fs-network`) for `Buffers::store_file`. It consumes
an idle dedicated native DATASTORE client, streams full D/I insertion, checks EOF
before the final root PUT, and counts only accepted store replies. Optional
reservations use exact tree byte/entry budgets. No possibly processed PUT is
automatically replayed: duplicates can add priority and replication scores. `StoredFile` preserves known acceptance when reservation cleanup fails. It makes
no new-vs-existing, durable-backend or remote-replication claim.

`Buffers::store_indexed_file` hashes the original descriptor, obtains a real
FS index acknowledgement, and reuses the streaming encoder for type6 leaves and
normal IBLOCKs. Reservations count descriptor/IBLOCK bytes. A second
whole-file hash, EOF and descriptor/path metadata checks precede the final root
PUT. Registration certainty and acknowledged storage progress remain separate;
failure never automatically unindexes a possibly preexisting registration.

`network::ublock` adds keyword and caller-keyed namespace publication through
type9 PUTs. KSK terms retain order and multiplicity, including repeated
weighted terms; mandatory markers affect search only. URI, update label and
caller-selected metadata are sealed through the existing artifact core. Reused
buffers hold one record/label at a time. Exact prior ACKs, failed input index and
uncertain writes survive failure; weighted PUTs are never automatically retried.

## Namespace keys and graph

`namespace::key::KeyFile` creates and opens ordinary raw32 Ed25519 namespace
seeds. Exclusive creation uses private permissions, original parent/file
identities and file synchronization. `directory_sync` separately reports the
actual [parent naming barrier](../native-std/API.md#anchored-filesystem-operations)
observed at creation. Typed failures retain creation, file synchronization,
naming observations and original native errors; failures never delete or replace keys. Loaded
signers and temporary seed/fingerprint storage zeroize on drop. Before managed
publication, complete seed re-read and native name/permission/stamp checks
revalidate the original selected authority. Files must be private and single-link;
Unix seeds also require owner-readable, nonexecutable data permissions.
Key bytes never enter the graph WAL
or diagnostic formatting.

`namespace::graph::Graph` durably binds one private locked WAL to the public
namespace. It retains exact identifier/update bytes, canonical target URI and
strictly validated selected metadata, including repeated publications under one
identifier. Metadata/URI payloads stay in the WAL and one reusable record buffer;
reads verify the original accepted digest and can return storage errors. The graph retains bounded unique labels, edges and
per-label links provide O(k) child enumeration. Iterative SCC traversal uses
bounded workspace without recursion proportional to graph depth. `roots()`
returns source-component record IDs for a minimum reachable cover. Use
`record_identifier(id)` and `children(identifier)` to enumerate metadata IDs,
then `record(id)?` to read each checked body before following updates. `component_roots()` exposes representatives of all SCCs. This distinguishes the
official header's SCC wording from the pinned C chain test's reachable roots. No C-internal tree IDs or private persistence layout are reproduced.

`Buffers::store_managed_namespace` composes the existing single-label
publisher with explicit key and graph owners. It validates the graph binding,
metadata and numeric WAL budget before any PUT. Actual nonnegative PUT STATUS
acceptance permits the graph append. Zero means already present; duplicate PUTs
can still add priority/replication, so zero never authorizes replay. An independent MQ cleanup failure keeps its original
acceptance and does not suppress the graph record. A post-ACK graph failure
returns both the original publication receipt and `AcceptedPending`; its
explicit `record` retry touches only the original graph. Reopening and finding
that exact original record confirms it without another append or weighted PUT.

The update parameter is `Option<&[u8]>`: None makes no local graph record;
Some(empty) retains an empty update. Both encode the same empty wire update,
which remote search does not follow. The local graph can still link an empty
update to a published empty identifier. Metadata stored by this SDK is the exact
explicit Plan selection sent on the wire, with its selection report retained in
the publication result. This differs from C's private graph copy of the caller's
complete, potentially unpublished metadata container. All four valid target URI
variants remain available.

These are immediate publications. A process crash after ACK and before graph
append can leave a missing graph record; the in-memory pending receipt is not a
persistent publication task or an automatic replay authorization. Autonomous
scheduling remains required work.

Persistent managed namespace tasks recover graph bookkeeping once the original
ACK is durable in the task WAL. Preparation seals the genuine signed UBLOCK and
records the selected original graph identity;
it performs no native PUT or graph append. The private graph schema stores a
stable task origin. Its O(1) origin index confirms one exact original graph body
without consuming a new record, including when the graph has reached its record
quota. Two independently prepared tasks with identical content remain two
publications; preparation does not reserve a graph row number. Conflicting reuse
of an origin or a different graph identity refuses rather than merging records.

`Task::create_managed_namespace` retains `Option<&[u8]>`: None is untracked and
Some(empty) requires a graph entry, while both preserve the same empty official
wire update. After successful preparation neither execution nor local recovery
needs the seed file. `run_managed` reauthenticates the signed payload and
original request/reply history, preflights the original graph before any new PUT,
then records native acceptance before graph bookkeeping. A tracked task
cannot report Complete without its graph fact and current exact graph confirmation. PUT quotas or caller stops can pause after a ACK and before graph work.

`record_namespace_graph` performs explicit local reconciliation with no service
endpoint, native client or runtime deadline. It requires the original ACK
prefix; Unknown or a receipt-less PUT intent cannot use graph/readback as a
substitute. A graph failure retains the original native result; graph success
followed by task WAL failure retains an private `GraphResult`. Its `record`
method admits only that original task fact, without another graph append or PUT. On restart, exact task-origin/body confirmation resolves the local graph bookkeeping
without repeating the weighted publication. Historical graph facts, this-run graph
verification and a newly appended graph row are reported separately. Graph-only
reconciliation after cancellation preserves Cancelled and cannot start fresh PUTs;
cancellation itself never creates a graph entry.

The CLI exposes `namespace-create <new-key-file> <new-graph-directory>`,
`namespace-list <key-file> <graph-directory> [identifier]`, and
`namespace-publish <datastore-socket> <key-file> <graph-directory> <identifier>
<target-URI> [--update identifier] [--timeout seconds]` under `fs`. Omitting --update selects None; an empty quoted value selects Some(empty). Root listing emits every publication under each chosen entry label.

## Search

`search::Session` opens keyword/namespace queries from a caller's endpoint
factory. It authenticates/decrypts UBLOCKs, intersects mandatory matches, counts
optional support and merges metadata. Signed namespace update identifiers create
bounded same-namespace follow-up queries; graph reuse prevents cycles from
spawning unlimited connections. Search opts into source-absolute-time UBLOCK
expiry filtering before raw seen commitment. D/I expiry policy remains unchanged. `fs search <fs-socket> <KSK-or-SKS-URI> [timeout-seconds] [max-visible-results]`
streams authenticated results, metadata and update provenance. The same
ordinary command also accepts `fs search <fs-socket> <keyword>...`, preserving shell
argument boundaries, or `--keywords '<text>'` for balanced-quote/whitespace grouping. An initial plus before quote removal makes a keyword mandatory; all percent and
non-ASCII bytes remain literal. Keyword mode selects `--timeout seconds` and
`--max-visible-results count`; URI mode retains its positional numeric options. Use `--` before literal arguments beginning with a minus. Optional empty terms or
quoted optional leading-plus terms remain queries even though the official
KSK URI grammar has no faithful serialization; the start event then has a null
query URI. All paths use the original Session, bounds, result and cleanup owners. Deadline or result quota stops caller observation and closes the original queries; a
quiet search never becomes a not-found or whole-network completion claim. Native
I/O progress is counted without flooding result output. This CLI is immediate;
persistent searches use the explicit task API below.

A finite Session captures one native allowance before source-clock registration.
Initial queries, namespace updates and reconnects share that target; a stalled
source clock cannot renew it. Preparing a Session requires no Tokio runtime;
its native timer is installed on first poll. Historical replay and completed
detached probes preserve the greatest actual UTC observation independently of
that live target. Expiry closes every original query MQ while keeping accepted
results and completed probe observations available. Already detached probes keep
their own lifetime; expiry prevents admission of new tickets.

`search::Session::drive_staged` prepares a genuinely authenticated advertisement
without changing aggregate results or the update graph. `observation` borrows its
original native ciphertext, query binding, expiry and observation time;
`accept_staged` checks the same original lifetime before aggregation or update
query creation, including after a caller's journal write. A deadline retains the
durable raw record for explicit replay without accepting a late live result.
Ordinary `drive` is a thin stage/accept composition. One bounded decoded artifact can be retained separately
from accepted result storage. Resource refusal keeps the original native frame
for explicit retry, rather than asking the service to send it again.

`search::task::Task` persists an immutable KSK/SKS query and complete numeric
policy in the existing private locked Store. No GNUnet message or C-internal
persistence format is introduced. Opening/status performs structural history
checks only and opens no runtime/query. Each explicit run supplies an endpoint
and a fresh finite UTC-source deadline. The original deadline and native lifetime
tokens are not persisted. A mutable run borrow excludes concurrent writers;
control and progress need no per-block state mutex.

The task syncs each authenticated original observation before aggregate result
admission or a caller result event. Raw records and aggregate summaries are
separate: a recorded observation can still encounter a later resource, semantic
or query-factory refusal. Resume reauthenticates the complete signed UBLOCK and
reconstructs query labels, lookup keys, namespace bindings, mandatory
matches, metadata and update children through the same Session. It never restores
an aggregate result from a trusted projection or forges a native Received token. Only raw WAL spans and small record indices are retained, without another copy
of every ciphertext body. Repeated advertisements already matched in the rebuilt
Session do not append duplicate result observations.

Historical expiry/time fields are local observation facts, not signed UBLOCK
fields. The native expiry rule rejects expiration earlier than the original
observation; equality is allowed. Reauthentication can therefore retain an
originally valid historical result after its advertised expiry. It does not
claim current freshness or availability. The reconstructed query graph is
created before live I/O; only visible historical results are emitted as restored,
while mandatory-pending records remain available for later complementary hits. A fresh source clock which regresses behind retained observations is refused
before live work. Strict signature/URI/metadata refusal remains distinct from an
authenticated advertisement rejected by aggregate policy.

Pause/cancel intent is synced before original MQ retirement; a settled phase is
written only after retirement succeeds. Deadline and visible-result quotas pause
caller observation and never mean search completion or absence. Independent
query failures, native retirement, original deadline and state-write errors are
retained separately. Dropping the run future closes its owned native Session but
writes no settled phase: reopened Running history is interrupted. Cancelled
searches retain their records and cannot implicitly continue. Idle cancellation
starts no query. Status distinguishes complete raw records from the last
historical aggregate summary, which can lag a raw tail. A partial/zero replay
pause does not overwrite established historical counts with an empty prefix.

The CLI exposes:

```text
fs search-task-create <new-task-directory> <KSK-or-SKS-URI>
fs search-task-run <fs-socket> <task-directory> [timeout-seconds] [new-visible-results-per-run]
fs search-task-status <task-directory>
fs search-task-cancel <task-directory>
```

During `search-task-run`, Ctrl+C or a supported termination signal requests
a pause. The command continues driving the original task through durable
pause and source retirement, and reports failures from the signal source
alongside any task failure.

The quota counts results first becoming visible during live work, including a
saved partial match completed by a new hit. Historical revalidation does not
consume it. Zero pauses before replay and makes no new result-authentication
claim. Task/status operations require the exclusive writer lock. Numeric
policies remain fixed; exhausting an aggregate bound retains the original raw
facts and reports the refusal, without inventing an empty successful result. Filesystem/WAL barriers are synchronous; embedding applications choose their
filesystem executor as needed. Autonomous search scheduling and availability
probes remain separate implementation work.

The CLI exposes `fs publish <datastore-socket> <file> [timeout-seconds]` and
`fs fetch <fs-socket> <CHK-or-LOC-URI> <new-file> [timeout-seconds]`. The default
300-second deadline and publication metadata are CLI policy, not wire changes.

`Buffers::store_directory` streams a prepared official directory plan through the
same acknowledged publisher. `download_directory` and ordinary file download
share one authenticated transfer loop and native Lookup owner; its lending
callback receives source-bound entries without buffering the directory payload.

## Directory trees

`input_tree::InputDir` anchors a selected source handle on Unix and Windows.
`open_child` accepts one native component and checks its original identity
before and after opening; symlinks, name surrogates and special files refuse.
`open_regular` selects the parent once and applies the same child contract.
Bounded snapshots preserve native names and complete platform identities.
Windows protocol metadata requires Unicode names; local WTF-8 is never emitted
as network text. Publication event format 5 and automatic-sharing format
`FSASHR03` bind the revised local source fingerprints; superseded formats refuse.

The recursive publisher opens children through no-follow native calls,
refuses symlinks/special files, and publishes files and directories in postorder. Directory MIME and protocol basename metadata reference only acknowledged CHKs. One frame allocation is reused across dedicated per-object DATASTORE clients;
the live DFS stack retains bounded names/metadata/record arenas, never payloads. Whole-tree byte, depth and entry budgets apply before admitting work. Completed
object events let a caller explicitly journal receipts. Failures retain the exact
current ACK prefix, prior complete objects and original cause without rollback.

Per-file descriptor observations and a final bounded stat walk detect source
changes. This final walk can fail after root acceptance, which remains reported. It is not an atomic filesystem snapshot. Native directory/stat calls can block;
embedders should run them on their filesystem worker when required by the executor.

`OutputDir::download_tree` uses the pure retained Walk for every source-bound
entry and each original attempt. Distinct paths sharing content are all emitted;
ancestor cycles, unsafe names, collisions and existing targets are refused. Missing names use stable entry offsets; official directory trailing-slash markers
are accepted. Each complete parent is authenticated/parsed before child output. Optional inline data is re-encoded and compared against its whole CHK before
local FileReader consumption; bad hints fall back to retrieval. SKS children
use authenticated native namespace search, selecting the first observed CHK/LOC;
LOC targets remain specific to the corresponding object. One deadline covers the
whole tree. Known outputs survive failure/cancel; active temporary cleanup and
the original control interruption remain independently visible. Final naming
barrier failure may leave the reported path present for reconciliation.

`OutputDir::download_tree_resumable` reopens output directories and applies the
resumable file owner to each authenticated file. Directory membership is
verified on every invocation. Completed files are reauthenticated in place.
File and request parallelism share the same bounds as immediate extraction.

`Buffers::store_indexed_tree` shares the same source traversal/planner and accepts
an explicit named source root plus FS and DATASTORE endpoints. The canonical root
must match the original directory descriptor; every ordinary file then uses the
existing indexed-file owner for IndexStart and type6 leaves. Generated
directories remain full D/I insertions. Admission caps the indexed owner's newly
sampled file size to the original tree budget before any registration or PUT.

Indexed-file count includes every acknowledged source path, even when identical
contents share one file ID and the service retains its older registered path. No new-registration ownership or automatic Unindex rollback is inferred. Exact accepted descriptor bytes have their own whole-tree budget and accounting;
computed ciphertext remains separate work. Events retain file IDs, and
typed failures preserve registration certainty, partial ACKs and both independent
index-MQ/DATASTORE cleanup outcomes. The original source must stay accessible to
the FS service for subsequent on-demand reads.

The CLI exposes `fs publish-tree <datastore-socket> <source-directory>`,
`fs publish-tree-indexed <fs-socket> <datastore-socket> <source-directory>` and
`fs fetch-tree <fs-socket> <directory-CHK-or-LOC-URI> <new-directory>`, with the same
optional deadline policy. These are immediate jobs. Native byte metadata is retained;
the local filesystem may refuse names it cannot represent (for example non-UTF-8
names on APFS), yielding its I/O error without lossy renaming.

`durable::Task` adds explicit persisted directory and regular-file downloads under `service`. The immutable manifest retains the original CHK/LOC, native output name and
resource policy. Each run requires the selected parent descriptor, endpoint,
cache and a fresh finite source-clock deadline. Opening/status starts no runtime. Local download events use version 3 in the bounded, checksummed, exclusively locked TaskStore WAL;
an uncertain append fences that writer. It does not change GNUnet wire formats. There is no v1 compatibility or migration path.

`Task::create` explicitly selects a directory root. `Task::create_file` takes
`FileOptions`, with the original `DownloadOptions` and an optional absolute
range; absence freezes `0..content.size`. Both CHK and verified LOC roots retain
their original identity, and LOC retains its signed placement peer. A CHK has
no file-type field: directory parse failure never implicitly switches modes. File tasks use the existing selected transfer, authenticated cache, lifecycle,
WAL and download job kind. Pause/restart authenticates each reused encrypted
cache block again; retained byte counts do not mint a proof. A failed original
temporary is retired exactly before a fresh run rebuilds output from the cache.

A range task writes at absolute offsets into a full-size sparse file. Its
`ReadRange` authenticates only the selected interval, including an explicit
`EmptySelection` for zero bytes in a nonempty file. `destination` distinguishes
`SinkCompleted`, `ExistingFileCompared` and `Untouched`; revalidation never
claims a new sink write or finish call. `Outcome.file` and `FileProgress` keep
selected authentication, delivery and naming disposition separate from the
directory walk's whole-file counters. File output uses a task-specific hidden
0700 staging directory in its selected parent, with the same private
owner marker. The WAL binds both original parent and staging identities. Its
temporary and final parents remain separate held descriptors; other entries
in the user's parent do not belong to the task.

Immediate and durable directory extraction share one authenticated traversal/transfer
owner. Resume rebuilds Walk from authenticated parents and compares stable
source/range/path/content bindings. Committed files are opened through original
parent descriptors and fully re-encoded, compared against the complete CHK,
read through the authenticated FileReader and synced again. Existing names,
ledger entries, sizes or timestamps alone cannot authorize completion. Selected
SKS content retains the original signed UBLOCK/update lineage and immutable
CHK/LOC; replay verifies that proof against the parent namespace instead
of querying a potentially changed label. Ordinary search retains no proof copy.

Revalidation permits at most two source verification attempts. A ctime-only change,
including deferred native unlink bookkeeping, starts one fresh verification;
all identity, content and synchronization checks run again. `source_attempts`
records the attempts in a successful result; its receipt and progress belong
to the final pass. A repeated failure retains the earlier refusal in `previous`.
Content, identity, size or mtime changes, cancellation and uncertain barriers
are not retried. Metadata never substitutes for authenticated bytes.

Exact temporary ownership and commit intent are synced before the final link. Known final commits and exact cleanup are independent facts. After interruption,
a final name matching the original intent inode is fully authenticated before
confirmation; an absent final name permits exact original temporary cleanup and
retry. Foreign/replaced output or unclaimed names require reconciliation and are
retained. Completion scans owned directories for unexpected entries. Output
roots and subdirectories retain private `.gnunet-fs-owner-v1` markers; that name
is reserved by this local extraction policy. Preserve task state and output.

Pause/cancel requests are durable before fresh work stops. Settled outcomes
require original query/output retirement and no unresolved intent or temporary
cleanup. Quiet pending queries observe control without restarting their query or
deadline. A dropped run remains interrupted; it never writes a settled outcome. Cancellation retains completed output. An interrupted CancelRequested task cannot
resume fresh work: explicit `settle_cancel` reconciles only its recorded effects. Historical committed facts remain separate from current-run revalidation. Progress snapshots are constant-time; state updates touch only the affected entry.

The CLI exposes:

```text
fs task-create <new-task-directory> <directory-CHK-or-LOC-URI> <new-output-directory>
fs task-create-file <new-task-directory> <CHK-or-LOC-URI> <new-file> [--offset BYTES] [--length BYTES] [-a|--anonymity LEVEL] [--local-only]
fs task-run <fs-socket> <task-directory> <output-directory> [timeout-seconds] [new-files-per-run]
fs task-status <task-directory>
fs task-cancel <task-directory> <output-directory>
```

`task-run` resumes across processes using `<task-directory>/cache`. Its optional
quota counts newly committed files; historical revalidation does not consume it. Zero requests an immediate settled pause. Omit the quota to finish. `task-status`
reports historical facts and needs the exclusive writer lock to be available. `task-cancel` performs explicit local request/settlement without opening an FS
connection. These commands do not expose remote control of an active writer;
SDK callers use the run callback for cooperative active pause/cancellation. Filesystem checks and WAL syncs are synchronous; use a filesystem executor when
embedding requires reactor latency isolation. Autonomous publication/search
scheduling remains separate implementation work; weighted PUTs are never
replayed by download recovery.

## Publication tasks

`publication::Task` implements prepared full-file, indexed-file, recursive tree,
KSK and SKS publications under `network`. Preparation streams encrypted D/I blocks or seals the selected
signed UBLOCKs into immutable disk objects beneath the original task directory
FD. The ordered plan retains duplicate leaves, file paths and keyword terms as
separate weighted PUTs. Full-file/tree sources and namespace seeds are not needed
after successful preparation; indexed sources remain required. Task files contain
no secret seeds. Preparation submits no native
request and may leave useful local objects if it fails.

Each run verifies every payload through the existing complete file reader or
strict signed-block context before sending anything. It then recomputes the exact
original PUT hash for every historical accepted row. One payload and request
buffer are reused; plan indexes, payload totals and WAL bytes have separate
explicit bounds. The default plan permits 16,384 PUTs, 8 MiB of logical plan data
and 1 GiB of ordered payload work. Verification uses bounded O(PUT count)
workspace; the complete file is never collected in RAM. WAL and spool syncs are
synchronous, so embedded callers choose an executor when required.

The task journals an exact local intent before one original native PUT. Only its
nonnegative STATUS advances the accepted prefix; raw reply bytes and any
original interruption remain available. Official DATASTORE documents zero as
already present and positive values as success; duplicate insertion can still
sum priority/replication. A negative reply remains a refusal until an explicit
`retry_refused`; bare intents and Unknown can never use this retry authorization. A disconnected owner cannot infer its weighted write from readback. Task identity
and original intent generation prevent an older receipt from settling a later
retry. Journal failure keeps new acceptance separate from recorded
history; a retained `NativeResult::record` can reconcile its original receipt
without sending another PUT. After process loss, an intent with no retained
receipt conservatively remains unresolved.

Pause requires original operations to settle without an unresolved request. Cancellation permanently stops fresh work while retaining accepted/unknown
remote effects. Drop changes only live ownership; it does not claim settlement. Completion requires fresh payload proof and the entire original accepted prefix. It confirms DATASTORE replies, not remote replication or continued availability. `status` loads structural historical facts only. Every command takes the exclusive
local writer lock; active callers use the run callback for cooperative control.

Recursive preparation shares source enumeration, bounded metadata/record arenas
and directory packing with immediate tree publication. Objects and their weighted
PUT ranges are postorder. Every resume authenticates each complete file and
strictly parses each directory, matching every raw filename, child CHK and
directory claim exactly once to the saved object graph. Root geometry or a list
of individually valid but unrelated file CHKs cannot establish tree completion. Paths and callback expansion are bounded before allocation; no directory or
complete source tree is collected as plaintext.

Indexed preparation keeps each original canonical raw path, full-file SHA-512
and native change observations. Each leaf owns an exact 72-byte type6 descriptor;
IBLOCKs and directories retain full ciphertext. Resume reconstructs leaf
ciphertext from the original file through the genuine FileReader, checks every
query/descriptor/position and complete file hash, and refuses missing or changed
sources even if the descriptor spool is intact. The runner retains only the
current source FD, reuses it across that object's PUTs and checks its original
path/FD around mutations. A final source pass checks availability/change bindings
before Complete; this is not an atomic filesystem snapshot or a future retention
guarantee.

The original FS INDEX_START ledger is independent of the DATASTORE ledger. All
named registrations must receive IndexStarted replies before any PUT. Raw IndexStarted/IndexFailed frames, request hashes and intent generations are
retained separately; STATUS cannot stand in for them. Resume checks original
registration history without sending accepted registrations again. A fully or
partially written registration without a reply stays Unknown. Explicit retry
is available only for an recorded IndexFailed. An original retained
NativeIndexResult can reconcile its own WAL failure without another registration. Independent registration cleanup trouble keeps its acceptance. No automatic
Unindex rollback is performed. This private version-checked task WAL uses schema v5;
original runtime deadlines and native capabilities are never serialized.

Indexed sources retain `PathBuf` names and complete native file identities,
lengths and modification/change fences. The private codec retains both 128-bit
time observations without assuming a portable epoch. Complete source hashing and
FileReader verification remain required; matching metadata grants no content proof.
Windows protocol filenames must be Unicode, while local path serialization uses
the native lossless codec.
Native identities remain private storage fields. `INDEX_START` retains the
[official zero device/inode fallback](https://docs.gnunet.org/doxygen/db/d14/structIndexStartMessage.html),
which requires the service to check the complete content hash.

```text
fs publish-task-file <new-taskdir> <source-file>
fs publish-task-indexed <new-taskdir> <source-file>
fs publish-task-tree <new-taskdir> <source-directory>
fs publish-task-tree-indexed <new-taskdir> <source-directory>
fs publish-task-keywords <new-taskdir> <KSK-uri> <target-uri>
fs publish-task-namespace <new-taskdir> <key-file> <identifier> <update-or-empty> <target-uri>
fs publish-task-managed-namespace <new-taskdir> <key-file> <graph-directory> <identifier> <target-uri> [--update label]
fs publish-task-run <datastore-socket> <taskdir> [timeout-seconds] [new-acks-per-run]
fs publish-task-run-indexed <fs-socket> <datastore-socket> <taskdir> [timeout-seconds] [new-acks-per-run]
fs publish-task-run-managed <datastore-socket> <taskdir> <graph-directory> [timeout-seconds] [new-acks-per-run]
fs publish-task-record-graph <taskdir> <graph-directory>
fs publish-task-status <taskdir>
fs publish-task-cancel <taskdir>
fs publish-task-retry-refused <taskdir>
fs publish-task-retry-index-refused <taskdir>
```

The per-run quota counts new accepted replies, excluding history. Zero
pauses before payload verification. FS registration ACKs have their own historical,
recorded and this-run counters and never consume the PUT quota. Indexed runs need
an explicit FS port as well as DATASTORE; callers supply a common source-clock
deadline domain. One native allowance spans verification, every index
registration and all PUTs in the same run. Tracked namespace runs require their
original graph port. Task discovery and scheduling have separate catalog/job
owners. This local persistence format introduces no GNUnet wire fields.

Enable `server` (SDK `official-fs-server`) for the independent Rust FS service. Construct `gnunet_fs::service::Service` over caller client/query/seen buffers, then
move it into `server::Server` with explicit DATASTORE, LOC signer, index and peer
ports. The pure owner validates query/type/signature associations before seen
admission and commits reply state only after the original native output queue
owns its bytes. Query/attempt tokens never become private wire identifiers. `SEARCH_CONTINUED` assembles matching inputs, following the documented protocol
rather than the pinned C unequal-query merge bug. A local miss emits no END.

The native host retains one original DATASTORE lookup until settlement,
even after its requesting FS peer closes. Stale replies cannot authorize a new
client in a reused slot. `server::ports::Datastore` drives the existing official
client; `PilsSigner` obtains the observed peer and verifies the actual
purpose5 signature. A client-scoped close drains its original signer operation
without disabling other clients. Unknown index mutation or worker failure is
retained even when the original requesting client has already gone.

`index::Index` validates registrations through a whole-file streaming hash
or the official Unix filesystem-ID/inode fast path. Windows uses the full hash
path without truncating its native file identity. It persists bounded
filename metadata in its own Rust WAL-backed directory, retaining the existing path
for duplicate file IDs. On-demand type6 records contain the exact file hash and
NBO offset; resolution reads one source block through its original file
descriptor and re-encodes/checks its ciphertext query. It does not buffer a whole
file or invent on-demand IBLOCKs. Index registration, listing and removal run on
one bounded worker. Lists retain one entry at a time while excluding mutations;
periodic orphan cleanup is also bounded. Shutdown settles original index jobs
and joins the worker before reporting quiescence. `Index::directory_sync` exposes
the underlying store's naming observation independently of file-data and logical
commit. IPC names retain Unix native bytes or Windows Unicode UTF-8; local WTF-8
is never substituted for protocol filenames. The stored filename representation
lends both native paths and IPC bytes without keeping a duplicate path buffer.

Malformed descriptors and proven missing/changed source blocks trigger precise
DATASTORE REMOVE of the original key/value. Missing index registrations and
uncertain backend failures keep their records. Already admitted cleanup remains
owned by the service after the requesting FS client closes, retains original
STATUS bytes or uncertainty, and settles before dependency shutdown.

## Serving and routing

The FS server retains a local search across an interrupted DATASTORE read.
The next scheduled sweep uses a fresh GET from UID zero because a replacement
backend may assign different UIDs. The original FS client, query and verified
seen hashes remain in place. An actual DATA_END on the fresh sweep establishes
local exhaustion.

`server::PeerRouter` is an explicit independent network composition port. Its
result-delivery gate allows IO/timers/cancellation to keep progressing behind a
slow local output. A received frame keeps its original route until native
delivery or owner cancellation, including across provider errors. Failed ports
require explicit recovery. `NoPeers` represents zero connected peers and returns
no synthetic network result or success. `server::cadet::Router` implements direct
non-anonymous D/I retrieval through an explicitly supplied native CADET client. Each bounded route owns its channel; replies match that channel, peer,
port, block type and ciphertext hash. The router preserves received positives
behind consumer backpressure, records query writes separately, and never
replays queries on MQ loss. `PeerProgress::CadetReply` retains the original
type141 application frame with explicit local transmission metadata; the FS
server validates it and encodes a new local ClientPut response. Each direct route captures its native hard bound before source-clock deadline
registration. Cancellation and logical-clock rollback retain that original
bound while channel, write or receive-ack debt drains. One shared earliest
native timer and IO guards enforce it; a stalled original MQ is actually retired
and reconnected, recording its pending token/exposure and Requested loss. The sole pending native frame retains its originating hard even if a service
channel-destroy notification has already removed the logical route. Old queries
are not replayed. A full route table reports no-effect Idle and consumes the
original serial, allowing subsequent fresh requests without permanently closing
the direct provider. Newly matched replies recheck their original logical/native
bounds before admission. Positives genuinely retained before expiry can wait for
the consumer beyond that bound and survive another route's retirement of their
shared MQ. That source retirement ends the other old routes without a
retained positive; it does not establish remote absence or acknowledgement.
The [foreground process](../../apps/gnunet-service-fs/README.md) enables this
backend by default. Explicit `[fs-rust] DIRECT_CADET=NO` disables only direct
CADET retrieval; local serving, index, signing and DHT lookup remain separate.

`server::cadet_server::Server` serves the official `fs-block` port with bounded
channels, one active source job and native CADET flow control. Its
`source::Datastore` reads D/I records and resolves type6 descriptors through
the local server's weak `on_demand_resolver()`. This shares the existing bounded
index worker and index lock. Rejected rows retain original metadata and causes;
the next UID is requested only after the previous GET actually settles. Record
limits and local read failures emit no invented negative peer reply. One failed
channel/source does not stop other requests. Shutdown withdraws the port, drains
the original source job, closes CADET and then joins the local index worker. Retiring a channel drains its admitted GET/resolution and retains that actual
observation, then stops unsubmitted UID continuation. A permanently closed
DATASTORE owner reports its original cause, withdraws serving and triggers
controlled foreground shutdown; record and source-file failures remain local. The foreground enables this separately by default; explicit
`[fs-rust] SERVE_CADET=NO` or official `[fs] MAX_CADET_CLIENTS=0` disables it. The incoming capacity is bounded by both official and Rust resource caps. Discovery and routing use the separately configured backends.

`server::gap::Router` uses a native CORE client for official137/138/139
and a caller-storage GAP book. Construction requires an explicit accounting
mode. The foreground binds PEERSTORE to the same runtime clock as CORE. The
unmetered mode supports isolated caller-controlled topologies. The router
supports D/I/UBLOCK/ANY queries, bounded
fanout/reverse paths and incoming serving through the same DATASTORE/type6 source. UBLOCK signatures and query bindings use the shared envelope verifier. Each
original request owns its seen group, and a held result pauses streaming before
the next unsubmitted UID lookup. Actual source END, a record limit and an
uncertain read remain distinct; no private peer END or request ID is introduced. Actual payload write receipts remain local transmission facts; silence is not a
negative reply. `server::peers::Pair` preserves results independently of sibling
failures. Its explicit single-selection and bounded discovery policies share a
fixed route table and all native queues have explicit bounds. `Deferred` lets the foreground
construct Server first and pass its sole worker's weak resolver to the provider
factory; factory failure still requires ordinary explicit shutdown and join. The foreground enables this path unless official `[fs] DISABLE_ANON_TRANSFER=YES`
or explicit `[fs-rust] GAP=NO` disables it. A fixed-row cover
owner preserves requested levels and requires equivalent completed foreign
relay writes before higher-level local sends. Neighbor generation, message
type, block type and exact length bind credits; local requests and partial writes
earn no credit. Optional `[fs] DELAY=YES` uses bounded randomized release with
one original target. ANY at every level and unknown-source anonymity0 D/I
queries use this explicit CORE backend with their original level and local route. They
emit the same standard137/138 frames and keep the original verification,
deadlines, cancellation and source debts. A missing/disabled GAP capability
still admits no network work. If the nonanonymous CADET/DHT chain reports
Idle (no peer effect), is absent or already retired, the same original
level0 D/I/UBLOCK request can instead enter CORE, retaining its target, seen
hashes and numeric0. `Pair::discovery`, used by the normal foreground, also
plans one independent configured CORE child before the optional level0
primary starts. A nonfatal primary refusal retains its cause and cleanup
without canceling this original CORE plan. Both admitted children keep their
timers, native
operations and metadata. A child Ended only ends its delivery authority; its
old native cleanup still polls, and the other admitted child keeps the canonical
route live. D/I completion or client cancellation cancels both original callbacks
without relabeling outstanding native debt. The canonical FS query verifies and
deduplicates UBLOCKs across both sources before local output admission. No failure, timeout or Ended starts a new child or refreshes a deadline. Errors
still propagate explicit Refused through nested compositions while retaining
original typed failure/cleanup; a second-child failure cannot orphan or close
the healthy first child. `Pair::new` remains the explicit single-selection policy. With no remote peer, the configured GAP owner instead retains the original
unadmitted intent within its existing local-route bound. It saves no seen list,
source job, native send or query timer. Actual guarded peer attach or resource
collection can request one current input through `input_needed`/`refresh`; the
Server validates the original active query/client/attempt and borrows its latest
seen set. First admission keeps the same serial even after newer reservations;
it does not restart CADET/DHT or use periodic route retry. Capacity-blocked inputs
rotate and wait for progress. Cancel/stop removes their old authority without
clock or network work. An already admitted, Ended or Refused child cannot create
such an intent again. `initial_deferred` counts retained no-effect intents and
`initial_activations` counts their local GAP admission; neither is a CORE
payload completion. Generated dummy traffic and full network anonymity remain
outside this composition. Peer PUT138 supplies no anonymity field, so unknown peer provenance stays
distinct from local DATASTORE anonymity.

`server::dht::Router` connects non-anonymous UBLOCK searches to the actual
native DHT client after local lookup. It preserves the original query/GetId,
type9, public DEMULTIPLEX_EVERYWHERE option, replication5 and initial known
hashes. Every candidate must pass the shared UBLOCK envelope verifier and the
normal Server's original-route validation before client output. One retained
native response backpressures reads while original STOP/FIFO writing continues. MQ replacement keeps active read identities and bounds. Cancel drops only its
callback/held result; STOP writing or old-MQ retirement settles its debt. The same original native hard also bounds STOP debt, using MQ retirement
when necessary. No peer END, negative reply or DHT storage ACK is invented.

The same bounded Pair implementation composes non-anonymous CADET versus DHT,
then non-anonymous versus positive-anonymity GAP. Each query keeps its original
anonymity; failures remain independent. Native input, bytes, routes and duplicate
history are bounded.

`server::dht::publication` periodically selects zero-anonymity UBLOCK
rows through one explicit DATASTORE source. Its 16-byte caller request buffer
is separate from bounded native response storage. Each selected original key,
payload and expiration reaches PUT with replication5 and
DEMULTIPLEX_EVERYWHERE through the same DHT client/reader used by lookup. UID
selection and DATA_END govern the next pass; an empty pass waits five
minutes. The estimated row count sets a bounded cadence. One original 30-second
budget covers selection and PUT; only one selection/frame/PUT can be retained. Future periods select again rather than replaying an uncertain original PUT. Actual DATASTORE replies/retirement and DHT Written/Lost/cancellation reports
remain distinct. Shutdown first consumes existing completion notices, then
cancels only a still-live operation and physically retires its original IO. Written is a local MQ observation, not a remote storage acknowledgement.

P2P GET137 accepts the C-produced optional hint: a four-byte native nonce
followed by all 8..32768 power-of-two Bloom bytes. It retains the original nonce
bytes and complete bits using the existing BLOCK hash/bit algorithm. Small
groups remain inline; the optional pure `alloc` feature permits fallible larger
groups charged by capacity against an aggregate heap budget. Existing
routes merge before any new allocation; retiring groups remain charged until
released. A no-allocation profile refuses an oversized group with Capacity. The pinned C checker erroneously applies its power-of-two test to the whole
nonce-plus-filter tail, so normal outgoing GETs retain the legal empty hint. Ordinary FS search IPC instead carries complete 64-byte seen hashes; it has no
such Bloom tail.

`gap::storage` owns bounded cache PUTs, original replication selections and
MigrationStop139 durations. The foreground installs its native Driver with one
extra explicit DATASTORE connection and the existing weak index resolver. Only original STATUS advances cache storage; GET_REPLICATION
preserves selected UID, pre-decrement score, anonymity and raw DATA. Type6 uses
the sole worker before becoming transferable DBLOCK. Dedicated unsolicited paths
cannot merge with GETs, preserve source anonymity through the cover gate,
and reserve query/return capacity for other traffic. Sixteen-byte pressure
controls retain their original native writes; relative/FOREVER/zero pauses apply
only to unsolicited work for that exact peer generation. Lost exposed mutations
stay Unknown and fence storage admission. A CORE write never proves remote
storage. Cache/push scheduling adds no private request ID, ACK, END or discovery.

They
do not prove unchanged-C FS/DATASTORE IPC or mixed-node interoperability. Bounded automatic probes and durable task catalogs/workers are implemented in
the client layer. Live multi-process administration remains work.

## Unindex tasks

`unindex_task::Task` adds the public persisted unindex lifecycle over the sole
existing `Buffers::unindex_file` pipeline. A private bounded locked WAL records
full source SHA512/size and the original selected keywords before destructive
work, intent before each original REMOVE/FS Unindex, then response facts. Resume rehashes the complete source before old receipt reuse. A settled keyword
selection is skipped as a whole, so recovery cannot choose and delete a second
row after the originally selected row disappeared. Historical receipts and
current STATUS/Unindexed responses remain separate counters and capabilities. An original paired STATUS remains durable progress even when logical
cancellation/deadline or physical retirement returns the run as a failure. That
receipt never changes the original failed run into success.

A positively unsubmitted native request gets its own non-success terminal
record. An admitted unfinished request remains pending and blocks ordinary
resume/worker scheduling. Only explicit `restart_uncertain` can retain that old
request as Unknown and permit a new independently bounded attempt. It issues no
IO and never acknowledges the old request. Cancellation is permanent. Native
failures, replies and independent WAL/cleanup failures remain typed;
returned status clears the live-run marker, and dropped futures retain their
original pending intent. Raw zero REMOVE statuses remain absence/backend-error
ambiguity, including when the local workflow reaches Complete.

The fifth catalog kind opens the same typed task under its original random
identity and physical directory. Its worker run constructs one bounded
DATASTORE client with the same FS clock and captures the native hard before
canonical sampling. Per-run quota counts only current positive/zero STATUS
replies. Original safe Pause/deadline retirement permits another time slice via
the Task's authoritative `resumable`; pending, failed or fenced work is never automatically restarted. An interrupted
run without an unfinished intent can resume through a fresh bounded run because
every destructive admission first records that original intent. A slice must allow the source rehash to
finish before historical receipts can be reused. The CLI provides
`fs unindex-task-{create,run,status,cancel,restart}` and `jobs-add ... unindex`. This adds no GNUnet wire, old-format migration or new dependency.

## Automatic-sharing storage

Catalog snapshots retain an original read-only handle and require unchanged
identity, length, modification/change timestamps and selected directory entry.
Publication synchronizes and closes the staged writer before replacing the
canonical name. Refusals distinguish read-extent changes, held-file metadata
changes, native file policy errors and a name selecting another object.
Diagnostics retain the before/after
metadata and original native error chain. A later name observation only explains
the refusal; it cannot replace the failed check or restore acceptance.

## Metadata and automatic keywords

The normal `gnunet-cli fs publish`, `publish-indexed`, `publish-tree` and
`publish-tree-indexed` entries compose the existing `auto_prepare::prepare`
with the content and per-object keyword Task runners. Directory metadata
and keyword metadata refer to the same prepared original CHKs. Only safe
basenames are included; the full local filesystem path is not advertised. Built-in
extraction uses the original descriptor and an explicit probe budget. The PNG
scanner skips image payloads by checked chunk lengths, then verifies the CRC
of each selected metadata chunk before emitting fields. JPEG APP1 and PNG eXIf
pass their original profile to the same classic TIFF reader. It resolves
primary, EXIF and GPS directories within the profile and suppresses duplicate
tags. An EXIF JIS user comment is decoded as ISO-2022-JP and its UTF-8 value
must fit the text limit. Standalone TIFF, BigTIFF and Olympus ORF use the same
reader with positioned directory and field reads. ORF selects classic directory
geometry through its own header signature. First-directory dimensions and
text use the GNU TIFF metadata mapping. The reader skips raster strips and
tiles.

RAF reads image dimensions from its record directory and metadata from the
declared JPEG preview and optional CFA TIFF. MRW reads the TIFF carried in
the TTW block inside the metadata container. Each nested read uses the bounds
of its declared payload and the original file's remaining probe budget.
Sigma and Polaroid X3F read dimensions and rotation from the FOVb header and
camera and exposure fields from UTF-16LE property lists. The footer directory
bounds its sections. The largest eligible JPEG preview supplies missing fields.
CAMF types 2, 4 and 5 supply missing camera identity, serial number, active
dimensions, aperture, exposure time, exposure compensation, ISO and white
balance within a 1 MiB decoded metadata limit.
Canon CR3 uses CMT1 through CMT4 for the image, camera, MakerNote and GPS
directories. Each directory resolves offsets within its own TIFF extent.
CMT2 supplies image dimensions. CMT3 supplies macro mode, image quality,
exposure mode, ISO, white balance and flash bias. CR3 XMP is carried by a
top-level Adobe UUID box. CTMD samples from classic and fragmented tracks
fill missing metadata fields in sample order.

Classic Panasonic and Leica RAW share the sensor and camera field reader
with Panasonic RW2. The complete RW2 header extension selects
`image/x-panasonic-rw2`. The classic header selects `image/x-panasonic-raw`.
A bounded JPEG preview supplies EXIF fields absent from the native
directories. Canon CRW reads image geometry, camera and shot fields from
their assigned CIFF directories in either byte order.

TIFF-based RAW identifies CR2 from its extended header, DNG from
`DNGVersion` in IFD0, and vendor subtypes from private compression values
in the primary directory. Shared packed RAW compression uses the IFD0 Make.
The PackBits value identifies Samsung SRW when IFD0 names Samsung and the
selected image declares a color filter array. A qualified Samsung sensor
directory accepts SHORT or LONG compression tags. NX1100, NX300 and NX500
also allow odd offsets for direct SubIFDs after sensor and strip validation.
Nikon CFA sensor directories
use their Nikon MakerNote to identify additional NEF and NRW layouts.
For an uncompressed or packed Nikon sensor, a bounded old-style JPEG thumbnail
in IFD0 can identify NRW when the MakerNote lacks the private NRW marker.
For the Coolpix 5700, the primary-image selector accepts the legacy
`NewSubfileType` sentinel in a qualified 12-bit CFA directory.
Mamiya ZD MEF uses the original camera identity and a full-size uncompressed
12-bit CFA directory. Hasselblad 3FR combines the TIFF Make field with the
PRONOM format marker and reads the embedded TIFF within its owning field.
Leaf MOS reads bounded `PKTS` records for digital-back identity, ISO and
JPEG preview metadata.
Sony SR2, SRF and ARW can also use Sony-specific evidence in the owning
TIFF directories. Prioritized traversal selects full-size RAW
geometry while preserving IFD0 as the source for EXIF links, GPS, IPTC and
XMP. CR2 uses its camera EXIF pixel dimensions, then the RAW directory
dimensions when the camera dimensions are unavailable. The publication probe
emits the identified media type before the other file fields.
TIFF files without a recognized RAW identity still supply standard tags
through the TIFF reader.
Canon, Fujifilm, Nikon types 1–3, Olympus and OM System MakerNotes supply
camera fields through directories bounded by the declared EXIF field extent.
Canon, Nikon types 1 and 2, and classic Olympus resolve value offsets from the
parent TIFF header. Fujifilm, modern Olympus and OM System use note-relative
offsets. Nikon type 3 uses an embedded TIFF header. Each directory supplies
the byte order used to decode its fields.
Pentax `AOC` directories use parent TIFF offsets. `PENTAX` directories use
note-relative offsets. Both use the MakerNote marker for byte order.
Panasonic and compatible Leica directories use the parent TIFF byte order
and supply image quality, white balance and macro mode.
Sony headered and bare directories also supply their recorded rating. For
Sony SRF, the bounded encrypted MakerNote supplies the as-shot white-balance
coefficients in red, green and blue order with green as the reference.
Ricoh notes use either the classic Ricoh directory or the note-relative
Pentax-compatible directory used by GR III and GR IV.
Minolta and Konica Minolta use the bare IFD, classic, 5D and 7D camera
settings, or the Olympus-compatible `MINOL` and `CAMER` layout. Model-dependent
packed settings use the IFD0 Model associated with their MakerNote source.
Sanyo classic notes supply image quality, macro and flash settings. Casio
classic and QVC Type 2 notes provide camera settings, with Concord DCI notes
using the Type 2 layout. Samsung Type 2 supplies inline ISO and 35 mm equivalent
focal length in either byte order. Qualified NX, WB2000 and EX2F notes supply
aperture, exposure time and exposure compensation through note-relative
offsets bounded to the value area after the directory. Aperture and exposure
time use the first value of a single or paired rational field. The model
profile specifies the focal-length units and recognized placeholder values.
Epson R-D1 notes supply image quality and camera software. Kodak DCS
profiles read shooting settings from their separately linked IFD0 directory.
A Kodak P712, P850 or P880 MakerNote supplies aperture, exposure time and ISO
when EXIF leaves them unset. Its linked CameraInfo directory stays inside the
MakerNote extent and uses the note's byte order.
A Kodak KDC private directory can identify the RAW profile and supply the
selected white balance. DC120 identifies uncompressed and JPEG-compressed KDC
using the camera model, linked Kodak shooting directory and 8-bit CFA image
directory. Dimensions come from the selected image directory.

IPTC IIM packets share one parser and emit keywords, city, sublocation and
country in the GNU metadata registry. The decoder accepts the IIM Appendix C
graphic designations, including NATS, national ISO 646 variants, ISO 8859
sets, ECMA Cyrillic, CSN 369103 and JIS X 0208. Additional repertoires include
ISO-IR 42 JIS C 6226-1978, 154 Latin supplementary graphics, 155 box drawing,
156 ISO 6937 supplementary graphics, 166 Thai,
168 revised JIS X 0208, 197 and 209 Sámi, 204–206 Latin sets with the euro
sign, 226 Latin 10 and 228, 229 and 233 for JIS X 0213,
along with GB 2312-1980, JIS X 0212, KS C 5601-1987 and the seven registered
CNS 11643-1992 planes. An ISO 6937 accent must combine with a permitted base
or space to complete one character.
Each dataset starts from the declared ISO 2022 designation and invocation
state. Code-structure announcements constrain width, graphic areas, and
locking and single shifts, including the three ECMA-43 levels.
The ISO-IR 26 newspaper controls project line breaks, erase words and
characters, and apply one-character super shifts to an unambiguous alternate
set. Typographic instruction payloads are consumed within the dataset.
The ISO-IR 77 projection supports cursor and page movement, character and
line editing, and tab stops. Select Presentation Directions sets the page's
orientation and line progression. Select Character Path changes progression
along a line. Screen-relative cursor motion follows physical axes, and
editing and serialization use logical positions. When the update mode is
unspecified, a direction change preserves the logical data. Character tab
stops begin at eight-character intervals. Stops can change for one line or across the
page. Aligned stops position the text at either edge, its centre or a graphic
resolved from the invoked character set. A bounded field collects the text
before placement. Repetition and cancellation act on the preceding coded
graphic before it changes the page. Page motion preserves the active row and
column, and form feed selects
the next page's home row. Text is serialized in page order with form-feed
separators. Each coded character occupies one position, including a JIS X 0213
character represented by two Unicode scalars. The field byte budget bounds
text, gaps and separators, and input and output size bound editing work.
Directed and reversed strings preserve logical character order through
Unicode directional isolates. The decoder validates nested scopes and
rebuilds balanced isolates from the characters that survive editing. These
markers occupy no cells and share the field's UTF-8 byte budget. Historical
JIS characters with Unicode variation sequences also occupy one cell.
Inside ISO 2022 text, an ISO-IR 196 switch uses UTF-8 until the standard
return restores the preceding state. An ISO-IR 196 or 192 declaration in the
IIM header selects UTF-8 for the entire dataset. ISO-IR 176 UCS-2, 177 UCS-4
and 195 UTF-16 accept a byte-order mark and default to big-endian.
With no declaration, the decoder starts with ISO 646 IRV graphics, uses
ISO 4873 DV for eight-bit datasets and requires
a designation for right-hand graphics and C1 controls. JPEG and EXV
sidecars share the APP1, Photoshop APP13 and COM marker reader. TIFF reads
tag 33723 before falling back to image resources. PNG uses CRC-checked
ImageMagick text profiles, PSD and PSB use their image resources, and JPEG
2000 uses the IPTC UUID box.
PGF reads supported image and EXV carriers inside its declared user data.
Nested carriers share the file's probe budget and the outer PGF supplies the
media type and dimensions.

XMP uses one namespace-aware RDF/XML parser. JPEG Extended XMP is joined only
after the named fragments cover the packet exactly and match its MD5 digest.
TIFF uses IFD0 tag 700, PNG uses checked text chunks, Photoshop and JPEG 2000
use their XMP resources, and WebP uses the RIFF XMP chunk. GIF uses the
GIF89a Adobe XMP application extension with its complete magic trailer.

WebP uses dimensions from the extended canvas or the simple VP8 or VP8L
header. Its extended EXIF chunk uses the shared TIFF reader.
PNG and WebP publish embedded ICC profiles as binary color-profile entries
with the registered ICC media type. PNG checks the chunk CRC and bounds the
zlib expansion before decoding. Both carriers check the ICC tag extents and
preserve the original profile bytes under the metadata capacity.

JPEG XL reads orientation and dimensions from the bare codestream, the
codestream box or fragments. An intrinsic size takes precedence over the
coded size. Version 1 permits out-of-order fragments.
The parser keeps positioned ranges until it can read the codestream prefix in
index order. An embedded ICC profile is reconstructed from that prefix with
independent limits for probe input, the decoded command stream, and the final
profile. The profile is published as a binary entry. Decoding stops before
the pixel frames. Container XML and EXIF reads take precedence over ICC
payload reads. Plain and Brotli-compressed XML and EXIF boxes use their declared
bounds. All recognized XML boxes contribute XMP under the shared probe and
decompression budgets.

HEIF and AVIF apply the primary item's clean aperture, scaling, rotation and
mirror properties in `ipma` association order. Dimensions use the coordinate
frame of the separate orientation field. `cdsc` references select the primary
item's EXIF and RDF/XML metadata. A selected visual sequence track supplies
its display geometry and orientation. Its first nonempty local visual sample
selects `stmi` associations from `sbgp` or packed `csgp` mappings and `sgpd`
descriptions. The group names the metadata handler and item IDs. The extractor
searches the track, movie and file scopes in that order, including each scope's
`meco` container. A track without sample associations can supply track-local
EXIF and XMP items after a complete scan of its grouping boxes.

A linked `tref/cdsc` metadata track uses the visual sample's decode time.
The sample index selects the equal or closest preceding decode timestamp
across track timebases. Classic timing runs map that time to a sample ordinal.
Fragment runs with default duration, size and flags use arithmetic to find
the sample and its byte range. Explicit fields remain subject to the probe
budget. Empty visual runs with default extents advance without per-sample
reads. Timed EXIF overlays track metadata, the most recent preceding sync
sample for a delta, and the selected sample. A fragment delta can use a sync
sample from the classic table. The reader resolves duplicate TIFF tags within
each IFD before projecting publication fields and reads each value with its
original byte order and offsets. Timed XMP supports plain XML, zlib-wrapped
DEFLATE, gzip and Brotli. Image items also accept raw DEFLATE. Compressed timed
XMP and compressed items draw from one expansion allowance.

CR3 and HEIF/AVIF share a BMFF sample cursor that validates sample descriptions,
classic chunk mappings, fragment defaults and run offsets against local media
data. The cursor visits classic samples first, followed by ordinary `moof`
samples. Direct, `idat` and item-relative extents are checked against their
source and joined in declared order.
ISO `comp` files restore the original file type from `otyp` when present.
The extractor expands `!mov`, `!mof`, `!six` and `!ssx` using a bounded raw
DEFLATE decoder. Box and sample offsets use the reconstructed file coordinates.
Unchanged regions, including `mdat`, use positioned reads from the original
file. Segment-index entries are outside metadata lookup.
JPEG XL and HEIF use the same Brotli decoder with limits on both expanded
output and internal history allocations.

The PDF catalog selects its XML metadata stream. That stream uses its explicit
crypt filter when present and otherwise follows the document metadata-encryption
setting. Metadata and object streams can select an embedded file in the same
PDF through a file specification's `/EF` dictionary. The embedded file uses
its own decryption and decoding first, followed by the referring stream's
`/FFilter` pipeline. Ordinary XMP can resolve indirect stream controls from
compressed objects. Embedded streams inherit the referring stream's
parameter lookup scope.

For separate external streams, `PdfExternalStreams::bind` associates bytes
with a file specification key and an observed version of a held PDF file.
`MetadataSettings::with_pdf_external_streams` makes these bindings available
to inspection, automatic keywords and publication preparation. The decoded
file name or URL serves solely as the exact key for caller-supplied bytes.
External bytes share the original probe allowance and use the referring
stream's `/FFilter` pipeline. Private durable snapshots retain the supplied
bytes and verify the original PDF's identity, version and SHA-512 content
digest before using them. A durable unindex task snapshots only its own
document's bindings and reuses the digest from the normal unindex source read.

Native PDF extraction follows the final cross-reference and its previous
revisions to the catalog, page count and document information. It resolves
references by object number and generation. A hybrid cross-reference table
takes precedence over its supplement for every object number listed in the
table. Structural streams support ordered ASCIIHex, ASCII85, RunLength, LZW,
Flate, CCITTFaxDecode and the PDF 2.0 `BrotliDecode` extension. Each stage uses
the shared decoded-byte allowance, including intermediate output. LZW, Flate and Brotli
accept TIFF and PNG predictors. Brotli window storage is bounded by the
admitted output, including for large-window members. CCITTFaxDecode reconstructs
packed scanlines from Group 3 one-dimensional or mixed coding and Group 4
two-dimensional coding. Cross-reference stream controls are direct values.
Object-stream controls can reference uncompressed objects in the current
generation. Those positioned reads use the original probe
budget, which also caps retained parameter bytes. The PDF reader opens
Standard security revisions 2–6 with the implicit empty password and checks
the permission block for revisions 5 and 6. It applies the string filter to
standalone strings and the stream filter to object-stream bytes before other
decoders run. Strings inside an object stream inherit its protection. Text
uses PDFDocEncoding, UTF-16BE or UTF-8, and dates use the GNU UTC metadata
representation. Output uses standard v2 metadata and ordinary type9
advertisements. The optional standard libextractor profile below consumes
`[FS] EXTRACTORS` through the same source-bound preparation flow.

Adobe.PubSec `adbe.pkcs7.s3`, `s4` and `s5` use an explicitly bound
`PdfRecipientAuthorization`. Document-wide filters enforce the first matching
recipient's extraction permissions. Attachment-only protection leaves clear
document metadata readable. `PdfCertificateRecipient::from_der` accepts a DER
X.509 certificate and a matching unencrypted PKCS#8 key. A present key-usage
extension must permit the selected operation. The native opener accepts
definite and streamed BER CMS, identifies recipients by issuer and serial or
subject key identifier, and supports RSA PKCS#1 v1.5, RSAES-OAEP and
ephemeral-static ECDH on P-256, P-384, P-521, X25519 and X448. Restricted
RSAES-OAEP credentials enforce the effective parameters from the certificate
and private key. X25519 and X448 use X9.63 or HKDF with AES key wrap.
RSA-KEM supports RFC 9690 and the RFC 5990 key-transport encoding with AES
or Triple-DES key wrap. Use `from_rsa_kem_der` to bind a generic RSA
certificate to KEM-only use.
The authorization identity includes the effective RSA-KEM restrictions.
X9.42 finite-field DH supports ephemeral-static and static-static agreement.
One-pass ECMQV uses P-256, P-384 or P-521. Static agreement uses the CMS
originator certificate or a certificate supplied with `with_originator_der`.
Explicitly supplied originator certificates extend the public identity
recorded for resumption. ML-KEM supports 512, 768 and 1024 with the seed,
expanded, and combined PKCS#8 encodings.

`PdfKekRecipient` supplies a pre-shared AES, Triple-DES or RC2 key under its exact
public CMS identifier. `PdfPasswordRecipient` supplies password bytes for
bounded PBKDF2 or a pre-derived key for password recipients with an omitted
KDF. Use a distinct public identifier when rotating a credential. Content
ciphers include AES, DES, Triple-DES, RC2 and RC4. Attach the credential for
local extraction through `MetadataSettings::with_pdf_recipient`. A caller
can supply another CMS opener through the same authorization type.

Automatic labels retain original text, full Unicode lowercase followed by real
canonical NFD, filename tokens with each normalized form, bracketed filename
phrases and MIME-family terms. Extraction and network publication use the same
`unicode-normalization` tables. When the official C implementation uses a
different Unicode version, normalization can differ for newly assigned code
points. Preparation refuses normalization that expands beyond the policy cap.

Each ordinary publication owns one explicit preparation thread, joins it after
cancel/deadline, then runs each original Task once with the same service clock
and deadline. Synchronous filesystem operations may delay that join. SIGINT and
SIGTERM stop the original owners without detaching them. Retained partial and
Unknown effects prevent automatic retry and cannot be converted to completion. Success requires Complete plus payload verification for content and every
selected keyword task, with independent cleanup/output failure preserved. Enabled
extraction with no representable keyword task is refused; `-D` explicitly selects
content-only publication instead. The one-shot result states the number
of metadata objects and keyword tasks, not network-wide search reachability.
`auto_prepare::Prepared::directory_sync` reports the actual group-directory
barrier separately from synchronized metadata files and each task's own WAL.

`--state NEWDIR` selects a new private task group; the default is a new private
OS temporary directory. This directory is retained, including on success, and
its exact path is reported. Original `content` and `keyword-N` Task subdirectories
can be inspected/resumed through the existing publication-task commands. Never
retry an unresolved intent as a fresh publication to evade its Unknown fence.

### Standard metadata provider

`extraction::MetadataSettings` is a pure owned configuration snapshot, cheaply cloned across the existing file worker. `new(disabled, FS.EXTRACTORS, absolute_library)` performs no native load. Missing EXTRACTORS/library keeps the existing bounded builtin MIME/HTML/ID3v1 profile. A selected native library uses the standard optional libextractor leaf; explicit non-`-` EXTRACTORS without that library fails instead of silently publishing builtin-only metadata. Library/config bytes remain exact and bounded. Policy remains Copy and contains no native handle.

The selection has two explicit queries. `automatic_keywords_enabled` is false only for CLI-D disablement. `format_extraction_enabled` is false for both CLI-D and configured `-`. Configured `-` keeps the safe filename/date metadata and automatic KSK route: fixed C serializes its non-NULL empty metadata as a valid 12-byte v2 header, so the scanner's positive-metadata-tail branch inserts safe180. The scanner does not insert it unconditionally for every helper message. CLI-D additionally clears ordinary publication keyword intent.

`publication::auto_prepare::prepare_with_metadata`, `extraction::file_keywords_with_metadata` and `Owner::open_with_metadata` reuse the shared extraction kernel and original preparation/coordinator algorithm. Convenience entry points select the builtin profile through the same kernel. The Provider is created and explicitly closed on the worker, not moved between threads. Each native regular-file extraction uses the same original read-only descriptor in the existing Stamp/metadata/CHK chain; no original mutable filename is reopened and no whole-file Rust RAM copy is made. Actual inode/extent/time guards and CHK verification remain required. Native descriptor namespace and extension-hint limitations are retained; the original OFD cursor is restored by the leaf, with a restoration errno remaining a preparation failure.

The provider's source-byte bound is intersected with the file/tree content bound before scanning. Record, callback, name/value and returned Rust output caps are intersected with the operation's official metadata policy. A native-output reservation is charged to the same group/task Budget before each extraction and released after the original metadata attempt; there is no separate implicit 4MiB-per-object allowance. Pure configured endpoint/config capacity is included. Configured `-` and CLI-D allocate no unused format-probe buffer. Third-party plugin internal allocations, decompression, threads/processes and nonreturning C calls are not forcibly bounded or prevented by this leaf/host reservation; original guards are checked at the public boundaries and callbacks without renewing targets.

Real callback type, format, data, plugin and MIME are preserved in official metadata. Provider FILENAME(type2) and provider-supplied original-filename(type180) are filtered; the host regenerates type180 from its verified safe basename. No FD pseudopath or absolute local pathname is relabelled as the filename. Base metadata filenames are handled by the same safe projection. Bounded native observations are recorded on `MetadataArtifact::provider`; EmptyUnknown is normal lack of callbacks, not provider acceptance, successful validation, CHK authentication or KSK completion. Content-only and all original terms/normalization/group quotas and network receipts remain separate.

All ordinary errors, including original stop/native causes and independent provider-close failures, remain typed. Only a pure nested original cancellation with no independent restoration/cleanup failure may settle the existing worker stop normally. Explicit provider cleanup runs after success or failure before returning Prepared; it does not turn a partial preparation or unknown network effect into success. Normal CLI/PROGRAM configuration uses this same owned selection and worker API.

Explicit publisher annotations use `extraction::ManualMetadata`
and `MetadataSettings::with_manual`. This bounded owned data crosses the same
existing preparation-worker boundary; it contains no native provider/source. All canonical English names from the selected complete GNU libextractor table
(1.18 header, types0..293) are recognized, with descending duplicate-name
selection and the official type45/whole-original-text fallback. Locale aliases
are not guessed. Values use standard UTF8, NUL termination, `<gnunet>`/text/plain
and existing filename normalization. This is metadata, not a provider-load or
content-authentication receipt.

The existing canonical collector/metadata codec merge only the selected root's
fields after its automatic query terms were chosen. The original regular-file content CHK, child metadata and source identity are
preserved. A directory receives the merged root metadata through the actual
MetadataProvider before header/body encoding, so its new CHK binds that metadata. Actual type9 keyword tasks remain bound to that resulting exact target;
manual values reach both the persisted metadata artifact and keyword
payload. The existing raw Task/store_keywords metadata-plan parameters receive
the same bounded plan from the ordinary keyword re-publication commands. No
new wire format, dependency, helper or hidden worker is introduced. Owned input
capacities and Arc metadata are included in the preparation budget, and the
additional final root wire is charged before persistent output. Combined
metadata/item/group caps still apply and do not claim a hard process RSS cap. Preparation success is not network publication.

Namespace/SKS publication uses the same bounded metadata plan for direct,
managed and prepared tasks. Signing keys, update graphs and observed
write/commit boundaries retain their existing contracts.

`ManualMetadata::plan` keeps uncompressed v2 output. Its `plan_with_codec`
variant accepts caller-owned plain/coded workspaces, reusable codec state and
the standard `Compression` selection. Full item selection and the same metadata
limits apply; `Always` refuses an unavailable codec or insufficient coded
capacity. The direct URI publication CLI exposes that selection as
`--metadata-compression never|adaptive|always`, defaulting to `never`. Missing
manual annotations remain absent metadata.

Unindex task creation retains supplied runtime authority for that in-memory
owner. Reopening restores configuration only. `authorize_metadata_from` and
`authorize_native_metadata` explicitly reattach matching current authority before
native reconstruction. Already recorded keyword selections can be reused without
loading a provider. `jobs::Worker::set_native_metadata_authorization` supplies a
runtime capability to future dispatches; catalogs never retain it. Active owners
keep their original capability when future dispatch policy changes.

## Metadata-only inspection

The standalone `extraction` feature exposes `extraction::{Policy, Limits, Error, MetadataSettings}` and `input_tree` without Tokio, CLIENT, DATASTORE or service-runtime production dependencies. The facade selects it with `official-fs-extraction`. Publication keeps its Task/WAL/PUT limits and wraps the shared metadata policy in `publication::auto_prepare::Policy.metadata`; it explicitly translates only the descriptor/metadata bounds consumed by extraction.

Builtin extraction, original-handle reads, directory inspection and local
selection snapshots share Unix/Windows code. `MetadataSettings::new` and
`from_snapshot` produce configuration data. Native execution requires a matching
`NativeMetadataAuthorization`, constructed through its unsafe code/ABI trust
boundary and attached with `with_native_authorization`. Clones share that runtime
capability; snapshots omit it. `with_authorization_from` reattaches current matching
authority while preserving recorded settings. Different native path spellings or
plugin options are refused; authority cannot be inferred from a task directory. The optional
[GNU libextractor provider](../extractor-std/README.md) supplies separate native
input lifetimes beneath that code. Windows admits a demand-paged view using
`NativeMetadataLimits::mapped_input_bytes`; explicit borrowed buffers retain the
separate `memory_input_bytes` limit. Local snapshot format `FSMETA04` preserves
both limits, lossless native library paths, bound PDF streams and the selected
PDF recipient's public identity. Resumed extraction reattaches the matching
credential through `with_authorization_from`.

`extraction::inspect_with_metadata` streams an `ExtractedObject`
for each held file/directory descriptor through a caller sink. It shares the
publication extraction kernel, selected provider lifetime, metadata/term policy
and traversal bounds, without creating CHK payloads, publication tasks or a
repository. `InspectionFailure` retains the generated prefix and original
cause, including independent provider close errors. The sink owns its retained
results and must impose its own bound. A mutable tree is not an atomic snapshot. The ordinary CLI exposes this path through `fs extract`.

`server::PeerRouter` and `server::cadet_server::source::BlockSource` return `ProviderFailure` with an explicit `FailureScope`. The provider freezes Operation/Service scope before erasing its concrete cause;
Pair and Deferred preserve it without type guessing. A `PeerFailure` retains
original and independent cleanup failures separately, and service scope in
either requires the existing service shutdown policy. The Server only reads
that scope. This does not change wire messages, deadlines or automatic fallback.

The block source retains the same typed scope in rejected records, retired
selections and close failures. GAP and the normal CADET foreground consume the
scope directly; diagnostic wrapping cannot demote a shared worker/storage fault. Configured-provider construction failure and permanent unavailability
are explicit containing lifecycle faults and retain their original cause/scope.
