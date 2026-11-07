# FS host API

## Repository and output

`gnunet-fs-host` connects the official content/directory core to Unix files. `BlockSource` and `BlockSink` separate retrieval/storage from encoding and
authentication. `Repository` stores raw ciphertext+tag blocks by query hash,
anchors directory descriptors, refuses object symlinks and commits immutable
objects without replacement. Create its root under an existing parent directory. File and directory sync failures retain their uncertain outcome.

Reuse `Buffers` across imports and reads. Block/frontier buffers are bounded by
protocol geometry; record/decompression storage grows only when parsing needs it. `publish_directory` reads the prepared layout directly into block-sized buffers,
using logarithmic record lookup rather than allocating the entire directory. `visit_directory` lends authenticated parent entries to a recursive owner. Controlled operations sample cancellation between blocks.

`OutputDir` holds an existing output directory by descriptor. It rejects unsafe
relative names and symlink parents, creates private same-directory temporaries,
authenticates the entire file and syncs it before a no-clobber link. Existing
files stay intact. A known final commit and a cleanup failure remain distinct.

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
deadline and bounded local deduplication set. The default RecentWindow policy
works around the pinned C service's continuation merge condition; Continued
supports the complete official wire form when the service merges it correctly. Search silence has no completion or not-found meaning. Index acknowledgements
do not assert durable datastore publication.

## Downloads and ranges

`Buffers::download` retrieves each D/I block, authenticates its complete
root-bound file tree and writes through AsyncWrite. It can read/populate a
verified local block cache. One source-clock deadline covers blocks, reconnects,
writer backpressure and flush. Queries reuse a dedicated MQ with a caller-selected
rotation bound; delayed replies are routed by their ciphertext query. `OutputDir::download_file` uses the same fd-anchored commit/cleanup path as local
reads. Dropping a whole transfer closes its MQ and removes the private temporary.

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
identities and file/parent sync barriers. Typed failures retain whether
the name was created or synced; failures never delete or replace keys. Loaded
signers and temporary seed/fingerprint storage zeroize on drop. Before managed
publication, complete seed re-read and native name/permission/stamp checks
revalidate the original selected authority. Key bytes never enter the graph WAL
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
persistent searches use the explicit task API below. Availability probes remain
required work.

`search::Session::drive_staged` prepares a genuinely authenticated advertisement
without changing aggregate results or the update graph. `observation` borrows its
original native ciphertext, query binding, expiry and observation time;
`accept_staged` uses the existing aggregation path. Ordinary `drive` is a thin
stage/accept composition. One bounded decoded artifact can be retained separately
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

`input_tree::InputDir` anchors a selected source descriptor. Its
recursive publisher opens children through no-follow, nonblocking native calls,
refuses symlinks/special files, and publishes files and directories in postorder. Directory MIME and raw basename metadata reference only acknowledged CHKs. One frame allocation is reused across dedicated per-object DATASTORE clients;
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
cache and a fresh finite source-clock deadline. Opening/status starts no runtime. The private local download WAL is v2, bounded, checksummed and exclusively locked;
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
Unindex rollback is performed. This private version-checked task WAL uses schema v3;
original runtime deadlines and native capabilities are never serialized.

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
an explicit FS port as well as DATASTORE; callers supply a common monotonic
deadline domain. Tracked namespace runs require their original graph port. Task
discovery/catalogs and autonomous scheduling remain required work. This local
persistence format introduces no GNUnet wire fields.

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
or the official native filesystem-ID/inode fast path. It persists bounded raw
path metadata in its own Rust WAL-backed directory, retaining the existing path
for duplicate file IDs. On-demand type6 records contain the exact file hash and
NBO offset; resolution reads one source block through its original file
descriptor and re-encodes/checks its ciphertext query. It does not buffer a whole
file or invent on-demand IBLOCKs. Index registration, listing and removal run on
one bounded worker. Lists retain one entry at a time while excluding mutations;
periodic orphan cleanup is also bounded. Shutdown settles original index jobs
and joins the worker before reporting quiescence.

Malformed descriptors and proven missing/changed source blocks trigger precise
DATASTORE REMOVE of the original key/value. Missing index registrations and
uncertain backend failures keep their records. Already admitted cleanup remains
owned by the service after the requesting FS client closes, retains original
STATUS bytes or uncertainty, and settles before dependency shutdown.

## Serving and routing

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
retained positive; it does not establish remote absence or acknowledgement. Focused private Unix fixtures cover a partial-query prefix, cancellation,
hard-bound retirement/EOF and fresh-query recovery, plus retained-positive and
unattached-intent boundaries. They are local owner regression checks, not C or
peer interoperability acceptance. The [foreground process](../../apps/gnunet-service-fs/README.md) enables this
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
`[fs-rust] SERVE_CADET=NO` or official `[fs] MAX_CADET_CLIENTS=0` disables it. The incoming capacity is bounded by both official and Rust resource caps. Discovery, complete anonymous routing and whole-node CADET interoperability
remain incomplete.

`server::gap::Router` uses a native CORE client for official137/138/139
and a caller-storage GAP book. It supports D/I/UBLOCK/ANY queries, bounded
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
one original target. Unknown-source anonymity0 D/I queries also use this
explicit CORE backend, retaining numeric0 and the original local route. They
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

## Metadata and automatic keywords

The normal `gnunet-cli fs publish`, `publish-indexed`, `publish-tree` and
`publish-tree-indexed` entries compose the existing `auto_prepare::prepare`
with the content and per-object keyword Task runners. Directory metadata
and keyword metadata refer to the same prepared original CHKs. Only safe
basenames are included; the full local filesystem path is not advertised. The selected built-in extraction profile recognizes bounded magic MIME, HTML
fields and ID3v1, using standard v2 metadata and ordinary type9 advertisements. The optional standard libextractor profile below consumes `[FS] EXTRACTORS`
through the same source-bound preparation flow. Actual installed providers,
extraction results and platform interoperability remain runtime-unverified.

Automatic labels retain original text, full Unicode lowercase followed by real
canonical NFD, filename tokens with each normalized form, bracketed filename
phrases and MIME-family terms. The extraction feature uses pinned
`unicode-normalization =0.1.25`; network publication enables that same feature. The configured-provider integration adds one local native ABI leaf and preserves
existing registry package blocks. Unicode table/version differences from the
selected C libunistring are not claimed byte-identical for every code point. Required
normalization expansion beyond the explicit policy cap is a preparation
refusal, never silently omitted Unicode advertisement.

Each ordinary publication owns one explicit preparation thread, joins it after
cancel/deadline, then runs each original Task once with the same service clock
and deadline. Synchronous filesystem operations may delay that join. SIGINT and
SIGTERM stop the original owners without detaching them. Retained partial and
Unknown effects prevent automatic retry and cannot be converted to completion. Success requires Complete plus payload verification for content and every
selected keyword task, with independent cleanup/output failure preserved. Enabled
extraction with no representable keyword task is refused; `-D` explicitly selects
content-only publication instead. The one-shot result states the number
of metadata objects and keyword tasks, not network-wide search reachability.

`--state NEWDIR` selects a new private task group; the default is a new private
OS temporary directory. This directory is retained, including on success, and
its exact path is reported. Original `content` and `keyword-N` Task subdirectories
can be inspected/resumed through the existing publication-task commands. Never
retry an unresolved intent as a fresh publication to evade its Unknown fence.

### standard metadata provider

`extraction::MetadataSettings` is a pure owned configuration snapshot, cheaply cloned across the existing file worker. `new(disabled, FS.EXTRACTORS, absolute_library)` performs no native load. Missing EXTRACTORS/library keeps the existing bounded builtin MIME/HTML/ID3v1 profile. A selected native library uses the standard optional libextractor leaf; explicit non-`-` EXTRACTORS without that library fails instead of silently publishing builtin-only metadata. Library/config bytes remain exact and bounded. Policy remains Copy and contains no native handle.

The selection has two explicit queries. `automatic_keywords_enabled` is false only for CLI-D disablement. `format_extraction_enabled` is false for both CLI-D and configured `-`. Configured `-` keeps the safe filename/date metadata and automatic KSK route: fixed C serializes its non-NULL empty metadata as a valid 12-byte v2 header, so the scanner's positive-metadata-tail branch inserts safe180. The scanner does not insert it unconditionally for every helper message. CLI-D additionally clears ordinary publication keyword intent. No old getter alias is retained for this new API.

`publication::auto_prepare::prepare_with_metadata`, `extraction::file_keywords_with_metadata` and `Owner::open_with_metadata` reuse the shared extraction kernel and original preparation/coordinator algorithm. The older source APIs select Builtin through these same bodies. The Provider is created and explicitly closed on the worker, not moved between threads. Each native regular-file extraction uses the same original read-only descriptor in the existing Stamp/metadata/CHK chain; no original mutable filename is reopened and no whole-file Rust RAM copy is made. Actual inode/extent/time guards and CHK verification remain required. Native descriptor namespace and extension-hint limitations are retained; the original OFD cursor is restored by the leaf, with a restoration errno remaining a preparation failure.

The provider's source-byte bound is intersected with the file/tree content bound before scanning. Record, callback, name/value and returned Rust output caps are intersected with the operation's official metadata policy. A native-output reservation is charged to the same group/task Budget before each extraction and released after the original metadata attempt; there is no separate implicit 4MiB-per-object allowance. Pure configured endpoint/config capacity is included. Configured `-` and CLI-D allocate no unused format-probe buffer. Third-party plugin internal allocations, decompression, threads/processes and nonreturning C calls are not forcibly bounded or prevented by this leaf/host reservation; original guards are checked at the public boundaries and callbacks without renewing targets.

Real callback type, format, data, plugin and MIME are preserved in official metadata. Provider FILENAME(type2) and provider-supplied original-filename(type180) are filtered; the host regenerates type180 from its verified safe basename. No FD pseudopath or absolute local pathname is relabelled as the filename. Base metadata filenames are handled by the same safe projection. Bounded native observations are recorded on `MetadataArtifact::provider`; EmptyUnknown is normal lack of callbacks, not provider acceptance, successful validation, CHK authentication or KSK completion. Content-only and all original terms/normalization/group quotas and network receipts remain separate.

All ordinary errors, including original stop/native causes and independent provider-close failures, remain typed. Only a pure nested original cancellation with no independent restoration/cleanup failure may settle the existing worker stop normally. Explicit provider cleanup runs after success or failure before returning Prepared; it does not turn a partial preparation or unknown network effect into success. Normal CLI/PROGRAM configuration uses this same owned selection and worker API. No library load, content parse, test/model, worker, crypto, storage or network execution was performed.

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

The same bounded metadata Plan is also supplied by the four ordinary
namespace/SKS re-publication frontdoors (direct, managed and prepared Task
variants). They retain their existing signing key/update graph and actual
write/commit/uncertainty boundaries. Together with four file/tree routes and two
KSK routes, ten normal publication paths carry explicit annotations.

## Metadata-only inspection

The standalone `extraction` feature exposes `extraction::{Policy, Limits, Error, MetadataSettings}` and `input_tree` without Tokio, CLIENT, DATASTORE or service-runtime production dependencies. The facade selects it with `official-fs-extraction`. Publication keeps its Task/WAL/PUT limits and wraps the shared metadata policy in `publication::auto_prepare::Policy.metadata`; it explicitly translates only the descriptor/metadata bounds consumed by extraction.

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
