# Rust FS standard SERVICE

`gnunet-service-fs -c CONFIG [-d] [-L LEVEL] [-l FILE]` runs the independent
Rust FS service through the shared standard SERVICE entry. It serves official local FS IPC, persistent file-index administration,
on-demand indexed content and PILS LOC signatures. DATASTORE, PILS and
the CADET, CORE and DHT backends use explicit official IPC endpoints and the same
caller-driven Resolver and canonical clock.

Node-wide `[PILS] PROFILE` selects the LOC signer's HELLO/PILS verification
once during startup. The default is `reference029` (`reference-0.29.1` is an
alias); `deterministic` selects the official conditional address-derived mode. Explicit `lsd0014-text` selects the separate published textual interpretation,
without claiming official C compatibility. Invalid choices fail before index or
native startup, and signature verification never falls back to another mode. Existing signer identity, result and request-retirement checks remain unchanged.

Configure `[cadet]` to retrieve D/I blocks
from an explicitly known peer at anonymity zero. The service sends official
FS_CADET_QUERY messages and validates original FS_CADET_REPLY frames under their
original route/channel. Local response metadata comes from query writes. The service also listens on the official `fs-block` port and
answer D/I queries from DATASTORE records, including type6 reconstruction
by the same index worker. Serving is independent of direct retrieval. Explicit
`[fs-rust] DIRECT_CADET=NO`/`SERVE_CADET=NO` disable those respective capabilities. Official `[fs] MAX_CADET_CLIENTS=0` also disables incoming serving. Local
misses and source failures produce no negative peer reply; invalid records remain
diagnostic before bounded UID fallback.

Configure `[core]` to route D/I/UBLOCK/ANY queries
and serve incoming official137/138 queries over a CORE client. GAP and direct
CADET can coexist under one canonical local route. GAP uses the
same sole index worker for type6 reads. A provider's local write completion is
not peer receipt. UBLOCK requests retain multiple verified results and independent
seen groups. Higher requested levels use equivalent completed foreign relay
writes and bounded release; this is local cover policy, not full mix-network
anonymity. Ordinary CHK requests at anonymity0 with no LOC target discover
D/I content through the enabled GAP backend and connected CORE peers;
the original numeric0, block verification, deadlines and cancellation remain. Known-target CADET and level0 UBLOCK/DHT keep their original backends. The
normal foreground independently plans a configured CORE discovery child before
the optional primary starts. Its nonfatal refusal keeps the original cause and
cleanup without blocking this original CORE plan. A persistent DHT lookup or
an unanswered direct channel
does not block connected CORE peers. Each child retains its own original timer,
source, native output and cleanup debt. Both use the same canonical query;
verified UBLOCK results share its duplicate history, and D/I completion or client
retirement cancels both callbacks while native cleanup continues. Refused stays
distinct from no-effect Idle, with original error/cleanup retained. No later
failure, timeout or Ended replays the request or starts another deadline. A GAP
provider with no remote peer retains only a bounded original unadmitted intent. Actual peer attach/resource release requests a current query/seen snapshot from
the same original client/attempt before its first CORE admission; it does not
restart the primary or mint another route identity. Waiting uses no query timer
or source/native job, and cancellation/stop removes the exact old intent. Blocked
inputs rotate until progress; admitted/Ended/Refused children never rearm
this path. Normal reports separate retained `initial_deferred` intents from
`initial_activations` and native `completions`. Generated dummy traffic is not added, and full network anonymity and whole-node
interoperability remain unqualified. Official
`[fs] DISABLE_ANON_TRANSFER=YES` disables GAP unless an explicit conflicting
`[fs-rust] GAP=YES` is supplied, which remains an error. Explicit GAP=NO is also
supported. Non-anonymous UBLOCK local misses use a separate actual `[dht]`
client, with original key/type9, replication5, DEMULTIPLEX_EVERYWHERE, empty
ordinary XQUERY and known hashes. This path does not lower a positive anonymity
request to zero. Verified multiple replies retain their original route.

Cancellation retains the terminal result of an admitted read and stops
later unsubmitted lookups. Permanent DATASTORE closure withdraws serving and
exits through controlled shutdown for supervision; a bad record or missing
indexed source file remains local to its query.

Direct CADET cancellation keeps the original native query bound until its
channel and partial output really retire. A full route table parks the new
request; it does not permanently disable the direct backend. Already observed
valid replies remain available through source loss while their original caller
is live. Inbound channel idle periods also have native bounds, including a held
reply waiting for send credit. Each admitted output keeps its original
`CADET_SERVE_WRITE_TIMEOUT`; partial progress does not renew it. Shutdown uses
one `CADET_SERVE_DRAIN_TIMEOUT` across all remaining native cleanup. Expiry
physically retires the original MQ before releasing its channel/write records. An unfinished block-source job stays associated with its old query until its
terminal or an explicitly unknown close; it cannot feed a new channel.

```ini
[fs]
UNIXPATH = /private/tmp/example-fs/fs.sock
UNIX_MATCH_UID = YES
[fs-rust]
DIRECTORY = /private/tmp/example-fs/index-rust
DIRECT_CADET = YES
GAP = YES
CADET_TIMEOUT = 30 s
SERVE_CADET = YES
CADET_SERVE_CHANNELS = 64
CADET_SERVE_BLOCK_BYTES = 64332
CADET_SERVE_IDLE_TIMEOUT = 120 s
CADET_SERVE_WRITE_TIMEOUT = 10 s
CADET_SERVE_DRAIN_TIMEOUT = 10 s
CADET_SERVE_RECORDS = 64
[datastore]
UNIXPATH = /private/tmp/example-fs/datastore.sock
[pils]
UNIXPATH = /private/tmp/example-fs/pils.sock
[cadet]
UNIXPATH = /private/tmp/example-fs/cadet.sock
HOSTNAME = localhost
PORT = 0
[core]
UNIXPATH = /private/tmp/example-fs/core.sock
```

The process uses the existing shared SERVICE `c/d/h/L/l/v` parser and standard
configuration loader, including the selected log level/file. Original inherited
listeners and parent control are captured once before option/config/runtime
resources. `-d` performs the fresh-process detach before NSS lookup,
runtime, listener path guards, index recovery, providers or workers. The parent
releases its captured descriptors and waits only on its original child-status
pipe; EOF/failure never means ready and it does not wait for the live daemon to
exit. The child's selected logfile remains its original owned file and its Logger
refreshes the child PID. Foreground mode follows the same service path.

TCP/activation listeners are prepared and retained before applying
`[fs] USERNAME`; new Unix endpoints are finished by that target identity with
the same `[fs] UNIX_MATCH_UID/GID` policy used by kernel credential admission. Existing path ownership/permissions are not rewritten. Index recovery and the
single index worker remain under the configured account. `[fs-rust]
DIRECTORY` selects the Rust index; otherwise it defaults to
`${GNUNET_DATA_HOME}/fs/index-rust`. Unresolved paths fail explicitly. The old
private `--storage` parser is removed; no migration/compatibility startup path is
kept.

One SharedClock authority, including configured testing skew, reaches
Reporter and the same Resolver/FS/DATASTORE/PILS/CORE/CADET owners. The standard
default remains Immediate shutdown; explicit supported soft shutdown retains its
existing semantics. The existing recovered Index, Server/worker, configured
peer factory and optional inbound owner must be constructed before READY is
flushed and the original child is notified once. This is local service readiness,
not a claim that every external asynchronous dependency has connected or that a
PILS signature, peer route or remote storage operation completed.

Socket, Resolver, provider and retirement diagnostics use that selected
Reporter with constant-severity sites. A permanent Reporter failure wakes the
same owner and fences the next active I/O class; cleanup can still poll original
source/index/provider/native debts. No new Resolver work runs after its own or
the logging source's permanent failure. SIGINT/SIGTERM and original parent
control enter the existing shutdown path. Inbound admissions stop first while
existing type6 reads retain the same index worker; their original terminal or
explicit unknown/forced-close facts are preserved. Only then does the same
`Server::shutdown` future settle and actually join its original worker, with the
same healthy Resolver polled independently when still allowed. No new grace,
request, FD, epoch or quiescence proof replaces those owners. A failed clock or
Logger cannot prevent physical Resolver/IPC retirement. Uninterruptible OS
filesystem/worker operations are not force-cancelled or declared successful by a
local timer.

Every independent main/drain/native/source/read/Resolver-drive/Resolver-close/
local-close/worker/Logger cause has bounded retained storage. A terminal failure
also owns the Server/inbound reports, inbound typed diagnostics and both
original peer backend causes; it does not preserve them only as formatted ticket
metadata. Nonfatal record/peer observations keep their existing policy. The
selected Logger is not bypassed by a second unconditional stderr diagnostic. READY remains a flushed local status line; final owner reports are selected-log
diagnostics. No FS packet, crypto, flow, DATASTORE, index/worker, routing or
anonymity algorithm changed in this entry refactor.

Internal `[fs-rust]` bounds include `MAX_CLIENTS=64`, `MAX_QUERIES=128`,
`SEEN_HASHES_PER_QUERY=256`, `INDEX_QUEUE=16` and `IO_SLICE_BYTES=65535`. `DATASTORE_TIMEOUT=10 s`, `RESCAN_INTERVAL=10 s`, `CADET_TIMEOUT=30 s` and
`DHT_QUERY_TIMEOUT=30 s` must be finite and nonzero. `DIRECT_CADET` defaults to YES;
its channel/route capacity is
`MAX_QUERIES`, with no whole-file network buffer. Index defaults are
`INDEX_MAX_ENTRIES=16384`, `INDEX_MAX_PATH_BYTES=16384`,
`INDEX_MAX_TOTAL_PATH_BYTES=64 MiB` and `INDEX_MAX_FILE_BYTES=256 GiB`. `MAX_BLOCK_BYTES` uses the pure FS default; `EXPIRE_UBLOCKS` defaults to NO. `SERVE_CADET` defaults to YES. Its channel bound is at most 1024 and also respects
official `MAX_CADET_CLIENTS` (default128, zero disables serving); the source record
bound is at most 4096. The default inbound block bound is the smaller of the
local block limit and 64332 bytes. Limits and idle timeout must be nonzero.

`GAP` defaults to YES unless the official anonymous-transfer disable flag is set. Its defaults are 64 neighbors, `MAX_QUERIES` routes, twice
as many return paths, 61456 block bytes, 4 retained input packets, 64 source rows
and fanout 4. `GAP_RESIDENCE=60 s`, `GAP_QUERY_TIMEOUT=30 s` and
`GAP_SEND_TIMEOUT=10 s` are finite independent local bounds. Configurable
`GAP_NEIGHBORS`, `GAP_ROUTES`, `GAP_RETURN_PATHS`, `GAP_BLOCK_BYTES`,
`GAP_SOURCE_RECORDS`, `GAP_INPUT_PACKETS`, `GAP_FANOUT` and `GAP_PRIORITY`
have checked limits. Small group filters use 1024 inline bytes per route;
`GAP_FILTER_BYTES=1 MiB` bounds aggregate extra capacity for larger incoming
filters. Result bytes, inline filters, that extra budget and configured
cache/migration payload queues share the 64 MiB ceiling. The complete incoming
C nonce/filter is retained up to 32768 filter bytes, with allocation deferred
until a new route actually needs it.

`GAP_COVER_CLASSES=256` bounds equivalent relay buckets; `GAP_MIX_QUEUE` defaults
to routes times fanout plus return paths, capped at 16384. Cover/release metadata
is capped at 4 MiB. `GAP_COVER_WINDOW=1 s` expires each bucket from its first
receipt without extension. `[fs] DELAY=YES` selects a uniform release delay up to
`GAP_MIX_MAX_DELAY_MS=1000`; otherwise delay is disabled. With delay enabled, the
cover window cannot exceed that maximum delay. Only completed foreign
payload writes earn credit; this is a CORE handoff observation, not peer storage
or processing. Incoming PUT138 has no numeric anonymity metadata. Explicit
source, query and send bounds remain independent of the cover/release policy.

With GAP enabled, official `[fs] CONTENT_CACHING=YES` and
`CONTENT_PUSHING=YES` select local cache PUTs and native GET_REPLICATION
operations. Both default to YES. One additional serialized DATASTORE connection
uses the same source clock and weak index resolver. Original STATUS/DATA, UID,
returned score and uncertainty remain available; a written CORE frame does not
acknowledge remote storage. Unknown mutations stop future storage work and take
the controlled service-failure path. Relative/FOREVER/zero MigrationStop139
durations pause only unsolicited traffic for their original peer generation.

`[fs] MIN_MIGRATION_DELAY=100 ms` bounds selection frequency. An empty datastore
waits at least 5 s before another selection. `[fs-rust] GAP_CACHE_QUEUE=4` and
`GAP_MIGRATION_QUEUE=8` each allow 1 through 64 rows; a disabled feature allocates
no corresponding payload queue. `GAP_CACHE_BUSY_PAUSE=5 s` is finite and positive. Cache/route/migration byte regions share the 64 MiB ceiling. Pushing requires at
least two route/path rows so ordinary queries retain capacity. Local cache
admission caps expiry at one year and uses explicit cache policy anonymity1 and
replication0; these are not inferred original peer metadata. Actual selected
local DATA anonymity remains unchanged when pushed through the cover gate.

`READY fs DIRECTORY route-backend=... serve-backend=disabled|cadet` confirms local
construction and listener readiness. Route values include `dht`, optional
`direct-cadet` and optional `gap-core-fs-cover-budget`. Dependency availability and peer receipt are observed
separately; `LISTENING fs cadet source=...` records the port write. SIGINT, SIGTERM or the corresponding parent-control signal closes
the original sockets, settles admitted dependency/index work and joins the
index worker before the final STOPPED report. Transport loss retains uncertainty;
neither full writes nor local deadlines produce remote acknowledgments.

Official Unix/TCP/inherited listener options, ACL, tolerant mode and Unix UID/GID
checks use the shared service runtime. The service owns its Rust index format;
there is no legacy migration, C ABI/FFI or production C process wrapper.

The normal composition includes non-anonymous DHT lookup and enabled
GAP/CADET defaults. One held DHT reply pauses input while STOP/FIFO output and
original timers continue. Original GET identities/deadlines survive MQ loss;
STOP writing or physical retirement settles cancellation, without a
fabricated search END or storage acknowledgement. A separate one-slot DATASTORE
selection source periodically advertises zero-anonymity UBLOCK rows through
that same DHT client. Original UID/END, row key/payload/expiry and a whole-cycle
30-second bound govern each PUT. An empty pass waits five minutes; later periods
select fresh rows and never replay uncertain PUTs. Actual selection, local
Written, loss, cancellation and physical cleanup remain separate reports. The fixed reference is v0.29.1 commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`: the FS producer uses
`GNUNET_SERVICE_MAIN(...,"fs",GNUNET_SERVICE_OPTION_NONE,...)`; generic
`src/lib/util/service.c` supplies the standard detach/log options. Rust internal
owners/worker layout need not reproduce C internals. The publisher/Bloom
successor passes affected strict macOS/Linux compilation, the pure M0 noalloc
profile, full root/embedded metadata and dependency/feature/lint guards. No
model/test, main/help, daemon/fork/privilege, key/crypto/entropy,
file/index/storage/worker/native or C execution was performed for this successor;
runtime/interoperability qualification remains open.
