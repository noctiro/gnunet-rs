# CLI command reference

## Statistics

```sh
gnunet-cli --help
gnunet-cli --version
gnunet-cli statistics get /path/to/statistics.sock
gnunet-cli statistics get /path/to/statistics.sock core
gnunet-cli statistics get /path/to/statistics.sock core peers
gnunet-cli statistics set /path/to/statistics.sock app counter 42 --persistent
gnunet-cli statistics set /path/to/statistics.sock app counter -7 --relative --persistent
```

Use `-` to select the normal configured `[statistics]` Unix/TCP endpoint:

```sh
gnunet-cli statistics get -c /path/to/gnunet.conf - core peers
gnunet-cli statistics set -c /path/to/gnunet.conf - app counter -7 --relative --persistent
```

An explicit Unix socket path remains available and disables TCP fallback. GET,
SET and WATCH share the normal PROGRAM configuration, selected Logger, clock,
foreground parent control and Resolver. GET/SET common `-c/-L/-l` options precede
the endpoint; `--` can explicitly end those options. Their `GNUNET_ARGS` tokens
are prefix defaults, with explicit command-line options taking precedence. WATCH
retains its existing PROGRAM option/environment ordering. Native endpoint and
selector bytes are preserved. Empty or omitted GET subsystem/name are wildcards. SET accepts trailing `--relative`/`--persistent`; a relative value is a signed64-bit
integer, including `-7`, and an absolute value is an unsigned64-bit integer.

STATISTICS stdout is newline-delimited JSON. Each GET row contains numeric `uid`,
boolean `persistent`, numeric `value`, display `subsystem`/`name` and exact byte
arrays `subsystem_bytes`/`name_bytes`. Only the original GET's END produces
`statistics_end` with the count of fully written rows. There is no aggregate row
cap: one row is retained at a time, bounded by the official65535-byte frame and
its JSON expansion (at most1MiB, allocated on demand). A pending stdout row pauses
further native GET reads, retaining the original cursor instead of buffering a
listing or creating another query.

A nonzero relative or any absolute SET is admitted once. The same native handle
orders its original update and DISCONNECT; only processing confirmation,
with no discarded or unconfirmed mutation, produces `statistics_set_confirmed`. This is service IPC processing confirmation, not an independently verified disk
commit. Relative zero follows the native API's complete no-op and reports
`statistics_set_noop`; it opens no connection and changes no persistence bit. Failures and source loss never replay an admitted SET or join another epoch's
receipt to the original mutation.

One ten-second native deadline bounds GET/SET admission, rows and terminal output. The native handle's own fixed destroy deadline remains authoritative for its
barrier. SIGINT/SIGTERM, parent stop, clock/Resolver/source loss, malformed frames,
missing END/confirmation, output failure or expiry return nonzero and retain the
original failure alongside independent flush/cleanup causes. The original GET is
cancelled when still owned; the original handle then physically retires, with a
separate five-second cleanup bound, followed by the same Resolver. No background
worker or second request owner is created. Borrowed stdout flags are unchanged;
a synchronous filesystem/TTY write or flush cannot be preempted, and a late
return is reported. Already written rows may precede failure, so consumers must
require exit zero as well as the terminal event.

## FS local repository

Local FS commands use official content blocks and CHK/LOC URIs:

```sh
gnunet-cli fs import /existing-parent/repository input-file
gnunet-cli fs pack /existing-parent/repository first-file second-file
gnunet-cli fs cat /existing-parent/repository gnunet://fs/chk/...
gnunet-cli fs export /existing-parent/repository gnunet://fs/chk/... new-output-file
gnunet-cli fs ls /existing-parent/repository gnunet://fs/chk/...
```

Import prints its CHK URI; pack imports an explicit file list and streams
an official directory of the resulting CHKs. Cat streams authenticated plaintext; export
publishes a fully authenticated new file without replacing an existing target. Directory listing emits JSON entries with raw URI/filename bytes and parent
coordinates. FS filesystem arguments retain native Unix bytes. These commands
use the selected local repository.

## FS metadata inspection

Offline metadata and keyword preview uses the same extraction policy as publication:

```sh
gnunet-cli fs extract input-file-or-directory --timeout 30
gnunet-cli fs extract input-file -D -m '4:Selected title'
```

Each newline-delimited JSON object carries its root-relative path, metadata
and automatic terms. The terminal event reports generated/emitted counts and
worker join. Require exit zero and `fs_extract_complete` for a complete walk. No publication task, repository or service connection is created. Extraction
streams through a bounded channel; cancellation and output errors stop the same
worker and join it. Native plugins and synchronous file/output calls cannot be
force-preempted. `-c`, `--extractors` and `--extractor-library` select providers
explicitly, as with publication; manual metadata applies only to the root.

## FS publication and download

Service-backed publication and download use explicit official service sockets:

```sh
gnunet-cli fs publish /path/to/datastore.sock input-file
gnunet-cli fs publish-indexed /path/to/fs.sock /path/to/datastore.sock input-file
gnunet-cli fs publish-keywords /path/to/datastore.sock 'gnunet://fs/ksk/alpha+alpha+beta' 'gnunet://fs/chk/...'
gnunet-cli fs publish-namespace /path/to/datastore.sock namespace.seed label '' 'gnunet://fs/chk/...'
gnunet-cli fs fetch /path/to/fs.sock 'gnunet://fs/chk/...' new-output-file
gnunet-cli fs publish-tree /path/to/datastore.sock source-directory
gnunet-cli fs publish-tree-indexed /path/to/fs.sock /path/to/datastore.sock source-directory
gnunet-cli fs fetch-tree /path/to/fs.sock 'gnunet://fs/chk/...' new-output-directory
```

## FS search export

FS search can save the result references as a standard GNUnet directory:

```sh
gnunet-cli fs search /path/to/fs.sock 'gnunet://fs/ksk/alpha' 30 100 --output new-results.gnd
gnunet-cli fs search /path/to/fs.sock +alpha 'two words' --timeout 30
gnunet-cli fs search /path/to/fs.sock --keywords '+alpha "two words"' --timeout 30
```

`-o` is the short form of `--output`. After the original search is canceled, the
export uses its final visible URIs and merged metadata without downloading the
referenced content. The timeout, result limit, SIGINT or SIGTERM ends this finite
observation; `partial_search` remains true. Empty observations produce a valid
empty directory. A search or JSON-output failure still attempts to save results
already retained, and search, export and cleanup failures remain independent.

The output parent must exist. The descriptor-anchored writer refuses existing
files and symlinks, streams the directory into a temporary file, then syncs and
links it without replacement. Reports distinguish written bytes, an exposed
commit with uncertain durability, and a durable commit. Export is a separate
bounded local phase after search; synchronous filesystem calls are not preempted
by the search timeout. The profile accepts up to 1024 entries, 2 MiB per metadata
encoding, 32 MiB of retained entry artifacts and a 64 MiB directory.

An optional final argument selects a positive timeout in seconds (default 300). Publication requests anonymity 1, priority 365, replication 1 and a two-year TTL;
these values are CLI policy. Completion means local storage acceptance. Indexed publication registers the source and stores on-demand leaf records;
the source file must remain available. Repeated keywords add their requested
weight independently. Namespace publication takes exactly 32 raw seed bytes,
stores one signed label and optionally embeds the next update label (empty above). Persistent publication jobs and namespace graph management use the actual
[FS adapter task owners](../../adapters/fs-std/README.md); complete official
interoperability remains pending.

Publication JSON retains acknowledged counts and partial failures. UTF-8 target
URIs use `target_uri`; opaque URI bytes use `target_uri_bytes` when UTF-8 is
unavailable. A zero exit and completion event are required for success. Unknown
weighted writes are never automatically replayed. Full FS peer routing and
mixed-node interoperability remain incomplete.

Tree publication streams full insertion in postorder, including directory MIME
and basename metadata; it refuses symlinks/special files and reports source
changes alongside any already accepted content. Tree extraction requires a new
destination, authenticates complete parents before children, and refuses unsafe
or conflicting names. It supports verified inline content and native namespace
resolution. Partial output remains on failure, with committed counts and
the failed path reported. These commands share one deadline across the tree and
use explicit resource bounds; they do not yet persist tasks across process exits.

`publish-tree-indexed` keeps directories fully inserted and registers ordinary
files through the FS service. Leaves are on-demand descriptors; keep source
files available to that service. Repeated content can share an older registered
path. Completion counts `indexed_files` per acknowledged source path;
`stored_bytes` counts accepted descriptor/IBLOCK/directory payload separately from
computed `encoded_bytes`. Partial failures expose the original indexed file ID
and registration certainty when available. Unknown mutations are not replayed,
and no shared file-ID registration is automatically unindexed.

## FS unindex tasks

Persisted unindex uses the same native workflow with a separate locked task:

```text
gnunet-cli fs unindex-task-create new-task indexed-file
gnunet-cli fs unindex-task-run /path/to/fs.sock /path/to/datastore.sock new-task 300
gnunet-cli fs unindex-task-status new-task
gnunet-cli fs jobs-add catalog unindex new-task --slice 300 --quota 32 --repeat 1
```

Resume rehashes the original file and distinguishes old accepted receipts from
current responses. The quota counts only this run's REMOVE STATUS replies;
a zero status still carries the service's absence/backend-error ambiguity. An
unfinished mutation blocks automatic resume. `fs unindex-task-restart <task>`
explicitly leaves that request Unknown and permits a fresh attempt; it sends
nothing and gives no old request a successful outcome. `fs unindex-task-cancel`
permanently stops future work. SIGINT/SIGTERM during a run pauses and drains the
same native owner before returning. Task access uses an exclusive physical lock;
this is not a new multi-process live-control protocol.

## FS unindex

File-level unindex uses the original FS and DATASTORE services:

```sh
gnunet-cli fs unindex /path/to/fs.sock /path/to/datastore.sock indexed-file 300
gnunet-cli fs unindex /path/to/fs.sock /path/to/datastore.sock indexed-file 300 --keywords 'gnunet://fs/ksk/known+labels'
```

The current regular file must be available and stable. The operation hashes and
re-encodes the same open descriptor, removes exact local on-demand leaf records
and index ciphertext, then cleans matching keyword records before requesting the
original FS index removal. Returned keyword rows are authenticated and matched
against this file's CHK before their original bytes are selected for removal. Default keywords use the bounded current-file extractor; repeatable `--keywords`
adds known custom KSK terms. This cannot reconstruct every historical label or
revoke remote copies. A changed or missing file cannot establish that an older
version's index was removed.

`fs_unindex_complete` requires the FS acknowledgement and no zero REMOVE
statuses. `fs_unindex_partial` retains zero statuses, which can mean absence or a
backend failure; its zero exit means the index acknowledgement was received,
with that ambiguity explicitly reported. Positive REMOVE statuses are local
service replies, not counts of deleted rows or independent durability receipts. `fs_unindex_failed` retains partial work and the original failure, with a
nonzero exit. Cleanup, signal and diagnostic-output failures remain independent;
an output failure can occur after index removal. Unknown mutations are never
automatically replayed.

The default 300-second deadline covers both file passes and every service phase. SIGINT/SIGTERM cancels the same operation through its settlement and physical
connection close. Regular-file and metadata calls are synchronous OS boundaries;
they cannot be interrupted while an individual call is blocked. The tree streams
through reusable block buffers. Defaults bound files to 256 GiB, the combined
keyword set to 256, returned rows to 4096 per keyword and 16384 overall, and
metadata probing to 64 KiB. Exact local value removal can also affect identical
shared content under the official DATASTORE contract.

## FS index listing

List the indexed files observed through one original FS service query:

```sh
gnunet-cli fs list-indexed /path/to/fs.sock
gnunet-cli fs list-indexed /path/to/fs.sock 30 100000
```

The optional arguments are timeout seconds (default 300) and maximum records
(default 65536, range 0..1000000). Each `fs_indexed_file` row streams the actual
64-byte `file_id_bytes` and original `filename_bytes`. `filename` contains the
UTF-8 name when valid, otherwise null. No whole-list collection or filename
opening is performed. These are service observations, not authority to open
those paths or an atomic filesystem snapshot.

The final `fs_index_list_stopped` row marks `complete` only after an actual
IndexEnd. Exactly N entries still permit IndexEnd at a bound of N; entry N+1
ends the query as partial, counting that extra observation without emitting it. A zero limit can complete an empty list. Timeout, SIGINT/SIGTERM, EOF, service
loss and capacity failure retain partial facts and return nonzero. Rows from a
replacement connection are never appended to the original list.

`observed_records` counts received entries; `emitted_records` advances only
after a complete row and flush. Output failure can leave a partial JSON line. Require exit zero, `complete: true` and `output_rows_complete: true` before
treating output as a complete list response. The original native deadline never
renews between rows, and shutdown retains operation, physical close, signal,
row-output and terminal-output errors separately. Individual synchronous output
calls cannot be preempted by the deadline.

## FS metadata options

Ordinary file/tree publication, both indexed and full insertion, accepts repeated
`-m/--meta TYPE:VALUE`. The two keyword re-publication frontdoors
`fs publish-keywords` and `fs publish-task-keywords` accept the same option. For example, append `-m 'title:My public title' -m 'description:Public annotation'`
to the existing publication command. Standard canonical English libextractor
names are resolved without loading a library; duplicate names select the highest
numeric type as in the official descending search. Unknown names retain the
entire original argument as type45. Values remain UTF-8 with one terminating
NUL, plugin `<gnunet>` and MIME `text/plain`; filename separators use the existing
standard normalization. Empty values remain metadata rather than absence. The default limits are32 original inputs and32768 retained/canonical bytes, plus
the existing combined per-object metadata/item/group limits. Oversize, invalid
UTF-8, NUL, allocation or serialization errors fail rather than truncate or drop.

User fields are merged only into the selected top-level object's metadata. The original regular-file content CHK stays unchanged. A directory builder
receives the merged root metadata before encoding its header, so its
body and resulting CHK correctly change with those annotations. The actual
keyword payload and
retained `metadata-N` artifact contain the merged values. Child annotations are
not overwritten. Automatic query terms are chosen before this merge, matching
the reference publisher: user annotations do not invent extra automatic query
keys. They remain present with `-D`; that flag still disables automatic KSKs,
so an explicitly selected `fs publish-keywords ... -m ...` can annotate an
existing CHK using the user's KSK query. No configured native extractor
is needed for manual-only parsing/encoding. A local metadata plan is not a
DATASTORE acknowledgement; all original task, uncertain-write, deadline,
cancellation, same-file verification and worker/provider cleanup rules remain.

`fs search -n/--no-network` restricts every original initial and namespace-update
query to the local FS datastore using SEARCH_LOOPBACK_ONLY. Defaults remain
network-enabled. For example:
`gnunet-cli fs search /path/to/fs.sock --no-network +alpha --timeout 30`. After `--`, the flag text is a literal keyword. Local silence or expiry is not
proof of network-wide absence; result export and original cancellation remain
independent of that selector.

The four namespace frontdoors also accept that same repeated bounded
`-m/--meta TYPE:VALUE`: `publish-namespace`, `namespace-publish`,
`publish-task-namespace` and `publish-task-managed-namespace`. They pass the
original selected standard metadata Plan to the existing SKS sealer, with the
same original namespace key, identifier, update and target URI. A managed graph
stores the identical selected metadata after the PUT acknowledgement;
a persistent task seals and retains it in its original signed artifact. Running or recording an existing task does not reconstruct new metadata.

The shared argument parser consumes each original `--update LABEL` or
`--timeout VALUE` before interpreting another option: a label literally `-m`
is not stolen as a metadata flag. `--` ends all option recognition, including
manual metadata and named namespace options. Existing default absence, explicit
empty update versus untracked graph, original publication deadlines, native
receipts, Unknown outcomes and independent cleanup/output errors remain. No extractor/provider or content copy is needed for these direct URI records. This names those four namespace entrypoints; it does not qualify every possible
publication tool or claim executed native/C interoperability.

## NAMESTORE delegation import

NAMESTORE can import a public delegation URI into an explicitly selected ego:

```text
gnunet-cli namestore import-uri /path/to/namestore.sock 'gnunet://gns/<58-character-typed-public-key>/<label>' --identity-socket /path/to/identity.sock --ego local-zone --expiration-us 31536000000000 --relative 1
```

This replaces the complete label set with one PKEY or EDKEY record, after real
IDENTITY lookup. It accepts the existing GNUnet typed public-key text, preserves
case/Unicode in the label for service NFC, and refuses empty labels, additional
path components, queries, fragments and whitespace. Percent sequences are literal
label bytes; no URL decoding or URI-provided private key is used. Expiration is
absolute microseconds unless `--relative 1`; `--shadow 0|1` and
`--maintenance 0|1` set the standard record flags, defaulting to zero.

The record contains the 32-byte public key, with its type in the record header,
as required by the public `GNUNET_GNSRECORD_data_from_identity` conversion. The
pinned C NAMESTORE URI branch instead passes the entire 36-byte typed structure;
this command uses the valid delegation representation and leaves the shared
record schema unchanged. Decoding public text does not authenticate the key. Success requires the NAMESTORE result; exposed writes with an unknown
outcome are reported and never replayed. A URI dispatcher needs an explicitly
configured wrapper to supply the socket, ego and expiry; the historical C
`[uri]` handler string alone supplies no ego and is not claimed to work here.

## NAMESTORE zone files

NAMESTORE also imports the public zonefile text format through the clients:

```text
gnunet-cli namestore import-zonefile /path/to/namestore.sock --identity-socket /path/to/identity.sock --input public-zone.txt --timeout-ms 60000
```

Input defaults to stdin. A synchronous bounded read finishes before any ego,
entropy or STORE operation; a blocked OS read is not advertised as cancelable by
an asynchronous timeout. The subsequent single deadline covers parsing and all
protocol operations, without being renewed for each origin or record set. Defaults are16MiB complete UTF-8 input,65536 records and128 retained origins;
`--max-input-bytes`, `--max-records` and `--max-zones` can select bounded limits. Physical lines are limited to4096 bytes, logical records to65535 bytes and each
adjacent name group to50 records fitting one standard STORE frame.

`$ORIGIN` selects the literal ego name without its final dot. Only an actual
IDENTITY lookup result `IDENTITY_NOT_FOUND` permits creating that origin as an
EdDSA ego. Other errors, unavailable sources and unknown CREATE results stop the
import. An optional `--zone EGO` supplies an initial literal existing ego;
it never creates a missing initial ego. `$TTL` takes decimal seconds and starts
at zero; each record keeps the TTL current when it was parsed, with the standard
relative-expiration flag. `$TTL` does not flush or rewrite older records.

Relative owners, FQDN owners under the current origin, the origin apex `@`, and
owner inheritance on `IN` lines are accepted. Quoted values and parenthesized
physical continuations retain their quotes, parentheses and backslashes for the
existing record text codec. RDATA domain names are not expanded by `$ORIGIN`. Unsupported directives/classes/types and incomplete final quotes/parentheses
are explicit errors. Owner Punycode conversion uses the existing IDNA utility;
`--record-profile native|little|big` selects existing packed Messenger record
layout where relevant and defaults to native.

The importer replaces a complete adjacent origin/owner group on the same actual
NAMESTORE MQ, and flushes the final group at legal EOF. It does not append, merge
nonadjacent repetitions, or promise a whole-file transaction. Each successful
original STORE result advances the stored set/record counts before output is
attempted. A late syntax, conversion or service failure preserves these known
results and reports the staged or unknown remainder, including a converted record
that was not yet inserted into a group. `converted_records` counts completed text
conversions; `converted_unstaged_record` exposes that separate pending record. CREATE/STORE outcomes with
possible exposure are never replayed. Shutdown physically closes the original
MQs and retains business, entropy and independent diagnostic/flush failures;
local admission or whole socket writes are not successful service results.

## NAMESTORE record lines

NAMESTORE reads and writes the standard record-line format through the same
original native clients:

```text
gnunet-cli namestore export-recordline /path/to/namestore.sock --identity-socket /path/to/identity.sock --ego alice > records.txt
gnunet-cli namestore import-recordline /path/to/namestore.sock --identity-socket /path/to/identity.sock --input records.txt
```

A group begins with `<label>.<owner>:`; the first dot separates its literal label
from an existing ego name or a standard typed public key. The record lines are
`  TYPE EXPIRATION [pSrsC] VALUE`. Expiration is raw unsigned microseconds: `r`
means a relative duration, otherwise an absolute expiry. `p` means public;
without it a record is private. `S` means supplemental, `s` shadow and `C`
critical. Values use the existing active GNS record text codecs and the selected
`--record-profile native|little|big` (default native). No ego or key is created or
imported. Public owner headers are matched against a ended IDENTITY
inventory; malformed typed-public-key text falls back to an ego lookup. An ego name that itself names another valid public key is exported using its
public-key spelling, so reimport selects the intended authority.

Each explicit header ends the previous group, including repeated identical
headers. Each nonempty group replaces the complete label set with one original
atomic STORE; later repeated groups replace earlier ones. Blank lines and
header-only groups have no write effect. The final nonempty group is submitted
only after a legal EOF. This is a sequence of label replacements, with no
whole-file transaction or append/merge promise. Every STORE result keeps
the original group's line range and raw service/local outcome. Only code zero
increments stored counts. Local unsent, rejected and exposed unknown writes are
distinguished; shutdown drains the original completion after physically closing
its source and retains its original loss cause. No uncertain mutation is
replayed. A late syntax, conversion, IO or service error preserves known earlier
results and the staged or unknown remainder.

Import uses stdin by default (`--input -`) and a zeroizing 8KiB read buffer plus
one bounded line/current record group. It does not retain the whole file. Export converts a complete returned group before writing that group and counts
successful partial OS writes separately from complete groups. Its text goes to
stdout; its terminal JSON diagnostic goes to stderr. Import emits JSON receipts
and a terminal diagnostic on stdout. A complete result requires exit zero and
`complete: true`; export additionally requires the original iterator END,
not a local limit, STOP write or elapsed observation window. Service-side
iteration filters and concurrent changes retain the standard service semantics. Export `--filter U16` defaults to the public CLI's ordinary filter0; maintenance1
and omit-private2 bits can be selected explicitly, including their combination. Other bits are passed to the service. A complete export means END for
this selected view, not an atomic raw database image or a promise to include
filtered maintenance/private records or expired records.

The same original `--timeout-ms` budget (default30000, maximum86400000) covers
input opening/reading, conversion, owner resolution and all protocol work;
it is never renewed per group or ego. Synchronous OS input/output, including
flush, cannot be interrupted by the asynchronous deadline; an expired budget
is observed on return and prevents further protocol work or successful exit. `--max-bytes` bounds complete input on import or output on export (default16MiB,
maximum64MiB). `--max-records` and `--max-sets` default65536, maximum1000000;
`--max-egos` defaults128, maximum4096. `--max-records-per-set` defaults4095, the
16-bit frame/header bound, and can be reduced explicitly. Actual serialized
padding and NAMESTORE prefixes impose the exact smaller per-frame limit; the
service's configured record limits still apply. Physical input lines are bounded
to262652 bytes. Reaching a bound is an error, never a fabricated EOF or END.

The pinned C importer recognizes lowercase `s` for SHADOW, while its exporter
incorrectly emits a second uppercase `S`; this exporter uses the readable
lowercase spelling. The public line format has no maintenance/unknown flag
spelling, no escaped header labels and no multiline value representation. If the selected view returns maintenance records, their unsupported flags are
refused explicitly. Unknown/inactive types, unsupported flags, labels with a dot or
leading whitespace, embedded line terminators and values whose normal text codec
cannot reproduce their binary bytes fail instead of silently changing data. Synthetic NICK records attached to non-apex iterator rows are excluded like the
public exporter. The existing numeric JSON interface remains available when a
record cannot be represented in this public text grammar.

The private protocol CLI, configuration, data formats and migration commands have
been removed. Unsupported official services are still pending implementation.

## VPN

VPN allocation uses one explicit official VPN service socket:

```sh
gnunet-cli vpn internet /path/to/vpn.sock 192.0.2.1 --family 4
gnunet-cli vpn internet /path/to/vpn.sock 2001:db8::1 --family 6 --lease-ms 60000
gnunet-cli vpn service /path/to/vpn.sock PEER service-name tcp --lease-ms forever
```

`service` accepts `tcp` or `udp`; the descriptor hashes the exact UTF-8 name
bytes using the official service-name algorithm. Default lease duration is five
minutes and the independent response timeout is ten seconds. `--family any`
sends AF_UNSPEC. `--af-profile native|linux|darwin` explicitly selects the service
endpoint's C family constants, with native as default. No DNS name resolution is
performed for a numeric Internet target.

Only a matching USE_IP result produces `vpn_allocation`; `allocated:true`
and exit zero indicate address allocation, without asserting a connected exit,
packet forwarding or host route installation. A service allocation failure has
`allocated:false` and a nonzero exit. A local deadline/cancellation/loss emits
`vpn_local_end` with `unsent` or `unknown`; unknown means a lease may exist. No
request is replayed after loss. Ctrl-C suppresses the callback, drains only an
original partial IPC frame under a finite bound and closes the original MQ. The command creates no TUN device and does not change addresses or routes.

## REGEX

REGEX uses an official service socket and one retained registration per command:
The official byte grammar uses grouping, alternation and postfix `*`, `+`, `?`;
`.` and brackets are literal bytes.

```sh
gnunet-cli regex search /path/to/regex.sock 'literal string'
gnunet-cli regex search /path/to/regex.sock 'literal string' --max-results 0 --timeout-ms 30000
gnunet-cli regex announce /path/to/regex.sock 'prefix(a|b)+' --compression 4 --refresh-ms 1000 --hold-ms 5000
```

Search prints each peer with complete GET/PUT paths, the original native
job/source epoch, result ordinal and source-clock observation time. No copied
result can be assigned to a new query. The default stops after one observed
result; `--max-results 0` keeps observing under the original finite deadline. Every result is a native observation, including repeated peer/path combinations;
no unbounded deduplication table is kept. Actual search results are discovery,
not peer authentication or proof of reachability. There is no wire DONE. An expired original deadline with zero or more observations is inconclusive and returns nonzero,
never an invented successful empty result set. A local result limit may return
zero after observations, without claiming the search was exhaustive.

Announce supports the pinned official CLI's16-bit compression and relative
refresh fields (`--compression`/`-c`, `--refresh-ms`/`-r`). Millisecond values are
converted to official microseconds; `--refresh-ms forever` preserves FOREVER. The Rust defaults are compression0, refresh300000 ms and hold300000 ms: the
original announcement registration remains owned for five minutes after its first whole
local write, under an original315000 ms overall deadline. The C source leaves
its static compression/refresh fields zero by default; this CLI does not copy
that zero-refresh/scheduler timing as a usable publication-lifetime default. Explicit `--refresh-ms 0` remains representable with its official wire
meaning. `--hold-ms N` changes the finite retention interval; explicit
`--hold-ms 0` chooses whole-write-only exit. `regex_announcement_holding` reports
the requested holding interval, refresh value, original logical command deadline
and remaining native hard budget. Source loss re-registers under the same hold
and overall targets; it never restarts either interval. A hold ending before
restoration returns nonzero. Output distinguishes `regex_queued` from
`regex_written`. Neither is publication, DHT visibility or service acceptance;
REGEX ANNOUNCE has no success ACK. Exit zero means only that the selected local
write/hold policy completed. Already published effects may outlive MQ closure.

Both commands accept `--timeout-ms` (default30000 for search,315000 for announce),
`--send-timeout-ms` (defaultmin(10000,overall)), `--io-slice-bytes` and `--path-entries`. Search additionally
accepts `--first-result-ms` (defaultoverall). The original send/first/lifetime
deadline order and zero native IO are validated before any native connection. Quote one exact expression/string argument; Unix argument bytes are retained
without silently joining or reparsing later option words. Empty canonical
strings remain representable; the service determines regex acceptance.

Output is newline-delimited JSON and flushed per observation. `regex_local_end`
contains the native end cause, original submission exposure and an
explicit local policy; it always records `wire_done:false` and
`publication_ack:false`. Ctrl-C and observation timeout immediately close the
original MQ. Canceling an awaited drive preserves partial original
cursors before that explicit close. There is no private CANCEL frame, attached
mutation replay or remote revocation acknowledgement. `regex_source_lost` retains
the retired epoch/cause/write exposure; a fresh epoch registers the exact
original search or announcement. The first-result and overall targets do not
renew. Writer/clock/protocol errors close the owner before returning the error. No hidden
Resolver, private key, C implementation, device or host route is used.

This does not
establish interoperability with an official REGEX service or DHT publication.

## IDENTITY keys

Explicit IDENTITY private-key backup and restore use the existing official key
format, not a repository/export envelope:

```text
gnunet-cli identity export /path/to/identity.sock EGO
gnunet-cli identity create /path/to/identity.sock RESTORED_EGO --private-key PRIVATE_KEY
gnunet-cli identity lookup /path/to/identity.sock EGO --private-keys
gnunet-cli identity list /path/to/identity.sock -p
```

`export` is an explicit sensitive action: success writes exactly one58-character
Base32GNS private key and newline, with no JSON or cleanup rows mixed into the
backup. It waits for the exact-ego lookup. Ordinary JSON commands continue
to contain only public keys. Explicit `--private-keys`/`-p` adds `private_key` to
list, monitor, exact/suffix lookup and successful-create JSON output. This field
is written directly from an erased fixed buffer, not retained in an ordinary
JSON Value/String. Users own the destination of this deliberately sensitive
output; the program creates no backup file or permission policy on their behalf.

CREATE accepts `--private-key`, `--privkey` or `-P`, including the two long
`--option=value` spellings. The standard unpadded Base32GNS value encodes all36
bytes: the official network-order four-byte key type followed by the original32
private bytes. Supported ECDSA/PKEY and EdDSA/EDKEY types are preserved; imported
material is never regenerated or reinterpreted through `--type`. Combining an
import with `--type` is refused. Case, O/I/L/U aliases and unused final padding
bits follow the existing official Base32GNS codec. Raw32-byte seed text, hex,
extra whitespace and unknown key tags are not a second accepted private format.

Private argv values are inherently visible to OS process inspection, as with
C's `-P`. The CLI moves its owned private-argument buffer into a zeroizing owner
before normal option parsing, replaces the original owned argument, and never
echoes unknown arguments or material in errors/Debug. Decoded36-byte and encoded
58-byte buffers are also zeroizing. No claim is made about OS argv memory,
stdout's external destination or copies retained by another process.

Import uses the original `Client::create` and ordered result. No entropy
provider is opened for an import. A local whole write is not CREATE success;
partial/lost/unknown results never replay. After timeout, interrupt, output error
or a result, the same original source is physically closed and its local terminal
queue is drained without a clock/reconnect. Error reports retain original
operation, status/material-presence, original source loss, exposure and
independent diagnostic/cleanup failures without any private bytes. Default
finite operation bounds and existing CRUD/generation remain in place.

The public source contract is GNUnet v0.29.1 commit346358e26d4dcc2dc4f51bef5d52dca29c7d8165,
`src/cli/identity/gnunet-identity.c` CREATE/privkey/private-keys branches and
`src/lib/util/crypto_pkey.c:66–82,411–452`. C's unchecked CLI decode return is not
copied: malformed imported material is refused before any native CREATE.

## IDENTITY message envelopes

IDENTITY also exposes the official one-shot message envelope through actual
normal commands:

```text
gnunet-cli identity encrypt TYPED_PUBLIC_KEY MESSAGE [--timeout-ms 30000]
gnunet-cli identity decrypt /path/to/identity.sock EGO BASE32_ENVELOPE [--timeout-ms 30000]
```

These correspond to the public C `-W`/`-k` and `-R`/`-e` operations. Encryption is
local and needs no service lookup or new identity. Decryption performs a real
exact-ego IDENTITY lookup and uses that returned opaque secret directly. It
creates no new key or service mutation and never retries the original lookup. Ciphertext and plaintext are native argument bytes; no UTF-8 conversion or JSON
String owns them. Successful output is one raw Base32 ciphertext line or the
authenticated original plaintext bytes plus newline; cleanup JSON is not mixed
into either stream. Normal list/lookup still do not expose private data.

The existing HPKE one-shot primitive supplies the standard `enc32 || ciphertext
|| tag16` envelope with empty info/AAD. The CLI encrypts the original message plus
one terminal NUL and serializes the whole envelope as Base32GNS. On decryption it
authenticates before using any plaintext, requires that exact terminal NUL and
refuses an interior NUL instead of silently truncating authenticated bytes. Empty
messages remain valid. Both supported typed identity key families use the
existing Edwards/ECDHE conversion; there is no new encryption algorithm, extra
wire prefix, version negotiation or plaintext fallback.

The explicit local message bound is1MiB before the terminal NUL. All owned input,
plaintext, envelope and encoded buffers are zeroizing. The CLI takes its message
argument ownership before ordinary parsing and never includes that input, the
recipient string or a private key in an error/Debug value. As with C's message
options, argv and external stdout destinations remain OS/user-owned exposures.

A single original finite native deadline and same Ctrl-C future cover each
command. Decryption additionally retains the original lookup's canonical target
and same Clock Arc. Real guards run after preparation, before each conversion or
HPKE operation, and around output; entropy reads also check the original hard
and known stop state and erase a partial fill on error. Synchronous crypto,
entropy reads and stdio cannot be forcibly preempted by an asynchronous signal;
these are documented synchronous boundaries, not claimed cancelable workers. Actual primitive, entropy, signal and output causes are retained independently. The same original IDENTITY source closes even when decryption or output fails. Monitor loss likewise retains its typed source cause before any diagnostic
writer can fail.

## TRANSPORT monitoring

TRANSPORT queue monitoring and virtual-link enumeration use the native
CLIENT owner and standard PROGRAM/configuration/Resolver/clock path:

```sh
gnunet-cli transport links - -c /path/to/gnunet.conf --include-unconfirmed
gnunet-cli transport links /path/to/transport.sock --peer PEER
gnunet-cli transport monitor - --one-shot --timeout-ms 30000
gnunet-cli transport monitor - --continuous --duration-ms 300000
```

`-` selects the configured `[transport]` Unix/TCP endpoint. An explicit socket
path disables TCP fallback. `--peer` accepts the existing GNUnet peer spelling or
hex form. Records are bounded NDJSON with physical source epochs, all
public numeric fields and exact address/communicator bytes as hexadecimal. No
aggregate row count limit narrows an otherwise valid server listing.

A one-shot succeeds only after the expected MONITOR_END/LINK_LIST_END,
the complete terminal output line and stdout flush. EOF, timeout and cancellation
never stand in for END. Continuous mode emits source boundaries, explicitly
restarts retired transient sources within the unchanged original lifetime, and
retains original losses; any source gap makes its eventual exit nonzero even if
later epochs supplied records. Duration or SIGINT/SIGTERM is a local stop and
produces no fabricated service END. Protocol/configuration/clock-port/resource
failures remain explicit. Already emitted rows may precede a later failure.

One held output row is bounded by the official65535-byte frame and its bounded
JSON expansion. Native/parent/signal/row/whole-operation guards precede each new
source or stdout step; slow output stops the original client rather than
building an unbounded queue. Borrowed stdout flags are unchanged. A synchronous
filesystem/TTY write or flush cannot be preempted; a returned late operation is
reported without inventing a completed snapshot. The pinned C server's missing
MONITOR_END and initial-filter bug remain reference behavior limits, not reasons
to fabricate a completion or add a private protocol.
