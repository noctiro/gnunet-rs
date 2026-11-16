# gnunet-zoneimport

The standard PROGRAM takes numeric DNS resolver IP addresses as positional
arguments (port 53) and reads one full hostname per stdin line. After EOF,
one caller-owned online importer performs the IDENTITY inventory, creation
of needed child zones/delegations, NAMESTORE cache iteration, DNS NS requests,
matching response conversion and STORE-result handling. Refresh continues
until native stop signals, parent control, PROGRAM stop or a fatal original cause. The host owns those transactions; this executable invents no DNS/STORE success. Actual IDENTITY/NAMESTORE EOF or IO loss reconnects the same existing client after
its original operations retire, without replaying any unknown mutation. Healthy
independent names continue. Initial inventory keeps the original fixed hard;
already active inventory is not rebuilt. Protocol/resource/port errors remain
fatal. Failed input names and uncertain names remain visible in the final
report and produce a nonzero result, independently of successful reconnection. An original terminal CREATE or parent-delegation rejection drained after stop
still counts as a failure. User-requested cancellation of healthy unsent
work does not create a business failure; uncertain exposed mutations remain
uncertain through cleanup.

## Options

Standard `-c`, `-L`, `-l`, `-h`, `-v`, testing-clock and logging policy are handled
by the shared PROGRAM. `-m`/`--minimum-expiration` is the original record-expiry
floor, including FOREVER, independent of finite operation deadlines. `-s`/`--size`
is an initial allocation hint for the Rust input-name/index table (default
1024, clamped to its independent name cap); it does not emulate C hash buckets or
change the maximum input size. The bounded business core reserves its own pools.

## Native input

The original stdin route is captured once before logger/runtime construction.
Unix uses unbuffered bounded reads after `poll(2)` readiness without changing
shared descriptor flags. Idle input wakes every 25ms. Windows uses one
capacity-one reader: console UTF-16 becomes UTF-8, while redirected files and
pipes preserve bytes. Split surrogate pairs and partial UTF-8 output are
retained; invalid console Unicode is an input error. Console Ctrl-Z at the
start of a line ends input.

Cancellation retires that same pending read and observes native cancellation,
worker exit and original-handle close separately before importer admission.
A retirement deadline preserves an unresolved result. Synchronous Unix file
reads remain nonpreemptible. Resolver, native stop/parent control and Reporter
failure remain active while collecting input. No importer is constructed before
EOF and successful input retirement. CRLF and a final line without LF preserve
the full name. Invalid IDNA/FQDN names are counted and skipped; allocation,
capacity and native failures stop through same-owner cleanup.

## Configuration and ownership

`[zoneimport-rust]` sets explicit finite resource policy. Defaults are NAMES=65536,
INPUT_BYTES=16777216, NAME_BYTES=16777216, ZONES=4096, JOBS=100,
RECORDS_PER_SET=4096, DNS_REQUESTS=64, TCP_REQUESTS=4, RESPONSE_BYTES=65535,
IO_BYTES=8192, DNS_ARENA_BYTES=4194304, DNS_RECORDS=8192,
OPERATION_SECONDS=30 and CLEANUP_SECONDS=5. Each physical input line is bounded to
4096 bytes; at most 16 resolver addresses are accepted. These are resource bounds,
not new GNUnet wire fields. Capacity exhaustion is an explicit error.

IDENTITY, NAMESTORE, Resolver and nonpersistent STATISTICS share the live
configuration and exact process clock Arc. A thin metric definition uses the
host's 17 public `zoneimport` observations with the existing shared Producer. Only original local whole writes settle publisher coordinates. A lost/unknown
publisher is fenced and never recreated to replay deltas; its failure does not
stop otherwise healthy import work. Queueing is neither a STORE result nor a
remote/durable statistics acknowledgement.

Every post-construction error closes the same importer and polls its clockfree
original retirement. A fixed native cleanup hard is created once; expiry retains
the unretired metadata and causes physical Drop, never a fabricated
Closed. The input worker is retired before the importer starts; the importer owns no subprocess. Normal final metrics are
frozen once for bounded publisher drain; fatal source/logger/cleanup failure
physically aborts that same publisher instead. Resolver disconnect/Drop is last. Original business, cleanup, statistics, Resolver and selected Logger errors stay
with the owned terminal report, including a Logger-only failure. The
summary is a selected-log diagnostic; stdin data never becomes protocol output.
