# Native TCP communicator

`gnunet-communicator-tcp -c official.conf` runs the Rust TCP sessions over actual
TCP sockets and official PILS, TRANSPORT, PEERSTORE, NAT and STATISTICS IPC. The
protocol source basis is GNUnet v0.29.1. Rust owns its protocol state machines,
bounded session storage and runtime adapters independently of the C process split.

The standard PROGRAM entry uses the selected shared Logger/Reporter and one
Services context, Resolver broker and clock Arc. `BINDTO` accepts a bare port,
numeric IPv4/bracketed IPv6 or a hostname with optional port. Hostname lookup uses
that same official Resolver, with a fixed 60-second native/logical budget and up
to 16 callbacks/listeners. Each callback performs its bind before returning
its lease; excess is explicit refusal, never silent truncation. Inherited FDs are
adopted once. All listener binding precedes configured `USERNAME`; the original
FDs and Services context survive that switch and enter the normal PROGRAM task. The original foreground future is retained outside the scheduler so a scheduler
failure can drive its cleanup instead of dropping its resources.

The configured `KEY_PROVIDER` is `existing-local`. It reads the existing
`[peer] PRIVATE_KEY` only after the PILS identity is available, and the
public identity must match that verified announcement. It creates no replacement
key. A healthy peer change on the original PILS MQ retires the old generation,
settles its replay worker and starts a fresh matched generation on the
same listeners. Physical PILS loss/replacement remains fatal. Same-key address
changes on the same MQ preserve healthy sessions. A Node may instead
inject its existing lawful key capability through the embedding API.

## Protocol and ownership layers

The pure core owns framing, handshake/rekey and replay comparison. The host
Manager retains session, ticket, physical-MQ epoch and PEERSTORE scan
identities. Pool owns one fixed backing allocation per configured session; pending
reversal parents reserve separate bounded registry metadata, without doubling the
payload/crypto backing. ProcessPorts supplies the original ClockPort and a single
replay Ledger/Worker to those same Manager operations. The runtime owns sockets,
publication and shutdown; the standard app injects the shared statistics Producer. The runtime and protocol host have no dependency on the native IPC publisher.

Process capability acquisition, Resolver and final publisher retirement stay in
`startup.rs`. `startup/generation.rs` owns one immutable matched key pair, Pool,
fixed backing, replay worker and its complete original cleanup. The listeners
are borrowed from the process owner. The old mutable current-key port is removed;
crypto operations cannot pick up another generation's private key. The process
supervisor retains its original observer, listeners, writer fence, Resolver and
statistics publisher. Successive generations exist one at a time; their buffers
and keys are released before the next generation is allocated. The first observed
cut starts one native/canonical 30-second recovery window. Repeated updates and
superseded replay preparation share it until a matched generation is ready. Actual source loss, uncertain history or failed retirement prevents replacement. Lifetime counters survive once, while queue gauges describe the current
owner. Only the first generation emits process READY; typed diagnostics report
subsequent local readiness without claiming reachability.

PublishedPool merges listeners, native interface snapshots and official
NAT ADDRESSES into canonical multi-source claims admitted to the original
TRANSPORT ADD/DEL FIFO. Loss withdraws only that source. A fresh NAT observer can
start after its End and old unsupported DEL admission; it never replays an
old mutation or renews the first cleanup deadline. Readiness describes local
listeners, service acquisition and READY output flush, not remote reachability.

IPv4 port-zero CREATE uses that same original NAT registration. Its reverse
admission retains the original expected peer/IP/generation and ten-second bound. The bounded prototype driver reads the official 4/36-byte preamble. A clear probe
cannot authenticate or consume an unrelated pending parent. Only a newly admitted
Session reaching Established for the exact parent can satisfy that request. NAT
connectback writes the probe and hands the same socket to the existing
Session. The Rust implementation deliberately waits longer than C's early
clear-probe cleanup; this changes internal ownership, not wire authentication.

## Persistent replay recovery

`[communicator-tcp-rust] STATE_DIRECTORY` defaults to
`$GNUNET_DATA_HOME/tcp-rust-state`. It contains independent V2 frontier files
(89 bytes) and a qualified replay namespace for each complete local peer:
`tcp-<64 lowercase hexadecimal peer bytes>.frontier` and the matching `.replay`. The frontier binds burned
signed-time ranges to the exact local peer, public LedgerId and minimum durable
ledger generation. The original unsuffixed `tcp.frontier.tcp-lock` writer fence remains
held across all generations, so another process cannot open this state root
or an old unsuffixed writer concurrently. Existing unsuffixed frontiers and
replay footprints are explicitly refused without migration or reset. Per-peer
frontiers keep their own original descriptor/writer fences too. V1 files are
also refused. Missing, foreign or older components do not authorize a fresh empty catalog. Returning to the same local identity selects the same complete path, rather
than a new counter or truncated-peer namespace. Namespace/writer-intent checks
do not by themselves qualify replay-floor recovery through normal identity
rotation. Disk history retention across unbounded identity changes remains
separate resource-policy work.

First initialization persists a min0 intent before any ledger directory, commits
an empty Unbound generation, persists the minimum generation, then commits Bound. The shared store publishes its complete marker directory with atomic no-replace
rename and parent sync. New-directory publication is implemented on macOS and
Linux GNU; other Unix platforms currently refuse first creation explicitly.

The Ledger retains a never-evicted maximum for each remote peer and each official
handshake, handshake-ack and rekey family. `REPLAY_RECORDS` defaults to 8192 and
bounds distinct peer/kind rows. Only stored > received rejects, retaining official
equality behavior. A local floor enters the original scan through a dedicated
comparison seam after START admission; it cannot manufacture NEXT or END. An outgoing original STORE waits for its exact worker Floor, durable frontier
minimum and private ReplayPermit. A newer verified value settles the old worker
job before a new one; an already admitted STORE is never replayed. A late remote
REPLACE cannot lower this local maximum.

Dirty restart requires the matching catalog at or above the frontier's
minimum. Reconnecting PEERSTORE, changing a PID/key or creating an empty directory
cannot substitute for that recovery. This pairing does not claim protection
against hostile simultaneous rollback of the entire trusted persistent state.

## Statistics and shutdown

The standard executable publishes the six nonpersistent official
`communicator-tcp` metrics through the existing shared Producer. Counts come from
verified BOX, incoming rekey and original receive outcomes. Retired session
counters are accumulated once; the active-queue gauge comes from the local
registered inventory. Final values are captured before dropping that owner,
without fabricating a zero gauge. Publisher failure fences that publisher while
healthy TCP continues. Its report and errors remain separate from TCP.

The same signal/parent/Reporter stop future gates prebinding, key work and each
native admission. Normal Stop closes original NAT/address debt and takes back
the same Pool before session/MQ drain. Clock/logger failure uses clock-free
retirement. One first-stop 30-second native deadline is retained across phases;
it never grants a clean epoch by timeout. Only the consumed Pool
Quiescent proof, successful original worker drain/join and frontier conditions
can finish that epoch. A blocked filesystem operation can delay join beyond
the diagnostic deadline; it is never reported as a stopped worker prematurely. The statistics publisher has its own fixed five-second final drain, polled fairly
alongside the same worker future and Resolver. Independent TCP, worker, frontier,
statistics and Resolver failures survive the final report.

Compiler and architecture checks are recorded separately from execution evidence. Historical source1197/baseRoot1184 C v0.29.1 TCP profiles and older component runs
retain their original source graphs; they are not acceptance of this revision.

## Local TRANSPORT service recovery

The normal foreground keeps its original Pool, listeners, established TCP
streams, prepared ciphertext positions, identity and durable replay epoch when
the local TRANSPORT MQ fails and the original Manager successfully retires that
source's callbacks. One retained Dial restarts native acquisition on its original
selector/Resolver/clock and receives its own eighth fair scheduling position. The original Manager continues duplex MQ and peer work while offline and during
replacement REGISTER and current queue reannouncement; recovery never waits for
all queue setup writes before permitting reads. Existing TCP bytes already
prepared on an original stream finish at that same cipher/write cursor; they are
not reencrypted or resubmitted as a replacement SEND.

The service-source generation invalidates old flow, SEND and CREATE
callbacks. Queued old SENDs and unclaimed CREATEs retire in the host; normal
claimed CREATE results are diagnosed and discarded without writing their IDs to
the replacement MQ. A port-zero reversal not yet submitted to NAT is canceled
and its old CREATE result retires. Already admitted NAT writes and native
prototypes keep their original source, byte positions and finite bounds; they
are not replayed and can only enter an ordinary authenticated Session through
the existing admission path.

PublishedPool notices the transport generation change and retires only
its old FIFO-admission flags. The same listener/NAT claims and original interface
freshness remain; expiry and complete scans still run during an outage. No ADD
is queued to an offline source. A replacement MQ receives only fresh standard
ADDs for claims still current after the existing guards, preserving their IDs;
there is no synthetic scan, NAT success, PILS FEED replay or renewed old source
operation. `TransportRetired` reports old FIFO retirement, while normal
`AddQueued` still means admission only.

Diagnostics separate source loss, replacement attachment, old CREATE
retirement and locally completed current queue announcements. The latter requires
the IPC FIFO to be empty after REGISTER/reannouncement flags settle;
it neither grants remote acceptance nor gates continued service reads/writes. Stop, selected Logger failure, physical PILS source loss, protocol refusal,
clock failure and uncertain replay history still fence recovery and retire the
original epoch. PEERSTORE recovery remains separate. Cancellation drops only
the retained native Dial attempt and preserves its unobserved failure/notice. This increment is source implementation; normal restart/runtime interoperability
is not established by these methods or diagnostics alone.

The normal startup selects the PILS identity/HELLO interpretation from
`[PILS] PROFILE` (default `reference029`, alias `reference-0.29.1`). An explicit
`[communicator-tcp-rust] PILS_PROFILE` must agree with the global choice. Both
`deterministic` and its `reference-deterministic` alias select the official
conditional address-derived identity; explicit `lsd0014-text` selects the
published textual derivation, with no official interoperability claim. The typed
choice reaches the PILS client and existing-key match; failed verification
never falls back. TCP handshake/rekey policy is independent. A healthy changed-key
announcement on the original observer selects a fresh generation only after
original retirement. It never replays old SEND/CREATE, NAT mutations,
handshake bytes or unknown STORE work.
