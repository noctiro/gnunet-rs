# Standard MESSENGER SERVICE

`gnunet-service-messenger -c gnunet.conf` uses the shared standard SERVICE
options (`-d`, `-L`, `-l`, `-h`, `-v`), selected logger, inherited listener and
parent-control owners, configured USERNAME, ACL/kernel Unix credentials, signals,
one shared Resolver/clock, one CADET MQ, one public/signing PILS MQ and one
explicit history worker. It does not wrap the service in a second PROGRAM task. No C identity or history file is opened or migrated.

Node-wide `[PILS] PROFILE` selects `reference029` (also `reference-0.29.1`, the
default) or official conditional `deterministic`. An optional `PILS_PROFILE`
under `[messenger-rust]` must agree with the explicit node choice. Unknown or conflicting
selections fail before service construction; verification never guesses another
mode. This controls PILS/HELLO verification, independently of Messenger
message byte order and original-producer body layouts. Healthy same-MQ identity
rotation settles original signing work before applying the next identity;
physical source loss remains a failure. The room owner preserves its hash-only listening-port intent on the original
CADET MQ. Healthy identity changes require no port-close/reopen exchange or
invented PID acknowledgement. A fresh OPEN reply carries the applied current
identity; immutable old notices and signed authors retain their original bytes.

The daemon split occurs before NSS/runtime/path guards or workers. The parent
waits on the original ready byte; EOF is failed startup. Original activation and
TCP preparation precede USER; newly created Unix paths are finished under the
target identity using the configured access mode. Existing activated
listeners are adopted, never rebound. Filesystem mode is not a substitute for
the existing kernel Unix-credential admission check.

The selected logger receives provider events, readiness, original errors
and cleanup failures. Its first failure permanently fences fresh work, wakes the
original service loop and is retained independently through cleanup. READY is
flushed and logged before ChildReady is written, after public PILS
identity, CADET attachment, live listeners and the initial/current committed
history cut. Standard C SERVICE_OPTION_NONE gives immediate shutdown by default;
an explicitly configured soft mode retains the existing finite grace path.

Durable history is the default. `[messenger-rust] HISTORY_DIRECTORY` selects a
new final private directory or the exact marked Rust namespace. Its parent must
already exist. The service creates the final directory/marker under the
configured UID/GID; it refuses existing unmarked, foreign or replaced ownership. Otherwise official `[messenger] MESSENGER_DIR` selects a **distinct sibling**
`<configured-path>.rust-history-v1`, or `${GNUNET_DATA_HOME}/messenger-rust-v1`
is used. Neither fallback opens the C path. Explicit `VOLATILE=YES` disables the
store. A previously marked generation-zero directory missing its canonical image
fails closed; a truly new store commits an initial empty image before READY. Committed history retains original authors and bounded own-signer provenance,
never a current private key, live source or write capability. A fresh actual
PILS observation supplies current authority, including after cold restoration
under a different PID; this does not claim those identities share a master. Its new historical checkpoint must actually commit before new output or READY. `OWN_SIGNER_IDENTITIES=256` bounds retained local signer metadata (max65536),
which is charged to Core's retained-byte budget. The new private archive format
is `GMSHIS06`; earlier private bodies are refused without a migration or reset.

`HISTORY_IMAGE_BYTES=16MiB` (max64MiB), `HISTORY_BATCH_EVENTS=32` and
`HISTORY_BATCH_DELAY=16ms` bound one full immutable snapshot and the gather cut. The image cap must cover configured RETAINED_BYTES in durable mode. Actual
serialization may still refuse a too-small image; it never truncates history. A single explicit storage worker performs file/directory sync. A worker admission
is not commit. New notifications, relay payloads and CADET receive_done are held
until the original cut is actually committed; already queued original partial
writes still drain. Unknown storage results latch failure and are not replayed.

The existing finite native/Core settings remain: MAX_CLIENTS16, MAX_ROOMS4,
ROOMS_PER_CLIENT4, MAX_TUNNELS16, DELIVERY_RELATIONS512, SIGNATURE_JOBS16,
CONTROLS_PER_CLIENT8, IO_SLICE_BYTES65535, CONTACTS256, SESSIONS_PER_ROOM64,
MESSAGES_PER_ROOM128, EPOCHS_PER_ROOM64, GROUPS_PER_EPOCH8,
SUBSCRIPTIONS_PER_ROOM64, MISSING_PER_ROOM64, NONCES_PER_EPOCH128,
RETAINED_BYTES8MiB, WORK_PER_TURN32. INPUT_LIFETIME30s,
OPERATION_LIFETIME60s, RETIREMENT_GRACE5s, SHUTDOWN_GRACE10s and
PILS_STARTUP_TIMEOUT30s use ordinary GNUnet time syntax. Archived room slots stay
bounded and are not silently evicted; exhaustion is an explicit resource refusal.

The official listener/ACL and MESSENGER_AUTO_CONNECTING/AUTO_ROUTING/GROUP_KEYS,
MIN_ROUTERS/LOCAL_REQUEST settings remain under `[messenger]`. `[cadet]` and
`[pils]` select explicit endpoints. No hidden network discovery is created.

## Original producers and relay transports

`PEER_ENDIAN=little|big` explicitly declares the default unchanged C relay ABI
(the local native order is the default). It is separate from an original member's
body grammar. `COMMON_FILE_NAME_BYTES=255` explicitly limits otherwise unknown
FILE producers to that NAME_MAX; `reject` refuses unknown FILE layouts instead. `LAYOUT_RULES=64` bounds each of the three fixed configuration directories. Each value below is whitespace-separated, with at most1MiB of configuration:

* `RELAY_LAYOUTS`: `peerhex64/port-order/name-max/incoming-padding-order/outgoing-padding-order`.
* `ROOM_LAYOUTS`: `roomhex128/creator-order/name-max`.
* `PRODUCER_LAYOUTS`: `member/pubhex72/order/name-max`,
  `peer/pubhex64/order/name-max`,
  `message-member/roomhex128/hashhex128/pubhex72/order/name-max`, or
  `message-peer/roomhex128/hashhex128/pubhex64/order/name-max`.

Orders are `little` or `big`; widths are checked positive decimal NAME_MAX values. These are local configuration facts, never private wire tags or inferred endian
probing. Exact per-message rules take precedence, then retained authenticated
message provenance, then original signer rules. Signature checks still decide
the original signer. Unknown non-FILE signed bodies can be forwarded as
portable network-order/opaque grammar. The pinned C implementation encodes and
decodes padding in its own host order, so cross-layout adaptation may require
independent incoming/outgoing declarations. Relay connection identity is never
substituted for every original author. Signed bytes/hash are never rewritten.

An unchanged C local application still has its own FILE NAME_MAX assumptions;
there is no IPC layout tag. The separate Rust high-level client's fully generic
mixed-layout decryption/identifier handling is implemented by its separate M5
`ClientLayout`/`Profiles` API, not by daemon private-key access. App SEND follows
its bound OPEN principal's configured body layout and Core signature
admission. The daemon can retain and relay explicit third-party originals and
keeps their body layout through storage/recovery.

READY requires PILS identity, CADET attachment and the initial/current
durable cut, and reports generation/worker count. On normal/error
exit all physical network owners stop first, then the final original cut drains
and the explicit worker joins. Cancellation's emergency Drop joins any already
admitted worker but does not claim a new unsubmitted final cut was durable. Finite MQ grace does not imply cancelable fsync; STOPPED preserves stored
generation, cut status, original failures and independent cleanup. Remote
application delivery/quiescence remain unclaimed.

## Official statistics

The existing bounded native STATISTICS owner uses the same original Resolver and
clock, subsystem `messenger`, and six nonpersistent official keys:

* `# handles connected`: accepted live handles, including pre-CREATE.
* `# room openings` and `# room entries`: successful original local operations;
  the first count is at Opening/Entering -> Active, after the port or
  compatible entry is ready. A successful repeat on an active lease also counts.
* `# room closings`: successful release of an established handle-room
  lease, including disconnect. Merely queuing a CLOSE response does not count.
* `# rooms active`: distinct live rooms with established local handle leases;
  restored, unopened history is not a live room or a counter event.
* `# message notifications`: once when a complete service fanout marks its
  original work fanned, regardless of recipient count. Neither per-recipient
  write nor historical restore/INFO suppression increments it.

Cumulative values saturate at u64::MAX without failing business work. Gauge
updates and signed counter deltas enter only the original bounded statistics
owner. An admission error fences that owner; uncertain deltas are not replayed
through a new owner. Its final best-effort processing barrier has a finite native
cleanup bound and physical close; confirmation is not durable storage.

`try_install_history(&mut pending)` checks the original domain/profile and all
service preconditions before consuming the source-free History/Restored pair. An installation failure retains both original owners for explicit shutdown and
join; normal/error exit still performs `finish_history`. Original business,
final-cut, worker-join, native-close, Resolver, statistics, logger and output
failures remain distinct retained causes, including concurrent failures. Emergency Drop closes original network owners and joins already admitted worker
work; it cannot promise an unsubmitted final cut.

At shutdown, `accepted-cut-committed` describes successful final history
completion, independently of revoked live PILS authority. Explicit volatile mode
reports no durable commit. Local write completion and normal process exit remain
separate from remote delivery and remote-effect quiescence.
