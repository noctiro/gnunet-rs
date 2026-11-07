# TCP durable public replay floors

This host owner uses the qualified Snapshot `TransportTcp` namespace and
one original bounded Worker. It stores a fixed local public peer, public random
LedgerId, persisted bootstrap phase and sorted `(remote peer, ReplayKind, max
stamp)` records. No keys, ciphertext or nonce history is stored. Complete restore
checks namespace, image generation, exact lengths/count, local identity, phase,
reserved bytes and strict unique ordering. Capacity is caller-declared and no
record is evicted. A whole next image is serialized once; the live catalog is
not cloned, and a single-row delta is installed without allocation only after
its original Job/namespace/generation commit. Raw buffers are Zeroizing.

Official families remain distinct: `transport-tcp-communicator-handshake`,
`transport-tcp-communicator-handshake-ack`, and `transport-tcp-communicator-rekey`. Only stored > received rejects; equal values retain official behavior. An
session must already have verified its signature before submit. A local
Floor proves persistence, not signature, session acceptance or remote STORE. The caller retains the original session Ticket/client/native generation and
matches the returned original Token/peer/kind/stamp before any original effect.

Initialization first persists an original public-ID/local-peer min0 intent in
its V2 frontier, before creating any ledger directory. No signature, replay
floor authorization or external STORE is permitted by this phase. The same
intent then qualifies the TransportTcp namespace, commits empty Unbound gen1,
persists frontier min1, and commits Bound gen2. A complete marker and empty gen0
can recover only with that clean/reserved0 min0 intent; Unbound gen1 can
resume before or after min1. Once Bound, missing/foreign/lower-generation
frontiers or catalogs fail closed. Creating a new empty directory, local peer,
LedgerId or PID never resets burned signed time or an existing floor.

The shared TransportTcp first-create overlay publishes a fully synced marker
with an atomic no-replace directory rename, then syncs its parent. It does not
take over existing unmarked or partly marked final directories. This source
supports first creation on macOS and Linux GNU through that shared overlay;
other Unix targets explicitly refuse first creation. Existing qualified reopen
still uses the shared backend. `bind_frontier` reads only the explicitly paired
absolute public89-byte frontier, with O_NOFOLLOW, exact regular/private file,
original inode checks, file fsync and parent-directory fsync before submitting
Bound. One original frontier writer allocation is pinned per live ledger.

`open` retains constructor-started worker ownership in OpenRejected on
post-start admission failure. Poll preserves canceled jobs until completion:
committed canceled values still advance the catalog but produce Retired, never a
new Floor. Unknown/worker loss permanently fences the original source; no job is
resubmitted. `begin_close` is clock-free; `shutdown` drains original
outcomes and joins, preserving both first fault and independent join/store
results. Worker Drop is an emergency physical join, not business quiescence.

The runtime V2 frontier is89 bytes: original dirty/reserved signed time plus
LedgerId/local peer/minimum authorized ledger generation. V1 is explicitly
refused with no migration. An complete Catalog lease must match this
binding. Dirty restart then needs that same catalog at or above minGen;
it does not invent an old Quiescent proof. New local identities/ledgers do not
clear an existing frontier, including a clean one. Signed-time reserved ranges
remain independently burned. Before each original PS STORE, Floor must
pass ClockPort.authorize_replay's durable minGen barrier; only its private
ReplayPermit can authorize that original session/epoch effect. An old late
remote REPLACE can lower PS data but cannot lower the local max floor. Scans must
compare max(local floor, remote records), never manufacture END.

The complete companion integration supplies Manager ReplayHistory tasks and a
single ProcessPorts owner of this Ledger and the original ClockPort. A local
floor uses Session.replay_floor after PS Start admission and creates no
iterator credit or callback. Only PS END enables StoreReady. Every actual
Store byte string waits for the exact peer/kind/value worker receipt and its
frontier barrier; if a newer verified value arrives, the old worker settles
before a new higher intent. The normal startup companion performs this pairing
and always drains/joins the same worker before deciding whether the original
Pool Quiescent proof may clean its epoch. No NoLedger/Noop production fallback,
V1 migration, fake quiescence or public u64 durable-proof constructor exists.

This change adds no model, crypto, entropy, key, storage, worker or
native/product execution evidence. Historical runs retain their original source
graphs. The
snapshot and frontier guard against missing/foreign/older components within
this paired deployment; they do not claim protection against simultaneous
hostile rollback of all persistent files or a hostile replacement of the
entire trusted storage root.
