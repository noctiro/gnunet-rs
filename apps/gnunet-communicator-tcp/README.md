# TCP communicator PROGRAM

Run `gnunet-communicator-tcp -c official.conf`. Shared PROGRAM handles `-h`, `-v`,
`-L LEVEL` and `-l FILE`; no private capability/state flag is required. The protocol
source basis is GNUnet v0.29.1.

`[communicator-tcp]` supports bare-port/numeric/hostname `BINDTO`, `DISABLE_V6`,
queue/rekey settings and configured `USERNAME`. New listener sockets are prebound
before USERNAME; inherited sockets are adopted once. One current-thread runtime,
Services context, original Resolver broker and clock span lookup, account switch
and normal PROGRAM. Hostname lookup has a fixed 60-second budget and at most 16
address callbacks, each bound before its original lease is acknowledged.

Rust-specific settings live in `[communicator-tcp-rust]`:

- `KEY_PROVIDER = existing-local` (default): reads the existing `[peer] PRIVATE_KEY`
  only after the PILS identity and requires the same public identity. No
  key is generated or replaced.
- `STATE_DIRECTORY`: independent V2 state, default
  `$GNUNET_DATA_HOME/tcp-rust-state`; no C store import or legacy migration.
- `REPLAY_RECORDS`: maximum distinct remote peer/replay-kind floors, default 8192.
  Floors are never silently evicted; capacity exhaustion refuses new work.

Each complete local peer has its own V2 89-byte `tcp-<64 hex peer>.frontier`
and matching `.replay` catalog, which form one durable
pair. Matching catalog floors protect recovery after dirty loss and prevent late
remote PEERSTORE REPLACE from lowering local replay protection. Missing, foreign,
older or V1 state is refused without reset. The normal entry initializes and
reopens this pair before starting its original Pool; reconnect/PID/key
changes cannot create recovery authority. First-create atomic directory publication
currently supports macOS and Linux GNU; other Unix targets explicitly refuse it.

listeners, interface snapshots and NAT notifications publish canonical
ADD/DEL claims through the same Pool. IPv4 `tcp-IP:0` CREATE uses that same NAT
registration and the reversal driver. Clear 36-byte probes do not authenticate
a peer; the existing Session completes identity, signature, replay and challenge
checks before satisfying its exact pending parent. Local queue/write admission,
READY output, peer authentication and remote delivery remain distinct outcomes.

The standard entry injects a shared Producer for the six official
nonpersistent `communicator-tcp` statistics. It uses the same Resolver and clock;
no second IPC runtime is added to the protocol host. Publisher failure remains an
independent result and does not stop healthy TCP or retry uncertain updates.

SIGINT/SIGTERM, inherited parent control, Logger failure and clock/source
failure retain the original foreground future, Pool, partial I/O and cleanup debt. Normal shutdown captures final metrics before dropping the Pool, drains and
joins its replay worker, and requires that Pool's consuming quiescence
proof before cleaning the original epoch. The first 30-second cleanup deadline
is not renewed and cannot masquerade as a successful join. Statistics retains its
own five-second final drain alongside the original join; all original and cleanup
errors, including Resolver disconnect, remain independent. Healthy changed-peer
announcements on the original PILS observer retire the original immutable
generation and start a fresh verified generation on the same listeners. The original process writer fence, Resolver and publisher survive. Repeated
updates share one recovery bound; physical observer loss remains fatal.

READY reports local listening/service acquisition and successful output
flush, not remote reachability. C peer, helper/device, remaining
fault/restart and performance profiles remain separate. Older runtime receipts
retain their original source bindings.

The normal foreground reconnects after an isolated local TRANSPORT I/O loss. It retains its original listener and healthy TCP sessions, key and paired replay
state while retiring old source callbacks. Its existing fair driver performs
replacement connection, standard REGISTER and current queue/address announcements
without replaying old SEND/MID, CREATE or NAT reversal operations. Address claims
keep their original freshness. Stop, Logger, physical PILS loss, clock, protocol or
replay uncertainty still stop this owner; PEERSTORE recovery is separate. The standard Reporter exposes the local source and original CREATE
retirement facts. This source addition does not itself qualify normal restart
interoperability or full TCP/GNUnet completion.

TRANSPORT attachment, whole local queue reannouncement, and retired address
source generations use the ordinary INFO level. Builds without optional DEBUG
logging retain these bounded source-transition observations; they imply neither
peer delivery nor remote validation.

Normal identity selection follows `[PILS] PROFILE`: `reference029` (also
`reference-0.29.1`) remains the default, `deterministic` (also
`reference-deterministic`) selects the official conditional address-derived
profile, and explicit `lsd0014-text` selects the published textual derivation
without claiming official interoperability. Optional
`[communicator-tcp-rust] PILS_PROFILE` must agree with an explicit global choice. This typed choice reaches the PILS client and existing private-root match;
it does not alter TCP handshake/rekey policy. Changed active identities retain
the existing drain-and-exit boundary described above.
