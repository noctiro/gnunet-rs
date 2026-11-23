# Independent official TRANSPORT SERVICE

This package provides a caller-driven independent official TRANSPORT service owner and, with `program`, the standard `gnunet-service-transport` foreground. It uses the admitted direct-queue Engine and external PILS, PEERSTORE and zero-binding NAT clients. It does not launch a peer aggregator, communicator, hidden Resolver, embedded PEERSTORE or C FFI backend.

The `Owner` constructor takes caller-owned branded instances, one coherent snapshot of the external endpoints, and the same RuntimeClock Arc. A source-matched PILS identity is required before Engine creation or local IPC admission. A deferred purpose35 job is copied once with the original request token and finite UTC/native targets; the original PILS SIGN reply is checked against its epoch and expected key before the original Engine effect can complete. There is no local private-key fallback.

## Native service composition

The standalone SERVICE uses shared options and separate native entries. Unix
captures descriptor/control ownership and performs fresh-process detachment
before runtime or private work; TCP/activation preparation precedes configured
identity selection, and new local paths finish afterwards. Windows captures
native activation/bootstrap, verifies the configured SID and registers the
original qualified parent and native stop subscriptions.

`foreground::Listening` carries completed listeners, registered `StopSignals`
and an optional original `Readiness` future before any reservation worker starts.
`foreground::service` uses the same session/DV driver as the PROGRAM embedding;
neither async path changes process identity or invents a PROGRAM preparation.
Entropy requests use the shared native OS provider on every platform.

The explicit process-owned `Reports` callback carries ready and diagnostic
facts, without a global logger or native queue. All original foreground, session,
Resolver, DV receipt and worker-cleanup diagnostics use the caller's selected
Logger policy/output. A first callback IO failure wakes ordinary shutdown; its
error is returned after original jobs and workers really settle, independently of
other failures. The ready callback occurs only once when Owner is actually
admissible after original PILS authority and persistence, not when a listener is
created or a publication is queued. The optional asynchronous notification is polled only after that real readiness,
with one fixed ten-second native deadline. It retains the original outbox across
waiting polls; failure latches the process and cannot start a new session retry.
Shutdown with an unsettled notification fails rather than claiming acknowledgement.
Embedding's default diagnostics create no external ready owner.

The listener still supports configured Unix/TCP endpoints, inherited activation,
ACL, Unix credentials, accept diagnostics and EMFILE suspension. TOLERANT still ignores only unknown official handler types. SOFT stops new
admission, drives non-monitor leases until completion or original finite
socket grace, then physically closes remaining sources. Source epoch rebuilds,
queued/partial/FC retirement and Provider/reservation worker joins retain
their original owners. An admitted filesystem operation is not cancelled by socket
grace. No communicator process, private aggregator or key fallback is started.

## Persistence and publication

`generation::Reservations` retains the admitted T1 contract: an explicitly new or matching Rust-marked private namespace stores only the eight-byte public monotime highwater. A stamp is returned only from a matching original worker commit receipt; native naming-barrier observations remain separate. New-store initialization commits an initial image before readiness; marked roots missing their canonical state fail closed. This is independent of PILS keys and any C key/store paths.

`ValidatedStore` holds one original authenticated foreign-address effect behind Server's asynchronous persistence barrier. Pending means the same STORE/source/deadlines are retained. Only matching STORE_RESULT1 releases the barrier. A loss or partial/unknown write is not replayed under a new MQ. Every independent native guard and worker completion remains driven while later domain effects are paused.

Own address records reuse `gnunet_transport::own::Certificate` preparation, purpose29 signature verification, exact official record drafting and refresh calculations. STORE uses subsystem `transport`, key `transport-peer-hello`, option MULTIPLE0. The separate native receipt is named `StoredByService`. It never invokes the managed Journal's strong `commit_finished(Committed)` and never claims fsync from a PEERSTORE result. Retired ADD/sign/store/stamp jobs retain their original lease/offer until their outcomes settle; a late accepted store is historical and does not reactivate the address.

The exact current FEED uses the original address publication. The PILS getter contains a PeerUpdate envelope; it is decoded to its signed HELLO block, compared with the original current identity/address list and encoded as an ordinary HELLO with the unchanged purpose7 signature. The public PEERSTORE HelloAdd helper performs the exact-peer scan/stop/replace path and preserves ExistingNewer versus the original raw store result. No synthetic HELLO is signed locally.

## Candidate discovery and bounds

One shared URL-query MQ and a fixed number of dedicated HELLO-monitor MQs retain original observations, source epochs, scan credit, END/SYNC, cancellation suffixes and independent native deadlines. URL records use `transport/transport-communicator-url`; ordinary binary HELLO records use `peerstore/peerstore-peer-hello-uri`. Discovery supplies only untrusted candidates. It never grants communicator/peer authenticity. Capacity retains the original observation without granting NEXT or declaring a complete pass. Whole NEXT credit is owned by the admitted native client. Opaque valid C strings retain their bytes; UTF-8 is not an added Unix-path requirement.

The Clock emits `Times(MonoInstant(native_elapsed), AbsoluteTime(actual_canonical_sample))`. Each node's cloned providers share that native anchor and exact RuntimeClock Arc. It rejects only port errors, non-finite samples or impossible native rollback; ordinary absolute rollback/forward/revision is not a legacy profile error. Absolute correction can reach a previously captured logical operation target earlier, but cannot extend its original native hard deadline. Record expiration and a relative operation timeout remain separate values. The obsolete CLOCK_PROFILE_TOLERANCE setting was removed instead of retaining an inert advertised constraint.

Every child guard runs before an outer logical-clock observation. Source lifetime, initial handshake, first partial RX/TX, original job and retirement targets are finite. Ordinary progress/retry cannot remint them. Maintenance and deferred-work retry are bounded scheduled turns, not an idle spin. A pending persistence timer does not register an already-expired maintenance sleep. Output FIFO cursors stay in their owners. No task is spawned per request/peer.

The STATISTICS handle shares the process Resolver. Only the directly observed official nonpersistent foreign-address STORE failure counter is exported in this stage. Unexposed C internal counters are not fabricated. Post-admission statistics errors fence/destroy/drop their original owner without retrying relative mutations. This owner retires before Resolver shutdown.

## Clock and DV ownership

One immutable native anchor supplies monotonic scheduling time. The runtime
clock supplies absolute UTC for expiry and publication. Validated PEERSTORE
writes retain their original absolute expiration and native deadline. FLOW
sender-monotime uses a separate durable reservation.

The standard session drives the DV Runtime, Bridge and Scheduler. One independent PILS client and the independently marked `DV_STORE` provider belong to each DV source. The caller owns branded instances, fixed metadata and a small shared zeroizing plaintext pool; storage is lent once rather than placed in a self-referential owner. Bootstrap retains its original source/partial-input bounds and checks the same public peer and clock as Owner without equating their independent PILS MQ epochs.

Confirmed Actor routes enter the existing Engine transmit path. CORE payloads retain the original Job, Flow, UUID/span coverage, remote ACK state and enqueue deadline. A genuine new virtual retransmission gets a new BOX nonce; a retained native queue/partial-write retry keeps its exact immutable encoded bytes. Synchronous native observers record queue admission and positive writes before later cancellation can intervene. Actual1204 results settle local physical spans; they do not claim remote processing. Completed outer DV fragments go through the bounded Actor inbox, retain the first assembly Source and expiry, and never bypass decapsulation into CORE. Original canceled parents stop new Actor/native admission while already queued work retains its physical outcome.

Source retirement closes business admission while preserving Owner's old Engine gate. Original sends, ingress/FC owners and shared range receipts settle, the provider drains/joins, then Bridge releases the gate. Clock failure does not require a new sample to perform physical cleanup. Direct byte charging is preserved; virtual final-peer charging uses the inner network frame and carrier charging uses BOX/transport frames. This conservative local policy never trusts unverified `orig_size` as a measured length or turns sender-reported loss into a write acknowledgement. `USE_BURST_NAT=YES` uses the confirmed-route and native communicator burst ports. The official PILS/HELLO profile is selected once from `[PILS] PROFILE`: `reference029` (also `reference-0.29.1`) is the unchanged metadata-only default, while `deterministic` selects the official conditional address-covered profile. A supplied `[transport-rust] PILS_PROFILE` must name the same profile. PILS verification, public HELLO publication/STORE and discovery all use that typed choice; verification never falls back to another profile. External services and communicators must be running/configured; their absence produces errors. Other C internal statistics require exposed matching events before forwarding.

## Local identity rotation

PILS sends its initial signed HELLO on connection. On a peer change through
the same PILS connection, TRANSPORT fences the old signing authority and keeps
the communicator IPC streams, address leases and native queue identities.
The DV bridge retires its original source, CORE clients reattach, and admitted
FEED and PEERSTORE operations settle under their original identifiers and
deadlines. Incomplete input keeps its original connection and deadline until
the complete frame identifies its protocol. An old DV wrapper or fragment must
settle before a replacement DV source attaches.

A complete unsigned FEED write settles its local publication revision. A
verified PILS announcement can publish a HELLO when its addresses match the
live address book. Published PEERSTORE records retain their original expiration.

The reservation worker matches each receipt to its original request, identity
and consumer. A late commit still consumes its value. The service drains the
worker independently of Resolver shutdown. An unconfirmed, mismatched or
fenced worker state prevents the next session from starting.

The session supervisor retains listeners, Resolver, the clock anchor, the
reservation worker and statistics across reconnects. When a native source fails,
the supervisor retires the session and drains outstanding work before reconnecting.
Retry delays range from 100 ms to 25.6 s. The supervisor retains up to 32
consecutive failures and resets the budget after a stable session. Signals remain
active during backoff. Disk synchronization and worker join can block beyond
socket deadlines.

FLOW sender-monotime requires an exact Engine demand and an exclusive range
committed by the shared reservation worker. FLOW, DV and own-address
consumers receive nonoverlapping values. Identity rotation discards
unused values and keeps the committed high-water mark. DV scope branding
distinguishes repeated visits to the same peer identity.
`SENDER_MONOTIME_HORIZON` defaults to five minutes and accepts spans from one
minute to one day.

External interoperability and platform qualification follow the central
[compatibility contract](../../spec/gnunet/compatibility.md).
