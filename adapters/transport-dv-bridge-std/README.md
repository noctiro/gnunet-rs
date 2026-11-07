# Actual DV actor and shared TRANSPORT pipeline

This bridge connects the DV actor to the existing Engine/accepted-MQ Server. It owns bounded metadata, not a second Flow engine, key, MQ, worker, resolver, task or plaintext pool. All identities are original Engine/Actor leases. Raw1218/1219 never become CORE messages.

`Bridge::adopt_at(server, actor, limits, native_epoch)` takes the exact original Owner `Clock::native_bound(MonoInstant(0))`; it does not calibrate a fresh clock. `sync_neighbours` uses validated direct queue generations. `sync_paths` explicitly selects `SendPolicy::Bidirectional` and installs only the Actor's send-eligible route, fixed native lifetime and maximum plaintext. That policy accepts local-probe confirmation or a still-current, signed inverse route whose full reverse-link history and source watermark have actually passed the route layer. An inverse route remains `Freshness::Passive` with `rtt: None`; no local probe/measurement is manufactured. Receiving a private Granted by itself creates no return queue.

Inbound `receive_one` fairly handles complete native frames and Engine-reassembled outer DV bodies. The actor's explicit incoming disposition retains the same source, immutable body and first deadline on Deferred; Rejected/Expired consumes only that original input when physical FC disposal can proceed. A Source failure does not consume the frame as a remote protocol refusal. Every assembly is tagged with its first `Option<Source>`: None, old Source and replacement Source cannot combine. Reassembly completion carries the first expiry. Source retirement removes the exact old assemblies/held bodies before gate release. Only the actor's private `Granted` enters `deliver`, which reuses the original Flow/reliability/fragment/backchannel/CORE dispatcher. Completed plaintext held by CORE backpressure stays charged to its same Ingress and is not reprocessed as a fresh envelope.

That grant authorizes authenticated dispatch, not a return route. Incoming FLOW,
ACK and signed1304 responses can precede a usable reverse path. A1304 still has
to match the original peer, signature, nonce, origin window and live challenge
queue; multi-hop1303 remains forbidden. Only confirmed route synchronization
installs virtual reachability. Final CORE payload delivery checks current direct
validation or the same source's unexpired virtual path, including bodies completed
by reliability or fragmentation. Server never derives a route lifetime from an
incoming packet's remaining deadline.

Outbound CORE Jobs select an actually send-eligible virtual path through the existing `transmit_job`. The selected policy travels with the original path and immutable VirtualIntent into `SendOptions`; final Actor admission rechecks the same RouteId, target, first hop, policy and original proof generation rather than choosing a replacement route. The original Job, UUID/span, coverage, Flow budget, ACK and retry records remain the single owners. Bounded virtual staging supplies one original inner frame to Actor boxing. The production `transport-service-std::dv_transmit::Transmit` consumes the shared Scheduler's private persisted DV Stamp, then calls `send_virtual` with that exact budget and path. A true inner remote-ACK retry makes a fresh crypto attempt/nonce. WouldBlock/partial native IO retains the original already-sealed bytes. Control bypass comes only from the original Engine Job policy.

`queue_output` stages a Actor output as a normal direct Engine Job. It may therefore use the existing large-packet fragments/reliable envelope and retransmission algorithm. The concrete synchronous observer in `poll_server`, `poll_tick` and `poll_retry` calls Actor `queued` only after actual1209 MQ admission, and `exposed` only after positive bytes. `settle_send` aggregates original1210 SEND_ACK outcomes over all original spans before Actor `written`; this is the communicator's report, not remote processing. Local written metadata can be taken while the original common Job still waits for its remote ACK. The Written-to-take gap accepts that same immutable common Job retry without consulting an already-finished Actor output. An MTU too small for the fragment header fails explicitly, without subtraction underflow.

The synchronous native observer has one result handoff for normal IO, scheduled
ticks and retained retries. It consumes the same original-parent retirement
request and preserves actor failure plus independent cleanup under the same
precedence at all three entrances. A native protocol failure retains its
independent physical-close error even when no Actor failure supplied the cause. No observer borrow, task or packet queue survives that handoff.

`queue_output` and `deliver` return `TaskFailure` with Deferred, Task or Source
scope selected at their boundary. Shared source/time checks precede the
synchronous Engine port. Actor clock/source failures are not inferred from their
numeric Protocol cause; only its explicit original-task expiry is task-local. A synchronous signer error stays source-scoped even if its code is also
used for Engine capacity. Independent cleanup failure prevents local retry, and
delivery admission is saved before any independent failure returns. The Driver consumes these scopes without another task-error list.

Native preflight uses `NativeAdmission` rather than a boolean. `Admit` follows
the same Actor/source/budget checks; `Deferred` retains the original
without granting admission. `Retiring` immediately returns to this bridge's
same-parent transaction, before more native IO can expose the canceled frame. The original observer token remains inside this bridge; no new wire identity,
budget or completion is minted by the decision.

Accounting preserves the established direct path. Final virtual peer traffic uses the complete inner transport-frame length; physical carrier traffic uses BOX/outer-frame/fragment lengths. Forwarded unauthenticated `orig_size` is never trusted. This is a conservative window policy rather than a reproduction of C wrapper statistics. Blocked transmit requests an FLOW update; sender-reported loss normalizes credits. The original Flow replay checks and remote ACK coverage remain in the shared dispatcher.

`cancel_retired` cancels one exact admitted Outbound whose original CORE Job retired. The wrappers call it before advancing native IO; native preflight checks again after same-round Engine changes. `queue_output` returns `Queued::Retired` for cancellation. Earlier queued/partial work is retired on its same physical MQ and retains its written/loss outcome; it is never relabelled unsent. Conservative original-MQ closure may affect that communicator's other queues. There is no wire CANCEL.

A direct Job retired after only a successfully transmitted prefix can finish
as `TransferOutcome::Incomplete` once all chunk dispositions have ended. The bridge reports only that original output's loss with its retained exposure;
it does not report a whole write, an unsent packet or shared-source loss. Server
retirement preserves that MQ. The same rule applies to every already-settled
local outcome only after the original Job ended and all parent SendRows left. A Written result alone does not release the Job's remote-ACK/retry ownership;
deadline cancellation ends that logical owner without inventing an ACK. Any unknown chunk still requires the original drain/physical-retirement
policy, and packet failure/source loss keeps its original outcome.

`finish_output` first checks the completed Actor row, then settles any
fallible original native retirement while that row still owns its completion. The synchronous origin handoff returns a refused original `VirtualAttempt` to
the same Runtime slot, including outputs that never had a staged native Send. Only success removes the Actor row and records `actor_finished`. Independent
`reap_transfers` work runs separately; its failure cannot discard that result.

On closure: `begin_close`, fairly enumerate Actor input/output states, settle/retire original physical transfers, release original FC, call clock-free `drain_unadmitted`/`discard_inbox`, await Actor `shutdown`/Provider join, then `close` when quiescent and source debt is zero. `dv_source_active` remains the retirement gate; `dv_source_accepting` separately rejects new work. No fresh clock sample is required to discharge old source ownership. Independent cleanup errors remain visible.

All added pools are bounded by caller limits and existing Engine bytes. No new registry dependency is required. Existing ordinary Framed vectored IO is retained. The standard [TRANSPORT service](../transport-service-std/README.md) constructs this bridge and the DV actor in `dv_program`, drives them through `dv_driver` and supplies durable scheduler reservations through `dv_transmit`. The normal executable enters that composition through `foreground::service` and `session::run`. Existing live replay and persisted sender watermark scopes remain unchanged; no cross-restart exact-nonce disk protocol is added.

`sync_paths` reports true only for path installation/withdrawal. The
standard DV driver consumes that local progress even when the number of direct
neighbours did not change; newly queued CORE notifications and control work
therefore get another owner turn. Stable paths do not create a ready-spin. Discovery completes on the same actually usable `SendPath.life`, preserving its
original Passive/Confirmed evidence and fixed native hard instead of requiring a
closed local probe cycle that an acyclic A--B--C topology cannot supply.

The existing Engine `control_route_fits` and common `transmit_job` select these
installed virtual paths for ordinary traffic and return FLOW. FLOW stays
an existing control Job: it bypasses only the original outbound data-window gate
to avoid the documented reverse-window deadlock. It does not add data credit;
only the original authenticated peer FLOW update changes the data window. No
second Flow, queue, controller, message format or new network-validation ACK is
introduced. Durable wire stamp allocation and original BOX admission/written/
unknown/retirement ownership remain unchanged. Burst synchronization still uses
only a locally Confirmed route and an measured `Some(RTT)`; a usable signed
inverse path with unknown RTT cannot enable it.

This source composition does not establish A--B--C execution or
unchanged-C/mixed-peer interoperability. Required runtime qualification remains
outstanding; historical build and execution receipts retain their original scope.

Path synchronization replaces an eligible same-peer path through the Engine's
atomic install operation before replacing the bridge's private ledger entry. It does not withdraw first, create a transient CORE disconnect or discard the
old peer's queued common Jobs. A genuinely unavailable path is withdrawn from
both transmit selection and matching virtual reachability; output-slot pressure
retains the old ledger for a later original retry. Canceled old Actor admissions
retain their exact original lease, budget and callback/retirement owner; none is
transferred to the new path or reported as a physical write by synchronization.

`Bridge::output_diagnostic` copies only the exact original Actor token's current
bridge flags and `Engine::dv_transfer_diagnostic` metadata through the same
Server. The Engine snapshot distinguishes original message bytes covered by
successful local1210 callbacks from bytes only staged on the common Job's first
pass. It includes original queue-generation labels, current queue/FLOW counters,
remaining original Job metadata and bounded global occupancy/limits. Missing or
foreign records yield None and never change the original failure path. These
copies contain no payload/secret or reusable owner token, sample no clock,
perform no preflight/admission, and are never used as protocol decisions or
native/remote success evidence. Local communicator `sends=0` alone does not prove
that every original transfer's whole body had been staged and covered.
