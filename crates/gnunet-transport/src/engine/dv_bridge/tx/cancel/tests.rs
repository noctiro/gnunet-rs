//! Pure local staging/ledger boundaries, using real purpose35 signatures for
//! the queue. No native IO, AEAD grant or C interoperability is claimed here.
use super::*;
use alloc::vec;
use gnunet_crypto::EddsaPrivateKey;
use gnunet_wire::official::communicator::{Characteristics, Queue as WireQueue, Request};

fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
struct Key(EddsaPrivateKey);
impl Signer for Key {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.public_key().as_bytes())
    }
    fn sign_validation(&mut self, region: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(p2p::CHALLENGE_PURPOSE, region)?.as_bytes())
    }
}
struct Random(u8);
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.0 = self.0.wrapping_add(1);
        bytes.fill(self.0);
        Ok(())
    }
}
fn wire(request: Request<'_>) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; request.encoded_len()?];
    request.encode(&mut bytes)?;
    Ok(bytes)
}
struct Fixture {
    engine: Engine,
    source: Source,
    queue: DirectQueue,
    local: Key,
    random: Random,
}
impl Fixture {
    fn new(reliable: bool, grant: u64) -> Result<Self, Error> {
        let mut local = Key(EddsaPrivateKey::from_seed([41; 32]));
        let mut remote = Key(EddsaPrivateKey::from_seed([42; 32]));
        let mut random = Random(0);
        let mut engine = Engine::new(local.identity(), Limits::default())?;
        let owner = engine.accept()?;
        engine.receive(
            &owner,
            &wire(Request::Register {
                characteristics: if reliable {
                    Characteristics::Reliable
                } else {
                    Characteristics::Unreliable
                },
                can_burst: false,
                prefix: b"unix",
            })?,
            10,
            &mut local,
            &mut random,
        )?;
        engine.receive(
            &owner,
            &wire(Request::QueueSetup(
                WireQueue {
                    id: 7,
                    peer: remote.identity().0,
                    network: 1,
                    mtu: 64,
                    length: grant,
                    priority: 0,
                    status: 0,
                },
                b"unix-/private/pre-native-cancel",
            ))?,
            10,
            &mut local,
            &mut random,
        )?;
        let mut original = None;
        while let Some(output) = engine.output() {
            if let Output::Frame { bytes, .. } = output
                && Frame::decode(&bytes)?.header().message_type().value() == 1209
            {
                original = Some(bytes);
            }
        }
        let original = original.ok_or(Error::NotFound)?;
        let challenge = Challenge::decode(original.get(48..).ok_or(Error::Truncated)?)?;
        let mid = original
            .get(8..16)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        engine.receive(
            &owner,
            &wire(Request::Sent {
                status: 1,
                message_id: mid,
                queue: 7,
                peer: remote.identity().0,
            })?,
            10,
            &mut local,
            &mut random,
        )?;
        let validity = 60_000_000;
        let validation = Validation {
            nonce: challenge.nonce,
            origin: challenge.origin,
            validity,
            signature: remote
                .sign_validation(&Validation::signed_region(&challenge.nonce, validity))?,
        }
        .encode();
        engine.receive(
            &owner,
            &wire(Request::Incoming {
                flow_control: false,
                flow_id: [0; 8],
                validity,
                peer: remote.identity().0,
                neighbour: [0; 32],
                message: &validation,
            })?,
            10,
            &mut local,
            &mut random,
        )?;
        while engine.output().is_some() {}
        let source = engine.dv_attach_source(local.identity())?;
        let queue = engine
            .dv_direct_queues(Times::shared_coordinate(10))
            .next()
            .ok_or(Error::NotFound)?;
        Ok(Self {
            engine,
            source,
            queue,
            local,
            random,
        })
    }
    fn stage(&mut self, bytes: usize) -> Result<TransferId, Error> {
        self.engine.dv_enqueue_transfer(
            &self.source,
            &self.queue,
            &message(crate::dv::BOX_TYPE, bytes)?,
            false,
            Duration(50_000_000),
            Times::shared_coordinate(10),
        )
    }
    fn pump(&mut self) -> Result<(), Error> {
        self.engine.retry_deferred(10, &mut self.random)?;
        Ok(())
    }
    fn route(&self) -> Result<&crate::engine::Route, Error> {
        self.engine
            .routes
            .iter()
            .find(|q| q.serial == self.queue.route)
            .ok_or(Error::NotFound)
    }
    fn peer(&self) -> Result<&crate::engine::Peer, Error> {
        self.engine
            .peers
            .iter()
            .find(|p| p.id == self.queue.peer)
            .ok_or(Error::NotFound)
    }
}

#[test]
fn unpumped_parent_is_unsent_without_changing_original_grants_or_serials() -> Result<(), Error> {
    let mut f = Fixture::new(true, 32)?;
    let available = f.route()?.available;
    let serial = f.engine.message_serial;
    let parent = f.stage(80)?;
    check(f.engine.dv_transfer_state(&parent)?.job_pending && f.engine.buffered == 80)?;
    check(
        f.engine.dv_cancel_pre_native_transfer(&parent, None)?
            == TransferCancellation::Unsent { pending: false },
    )?;
    check(f.route()?.available == available && f.route()?.inflight == 0)?;
    check(f.engine.buffered == 0 && f.engine.message_serial == serial)?;
    check(
        f.engine.dv_transfer_state(&parent)?
            == TransferState {
                queued: false,
                exposed: false,
                outcome: Some(TransferOutcome::Unsent),
                job_pending: false,
            },
    )
}

#[test]
fn all_staged_chunks_and_exact_pending_cancel_atomically_without_touching_another_parent()
-> Result<(), Error> {
    let mut f = Fixture::new(false, 32)?;
    let available = f.route()?.available;
    let parent = f.stage(80)?;
    let other = f.stage(4)?;
    f.pump()?;
    f.pump()?;
    let Some(Output::Frame { client, bytes }) = f.engine.output() else {
        return Err(Error::NotFound);
    };
    let send = f
        .engine
        .dv_frame_tag(&client, &bytes)
        .ok_or(Error::NotFound)?;
    check(f.engine.dv_chunk_parent(&send) == Some(parent.clone()))?;
    let before = f.engine.snapshot();
    // The popped original is unlocated until the actual owner supplies it.
    check(
        f.engine.dv_cancel_pre_native_transfer(&parent, None)?
            == TransferCancellation::NeedsRetirement,
    )?;
    check(f.engine.snapshot() == before)?;
    let foreign = f.engine.accept()?;
    let before = f.engine.snapshot();
    check(
        f.engine.dv_cancel_pre_native_transfer(
            &parent,
            Some(StagedSend {
                owner: &foreign,
                send: &send,
                bytes: &bytes,
            }),
        )? == TransferCancellation::NeedsRetirement,
    )?;
    check(f.engine.snapshot() == before)?;
    let other_send = f
        .engine
        .dv_bridge
        .sends
        .iter()
        .find(|r| belongs(r, &other))
        .ok_or(Error::NotFound)?
        .id
        .clone();
    let other_state = f.engine.dv_send_state(&other_send)?;
    let other_job = f
        .engine
        .dv_bridge
        .tx
        .transfers
        .iter()
        .find(|t| t.id == other)
        .ok_or(Error::NotFound)?
        .job;
    let other_charge = f
        .engine
        .jobs
        .iter()
        .find(|j| j.id == other_job)
        .ok_or(Error::NotFound)?
        .charge();
    let history = f.peer()?.outbound_used;
    let serial = f.engine.message_serial;
    check(
        f.engine.dv_cancel_pre_native_transfer(
            &parent,
            Some(StagedSend {
                owner: &client,
                send: &send,
                bytes: &bytes,
            }),
        )? == TransferCancellation::Unsent { pending: true },
    )?;
    drop(bytes);
    check(matches!(f.engine.dv_send_state(&send), Err(Error::Stale)))?;
    check(f.engine.dv_send_state(&other_send)? == other_state)?;
    check(
        f.engine.dv_bridge.sends.len() == 1
            && f.route()?.inflight == 1
            && f.route()?.available == available - 1,
    )?;
    check(
        f.engine.buffered == other_charge
            && f.peer()?.outbound_used == history
            && f.peer()?.flow_dirty,
    )?;
    check(f.engine.message_serial == serial)?;
    check(f.engine.output.iter().any(|out| matches!(out, Output::Frame { client, bytes } if f.engine.dv_frame_tag(client, bytes).as_ref() == Some(&other_send))))?;
    let grants = (f.route()?.available, f.route()?.inflight);
    check(
        f.engine.dv_cancel_pre_native_transfer(&parent, None)?
            == TransferCancellation::Unsent { pending: false },
    )?;
    check((f.route()?.available, f.route()?.inflight) == grants)
}

#[test]
fn expired_attempt_refunds_only_the_unspent_grant_without_double_subtracting_inflight()
-> Result<(), Error> {
    let mut f = Fixture::new(false, 32)?;
    let available = f.route()?.available;
    let parent = f.stage(4)?;
    f.pump()?;
    let send = f
        .engine
        .dv_bridge
        .sends
        .iter()
        .find(|r| belongs(r, &parent))
        .ok_or(Error::NotFound)?
        .id
        .clone();
    let history = f.peer()?.outbound_used;
    f.engine.expire_outbound(6_000_010)?;
    check(f.route()?.inflight == 0 && f.route()?.available == available - 1)?;
    check(f.engine.completed.iter().any(|a| a.message_id == send.mid))?;
    check(
        f.engine.dv_cancel_pre_native_transfer(&parent, None)?
            == TransferCancellation::Unsent { pending: false },
    )?;
    check(f.route()?.inflight == 0 && f.route()?.available == available)?;
    check(!f.engine.completed.iter().any(|a| a.message_id == send.mid))?;
    check(f.peer()?.outbound_used == history && f.engine.remote_acks.len() == 0)
}

#[test]
fn partial_packet_callback_and_native_admission_cannot_be_reclassified_unsent() -> Result<(), Error>
{
    let mut f = Fixture::new(true, 32)?;
    let parent = f.stage(80)?;
    let unchanged = f.engine.snapshot();
    let original = f
        .engine
        .dv_transfer_diagnostic(&parent)
        .ok_or(Error::NotFound)?;
    check(
        original.peer == f.queue.peer
            && original.queue == f.queue.queue
            && original.route == f.queue.route
            && original.client_live
            && original.covered_bytes == 0
            && original.total_bytes == 80
            && original.live_chunks == 0
            && original.state.outcome.is_none()
            && original.job.is_some_and(|job| {
                job.serial == original.job_serial
                    && job.bytes == 80
                    && job.fresh_offset == 0
                    && !job.whole_sent
            }),
    )?;
    check(
        f.engine.dv_transfer_diagnostic(&parent) == Some(original)
            && f.engine.snapshot() == unchanged,
    )?;
    let foreign = Engine::new(f.local.identity(), Limits::default())?;
    check(foreign.dv_transfer_diagnostic(&parent).is_none())?;
    f.pump()?;
    let staged = f
        .engine
        .dv_transfer_diagnostic(&parent)
        .ok_or(Error::NotFound)?;
    check(
        staged.covered_bytes == 0
            && staged.total_bytes == 80
            && staged.live_chunks == 1
            && staged.job.is_some_and(|job| {
                job.fresh_offset == 32
                    && job.bytes == 80
                    && job.expires == original.job.map_or(0, |job| job.expires)
            })
            && staged
                .queue_state
                .is_some_and(|queue| queue.mtu == 64 && queue.inflight == 1),
    )?;
    let send = f
        .engine
        .dv_bridge
        .sends
        .iter()
        .find(|r| belongs(r, &parent))
        .ok_or(Error::NotFound)?
        .id
        .clone();
    f.engine.receive(
        &f.queue.owner,
        &wire(Request::Sent {
            status: 1,
            message_id: send.mid,
            queue: f.queue.queue,
            peer: f.queue.peer.0,
        })?,
        10,
        &mut f.local,
        &mut f.random,
    )?;
    check(f.engine.dv_transfer_state(&parent)?.outcome.is_none())?;
    let partial = f
        .engine
        .dv_transfer_diagnostic(&parent)
        .ok_or(Error::NotFound)?;
    // This is the existing scripted pure1210 callback through receive(): the
    // first32 original bytes are covered and the second32 are merely staged.
    // No native write, remote ACK or complete80-byte outcome is invented.
    check(
        partial.covered_bytes == 32
            && partial.total_bytes == 80
            && partial.live_chunks == 1
            && partial.state.job_pending
            && partial.state.outcome.is_none()
            && partial.job.is_some_and(|job| {
                job.serial == original.job_serial
                    && job.bytes == 80
                    && job.fresh_offset == 64
                    && !job.whole_sent
            })
            && partial.last_monotonic == MonoInstant(10),
    )?;
    let before = f.engine.snapshot();
    check(
        f.engine.dv_cancel_pre_native_transfer(&parent, None)?
            == TransferCancellation::NeedsRetirement,
    )?;
    check(f.engine.snapshot() == before)?;
    let other = f.stage(4)?;
    f.pump()?;
    let send = f
        .engine
        .dv_bridge
        .sends
        .iter()
        .find(|r| belongs(r, &other))
        .ok_or(Error::NotFound)?
        .id
        .clone();
    let _parent = f.engine.dv_chunk_queued(&send)?;
    check(
        f.engine.dv_cancel_pre_native_transfer(&other, None)?
            == TransferCancellation::NeedsRetirement,
    )
}

#[test]
fn original_unlimited_grant_is_not_refunded_after_queue_switches_to_finite() -> Result<(), Error> {
    let mut f = Fixture::new(true, u64::MAX)?;
    let parent = f.stage(4)?;
    f.pump()?;
    f.engine.receive(
        &f.queue.owner,
        &wire(Request::QueueUpdate(WireQueue {
            id: f.queue.queue,
            peer: f.queue.peer.0,
            network: 1,
            mtu: 64,
            length: 0,
            priority: 0,
            status: 0,
        }))?,
        10,
        &mut f.local,
        &mut f.random,
    )?;
    check(!f.route()?.unlimited && f.route()?.available == u64::MAX)?;
    check(
        f.engine.dv_cancel_pre_native_transfer(&parent, None)?
            == TransferCancellation::Unsent { pending: false },
    )?;
    check(f.route()?.available == u64::MAX && f.route()?.inflight == 0)
}

#[test]
fn grant_overflow_preflight_changes_no_staged_owner_or_counter() -> Result<(), Error> {
    let mut f = Fixture::new(true, 32)?;
    let parent = f.stage(4)?;
    f.pump()?;
    let delta = u64::MAX - f.route()?.available;
    f.engine.receive(
        &f.queue.owner,
        &wire(Request::QueueUpdate(WireQueue {
            id: f.queue.queue,
            peer: f.queue.peer.0,
            network: 1,
            mtu: 64,
            length: delta,
            priority: 0,
            status: 0,
        }))?,
        10,
        &mut f.local,
        &mut f.random,
    )?;
    check(!f.route()?.unlimited && f.route()?.available == u64::MAX)?;
    let before = f.engine.snapshot();
    let state = f.engine.dv_transfer_state(&parent)?;
    let history = f.peer()?.outbound_used;
    check(matches!(
        f.engine.dv_cancel_pre_native_transfer(&parent, None),
        Err(Error::Overflow)
    ))?;
    check(f.engine.snapshot() == before && f.engine.dv_transfer_state(&parent)? == state)?;
    check(
        f.route()?.inflight == 1
            && f.route()?.available == u64::MAX
            && f.peer()?.outbound_used == history,
    )
}

#[test]
fn replacement_route_with_same_owner_peer_and_qid_never_inherits_refund() -> Result<(), Error> {
    let mut f = Fixture::new(true, 32)?;
    let parent = f.stage(4)?;
    f.pump()?;
    f.engine.receive(
        &f.queue.owner,
        &wire(Request::QueueDown(f.queue.queue, f.queue.peer.0))?,
        10,
        &mut f.local,
        &mut f.random,
    )?;
    f.engine.receive(
        &f.queue.owner,
        &wire(Request::QueueSetup(
            WireQueue {
                id: f.queue.queue,
                peer: f.queue.peer.0,
                network: 1,
                mtu: 64,
                length: 11,
                priority: 0,
                status: 0,
            },
            b"unix-/private/pre-native-replacement",
        ))?,
        10,
        &mut f.local,
        &mut f.random,
    )?;
    let replacement = f
        .engine
        .routes
        .iter()
        .find(|q| q.owner == f.queue.owner && q.description.id == f.queue.queue)
        .ok_or(Error::NotFound)?;
    check(replacement.serial != f.queue.route)?;
    let original = (
        replacement.serial,
        replacement.available,
        replacement.inflight,
    );
    check(
        f.engine.dv_cancel_pre_native_transfer(&parent, None)?
            == TransferCancellation::Unsent { pending: false },
    )?;
    let replacement = f
        .engine
        .routes
        .iter()
        .find(|q| q.serial == original.0)
        .ok_or(Error::NotFound)?;
    check(
        (
            replacement.serial,
            replacement.available,
            replacement.inflight,
        ) == original,
    )
}

// Opaque, structurally complete producer-shaped boxes. Encoding and decoding
// this outer header prove no KEM/AEAD/signature success or native transmission.
fn opaque_control_box(size: usize) -> Result<Vec<u8>, Error> {
    opaque_box(size, true)
}
fn opaque_box(size: usize, without_fc: bool) -> Result<Vec<u8>, Error> {
    let ciphertext = vec![
        0x5a;
        size.checked_sub(crate::dv::BOX_PREFIX)
            .ok_or(Error::InvalidInput)?
    ];
    let mut bytes = vec![0; size];
    crate::dv::BoxHeader {
        without_fc,
        encapsulation: [0x21; 32],
        nonce: [0x32; 24],
        mac: [0x43; 16],
    }
    .encode(&[], &ciphertext, &mut bytes)?;
    check(crate::dv::BoxPacket::decode(&bytes)?.bytes() == bytes)?;
    Ok(bytes)
}
fn set_queue_mtu(f: &mut Fixture, mtu: u32) -> Result<(), Error> {
    let bytes = wire(Request::QueueUpdate(WireQueue {
        id: f.queue.queue,
        peer: f.queue.peer.0,
        network: 1,
        mtu,
        length: 0,
        priority: 0,
        status: 0,
    }))?;
    check(matches!(
        f.engine.receive_maintenance_at(
            &f.queue.owner,
            &bytes,
            Times::shared_coordinate(10),
            &mut f.local,
            &mut f.random
        )?,
        Some(ReceiveOutcome::Accepted)
    ))
}

#[test]
fn flow_bypass_box_progresses_past_an_ordinary_partial_fragment_without_spending_its_window()
-> Result<(), Error> {
    // The same actual queue update covers both an unfragmented control BOX and
    // one that must still use normal fragmentation despite bypassing FLOW.
    for control_size in [250, 382] {
        let mut f = Fixture::new(true, 3)?;
        set_queue_mtu(&mut f, 256)?;
        f.engine.enqueue(
            Some(f.queue.route),
            f.queue.peer,
            &message(64, 512)?,
            None,
            false,
        )?;
        let ordinary = f.engine.job_serial;
        f.pump()?;
        let Some(Output::Frame { client, bytes }) = f.engine.output() else {
            return Err(Error::NotFound);
        };
        let mid = bytes
            .get(8..16)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let input = wire(Request::Sent {
            status: 1,
            message_id: mid,
            queue: f.queue.queue,
            peer: f.queue.peer.0,
        })?;
        check(matches!(
            f.engine.receive_maintenance_at(
                &client,
                &input,
                Times::shared_coordinate(10),
                &mut f.local,
                &mut f.random
            )?,
            Some(ReceiveOutcome::Accepted)
        ))?;
        let history = f.peer()?.outbound_used;
        let flow = Flow {
            sequence: 1,
            inbound_window: history + 1,
            outbound_sent: 0,
            outbound_window: p2p::DEFAULT_WINDOW,
            sender_time: 10,
            rtt: 0,
            sync_ready: false,
        }
        .encode();
        let input = wire(Request::Incoming {
            flow_control: false,
            flow_id: [0; 8],
            validity: 60_000_000,
            peer: f.queue.peer.0,
            neighbour: [0; 32],
            message: &flow,
        })?;
        check(matches!(
            f.engine.receive_maintenance_at(
                &client,
                &input,
                Times::shared_coordinate(10),
                &mut f.local,
                &mut f.random
            )?,
            Some(ReceiveOutcome::Accepted)
        ))?;
        let job = f
            .engine
            .jobs
            .iter()
            .find(|j| j.id == ordinary)
            .ok_or(Error::NotFound)?;
        check(job.fragment.is_some() && job.coverage.is_none() && job.fresh_offset() == 224)?;
        check(
            f.route()?.available == 1
                && f.route()?.inflight == 0
                && f.engine.attempts.is_empty()
                && f.engine.output.is_empty(),
        )?;
        let original_box = opaque_control_box(control_size)?;
        let parent = f.engine.dv_enqueue_transfer(
            &f.source,
            &f.queue,
            &original_box,
            true,
            Duration(50_000_000),
            Times::shared_coordinate(10),
        )?;
        f.pump()?;
        let Some(Output::Frame {
            client: owner,
            bytes,
        }) = f.engine.output()
        else {
            return Err(Error::NotFound);
        };
        let send = f
            .engine
            .dv_frame_tag(&owner, &bytes)
            .ok_or(Error::NotFound)?;
        check(f.engine.dv_chunk_parent(&send).as_ref() == Some(&parent))?;
        let packet = bytes.get(48..).ok_or(Error::Truncated)?;
        if control_size == 250 {
            check(crate::dv::BoxPacket::decode(packet)?.bytes() == original_box)?;
        } else {
            let fragment = p2p::Fragment::decode(packet)?;
            check(
                fragment.offset == 0
                    && usize::from(fragment.total) == original_box.len()
                    && fragment.body == &original_box[..224],
            )?;
        }
        let job = f
            .engine
            .jobs
            .iter()
            .find(|j| j.id == ordinary)
            .ok_or(Error::NotFound)?;
        check(job.fresh_offset() == 224 && job.coverage.is_none())?;
        check(f.peer()?.outbound_used == history && f.peer()?.outbound_window == history + 1)?;
        check(f.route()?.available == 0 && f.route()?.inflight == 1)?;
        let actual = f.engine.dv_transfer_state(&parent)?;
        check(
            !actual.queued
                && !actual.exposed
                && actual.outcome.is_none()
                && actual.job_pending == (control_size == 382),
        )?;
    }
    Ok(())
}

#[test]
fn a_partial_flow_bypass_box_does_not_hold_later_ordinary_data() -> Result<(), Error> {
    let mut f = Fixture::new(true, 4)?;
    set_queue_mtu(&mut f, 256)?;
    let original_box = opaque_control_box(600)?;
    let control = f.engine.dv_enqueue_transfer(
        &f.source,
        &f.queue,
        &original_box,
        true,
        Duration(50_000_000),
        Times::shared_coordinate(10),
    )?;
    f.pump()?;
    let control_job = f
        .engine
        .dv_bridge
        .tx
        .transfers
        .iter()
        .find(|t| t.id == control)
        .ok_or(Error::NotFound)?
        .job;
    let data = message(64, 40)?;
    f.engine
        .enqueue(Some(f.queue.route), f.queue.peer, &data, None, false)?;
    let ordinary = f.engine.job_serial;
    f.pump()?;
    let original = f
        .engine
        .jobs
        .iter()
        .find(|j| j.id == control_job)
        .ok_or(Error::NotFound)?;
    check(
        !original.control
            && original.fragment.is_some()
            && original.coverage.is_none()
            && original.fresh_offset() == 448
            && original.fresh(),
    )?;
    check(!f.engine.jobs.iter().any(|j| j.id == ordinary))?;
    check(f.engine.output.iter().any(|output| matches!(output, Output::Frame { client, bytes } if *client == f.queue.owner && bytes.get(48..) == Some(data.as_slice()))))?;
    check(f.peer()?.outbound_used == 40 && f.route()?.available == 0 && f.route()?.inflight == 3)
}

fn partial_box_prefix(f: &mut Fixture) -> Result<(TransferId, SendId, u64), Error> {
    set_queue_mtu(f, 256)?;
    check(f.route()?.available == 1)?;
    let bytes = opaque_box(512, false)?;
    let parent = f.engine.dv_enqueue_transfer(
        &f.source,
        &f.queue,
        &bytes,
        false,
        Duration(1_000),
        Times::shared_coordinate(10),
    )?;
    f.pump()?;
    let Some(Output::Frame { client, bytes }) = f.engine.output() else {
        return Err(Error::NotFound);
    };
    let send = f
        .engine
        .dv_frame_tag(&client, &bytes)
        .ok_or(Error::NotFound)?;
    check(f.engine.dv_chunk_parent(&send).as_ref() == Some(&parent))?;
    let fragment = p2p::Fragment::decode(bytes.get(48..).ok_or(Error::Truncated)?)?;
    check(fragment.offset == 0 && fragment.total == 512 && fragment.body.len() == 224)?;
    check(f.engine.dv_chunk_queued(&send)?.as_ref() == Some(&parent))?;
    // Explicit pure native-progress declarations exercise the ledger port;
    // actual Unix writes are covered by the Server fixture, not claimed here.
    f.engine.dv_ipc_progress(&send, bytes.len(), true)?;
    let diagnostic = f
        .engine
        .dv_transfer_diagnostic(&parent)
        .ok_or(Error::NotFound)?;
    check(
        diagnostic.live_chunks == 1
            && diagnostic.covered_bytes == 0
            && diagnostic.total_bytes == 512
            && diagnostic.state.queued
            && diagnostic.state.exposed
            && diagnostic.state.outcome.is_none()
            && diagnostic.job.is_some_and(|job| job.fresh_offset == 224)
            && f.route()?.available == 0,
    )?;
    let expires = diagnostic.job.ok_or(Error::NotFound)?.expires;
    Ok((parent, send, expires))
}
fn prefix_result(f: &mut Fixture, send: &SendId, now: u64) -> Result<(), Error> {
    f.engine.receive(
        &f.queue.owner,
        &wire(Request::Sent {
            status: 1,
            message_id: send.mid,
            queue: f.queue.queue,
            peer: f.queue.peer.0,
        })?,
        now,
        &mut f.local,
        &mut f.random,
    )?;
    Ok(())
}

#[test]
fn settled_prefix_and_expired_unscheduled_suffix_are_incomplete_without_native_debt()
-> Result<(), Error> {
    let mut f = Fixture::new(true, 2)?;
    let (parent, send, expires) = partial_box_prefix(&mut f)?;
    prefix_result(&mut f, &send, 10)?;
    let prefix = f
        .engine
        .dv_transfer_diagnostic(&parent)
        .ok_or(Error::NotFound)?;
    check(
        prefix.covered_bytes == 224
            && prefix.total_bytes == 512
            && prefix.live_chunks == 0
            && prefix.state.outcome.is_none()
            && prefix.state.job_pending
            && prefix.job.is_some_and(|job| job.fresh_offset == 224),
    )?;
    f.engine.tick(expires, &mut f.random)?;
    let retired = f
        .engine
        .dv_transfer_diagnostic(&parent)
        .ok_or(Error::NotFound)?;
    check(
        retired.covered_bytes == 224
            && retired.total_bytes == 512
            && retired.live_chunks == 0
            && retired.state.queued
            && retired.state.exposed
            && !retired.state.job_pending
            && retired.state.outcome == Some(TransferOutcome::Incomplete)
            && retired.job.is_none(),
    )?;
    let state = f.engine.dv_take_transfer(parent).map_err(|r| r.reason)?;
    check(state.outcome == Some(TransferOutcome::Incomplete))
}

#[test]
fn an_expired_partial_job_waits_for_its_exact_last_callback_before_becoming_incomplete()
-> Result<(), Error> {
    let mut f = Fixture::new(true, 2)?;
    let (parent, send, expires) = partial_box_prefix(&mut f)?;
    f.engine.tick(expires, &mut f.random)?;
    let waiting = f
        .engine
        .dv_transfer_diagnostic(&parent)
        .ok_or(Error::NotFound)?;
    check(
        waiting.live_chunks == 1
            && waiting.covered_bytes == 0
            && !waiting.state.job_pending
            && waiting.state.queued
            && waiting.state.exposed
            && waiting.state.outcome.is_none(),
    )?;
    let mut wrong = send.clone();
    wrong.mid[7] ^= 0x80;
    prefix_result(&mut f, &wrong, expires)?;
    check(f.engine.dv_transfer_diagnostic(&parent) == Some(waiting))?;
    prefix_result(&mut f, &send, expires)?;
    let retired = f
        .engine
        .dv_transfer_diagnostic(&parent)
        .ok_or(Error::NotFound)?;
    check(
        retired.covered_bytes == 224
            && retired.total_bytes == 512
            && retired.live_chunks == 0
            && retired.state.queued
            && retired.state.exposed
            && !retired.state.job_pending
            && retired.state.outcome == Some(TransferOutcome::Incomplete),
    )?;
    let state = f.engine.dv_take_transfer(parent).map_err(|r| r.reason)?;
    check(state.outcome == Some(TransferOutcome::Incomplete))
}

#[test]
fn a_normally_finished_job_still_requires_its_real_callback_after_cancel() -> Result<(), Error> {
    let mut f = Fixture::new(true, 2)?;
    set_queue_mtu(&mut f, 256)?;
    let parent = f.engine.dv_enqueue_transfer(
        &f.source,
        &f.queue,
        &opaque_box(200, false)?,
        false,
        Duration(1_000),
        Times::shared_coordinate(10),
    )?;
    f.pump()?;
    let Some(Output::Frame { client, bytes }) = f.engine.output() else {
        return Err(Error::NotFound);
    };
    check(
        crate::dv::BoxPacket::decode(bytes.get(48..).ok_or(Error::Truncated)?)?
            .bytes()
            .len()
            == 200,
    )?;
    let send = f
        .engine
        .dv_frame_tag(&client, &bytes)
        .ok_or(Error::NotFound)?;
    check(f.engine.dv_chunk_queued(&send)?.as_ref() == Some(&parent))?;
    f.engine.dv_ipc_progress(&send, bytes.len(), true)?;
    let before = f.engine.dv_transfer_state(&parent)?;
    check(before.queued && before.exposed && !before.job_pending && before.outcome.is_none())?;
    f.engine.dv_cancel_transfer(&parent)?;
    check(f.engine.dv_transfer_state(&parent)? == before)?;
    prefix_result(&mut f, &send, 10)?;
    let actual = f.engine.dv_transfer_state(&parent)?;
    check(actual.outcome == Some(TransferOutcome::Written) && actual.queued && actual.exposed)
}

#[test]
fn a_failed_chunk_does_not_hide_another_unknown_native_callback() -> Result<(), Error> {
    let mut f = Fixture::new(true, 3)?;
    set_queue_mtu(&mut f, 256)?;
    let parent = f.engine.dv_enqueue_transfer(
        &f.source,
        &f.queue,
        &opaque_box(512, false)?,
        false,
        Duration(1_000),
        Times::shared_coordinate(10),
    )?;
    let mut sends = Vec::new();
    for _ in 0..2 {
        f.pump()?;
        let Some(Output::Frame { client, bytes }) = f.engine.output() else {
            return Err(Error::NotFound);
        };
        let send = f
            .engine
            .dv_frame_tag(&client, &bytes)
            .ok_or(Error::NotFound)?;
        check(f.engine.dv_chunk_parent(&send).as_ref() == Some(&parent))?;
        check(f.engine.dv_chunk_queued(&send)?.as_ref() == Some(&parent))?;
        f.engine.dv_ipc_progress(&send, bytes.len(), true)?;
        sends.push(send);
    }
    let first = sends.first().ok_or(Error::NotFound)?;
    f.engine.receive(
        &f.queue.owner,
        &wire(Request::Sent {
            status: 7,
            message_id: first.mid,
            queue: f.queue.queue,
            peer: f.queue.peer.0,
        })?,
        10,
        &mut f.local,
        &mut f.random,
    )?;
    f.engine.dv_cancel_transfer(&parent)?;
    let diagnostic = f
        .engine
        .dv_transfer_diagnostic(&parent)
        .ok_or(Error::NotFound)?;
    check(
        diagnostic.state.outcome == Some(TransferOutcome::Failed(7))
            && !diagnostic.state.job_pending
            && diagnostic.live_chunks == 1
            && diagnostic.covered_bytes == 0
            && diagnostic.total_bytes == 512,
    )?;
    check(f.engine.dv_transfer_completion(&parent)?.is_none())?;
    let rejected = f
        .engine
        .dv_take_transfer(parent.clone())
        .err()
        .ok_or(Error::Conflict)?;
    check(rejected.reason == Error::NotReady && rejected.value == parent)?;
    let last = sends.last().ok_or(Error::NotFound)?;
    prefix_result(&mut f, last, 10)?;
    check(f.engine.dv_transfer_completion(&parent)? == Some(TransferOutcome::Failed(7)))?;
    let actual = f.engine.dv_take_transfer(parent).map_err(|r| r.reason)?;
    check(actual.outcome == Some(TransferOutcome::Failed(7)))
}
