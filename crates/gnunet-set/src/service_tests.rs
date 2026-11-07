//! Source-only cases for original ownership/transaction boundaries. The scripted
//! completions are pure inputs, not native write/peer interoperability evidence.
use super::*;
use crate::wire::{Abi, ClientRequest, ClientResponse, Element};
use alloc::vec::Vec;
struct Scripted;
impl Random for Scripted {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(7);
        Ok(())
    }
}
impl Compression for Scripted {
    fn compress(&mut self, _: &[u8], _: usize) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported)
    }
    fn decompress_exact(&mut self, _: &[u8], _: usize, _: usize) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported)
    }
}
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn element(n: &[u8]) -> Element<'_> {
    Element {
        element_type: 19,
        data: n,
    }
}
fn request<'id>(
    service: &mut Service<'id>,
    client: Client<'id>,
    m: ClientRequest<'_>,
) -> Result<(), Error> {
    service.client_request(client, m, 1, &mut Scripted)
}
fn next_ready<'id>(
    s: &Service<'id>,
    scan: &mut EffectScan<'id>,
) -> Result<Option<EffectId<'id>>, Error> {
    for _ in 0..4096 {
        match s.scan_effect(scan, 1) {
            EffectScanStep::Ready(e) => return Ok(Some(e.id)),
            EffectScanStep::End => return Ok(None),
            EffectScanStep::Pending => {}
        }
    }
    Err(Error::Deadline)
}
#[test]
fn lazy_copy_forks_at_connect_and_old_snapshot_is_immutable() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut s = Service::new(&mut instance, Limits::default(), Abi::native(), 0)?;
    let source = s.attach_client()?;
    request(&mut s, source, ClientRequest::Create { operation: 0 })?;
    request(
        &mut s,
        source,
        ClientRequest::Add {
            element: element(&[1]),
        },
    )?;
    request(&mut s, source, ClientRequest::CopyLazyPrepare)?;
    let effect = s.effect().ok_or(Error::NotReady)?;
    let id = effect.id;
    let Action::ClientFrame { bytes, .. } = &effect.action else {
        return Err(Error::Conflict);
    };
    let ClientResponse::CopyLazy { cookie } = ClientResponse::decode(bytes, Abi::native())? else {
        return Err(Error::Conflict);
    };
    s.admit_effect(id)?;
    let _actual = s.complete_effect(id, Completion::Written)?;
    request(
        &mut s,
        source,
        ClientRequest::Add {
            element: element(&[2]),
        },
    )?;
    let copy = s.attach_client()?;
    request(&mut s, copy, ClientRequest::CopyLazyConnect { cookie })?;
    let at = s.ci(copy)?;
    let frozen = s.content(at)?.1.snapshot()?;
    check(frozen.len() == 2)?;
    request(
        &mut s,
        source,
        ClientRequest::Remove {
            element: element(&[1]),
        },
    )?;
    check(s.content(s.ci(source)?)?.1.len() == 1)?;
    check(s.content(at)?.1.len() == 2)?;
    request(
        &mut s,
        copy,
        ClientRequest::Remove {
            element: element(&[2]),
        },
    )?;
    check(frozen.len() == 2)?;
    let third = s.attach_client()?;
    check(request(&mut s, third, ClientRequest::CopyLazyConnect { cookie }) == Err(Error::Stale))
}
#[test]
fn typed_duplicates_and_refused_growth_do_not_change_membership() -> Result<(), Error> {
    let mut c = Content::new(ContentLimits::default(), Abi::native())?;
    check(c.add(element(&[1, 2]))?)?;
    let original = c.snapshot()?;
    let generation = c.generation;
    let charge = c.charged_bytes()?;
    check(!c.add(element(&[1, 2]))?)?;
    check(c.generation == generation)?;
    check(c.add_with_allowance(element(&[3, 4]), 0) == Err(Error::Capacity))?;
    check(c.len() == 1 && c.generation == generation && c.charged_bytes()? == charge)?;
    check(c.add(Element {
        element_type: 20,
        data: &[1, 2],
    })?)?;
    check(c.len() == 2 && original.len() == 1)
}

#[test]
fn shared_body_lease_survives_membership_removal_snapshots_and_queued_results() -> Result<(), Error>
{
    use crate::content::{Body, BodyLedger};
    let limits = ContentLimits {
        body_bytes: 3,
        element_bytes: 3,
        ..ContentLimits::default()
    };
    let mut content = Content::new(limits, Abi::native())?;
    let value = element(&[1, 2, 3]);
    check(content.add(value)?)?;
    let snapshot = content.snapshot()?;
    let ledger = BodyLedger::share(&snapshot.ledger)?;
    let charged = ledger.charged_bytes()?;
    check(charged == BodyLedger::allocation_bytes() + Body::allocation_overhead() + 3)?;
    check(content.charged_bytes()? == content.metadata_bytes()? + charged)?;
    check(snapshot.charged_bytes()? == snapshot.metadata_bytes()? + charged)?;
    let other_snapshot = snapshot.try_clone()?;
    let mut copy = content.fork()?;
    check(alloc::rc::Rc::ptr_eq(
        &snapshot.ledger,
        &other_snapshot.ledger,
    ))?;
    check(!content.add(value)? && ledger.charged_bytes()? == charged)?;
    // A shared allocation does not weaken the independent per-view body cap.
    check(copy.add(element(&[4])) == Err(Error::Capacity))?;
    check(copy.len() == 1 && ledger.charged_bytes()? == charged)?;
    let mut output = crate::engine::Output::new(Limits::default());
    output.result(Status::Ok, Some(snapshot.members[0].clone()), 1)?;
    check(content.remove(value)?)?;
    drop(content);
    drop(copy);
    drop(other_snapshot);
    drop(snapshot);
    // An actual queued ResultValue still owns the same immutable allocation.
    check(ledger.charged_bytes()? == charged)?;
    output.clear_unadmitted();
    check(ledger.charged_bytes()? == BodyLedger::allocation_bytes())
}

#[test]
fn body_growth_refusal_preserves_live_charge_and_replacement_peak() -> Result<(), Error> {
    use crate::content::{Body, BodyLedger};
    let mut content = Content::new(ContentLimits::default(), Abi::native())?;
    let snapshot = content.snapshot()?;
    let ledger = BodyLedger::share(&snapshot.ledger)?;
    let empty = ledger.charged_bytes()?;
    // This covers the new payload and Rc allocation but cannot also hold its
    // actual initial membership allocation. No body may enter the live ledger.
    check(
        content.add_with_allowance(element(&[1, 2, 3]), Body::allocation_overhead() + 3)
            == Err(Error::Capacity),
    )?;
    check(content.is_empty() && content.generation == 0 && ledger.charged_bytes()? == empty)?;
    check(content.add(element(&[1]))?)?;
    // Fill the initial geometric membership allocation with unique bodies.
    let slots = content.metadata_bytes()? / core::mem::size_of::<alloc::rc::Rc<Body>>();
    for id in 2..=slots {
        let bytes = id.to_be_bytes();
        content.add(element(&bytes))?;
    }
    let before = ledger.charged_bytes()?;
    let metadata = content.metadata_bytes()?;
    let generation = content.generation;
    let value = [0xff; 16];
    // A replacement vector needs its entire new capacity while the original
    // vector remains alive, not just the final capacity difference.
    let incremental_only = metadata + Body::allocation_overhead() + value.len();
    check(content.add_with_allowance(element(&value), incremental_only) == Err(Error::Capacity))?;
    check(
        content.len() == slots
            && content.metadata_bytes()? == metadata
            && content.generation == generation
            && ledger.charged_bytes()? == before,
    )
}

#[test]
fn intersection_failure_keeps_body_charged_until_original_result_drops() -> Result<(), Error> {
    use crate::content::BodyLedger;
    let mut content = Content::new(ContentLimits::default(), Abi::native())?;
    content.add(element(&[1, 2, 3]))?;
    let snapshot = content.snapshot()?;
    let ledger = BodyLedger::share(&snapshot.ledger)?;
    let charged = ledger.charged_bytes()?;
    let result_body = snapshot.members[0].clone();
    let mut intersection = Intersection::new(
        snapshot,
        Role::Initiator,
        0,
        ResultMode::Full,
        wire::Options::default(),
        Limits::default(),
    )?;
    drop(content);
    intersection.out.result(Status::Ok, Some(result_body), 1)?;
    let original_result = intersection
        .out
        .results
        .pop_front()
        .ok_or(Error::NotReady)?;
    intersection.fail(Error::Capacity);
    check(intersection.outcome() == Some(Err(Error::Capacity)))?;
    check(ledger.charged_bytes()? == charged)?;
    drop(original_result);
    check(ledger.charged_bytes()? == BodyLedger::allocation_bytes())
}

#[test]
fn large_shared_sets_iteration_and_concurrent_unions_charge_payload_once() -> Result<(), Error> {
    use crate::content::BodyLedger;
    let mut instance = Instance::new();
    let limits = Limits::default();
    let mut service = Service::new(&mut instance, limits, Abi::native(), 0)?;
    let client = service.attach_client()?;
    request(&mut service, client, ClientRequest::Create { operation: 2 })?;
    let mut payload = alloc::vec![0; 65527];
    for id in 0..128u32 {
        payload[..4].copy_from_slice(&id.to_be_bytes());
        request(
            &mut service,
            client,
            ClientRequest::Add {
                element: element(&payload),
            },
        )?;
    }
    let ledger = BodyLedger::share(&service.bodies)?;
    let body_charge = ledger.charged_bytes()?;
    request(&mut service, client, ClientRequest::CopyLazyPrepare)?;
    let (effect, cookie) = {
        let effect = service.effect().ok_or(Error::NotReady)?;
        let Action::ClientFrame { bytes, .. } = &effect.action else {
            return Err(Error::Conflict);
        };
        let ClientResponse::CopyLazy { cookie } = ClientResponse::decode(bytes, Abi::native())?
        else {
            return Err(Error::Conflict);
        };
        (effect.id, cookie)
    };
    service.admit_effect(effect)?;
    let _local_handoff = service.complete_effect(effect, Completion::Written)?;
    let copy = service.attach_client()?;
    request(
        &mut service,
        copy,
        ClientRequest::CopyLazyConnect { cookie },
    )?;
    request(&mut service, copy, ClientRequest::Iterate)?;
    check(ledger.charged_bytes()? == body_charge)?;
    let before = service.retained()?;
    check(body_charge > 8 * 1024 * 1024 && before < 9 * 1024 * 1024)?;
    for request_id in 1..=4 {
        let owner = if request_id % 2 == 0 { copy } else { client };
        request(
            &mut service,
            owner,
            ClientRequest::Evaluate {
                result_mode: ResultMode::Symmetric as u32,
                target: [5; 32],
                app_id: [4; 64],
                request_id,
                options: wire::Options::default(),
                context: &[],
            },
        )?;
        check(ledger.charged_bytes()? == body_charge)?;
    }
    check(service.ops.len() == 4 && service.pending_effects() == 4)?;
    check(service.retained()? < before + 2 * 1024 * 1024)?;
    check(service.retained()? < limits.retained_bytes)?;
    service.detach_client(client)?;
    service.detach_client(copy)?;
    // Detaching the original membership cannot refund still-owned snapshots.
    check(ledger.charged_bytes()? == body_charge)?;
    // This is ordinary Rust owner destruction, not a synthetic native receipt.
    drop(service);
    check(ledger.charged_bytes()? == BodyLedger::allocation_bytes())
}
#[test]
fn eligible_heads_skip_only_independent_sinks_and_keep_admitted_fifo() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut s = Service::new(&mut instance, Limits::default(), Abi::native(), 0)?;
    let a = s.attach_client()?;
    let b = s.attach_client()?;
    let bytes = s.frame(ClientResponse::IterDone)?;
    let first = s.queue(Action::ClientFrame {
        client: a,
        operation: None,
        bytes,
    })?;
    let bytes = s.frame(ClientResponse::IterDone)?;
    let second = s.queue(Action::ClientFrame {
        client: a,
        operation: None,
        bytes,
    })?;
    let bytes = s.frame(ClientResponse::IterDone)?;
    let independent = s.queue(Action::ClientFrame {
        client: b,
        operation: None,
        bytes,
    })?;
    check(s.effect().is_some_and(|e| e.id == first))?;
    let mut scan = EffectScan::new();
    check(next_ready(&s, &mut scan)? == Some(first))?;
    check(next_ready(&s, &mut scan)? == Some(independent))?;
    s.admit_effect(first)?;
    scan.reset();
    check(next_ready(&s, &mut scan)? == Some(independent))?;
    let _actual = s.complete_effect(first, Completion::Written)?;
    check(s.effect().is_some_and(|e| e.id == second))?;
    scan.reset();
    check(next_ready(&s, &mut scan)? == Some(second))?;
    let mut foreign = Instance::new();
    let mut other = Service::new(&mut foreign, Limits::default(), Abi::native(), 0)?;
    let c = other.attach_client()?;
    let bytes = other.frame(ClientResponse::IterDone)?;
    let cursor = other.queue(Action::ClientFrame {
        client: c,
        operation: None,
        bytes,
    })?;
    let mut foreign_scan = EffectScan::new();
    check(next_ready(&other, &mut foreign_scan)? == Some(cursor))?;
    foreign_scan.end = false;
    check(matches!(
        s.scan_effect(&mut foreign_scan, 64),
        EffectScanStep::End
    ))
}
#[test]
fn original_offer_deadline_does_not_renew_on_accept_and_close_retains_adopt() -> Result<(), Error> {
    let mut instance = Instance::new();
    let limits = Limits {
        operation_lifetime: 100,
        ..Limits::default()
    };
    let mut s = Service::new(&mut instance, limits, Abi::native(), 0)?;
    let listener = s.attach_client()?;
    let set = s.attach_client()?;
    let app = [4; 64];
    request(
        &mut s,
        listener,
        ClientRequest::Listen {
            operation: 2,
            app_id: app,
        },
    )?;
    let open = s.effect().ok_or(Error::NotReady)?.id;
    s.admit_effect(open)?;
    let _actual = s.complete_effect(open, Completion::Written)?;
    request(&mut s, set, ClientRequest::Create { operation: 2 })?;
    let incoming = s.incoming(
        listener,
        [5; 32],
        app,
        wire::PeerMessage::OperationRequest {
            operation: 2,
            element_count: 0,
            app_id: [0; 64],
            context: &[],
        },
        1,
        &mut Scripted,
    )?;
    let notice = s.effect().ok_or(Error::NotReady)?.id;
    s.admit_effect(notice)?;
    let _actual = s.complete_effect(notice, Completion::Written)?;
    let accept = s.offers[s.ii(incoming)?].accept;
    s.client_request(
        set,
        ClientRequest::Accept {
            accept_id: accept,
            request_id: 8,
            result_mode: 3,
            options: wire::Options::default(),
        },
        80,
        &mut Scripted,
    )?;
    check(s.ops[0].expires == 101)?;
    let adopt = s.effect().ok_or(Error::NotReady)?.id;
    s.admit_effect(adopt)?;
    check(s.incoming_live(incoming))?;
    s.detach_client(listener)?;
    s.progress(80, &mut Scripted)?;
    // Listener ClosePort cannot overtake the retained local adoption.
    check(s.effect().is_none())?;
    let _actual = s.complete_effect(adopt, Completion::Written)?;
    check(!s.incoming_live(incoming))?;
    check(s.peer_owner_live(PeerOwner::Operation(s.ops[0].id)))?;
    check(matches!(
        s.effect().map(|e| &e.action),
        Some(Action::ClosePort { .. })
    ))
}
#[test]
fn paused_scan_fence_excludes_new_producers_until_explicit_reset() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut s = Service::new(&mut instance, Limits::default(), Abi::native(), 0)?;
    let a = s.attach_client()?;
    let b = s.attach_client()?;
    let bytes = s.frame(ClientResponse::IterDone)?;
    let first = s.queue(Action::ClientFrame {
        client: a,
        operation: None,
        bytes,
    })?;
    let mut scan = EffectScan::new();
    check(matches!(
        s.scan_effect(&mut scan, 1),
        EffectScanStep::Pending
    ))?;
    let bytes = s.frame(ClientResponse::IterDone)?;
    let later = s.queue(Action::ClientFrame {
        client: b,
        operation: None,
        bytes,
    })?;
    check(next_ready(&s, &mut scan)? == Some(first))?;
    s.admit_effect(first)?;
    let _actual = s.complete_effect(first, Completion::Written)?;
    check(next_ready(&s, &mut scan)?.is_none())?;
    scan.reset();
    check(next_ready(&s, &mut scan)? == Some(later))
}

#[test]
fn default_shared_budget_admits_two_concurrent_tiny_original_unions() -> Result<(), Error> {
    let mut instance = Instance::new();
    let limits = Limits::default();
    let mut s = Service::new(&mut instance, limits, Abi::native(), 0)?;
    let client = s.attach_client()?;
    request(&mut s, client, ClientRequest::Create { operation: 2 })?;
    request(
        &mut s,
        client,
        ClientRequest::Add {
            element: element(b"shared-original"),
        },
    )?;
    for rid in [1, 2] {
        request(
            &mut s,
            client,
            ClientRequest::Evaluate {
                result_mode: ResultMode::Symmetric as u32,
                target: [5; 32],
                app_id: [4; 64],
                request_id: rid,
                options: wire::Options::default(),
                context: &[],
            },
        )?;
    }
    check(limits.retained_bytes == 64 * 1024 * 1024)?;
    check(s.ops.len() == 2 && s.pending_effects() == 2)?;
    check(s.ops[0].id != s.ops[1].id)?;
    check(s.ops.iter().all(|op| {
        op.client == client && s.operation_live(op.id) && op.reservation < limits.retained_bytes / 4
    }))?;
    check(s.retained()? < limits.retained_bytes)?;
    // Both original opens remain independent; pure settlement is not native
    // interoperability or peer success. Neither op waits for the other to end.
    for rid in [1, 2] {
        let effect = s.effect().ok_or(Error::NotReady)?;
        let id = effect.id;
        let Action::OpenPeer { operation, .. } = effect.action else {
            return Err(Error::Conflict);
        };
        let at = s.oi(operation)?;
        check(s.ops[at].rid == rid)?;
        s.admit_effect(id)?;
        let _original = s.complete_effect(id, Completion::Written)?;
    }
    check(s.ops.iter().all(|op| op.opened && !op.gone))?;
    check(s.ops.len() == 2 && s.client_live(client))
}

#[test]
fn denied_union_ibf_growth_preserves_original_failure_and_retirement_owners() -> Result<(), Error> {
    let mut instance = Instance::new();
    // This smaller explicit shared budget leaves every algorithm limit intact.
    // A real advertised order20 fits the configured per-op IBF limit, while its
    // allocation cannot fit this service's remaining shared capacity.
    let limits = Limits {
        effect_bytes: 1024 * 1024,
        retained_bytes: 1024 * 1024,
        ..Limits::default()
    };
    let mut s = Service::new(&mut instance, limits, Abi::native(), 0)?;
    let listener = s.attach_client()?;
    let client = s.attach_client()?;
    let app = [4; 64];
    request(
        &mut s,
        listener,
        ClientRequest::Listen {
            operation: 2,
            app_id: app,
        },
    )?;
    let open = s.effect().ok_or(Error::NotReady)?.id;
    s.admit_effect(open)?;
    let _original = s.complete_effect(open, Completion::Written)?;
    request(&mut s, client, ClientRequest::Create { operation: 2 })?;
    request(
        &mut s,
        client,
        ClientRequest::Add {
            element: element(b"one-original"),
        },
    )?;
    let incoming = s.incoming(
        listener,
        [5; 32],
        app,
        wire::PeerMessage::OperationRequest {
            operation: 2,
            element_count: 0,
            app_id: app,
            context: &[],
        },
        1,
        &mut Scripted,
    )?;
    let (notice, accept) = {
        let effect = s.effect().ok_or(Error::NotReady)?;
        let Action::ClientFrame { bytes, .. } = &effect.action else {
            return Err(Error::Conflict);
        };
        let ClientResponse::Request { accept_id, .. } =
            ClientResponse::decode(bytes, Abi::native())?
        else {
            return Err(Error::Conflict);
        };
        (effect.id, accept_id)
    };
    s.admit_effect(notice)?;
    let _original = s.complete_effect(notice, Completion::Written)?;
    request(
        &mut s,
        client,
        ClientRequest::Accept {
            accept_id: accept,
            request_id: 17,
            result_mode: ResultMode::Symmetric as u32,
            options: wire::Options::default(),
        },
    )?;
    let (adopt, operation) = {
        let effect = s.effect().ok_or(Error::NotReady)?;
        let Action::AdoptPeer {
            incoming: original,
            operation,
        } = effect.action
        else {
            return Err(Error::Conflict);
        };
        check(original == incoming)?;
        (effect.id, operation)
    };
    check(s.failure_for_effect(adopt).is_none())?;
    s.admit_effect(adopt)?;
    let _original = s.complete_effect(adopt, Completion::Written)?;
    let owner = PeerOwner::Operation(operation);
    let mut strata_written = false;
    for _ in 0..128 {
        s.progress(1, &mut Scripted)?;
        if let Some(effect) = s.effect() {
            let id = effect.id;
            let Action::PeerSend {
                owner: original,
                bytes,
            } = &effect.action
            else {
                return Err(Error::Conflict);
            };
            check(*original == owner)?;
            check(matches!(
                wire::PeerMessage::decode(bytes, Abi::native())?,
                wire::PeerMessage::UnionStrata { .. }
            ))?;
            check(s.failure_for_effect(id).is_none())?;
            s.admit_effect(id)?;
            let _original = s.complete_effect(id, Completion::Written)?;
            strata_written = true;
            break;
        }
    }
    check(strata_written && s.pending_effects() == 0)?;
    let original_expiry = s.ops[s.oi(operation)?].expires;
    let before = s.retained()?;
    let columns = [0; 4 * 13];
    let message = wire::PeerMessage::UnionIbf {
        order: 20,
        reserved1: 0,
        reserved2: 0,
        offset: 0,
        salt: 42,
        buckets: wire::IbfSlice::decode(&columns)?,
    };
    let mut bytes = alloc::vec![0; message.encoded_len(Abi::native())?];
    message.encode(&mut bytes, Abi::native())?;
    check(s.receive(owner, &bytes, 1, &mut Scripted) == Err(Error::Capacity))?;
    let at = s.oi(operation)?;
    check(s.ops.len() == 1 && s.ops[at].rid == 17)?;
    check(s.ops[at].expires == original_expiry)?;
    check(s.ops[at].engine.outcome() == Some(Err(Error::Capacity)))?;
    check(s.ops[at].reservation == s.ops[at].engine.charge()?)?;
    check(s.retained()? <= before && s.retained()? <= limits.retained_bytes)?;
    check(s.pending_effects() == 0 && s.client_live(client))?;
    check(!s.peer_owner_live(owner))?;
    check(s.receive(owner, &bytes, 1, &mut Scripted) == Err(Error::Closed))?;
    s.progress(1, &mut Scripted)?;
    let close = s.effect().ok_or(Error::NotReady)?;
    check(matches!(close.action, Action::ClosePeer { owner: original } if original == owner))?;
    let close_id = close.id;
    check(s.failure_for_effect(close_id).is_none())?;
    s.admit_effect(close_id)?;
    // The physical peer fact cannot erase the independently admitted close.
    s.peer_lost(owner, Error::Closed)?;
    s.progress(1, &mut Scripted)?;
    check(s.oi(operation).is_ok())?;
    check(s.effects.iter().any(|effect| effect.id == close_id))?;
    let _original = s.complete_effect(close_id, Completion::Written)?;
    for _ in 0..128 {
        s.progress(1, &mut Scripted)?;
        if s.effect().is_some() {
            break;
        }
    }
    let failure = s.effect().ok_or(Error::NotReady)?;
    let Action::ClientFrame {
        operation: Some(original),
        bytes,
        ..
    } = &failure.action
    else {
        return Err(Error::Conflict);
    };
    check(*original == operation)?;
    check(matches!(
        ClientResponse::decode(bytes, Abi::native())?,
        ClientResponse::Result {
            request_id: 17,
            status,
            ..
        } if status == Status::Failure as u16
    ))?;
    let failure_id = failure.id;
    let retained = s.retained()?;
    let expected = OperationFailure {
        effect_serial: failure_id.value(),
        client_serial: client.value(),
        operation_serial: operation.value(),
        request_id: 17,
        kind: OperationType::Union,
        reason: Error::Capacity,
        expires: original_expiry,
    };
    // The old physical Closed fact and its whole close receipt cannot replace
    // the first Capacity cause. Only this exact final FAILURE frame matches.
    check(s.failure_for_effect(failure_id) == Some(expected))?;
    check(s.failure_for_effect(close_id).is_none())?;
    check(s.retained()? == retained && s.ops[s.oi(operation)?].expires == original_expiry)?;
    s.admit_effect(failure_id)?;
    check(s.failure_for_effect(failure_id) == Some(expected))?;
    check(!s.cleanup_one() && s.oi(operation).is_ok())?;
    let _original = s.complete_effect(failure_id, Completion::Written)?;
    check(s.failure_for_effect(failure_id).is_none())?;
    s.progress(1, &mut Scripted)?;
    check(s.oi(operation) == Err(Error::Stale) && s.client_live(client))
}

fn accepted_full_union<'id>(
    service: &mut Service<'id>,
    members: u16,
    remote_members: u32,
    byzantine: u8,
) -> Result<(Client<'id>, Operation<'id>), Error> {
    let listener = service.attach_client()?;
    let client = service.attach_client()?;
    let app = [4; 64];
    request(
        service,
        listener,
        ClientRequest::Listen {
            operation: 2,
            app_id: app,
        },
    )?;
    let id = service.effect().ok_or(Error::NotReady)?.id;
    service.admit_effect(id)?;
    let _original = service.complete_effect(id, Completion::Written)?;
    request(service, client, ClientRequest::Create { operation: 2 })?;
    for member in 0..members {
        request(
            service,
            client,
            ClientRequest::Add {
                element: element(&member.to_be_bytes()),
            },
        )?;
    }
    let _incoming = service.incoming(
        listener,
        [5; 32],
        app,
        wire::PeerMessage::OperationRequest {
            operation: 2,
            element_count: remote_members,
            app_id: app,
            context: &[],
        },
        1,
        &mut Scripted,
    )?;
    let (id, accept_id) = {
        let effect = service.effect().ok_or(Error::NotReady)?;
        let Action::ClientFrame { bytes, .. } = &effect.action else {
            return Err(Error::Conflict);
        };
        let ClientResponse::Request { accept_id, .. } =
            ClientResponse::decode(bytes, Abi::native())?
        else {
            return Err(Error::Conflict);
        };
        (effect.id, accept_id)
    };
    service.admit_effect(id)?;
    let _original = service.complete_effect(id, Completion::Written)?;
    request(
        service,
        client,
        ClientRequest::Accept {
            accept_id,
            request_id: 23,
            result_mode: ResultMode::Symmetric as u32,
            options: wire::Options {
                force_full: 1,
                byzantine,
                ..wire::Options::default()
            },
        },
    )?;
    let (id, operation) = {
        let effect = service.effect().ok_or(Error::NotReady)?;
        let Action::AdoptPeer { operation, .. } = effect.action else {
            return Err(Error::Conflict);
        };
        (effect.id, operation)
    };
    service.admit_effect(id)?;
    let _original = service.complete_effect(id, Completion::Written)?;
    for _ in 0..4096 {
        service.progress(1, &mut Scripted)?;
        if let Some(effect) = service.effect() {
            let Action::PeerSend { bytes, .. } = &effect.action else {
                return Err(Error::Conflict);
            };
            check(matches!(
                wire::PeerMessage::decode(bytes, Abi::native())?,
                wire::PeerMessage::UnionStrata { .. }
            ))?;
            let id = effect.id;
            service.admit_effect(id)?;
            let _original = service.complete_effect(id, Completion::Written)?;
            return Ok((client, operation));
        }
    }
    Err(Error::NotReady)
}
fn receive_full<'id>(
    service: &mut Service<'id>,
    owner: PeerOwner<'id>,
    data: &[u8],
) -> Result<(), Error> {
    let message = wire::PeerMessage::UnionFullElement {
        element: element(data),
    };
    let mut bytes = alloc::vec![0; message.encoded_len(Abi::native())?];
    message.encode(&mut bytes, Abi::native())?;
    service.receive(owner, &bytes, 1, &mut Scripted)
}
fn retire_cancelled_union<'id>(
    service: &mut Service<'id>,
    client: Client<'id>,
    operation: Operation<'id>,
) -> Result<(), Error> {
    request(service, client, ClientRequest::Cancel { request_id: 23 })?;
    service.progress(1, &mut Scripted)?;
    let close = service.effect().ok_or(Error::NotReady)?;
    let owner = PeerOwner::Operation(operation);
    check(matches!(close.action, Action::ClosePeer { owner: original } if original == owner))?;
    let id = close.id;
    service.admit_effect(id)?;
    service.peer_lost(owner, Error::Closed)?;
    check(service.oi(operation).is_ok())?;
    let _original = service.complete_effect(id, Completion::Written)?;
    for _ in 0..16 {
        service.progress(1, &mut Scripted)?;
        if service.oi(operation) == Err(Error::Stale) {
            break;
        }
    }
    check(service.oi(operation) == Err(Error::Stale) && service.pending_effects() == 0)
}

#[test]
fn byzantine_full_accepts_high_overlap_but_rejects_exact_replay_under_result_pressure()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut service = Service::new(
        &mut instance,
        Limits {
            output_frames: 1,
            received_records: 514,
            ..Limits::default()
        },
        Abi::native(),
        0,
    )?;
    // The modeled remote set has 512 common members and two fresh members.
    let (client, operation) = accepted_full_union(&mut service, 512, 514, 1)?;
    let owner = PeerOwner::Operation(operation);
    let original_bodies = service.bodies.charged_bytes()?;
    receive_full(&mut service, owner, b"fresh-a")?;
    let before = service.retained()?;
    check(receive_full(&mut service, owner, b"fresh-b") == Err(Error::WouldBlock))?;
    let at = service.oi(operation)?;
    check(service.ops[at].engine.size() == 513 && service.retained()? == before)?;
    check(service.ops[at].engine.out().results.len() == 1)?;
    // The first common element consumes no result capacity. Honest overlap
    // must not be mistaken for replay by a fresh/total count heuristic.
    receive_full(&mut service, owner, &0u16.to_be_bytes())?;
    service.progress(1, &mut Scripted)?;
    let (held, original) = {
        let effect = service.effect().ok_or(Error::NotReady)?;
        let Action::ClientFrame {
            operation: Some(actual),
            bytes,
            ..
        } = &effect.action
        else {
            return Err(Error::Conflict);
        };
        check(*actual == operation)?;
        (effect.id, bytes.clone())
    };
    service.admit_effect(held)?;
    // A blocked first receipt was not marked remote: the exact original input
    // is admitted after capacity returns, rather than being rejected as replay.
    receive_full(&mut service, owner, b"fresh-b")?;
    for member in 1..512u16 {
        receive_full(&mut service, owner, &member.to_be_bytes())?;
    }
    let at = service.oi(operation)?;
    check(service.ops[at].engine.size() == 514 && service.ops[at].engine.out().results.len() == 1)?;
    let original_expiry = service.ops[at].expires;
    let body_charge = service.bodies.charged_bytes()?;
    // The replay stays Replay even at the record cap and with a full result
    // queue. The service closes the original operation without another result.
    check(receive_full(&mut service, owner, &0u16.to_be_bytes()) == Err(Error::Replay))?;
    let at = service.oi(operation)?;
    check(service.ops[at].engine.size() == 514 && service.ops[at].expires == original_expiry)?;
    check(service.ops[at].engine.outcome() == Some(Err(Error::Replay)))?;
    check(service.bodies.charged_bytes()? == body_charge)?;
    check(service.ops[at].engine.out().results.is_empty())?;
    check(
        service.effects.len() == 1 && service.effects[0].id == held && service.effects[0].admitted,
    )?;
    check(
        matches!(&service.effects[0].action, Action::ClientFrame { bytes, .. } if *bytes == original),
    )?;
    request(
        &mut service,
        client,
        ClientRequest::Cancel { request_id: 23 },
    )?;
    check(
        service.effects[0].id == held
            && service.ops[service.oi(operation)?].engine.outcome() == Some(Err(Error::Replay)),
    )?;
    let _original = service.complete_effect(held, Completion::Written)?;
    retire_cancelled_union(&mut service, client, operation)?;
    check(service.bodies.charged_bytes()? == original_bodies && service.client_live(client))
}

#[test]
fn ordinary_full_repeated_elements_keep_official_behavior_and_record_bound() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut service = Service::new(
        &mut instance,
        Limits {
            output_frames: 1,
            received_records: 4,
            ..Limits::default()
        },
        Abi::native(),
        0,
    )?;
    // Two unique remote members are sent repeatedly; repeats do not enlarge
    // the original set's advertised cardinality.
    let (client, operation) = accepted_full_union(&mut service, 1, 2, 0)?;
    let original_bodies = service.bodies.charged_bytes()?;
    let owner = PeerOwner::Operation(operation);
    receive_full(&mut service, owner, b"fresh")?;
    let retained = service.retained()?;
    receive_full(&mut service, owner, b"fresh")?;
    receive_full(&mut service, owner, &0u16.to_be_bytes())?;
    receive_full(&mut service, owner, &0u16.to_be_bytes())?;
    let at = service.oi(operation)?;
    check(service.ops[at].engine.size() == 2 && service.ops[at].engine.out().results.len() == 1)?;
    check(service.retained()? == retained && service.ops[at].engine.outcome().is_none())?;
    check(receive_full(&mut service, owner, b"fresh") == Err(Error::Capacity))?;
    check(service.ops[service.oi(operation)?].engine.outcome() == Some(Err(Error::Capacity)))?;
    retire_cancelled_union(&mut service, client, operation)?;
    check(service.bodies.charged_bytes()? == original_bodies && service.client_live(client))
}
