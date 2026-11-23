//! Regression coverage for capture revocation and replay under native debt.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Tests assert independent verdicts while propagating fixture admission errors"
)]

use gnunet_wfp_dns::{
    Addresses, ClassifiedFlow, Error, Family, Flow, FlowId, FlowRemoval, Gate,
    InjectionObservation, LocalInterface, Path, PathError, ReceivePath, RequestId, State,
};
use std::num::NonZeroU64;

#[derive(Debug)]
enum TestError {
    Path,
    State,
}

impl From<PathError> for TestError {
    fn from(_: PathError) -> Self {
        Self::Path
    }
}

impl From<Error> for TestError {
    fn from(_: Error) -> Self {
        Self::State
    }
}

fn path(interface: u32, zone: u32) -> Result<Path, PathError> {
    let local = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut remote = local;
    remote[15] = 2;
    Path::new(
        Addresses::V6 { local, remote },
        [52_000, 53],
        7,
        LocalInterface::new(0x0123_0000, interface, 2)?,
        zone,
    )
}

fn received(path: Path) -> Result<ReceivePath, PathError> {
    ReceivePath::new(
        path.addresses(),
        path.ports(),
        path.compartment(),
        path.interface(),
        None,
    )
}

const FLOW: Flow = Flow {
    handle: NonZeroU64::MIN,
    endpoint: NonZeroU64::MIN.saturating_add(1),
    family: Family::V6,
    compartment: 7,
};

fn associate<const F: usize, const R: usize>(
    state: &mut State<F, R>,
    flow: Flow,
) -> Result<FlowId, Error> {
    let observation = state.begin_flow_observation()?;
    let pending = state.reserve_flow(observation, flow)?;
    state.confirm_flow(pending)
}

fn classified(flow: FlowId) -> ClassifiedFlow {
    ClassifiedFlow::new(flow, None, None)
}

#[test]
fn inbound_route_uses_its_own_fields_without_an_outbound_scope() -> Result<(), TestError> {
    let local = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut remote = local;
    remote[15] = 0x53;
    let addresses = Addresses::V6 { local, remote };
    let interface = LocalInterface::new(0x0123_0000, 4, 2)?;
    let path = Path::new(addresses, [52_000, 53], 7, interface, 0xe000_0000)?;
    let mut state = State::<1, 1>::new();
    let session = state.open_session()?;
    let flow = classified(associate(&mut state, FLOW)?);
    let request = state.capture(session, flow, path, 5, 20)?;
    state.dequeue_capture(session, request, 6)?;
    let _loan = state.begin_injection(session, request, 6)?;

    for different in [
        ReceivePath::new(addresses, [52_001, 53], 7, interface, None)?,
        ReceivePath::new(addresses, path.ports(), 8, interface, None)?,
        ReceivePath::new(
            addresses,
            path.ports(),
            7,
            LocalInterface::new(0x0124_0000, 4, 2)?,
            None,
        )?,
        ReceivePath::new(
            addresses,
            path.ports(),
            7,
            LocalInterface::new(0x0123_0000, 4, 3)?,
            None,
        )?,
    ] {
        assert_eq!(
            state.authorize_receive(request, flow, different, 7),
            Gate::Deny
        );
    }
    assert_eq!(
        state.authorize_receive(request, flow, received(path)?, 7),
        Gate::Authorize
    );
    assert_eq!(
        state.complete_injection(request),
        Ok(InjectionObservation::Authorized)
    );
    Ok(())
}

#[test]
fn link_zone_uses_interface_but_site_zone_requires_other_authority() -> Result<(), PathError> {
    let link = path(4, 0x2000_0004)?;
    assert_eq!(
        ReceivePath::new(
            link.addresses(),
            link.ports(),
            link.compartment(),
            link.interface(),
            Some(4),
        ),
        received(link)
    );
    assert_eq!(path(4, 0x5000_0004), Err(PathError::Interface));
    let Addresses::V6 { local, mut remote } = link.addresses() else {
        return Err(PathError::Endpoint);
    };
    remote[1] = 0xc0;
    let site = Addresses::V6 { local, remote };
    assert_eq!(
        Path::new(site, link.ports(), 7, link.interface(), 0x5000_0004),
        Err(PathError::Interface)
    );
    assert_eq!(
        ReceivePath::new(site, link.ports(), 7, link.interface(), Some(4)),
        Err(PathError::Interface)
    );
    Ok(())
}

#[test]
fn reported_native_handles_must_agree_in_both_directions() -> Result<(), TestError> {
    let mut state = State::<1, 1>::new();
    let session = state.open_session()?;
    let id = associate(&mut state, FLOW)?;
    let original = ClassifiedFlow::new(id, Some(FLOW.handle), Some(FLOW.endpoint));
    let contradictory = [
        ClassifiedFlow::new(id, Some(FLOW.handle.saturating_add(1)), Some(FLOW.endpoint)),
        ClassifiedFlow::new(id, Some(FLOW.handle), Some(FLOW.endpoint.saturating_add(1))),
        ClassifiedFlow::new(id, None, Some(FLOW.endpoint.saturating_add(1))),
    ];
    let path = path(4, 4)?;

    for observed in contradictory {
        assert_eq!(state.classified_flow(observed), None);
        assert_eq!(
            state.capture(session, observed, path, 5, 20),
            Err(Error::Stale)
        );
    }
    let request = state.capture(session, original, path, 5, 20)?;
    state.dequeue_capture(session, request, 6)?;
    let loan = state.begin_injection(session, request, 6)?;
    for observed in contradictory {
        assert_eq!(
            state.authorize_receive(request, observed, received(path)?, 7),
            Gate::Deny
        );
    }
    assert_eq!(
        state.authorize_receive(request, original, received(path)?, 7),
        Gate::Authorize
    );
    assert_eq!(
        state.complete_injection(RequestId::from_context(loan.context())),
        Ok(InjectionObservation::Authorized)
    );
    Ok(())
}

#[test]
fn a_matching_injection_authorizes_once_and_completion_retires_it() -> Result<(), TestError> {
    assert_eq!(path(4, 0x2000_0000), Err(PathError::Interface));
    assert_eq!(LocalInterface::new(0, 4, 2), Err(PathError::Interface));
    let mut state = State::<1, 1>::new();
    let session = state.open_session()?;
    let flow = associate(&mut state, FLOW)?;
    let path_one = path(4, 4)?;
    let request = state.capture(session, classified(flow), path_one, 5, 20)?;
    assert_eq!(
        state.authorize_receive(request, classified(flow), received(path_one)?, 6),
        Gate::Deny
    );
    assert!(state.has_capture(session, request, 6));
    assert!(matches!(
        state.begin_injection(session, request, 6),
        Err(Error::InFlight)
    ));
    assert_eq!(state.revoke_reply(session, request), Err(Error::InFlight));
    assert_eq!(state.complete_injection(request), Err(Error::Stale));
    state.dequeue_capture(session, request, 6)?;
    assert!(!state.has_capture(session, request, 6));
    assert_eq!(
        state.dequeue_capture(session, request, 6),
        Err(Error::Stale)
    );
    let loan = state.begin_injection(session, request, 6)?;
    let context = RequestId::from_context(loan.context());
    let unknown_flow = FlowId::from_context(flow.context().saturating_add(1));
    assert_eq!(
        state.authorize_receive(context, classified(unknown_flow), received(path_one)?, 7),
        Gate::Deny
    );
    assert_eq!(
        state.authorize_receive(context, classified(flow), received(path(5, 5)?)?, 7),
        Gate::Deny
    );
    assert_eq!(path(4, 5), Err(PathError::Interface));
    assert_eq!(
        ReceivePath::new(
            path_one.addresses(),
            path_one.ports(),
            path_one.compartment(),
            path_one.interface(),
            Some(5),
        ),
        Err(PathError::Interface)
    );
    let reused_index = Path::new(
        path_one.addresses(),
        path_one.ports(),
        path_one.compartment(),
        LocalInterface::new(0x0124_0000, 4, 2)?,
        path_one.remote_scope(),
    )?;
    assert_eq!(
        state.authorize_receive(context, classified(flow), received(reused_index)?, 7),
        Gate::Deny
    );
    assert_eq!(
        state.authorize_receive(context, classified(flow), received(path_one)?, 7),
        Gate::Authorize
    );
    assert_eq!(
        state.authorize_receive(context, classified(flow), received(path_one)?, 7),
        Gate::Deny
    );
    state.revoke_reply(session, request)?;
    assert_eq!(
        state.complete_injection(context),
        Ok(InjectionObservation::Authorized)
    );
    let replacement = state.capture(session, classified(flow), path_one, 8, 20)?;
    assert_ne!(request, replacement);
    assert_eq!(state.complete_injection(context), Err(Error::Stale));
    assert_eq!(state.native_debt(), 0);
    Ok(())
}

#[test]
fn replacement_and_expiration_revoke_the_gate_but_keep_native_debt() -> Result<(), TestError> {
    let mut state = State::<1, 2>::new();
    let session = state.open_session()?;
    let flow = associate(&mut state, FLOW)?;
    let same_path = path(4, 4)?;
    let request = state.capture(session, classified(flow), same_path, 5, 20)?;
    let idle = state.capture(session, classified(flow), same_path, 5, 20)?;
    state.dequeue_capture(session, request, 6)?;
    let loan = state.begin_injection(session, request, 6)?;
    let context = RequestId::from_context(loan.context());
    assert_eq!(
        state.authorize_receive(context, classified(flow), received(same_path)?, 20),
        Gate::Deny
    );
    assert_eq!(state.retire_flow(flow), Some(FLOW));
    let new_flow = associate(&mut state, FLOW)?;
    assert_ne!(flow, new_flow);
    assert_eq!(
        state.authorize_receive(context, classified(new_flow), received(same_path)?, 7),
        Gate::Deny
    );
    state.close_session(session)?;
    let new_session = state.open_session()?;
    assert_eq!(state.revoke_reply(new_session, idle), Err(Error::Stale));
    assert_eq!(state.sweep(30, 1), 0);
    assert_eq!(state.sweep(30, 1), 1);
    assert_eq!(state.native_debt(), 1);
    assert_eq!(
        state.complete_injection(context),
        Ok(InjectionObservation::NoAuthorization)
    );
    assert_eq!(state.native_debt(), 0);
    Ok(())
}

#[test]
fn endpoint_closure_revokes_all_its_flows_and_preserves_native_debt() -> Result<(), TestError> {
    let mut state = State::<3, 2>::new();
    let session = state.open_session()?;
    let first = associate(&mut state, FLOW)?;
    let second_native = Flow {
        handle: FLOW.handle.saturating_add(1),
        ..FLOW
    };
    let second = associate(&mut state, second_native)?;
    let unrelated_native = Flow {
        handle: FLOW.handle.saturating_add(2),
        endpoint: FLOW.endpoint.saturating_add(1),
        ..FLOW
    };
    let unrelated = associate(&mut state, unrelated_native)?;
    let original = path(4, 4)?;
    let submitted = state.capture(session, classified(first), original, 5, 20)?;
    let queued = state.capture(session, classified(second), original, 5, 20)?;
    state.dequeue_capture(session, submitted, 6)?;
    let loan = state.begin_injection(session, submitted, 6)?;
    state.close_endpoint(FLOW.endpoint);
    state.close_endpoint(FLOW.endpoint);
    assert_eq!(state.flow(first), None);
    assert_eq!(state.flow(second), None);
    assert_eq!(state.flow(unrelated), Some(unrelated_native));
    assert_eq!(state.owned_flow(first), Some(FLOW));
    assert_eq!(associate(&mut state, FLOW), Err(Error::Stale));
    assert!(!state.has_capture(session, queued, 7));
    assert_eq!(state.sweep(7, 2), 1);
    assert_eq!(state.native_debt(), 1);
    assert_eq!(
        state.authorize_receive(submitted, classified(first), received(original)?, 7),
        Gate::Deny
    );
    assert_eq!(state.retire_flow(first), Some(FLOW));
    assert_eq!(associate(&mut state, FLOW), Err(Error::Stale));
    assert_eq!(state.retire_flow(second), Some(second_native));
    assert_eq!(
        state.complete_injection(RequestId::from_context(loan.context())),
        Ok(InjectionObservation::NoAuthorization)
    );
    assert_eq!(state.native_debt(), 0);
    Ok(())
}

#[test]
fn endpoint_closure_before_reservation_refuses_original_indication() -> Result<(), TestError> {
    let mut state = State::<1, 0>::new();
    let original = state.begin_flow_observation()?;
    state.close_endpoint(FLOW.endpoint);
    assert!(matches!(
        state.reserve_flow(original, FLOW),
        Err(Error::Stale)
    ));
    assert_eq!(associate(&mut state, FLOW), Err(Error::Stale));
    assert_eq!(state.flow_count(), 0);

    let unrelated = Flow {
        endpoint: FLOW.endpoint.saturating_add(1),
        ..FLOW
    };
    let id = associate(&mut state, unrelated)?;
    assert_eq!(state.flow(id), Some(unrelated));
    Ok(())
}

#[test]
fn endpoint_closure_during_association_preserves_native_delete_debt() -> Result<(), TestError> {
    let mut state = State::<1, 1>::new();
    let session = state.open_session()?;
    let observation = state.begin_flow_observation()?;
    let pending = state.reserve_flow(observation, FLOW)?;
    let id = FlowId::from_context(pending.context());
    let path = path(4, 4)?;
    assert_eq!(state.flow(id), None);
    assert_eq!(state.owned_flow(id), Some(FLOW));
    assert_eq!(
        state.capture(session, classified(id), path, 5, 20),
        Err(Error::Stale)
    );
    assert_eq!(state.begin_flow_removal(0), FlowRemoval::Pending(id));

    state.close_endpoint(FLOW.endpoint);
    assert_eq!(state.confirm_flow(pending), Err(Error::Stale));
    assert_eq!(
        state.capture(session, classified(id), path, 6, 20),
        Err(Error::Stale)
    );
    assert_eq!(state.flow_count(), 1);
    assert_eq!(state.begin_flow_removal(0), FlowRemoval::Request(id, FLOW));
    state.refuse_flow_removal(id);
    assert_eq!(state.flow(id), None);
    assert_eq!(state.begin_flow_removal(0), FlowRemoval::Request(id, FLOW));
    assert_eq!(state.retire_flow(id), Some(FLOW));
    assert_eq!(state.flow_count(), 0);
    Ok(())
}

#[test]
fn original_association_settlement_cannot_reuse_replacement_slot() -> Result<(), TestError> {
    let mut state = State::<1, 0>::new();
    let observation = state.begin_flow_observation()?;
    let pending = state.reserve_flow(observation, FLOW)?;
    let original = FlowId::from_context(pending.context());
    assert_eq!(state.retire_flow(original), Some(FLOW));
    let fresh = associate(&mut state, FLOW)?;
    assert_ne!(fresh, original);
    assert_eq!(state.confirm_flow(pending), Err(Error::Stale));
    assert_eq!(state.flow(fresh), Some(FLOW));

    assert_eq!(state.retire_flow(fresh), Some(FLOW));
    let observation = state.begin_flow_observation()?;
    let pending = state.reserve_flow(observation, FLOW)?;
    state.refuse_flow(pending);
    assert_eq!(state.flow_count(), 0);
    Ok(())
}

#[test]
fn immediate_native_refusal_invalidates_original_context() -> Result<(), TestError> {
    let mut state = State::<1, 1>::new();
    let session = state.open_session()?;
    let flow = associate(&mut state, FLOW)?;
    let path = path(4, 4)?;
    let request = state.capture(session, classified(flow), path, 5, 20)?;
    state.dequeue_capture(session, request, 6)?;
    let loan = state.begin_injection(session, request, 6)?;
    let old = RequestId::from_context(loan.context());
    assert_eq!(
        state.capture(session, classified(flow), path, 6, 20),
        Err(Error::Capacity)
    );
    state.reject_injection(loan)?;
    let fresh = state.capture(session, classified(flow), path, 7, 20)?;
    assert_ne!(old, fresh);
    assert_eq!(
        state.authorize_receive(old, classified(flow), received(path)?, 7),
        Gate::Deny
    );
    assert_eq!(state.native_debt(), 0);
    Ok(())
}

#[test]
fn pending_native_removal_keeps_the_original_generation() -> Result<(), TestError> {
    let mut state = State::<1, 0>::new();
    assert_eq!(state.begin_flow_removal(0), FlowRemoval::Empty);
    let original = associate(&mut state, FLOW)?;
    assert_eq!(
        state.begin_flow_removal(0),
        FlowRemoval::Request(original, FLOW)
    );
    assert_eq!(state.begin_flow_removal(0), FlowRemoval::Pending(original));
    assert_eq!(associate(&mut state, FLOW), Err(Error::Capacity));
    assert_eq!(state.flow_count(), 1);
    assert_eq!(state.flow(original), None);

    state.refuse_flow_removal(original);
    assert_eq!(state.flow(original), Some(FLOW));
    assert_eq!(
        state.begin_flow_removal(0),
        FlowRemoval::Request(original, FLOW)
    );
    assert_eq!(state.retire_flow(original), Some(FLOW));
    assert_eq!(state.retire_flow(original), None);
    assert_eq!(state.flow_count(), 0);

    let replacement = associate(&mut state, FLOW)?;
    assert_eq!(
        state.begin_flow_removal(0),
        FlowRemoval::Request(replacement, FLOW)
    );
    state.refuse_flow_removal(original);
    assert_eq!(
        state.begin_flow_removal(0),
        FlowRemoval::Pending(replacement)
    );
    Ok(())
}

#[test]
fn pending_native_removal_denies_traffic_and_preserves_completion() -> Result<(), TestError> {
    let mut state = State::<1, 3>::new();
    let session = state.open_session()?;
    let flow = associate(&mut state, FLOW)?;
    let path = path(4, 4)?;
    let queued = state.capture(session, classified(flow), path, 5, 20)?;
    let issued = state.capture(session, classified(flow), path, 5, 20)?;
    let submitted = state.capture(session, classified(flow), path, 5, 20)?;
    state.dequeue_capture(session, issued, 6)?;
    state.dequeue_capture(session, submitted, 6)?;
    let loan = state.begin_injection(session, submitted, 6)?;

    assert_eq!(
        state.begin_flow_removal(0),
        FlowRemoval::Request(flow, FLOW)
    );
    assert_eq!(state.owned_flow(flow), Some(FLOW));
    assert_eq!(
        state.capture(session, classified(flow), path, 7, 20),
        Err(Error::Stale)
    );
    assert!(!state.has_capture(session, queued, 7));
    assert_eq!(state.dequeue_capture(session, queued, 7), Err(Error::Stale));
    assert!(matches!(
        state.begin_injection(session, issued, 7),
        Err(Error::Stale)
    ));
    assert_eq!(
        state.authorize_receive(submitted, classified(flow), received(path)?, 7),
        Gate::Deny
    );
    assert_eq!(state.retire_flow(flow), Some(FLOW));
    assert_eq!(state.native_debt(), 1);
    assert_eq!(
        state.complete_injection(RequestId::from_context(loan.context())),
        Ok(InjectionObservation::NoAuthorization)
    );
    assert_eq!(state.native_debt(), 0);
    Ok(())
}

#[test]
fn local_device_records_retain_the_original_token_and_disposition() -> Result<(), TestError> {
    use gnunet_wfp_dns::device::{
        self, COMPLETION_BYTES, Completion, Error as RecordError, Reply, TOKEN_BYTES,
    };
    let mut state = State::<1, 1>::new();
    let session = state.open_session()?;
    let flow = associate(&mut state, FLOW)?;
    let request = state.capture(session, classified(flow), path(4, 4)?, 0, 20)?;
    let mut record = [0; TOKEN_BYTES + 12];
    let mut dns = [0; 12];
    assert_eq!(device::encode(request, &dns, &mut record), Ok(record.len()));
    assert_eq!(device::query(&record), Ok((request, dns.as_slice())));
    assert_eq!(device::reply(&record), Err(RecordError::Direction));
    dns[2] = 0x80;
    assert_eq!(device::encode(request, &dns, &mut record), Ok(record.len()));
    assert_eq!(device::reply(&record), Ok(Reply::Datagram(request, &dns)));
    assert_eq!(
        device::reply(&record[..TOKEN_BYTES]),
        Ok(Reply::Discard(request))
    );

    let mut encoded = device::encode_completion(request, -1, true);
    assert_eq!(
        device::decode_completion(&encoded),
        Ok(Completion {
            request,
            status: -1,
            authorized: true,
        })
    );
    encoded[COMPLETION_BYTES - 1] = 2;
    assert_eq!(
        device::decode_completion(&encoded),
        Err(RecordError::Verdict)
    );
    assert_eq!(
        device::decode_completion(&encoded[..TOKEN_BYTES]),
        Err(RecordError::Length)
    );
    Ok(())
}

#[test]
fn maintenance_records_require_exact_operators_and_retirement_status() {
    use gnunet_wfp_dns::device::maintenance::{Phase, Progress, Request};

    let request = Request::Finalize.encode();
    assert_eq!(Request::decode(&request), Some(Request::Finalize));
    assert_eq!(Request::decode(&request[..3]), None);
    assert_eq!(Request::decode(&2_u32.to_le_bytes()), None);

    for (phase, status, valid) in [
        (Phase::Completion, 0, true),
        (Phase::NativeRetired, 0, true),
        (Phase::NativeRetired, -1, false),
        (Phase::Failed, 0, false),
        (Phase::Failed, -1, true),
        (Phase::Failed, 0x103, true),
    ] {
        let progress = Progress { phase, status };
        let mut response = progress.encode();
        assert_eq!(Progress::decode(&response), valid.then_some(progress));
        assert_eq!(Progress::decode(&response[..7]), None);
        response[0] = u8::MAX;
        assert_eq!(Progress::decode(&response), None);
    }
}

#[test]
fn cancellation_vetoes_only_the_original_pending_injection() -> Result<(), TestError> {
    let mut state = State::<1, 2>::new();
    let session = state.open_session()?;
    let flow = associate(&mut state, FLOW)?;
    let path = path(4, 4)?;
    let request = state.capture(session, classified(flow), path, 0, 20)?;
    state.dequeue_capture(session, request, 1)?;
    let injection = state.begin_injection(session, request, 1)?;
    state.revoke_reply(session, request)?;
    assert_eq!(state.native_debt(), 1);
    assert_eq!(
        state.authorize_receive(request, classified(flow), received(path)?, 2),
        Gate::Deny
    );
    assert_eq!(
        state.complete_injection(request),
        Ok(InjectionObservation::NoAuthorization)
    );
    assert_eq!(state.native_debt(), 0);

    let later = state.capture(session, classified(flow), path, 2, 20)?;
    state.dequeue_capture(session, later, 3)?;
    let later_injection = state.begin_injection(session, later, 3)?;
    assert_ne!(injection.context(), later_injection.context());
    state.revoke_reply(session, later)?;
    state.reject_injection(later_injection)?;
    assert_eq!(state.native_debt(), 0);
    Ok(())
}
