//! Source-derived pure transition tests. Native acknowledgments are injected inputs,
//! not claims that these tests execute a native child or daemon.
#![expect(
    clippy::expect_used,
    reason = "Finite tests fail explicitly on unexpected source transition or missing frame"
)]
#![expect(
    clippy::panic,
    reason = "Exhaustive native-effect discriminants fail this test when the wrong effect is issued"
)]
use gnunet_arm_core::wire::{self, ArmAbi, ResultCode, ServiceStatus, WireId};
use gnunet_arm_service_core::*;

static SPECS: [ServiceSpec<'static>; 2] = [
    ServiceSpec {
        name: b"finished",
        binary: b"configured-service-name",
        command: b"prepared-real-recipe",
        immediate: false,
        pipe_control: false,
    },
    ServiceSpec {
        name: b"empty-prefix",
        binary: b"owned-binary",
        command: b"",
        immediate: false,
        pipe_control: false,
    },
];
fn fixture(frame_count: usize, capacity: usize, test: impl FnOnce(&mut Owner<'_, '_, '_, '_>)) {
    let mut services = [ServiceSlot::new(), ServiceSlot::new()];
    let mut clients = core::array::from_fn::<_, 4, _>(|_| ClientSlot::new());
    let mut buffers = (0..frame_count)
        .map(|_| vec![0xA5; capacity])
        .collect::<Vec<_>>();
    let mut frames = buffers
        .iter_mut()
        .map(|b| FrameSlot::new(b))
        .collect::<Vec<_>>();
    let mut listeners = [];
    let mut scope = OwnerScope::new();
    let mut owner = Owner::new(
        &mut scope,
        &SPECS,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )
    .expect("valid registry");
    assert_eq!(owner.startup_next(), Ok(false));
    test(&mut owner);
}
fn frames<'scope>(owner: &mut Owner<'scope, '_, '_, '_>) -> Vec<(ClientId<'scope>, Vec<u8>)> {
    let mut output = Vec::new();
    while let Some(f) = owner.frame() {
        let ticket = f.ticket;
        output.push((f.client, f.bytes.to_vec()));
        owner.release_frame(ticket).expect("owned frame");
    }
    output
}
fn spawn<'scope>(
    owner: &mut Owner<'scope, '_, '_, '_>,
    client: ClientId,
    id: u64,
    name: &[u8],
    utc: u64,
) -> ChildId<'scope> {
    owner
        .start(client, WireId(id), name)
        .expect("start admission");
    assert!(
        owner.frame().is_none(),
        "effect alone is not a successful result"
    );
    let (ticket, child) = match owner.take_native().expect("epoch").expect("spawn effect") {
        NativeEffect::Spawn { ticket, child, .. } => (ticket, child),
        _ => panic!("expected spawn"),
    };
    assert!(
        owner.take_native().expect("epoch").is_none(),
        "lease exactly once"
    );
    assert_eq!(
        owner
            .spawned(ticket, SpawnOutcome::Admitted, utc)
            .expect("actual host outcome")
            .resource_closures,
        0
    );
    child
}
fn empty_rows() -> [wire::ServiceInfo<'static>; 2] {
    [wire::ServiceInfo {
        name: b"",
        binary: b"",
        status: ServiceStatus::STOPPED,
        last_exit_status: 0,
        restart_at: 0,
        last_started_at: 0,
    }; 2]
}
#[test]
fn wire_baseline_unknown_extension_reserved_list_and_snapshot() {
    fixture(8, 512, |o| {
        let c = o.connect().expect("client");
        let mut rows = empty_rows();
        o.receive(c, &[0, 4, 0xFD, 0xE8], 0, &mut rows)
            .expect("unknown extension ignored");
        o.receive(c, &[0, 4, 0, 15], 0, &mut rows).expect("TEST");
        let mut request = [0; 16];
        wire::Request::List {
            reserved: 123,
            id: WireId(0xFEDC_BA98_7654_3210),
        }
        .encode(&mut request)
        .expect("list");
        o.receive(c, &request, 0, &mut rows)
            .expect("nonzero reserved accepted");
        let out = frames(o);
        assert_eq!(out[0].1, [0, 4, 0, 15]);
        let list = wire::List::decode(ArmAbi::U64Align8, &out[1].1).expect("official list");
        assert_eq!(list.id().expect("id"), WireId(0xFEDC_BA98_7654_3210));
        assert_eq!(
            list.get(0).expect("row").expect("present").restart_at,
            u64::MAX
        );
        assert_eq!(
            list.get(1).expect("row").expect("present").name,
            b"empty-prefix"
        );
        assert_eq!(
            o.receive(c, &[0, 5, 0, 15, 0], 0, &mut rows),
            Err(Error::Malformed)
        );
    });
}
#[test]
fn native_failure_and_admission_are_distinct_from_unexecuted_effect() {
    fixture(4, 128, |o| {
        let c = o.connect().expect("client");
        o.start(c, WireId(7), b"EMPTY-PREFIX").expect("request");
        let ticket = match o.take_native().expect("epoch").expect("effect") {
            NativeEffect::Spawn { ticket, .. } => ticket,
            _ => panic!("spawn"),
        };
        assert!(o.frame().is_none());
        let report = o
            .spawned(ticket, SpawnOutcome::Failed, 99)
            .expect("actual failed host attempt");
        assert_eq!(report.resource_closures, 0);
        let out = frames(o);
        assert_eq!(
            wire::ResultReply::decode(ArmAbi::U64Align8, &out[0].1)
                .expect("result")
                .result,
            ResultCode::START_FAILED
        );
        let info = o.info(o.service(1).expect("service")).expect("info");
        assert_eq!(info.last_started, 0);
        assert!(info.force_start);
        assert_eq!(
            o.restart(999),
            Ok(None),
            "spawn failure does not create automatic retry"
        );
    });
}
#[test]
fn monitor_duplicates_deduplicate_and_queue1024_is_still_allowed() {
    fixture(8, 128, |o| {
        let c = o.connect().expect("client");
        o.monitor(c).expect("monitor");
        o.monitor(c).expect("repeat");
        assert_eq!(frames(o).len(), 2, "direct ack each time");
        o.set_mq_length(c, 1024).expect("queue");
        let child = spawn(o, c, 1, b"FiNiShEd", 123);
        let out = frames(o);
        assert_eq!(out.len(), 2);
        assert_eq!(
            wire::Status::decode(&out[0].1).expect("status").status,
            wire::MonitorStatus::STARTING
        );
        o.set_mq_length(c, 1025).expect("queue");
        assert_eq!(
            o.reaped(child, Exit::Exited(0), 124)
                .expect("actual reap")
                .resource_closures,
            0
        );
        assert!(frames(o).is_empty(), "skip >1024 optional broadcast");
        assert_eq!(
            o.info(o.service(0).expect("service")).expect("info").status,
            ServiceStatus::FINISHED
        );
    });
}
#[test]
fn old_native_attempt_cannot_ack_new_stop_of_same_child() {
    fixture(8, 128, |o| {
        let c = o.connect().expect("client");
        let child = spawn(o, c, 1, b"finished", 10);
        frames(o);
        o.stop(c, WireId(2), b"finished", 20).expect("stop");
        let first = match o.take_native().expect("epoch").expect("term") {
            NativeEffect::Term { ticket, .. } => ticket,
            _ => panic!("term"),
        };
        o.term_attempted(first)
            .expect("actual kill attempt, success/failure irrelevant");
        o.disconnect(c).expect("EOF");
        let c2 = o.connect().expect("reused slot");
        assert_ne!(c, c2);
        assert_eq!(
            o.info(o.service(0).expect("service")).expect("info").status,
            ServiceStatus::STARTED,
            "EOF clears stopping marker"
        );
        o.stop(c2, WireId(3), b"finished", 30).expect("retarget");
        let second = match o.take_native().expect("epoch").expect("term") {
            NativeEffect::Term { ticket, child: got } => {
                assert_eq!(got, child);
                ticket
            }
            _ => panic!("term"),
        };
        assert_ne!(first, second);
        assert_eq!(o.term_attempted(first), Err(Error::Stale));
        o.term_attempted(second).expect("actual second attempt");
        assert_eq!(
            o.reaped(child, Exit::Signaled(15), 31)
                .expect("real wait")
                .resource_closures,
            0
        );
        let out = frames(o);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, c2);
        let result = wire::ResultReply::decode(ArmAbi::U64Align8, &out[0].1).expect("result");
        assert_eq!(result.id, WireId(3));
        assert_eq!(result.result, ResultCode::STOPPED);
        assert_eq!(o.reaped(child, Exit::Signaled(15), 32), Err(Error::Stale));
    });
}
#[test]
fn clean_exit_never_schedules_forced_restart_by_itself() {
    fixture(4, 128, |o| {
        let c = o.connect().expect("client");
        let child = spawn(o, c, 1, b"finished", 100);
        frames(o);
        assert_eq!(
            o.reaped(child, Exit::Exited(0), 101)
                .expect("reap")
                .resource_closures,
            0
        );
        assert_eq!(o.restart(102), Ok(None));
        assert!(
            o.take_listener()
                .expect("no actual bound listeners")
                .is_none()
        );
        assert!(o.take_native().expect("epoch").is_none());
    });
}
#[test]
fn exact_source_backoff_origin_and_failed_scan_do_not_spin() {
    fixture(8, 128, |o| {
        let c = o.connect().expect("client");
        let child = spawn(o, c, 1, b"finished", 100_000);
        frames(o);
        assert_eq!(
            o.reaped(child, Exit::Exited(7), 100_001)
                .expect("reap")
                .resource_closures,
            0
        );
        let info = o.info(o.service(0).expect("service")).expect("info");
        assert_eq!(info.restart_at, 101_001);
        assert_eq!(info.backoff, 2000);
        let immediate = o
            .take_timer()
            .expect("immediate source epoch")
            .expect("IDLE callback request");
        assert_eq!(immediate.action, TimerAction::Arm { at_utc: 100_001 });
        o.timer_applied(immediate.ticket)
            .expect("actual immediate task registered");
        o.timer_fired(immediate.id)
            .expect("actual immediate task fired");
        assert_eq!(o.restart(100_001), Ok(Some(101_001)));
        assert!(o.take_native().expect("epoch").is_none());
        let timer = o
            .take_timer()
            .expect("timer epoch")
            .expect("real scheduler arm requested");
        o.timer_applied(timer.ticket)
            .expect("actual scheduler registration");
        o.timer_fired(timer.id).expect("actual source task fired");
        assert_eq!(o.restart(101_001), Ok(Some(101_001)));
        let ticket = match o.take_native().expect("epoch").expect("spawn") {
            NativeEffect::Spawn { ticket, .. } => ticket,
            _ => panic!("spawn"),
        };
        assert_eq!(
            o.spawned(ticket, SpawnOutcome::Failed, 101_001)
                .expect("native failure")
                .resource_closures,
            0
        );
        assert_eq!(
            o.restart(101_001),
            Ok(None),
            "scan resumes after failed entry, does not retry it forever"
        );
        let child = spawn(o, c, 2, b"finished", 999_999);
        frames(o);
        assert_eq!(
            o.reaped(child, Exit::Exited(9), 101_001 + 32 * 60_000_000)
                .expect("reap")
                .resource_closures,
            0
        );
        let info = o.info(o.service(0).expect("service")).expect("info");
        assert_eq!(info.restart_at, 101_001 + 32 * 60_000_000);
        assert_eq!(info.backoff, 2000);
    });
}
#[test]
fn capacity_rejection_has_no_partial_start_or_native_authority() {
    fixture(0, 128, |o| {
        let c = o.connect().expect("client");
        let id = o.service(0).expect("service");
        let before = o.info(id).expect("info");
        assert_eq!(o.start(c, WireId(1), b"finished"), Err(Error::Capacity));
        assert_eq!(o.info(id).expect("unchanged"), before);
        assert!(o.take_native().expect("epoch").is_none());
    });
}
#[test]
fn per_client_output_order_pinned_lease_and_stale_ticket() {
    fixture(8, 128, |o| {
        let c = o.connect().expect("client");
        let other = o.connect().expect("other");
        o.test(c).expect("test1");
        o.test(c).expect("test2");
        o.test(other).expect("other test");
        let first = o.frame().expect("first");
        let old = first.ticket;
        assert_eq!(first.client, c);
        let parallel = o.frame().expect("separate MQ may progress");
        assert_eq!(parallel.client, other);
        let separate = parallel.ticket;
        assert!(o.frame().is_none(), "same MQ later frame waits prior lease");
        o.release_frame(separate).expect("separate");
        o.disconnect(c).expect("EOF revokes old frames");
        let new = o.connect().expect("reuse");
        assert_ne!(new, c);
        o.test(new).expect("new frame");
        assert_eq!(o.release_frame(old), Err(Error::Stale));
        assert_eq!(frames(o).len(), 1);
    });
}
#[test]
fn shutdown_during_pending_spawn_really_requests_term_after_actual_admission() {
    fixture(4, 128, |o| {
        let c = o.connect().expect("client");
        o.start(c, WireId(1), b"finished").expect("start");
        let (ticket, child) = match o.take_native().expect("epoch").expect("spawn") {
            NativeEffect::Spawn { ticket, child, .. } => (ticket, child),
            _ => panic!("spawn"),
        };
        o.begin_shutdown(50);
        assert!(!o.children_drained());
        assert!(o.take_listener().expect("no actual listeners").is_none());
        assert_eq!(
            o.spawned(ticket, SpawnOutcome::Admitted, 51)
                .expect("actual fork admitted")
                .resource_closures,
            0
        );
        let ticket = match o
            .take_native()
            .expect("epoch")
            .expect("must TERM actual child")
        {
            NativeEffect::Term { ticket, child: got } => {
                assert_eq!(got, child);
                ticket
            }
            _ => panic!("term"),
        };
        o.begin_shutdown(52);
        assert!(
            o.take_native().expect("epoch").is_none(),
            "idempotent shutdown cannot duplicate leased signal"
        );
        o.term_attempted(ticket).expect("actual signal attempt");
        assert!(!o.children_drained());
        assert_eq!(
            o.reaped(child, Exit::Exited(0), 53)
                .expect("real wait")
                .resource_closures,
            0
        );
        assert!(o.children_drained());
    });
}
#[test]
fn source_self_stop_is_queued_then_generic_trigger_and_does_not_forge_eof() {
    fixture(4, 128, |o| {
        let c = o.connect().expect("client");
        o.monitor(c).expect("monitor");
        frames(o);
        o.stop_arm(c, WireId(91), b"ARM").expect("stop arm");
        assert_eq!(o.client_persisted(c), Ok(true));
        assert!(o.take_shutdown_request());
        assert!(!o.take_shutdown_request());
        let out = frames(o);
        assert_eq!(
            wire::Status::decode(&out[0].1).expect("status").service,
            b"ARM"
        );
        assert_eq!(
            wire::ResultReply::decode(ArmAbi::U64Align8, &out[1].1)
                .expect("result")
                .result,
            ResultCode::STOPPING
        );
        assert!(!o.children_drained(), "no fabricated generic shutdown");
        o.begin_shutdown(100);
        assert!(o.children_drained());
    });
}
#[test]
fn real_reap_is_not_lost_to_optional_resource_pressure() {
    fixture(2, 128, |o| {
        let c = o.connect().expect("client");
        o.monitor(c).expect("monitor");
        frames(o);
        let child = spawn(o, c, 1, b"finished", 10); // both slots contain admitted STARTING/status
        o.begin_shutdown(20);
        let report = o
            .reaped(child, Exit::Exited(0), 21)
            .expect("actual wait cannot fabricate live child");
        assert_eq!(report.resource_closures, 1);
        assert_eq!(o.resource_closures().collect::<Vec<_>>(), vec![c]);
        assert!(o.children_drained());
        o.disconnect(c).expect("actual host close acknowledgment");
        assert!(o.resource_closures().next().is_none());
        assert!(frames(o).is_empty());
    });
}

#[test]
fn list_envelope_is_actual_snapshot_while_service_state_changes() {
    fixture(8, 512, |o| {
        let c = o.connect().expect("client");
        let mut scratch = empty_rows();
        o.list(c, WireId(70), &mut scratch)
            .expect("snapshot queued");
        o.start(c, WireId(71), b"finished").expect("start");
        let ticket = match o.take_native().expect("epoch").expect("spawn") {
            NativeEffect::Spawn { ticket, .. } => ticket,
            _ => panic!("spawn"),
        };
        assert!(o.native_current(ticket));
        assert_eq!(
            o.spawned(ticket, SpawnOutcome::Admitted, 99)
                .expect("actual admission")
                .resource_closures,
            0
        );
        assert!(!o.native_current(ticket));
        let out = frames(o);
        let prior = wire::List::decode(ArmAbi::U64Align8, &out[0].1).expect("prior LIST bytes");
        assert_eq!(
            prior.get(0).expect("row").expect("present").status,
            ServiceStatus::STOPPED
        );
        assert_eq!(
            o.info(o.service(0).expect("service"))
                .expect("actual current state")
                .status,
            ServiceStatus::STARTED
        );
    });
}
#[test]
fn self_stop_required_reservation_cannot_overwrite_another_clients_reused_slot() {
    fixture(2, 128, |o| {
        let other = o.connect().expect("other client");
        o.monitor(other).expect("first subscriber");
        frames(o);
        let caller = o.connect().expect("self-stop caller");
        o.monitor(caller).expect("last subscriber visited first");
        frames(o);
        o.test(other).expect("one occupied slot");
        o.stop_arm(caller, WireId(999), b"arm")
            .expect("request admitted, caller resource closure explicit");
        assert_eq!(o.resource_closures().collect::<Vec<_>>(), vec![caller]);
        let output = frames(o);
        assert_eq!(output.len(), 2);
        assert!(output.iter().all(|(target, _)| *target == other));
        assert_eq!(output[0].1, [0, 4, 0, 15]);
        let status = wire::Status::decode(&output[1].1)
            .expect("must remain the other recipient's STATUS, never caller's RESULT");
        assert_eq!(status.status, wire::MonitorStatus::STOPPING);
        assert_eq!(status.service, b"arm");
        assert!(o.take_shutdown_request());
    });
}
