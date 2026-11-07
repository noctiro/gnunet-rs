//! Source-order pure control tests. Applied/reaped inputs are injected host reports,
//! never statements that these tests execute OS sockets or processes.
#![expect(
    clippy::expect_used,
    reason = "Source lifecycle controls require each ordinary setup and leased operation to succeed"
)]
#![expect(
    clippy::panic,
    reason = "A wrong native effect is a concrete regression in these finite controls"
)]
use gnunet_arm_core::wire::{ArmAbi, ServiceStatus, WireId};
use gnunet_arm_service_core::*;
static SPECS: [ServiceSpec<'static>; 2] = [
    ServiceSpec {
        name: b"first",
        binary: b"a",
        command: b"recipe-a",
        immediate: false,
        pipe_control: false,
    },
    ServiceSpec {
        name: b"second",
        binary: b"b",
        command: b"recipe-b",
        immediate: false,
        pipe_control: false,
    },
];
fn native_spawn<'s>(
    o: &mut Owner<'s, '_, '_, '_>,
) -> (NativeTicket<'s>, ChildId<'s>, ServiceId<'s>) {
    match o
        .take_native()
        .expect("native counter")
        .expect("native spawn")
    {
        NativeEffect::Spawn {
            ticket,
            child,
            service,
            ..
        } => (ticket, child, service),
        _ => panic!("expected Spawn"),
    }
}
#[test]
fn every_parent_listener_close_is_acknowledged_before_any_child_term() {
    let mut scope = OwnerScope::new();
    let mut services = [ServiceSlot::new(), ServiceSlot::new()];
    let mut clients = [ClientSlot::new()];
    let mut listeners = [ListenerSlot::new(), ListenerSlot::new()];
    let mut a = [0; 128];
    let mut b = [0; 128];
    let mut c = [0; 128];
    let mut d = [0; 128];
    let mut frames = [
        FrameSlot::new(&mut a),
        FrameSlot::new(&mut b),
        FrameSlot::new(&mut c),
        FrameSlot::new(&mut d),
    ];
    let mut o = Owner::new(
        &mut scope,
        &SPECS,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )
    .expect("owner");
    let first = o.service(0).expect("first");
    let second = o.service(1).expect("second");
    o.register_listener(first).expect("actual host-bound first");
    o.register_listener(second)
        .expect("actual host-bound second");
    assert_eq!(o.connect(), Err(Error::Busy));
    assert_eq!(o.startup_next(), Ok(false));
    for _ in 0..2 {
        let effect = o.take_listener().expect("listener epoch").expect("arm");
        assert_eq!(effect.action, ListenerAction::Arm);
        o.listener_applied(effect.ticket).expect("actual arm");
    }
    let client = o.connect().expect("serving client");
    o.start(client, WireId(1), b"first").expect("request first");
    assert!(o.take_native().expect("native").is_none());
    let disarm = o.take_listener().expect("epoch").expect("disarm");
    assert_eq!(disarm.action, ListenerAction::Disarm);
    o.listener_applied(disarm.ticket).expect("actual disarm");
    let (ticket, child1, id) = native_spawn(&mut o);
    assert_eq!(id, first);
    assert_eq!(
        o.spawned(ticket, SpawnOutcome::Admitted, 1)
            .expect("actual admitted")
            .resource_closures,
        0
    );
    o.start(client, WireId(2), b"second").expect("second");
    let disarm = o.take_listener().expect("epoch").expect("disarm second");
    o.listener_applied(disarm.ticket)
        .expect("actual second disarm");
    let (ticket, child2, id) = native_spawn(&mut o);
    assert_eq!(id, second);
    assert_eq!(
        o.spawned(ticket, SpawnOutcome::Admitted, 2)
            .expect("actual second admitted")
            .resource_closures,
        0
    );
    o.begin_shutdown(3);
    assert_eq!(o.phase(), Phase::Draining);
    assert!(!o.listeners_closed());
    assert!(o.take_native().expect("cleanup").is_none());
    let close1 = o
        .take_listener()
        .expect("close has no ordinary epoch")
        .expect("first close");
    assert_eq!(close1.action, ListenerAction::Close);
    assert!(o.take_native().expect("intent is not completion").is_none());
    o.listener_applied(close1.ticket)
        .expect("actual first close");
    assert!(o.take_native().expect("second parent still open").is_none());
    let close2 = o.take_listener().expect("close").expect("second close");
    assert_eq!(close2.action, ListenerAction::Close);
    assert!(
        o.take_native()
            .expect("leased second close still incomplete")
            .is_none()
    );
    o.listener_applied(close2.ticket)
        .expect("actual second close");
    assert!(o.listeners_closed());
    for expected in [child1, child2] {
        match o.take_native().expect("final TERM").expect("TERM") {
            NativeEffect::Term { ticket, child } => {
                assert_eq!(child, expected);
                o.term_attempted(ticket).expect("actual TERM attempt");
            }
            _ => panic!("TERM"),
        }
    }
    assert!(!o.children_drained());
    assert_eq!(
        o.reaped(child1, Exit::Exited(0), 4)
            .expect("actual first wait")
            .resource_closures,
        0
    );
    assert_eq!(
        o.reaped(child2, Exit::Exited(0), 5)
            .expect("actual second wait")
            .resource_closures,
        0
    );
    assert!(o.children_drained());
}
#[test]
fn leased_arm_is_not_lost_when_spawn_changes_desired_readiness() {
    let mut scope = OwnerScope::new();
    let mut services = [ServiceSlot::new(), ServiceSlot::new()];
    let mut clients = [ClientSlot::new()];
    let mut listeners = [ListenerSlot::new()];
    let mut data = [0; 128];
    let mut frames = [FrameSlot::new(&mut data)];
    let mut o = Owner::new(
        &mut scope,
        &SPECS,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )
    .expect("owner");
    let id = o
        .register_listener(o.service(0).expect("service"))
        .expect("actual bound listener");
    let arm = o.take_listener().expect("epoch").expect("arm");
    assert_eq!(o.startup_next(), Ok(false));
    let c = o.connect().expect("client");
    o.start(c, WireId(1), b"first")
        .expect("start while old arm lease retained");
    assert!(o.listener_current(arm.ticket));
    assert!(o.take_native().expect("not yet safely disarmed").is_none());
    o.listener_applied(arm.ticket)
        .expect("actual arm completion retained across cancellation");
    assert_eq!(o.listener_applied(arm.ticket), Err(Error::Stale));
    let disarm = o
        .take_listener()
        .expect("epoch")
        .expect("source disarm before fork");
    assert_eq!(disarm.listener, id);
    assert_eq!(disarm.action, ListenerAction::Disarm);
    assert!(
        o.take_native()
            .expect("intent not actual cancellation")
            .is_none()
    );
    o.listener_applied(disarm.ticket).expect("actual disarm");
    let (ticket, _, _) = native_spawn(&mut o);
    assert_eq!(
        o.spawned(ticket, SpawnOutcome::Failed, 1)
            .expect("real preparation/fork failure")
            .resource_closures,
        0
    );
    assert!(
        o.take_listener()
            .expect("failure does not silently rearm")
            .is_none()
    );
}
#[test]
fn old_readiness_registration_cannot_launch_after_a_new_arm() {
    let mut scope = OwnerScope::new();
    let mut services = [ServiceSlot::new(), ServiceSlot::new()];
    let mut clients = [];
    let mut listeners = [ListenerSlot::new()];
    let mut frames = [];
    let mut o = Owner::new(
        &mut scope,
        &SPECS,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )
    .expect("owner");
    let listener = o
        .register_listener(o.service(0).expect("service"))
        .expect("actual bound");
    assert_eq!(o.startup_next(), Ok(false));
    let arm = o.take_listener().expect("epoch").expect("arm");
    o.listener_applied(arm.ticket).expect("actual arm");
    let old = o
        .readiness(listener)
        .expect("listener")
        .expect("registration");
    o.demand(old).expect("actual one-shot readiness, no accept");
    let (ticket, child, _) = native_spawn(&mut o);
    assert_eq!(
        o.spawned(ticket, SpawnOutcome::Admitted, 1)
            .expect("actual child")
            .resource_closures,
        0
    );
    assert_eq!(
        o.reaped(child, Exit::Exited(0), 2)
            .expect("actual wait")
            .resource_closures,
        0
    );
    let arm = o
        .take_listener()
        .expect("epoch")
        .expect("rearm after clean exit");
    o.listener_applied(arm.ticket).expect("actual rearm");
    let fresh = o
        .readiness(listener)
        .expect("listener")
        .expect("fresh readiness");
    assert_ne!(old, fresh);
    assert_eq!(o.demand(old), Err(Error::Stale));
    assert!(
        o.take_native()
            .expect("stale event grants no spawn")
            .is_none()
    );
    o.demand(fresh).expect("new registration may launch");
    assert!(matches!(
        o.take_native().expect("epoch"),
        Some(NativeEffect::Spawn { .. })
    ));
}
#[test]
fn startup_gate_waits_all_real_attempts_and_does_not_replay_service_snapshot() {
    let specs = [
        ServiceSpec {
            immediate: true,
            ..SPECS[0]
        },
        ServiceSpec {
            immediate: true,
            ..SPECS[1]
        },
    ];
    let mut scope = OwnerScope::new();
    let mut services = [ServiceSlot::new(), ServiceSlot::new()];
    let mut clients = [ClientSlot::new()];
    let mut listeners = [];
    let mut data = [0; 128];
    let mut frames = [FrameSlot::new(&mut data)];
    let mut o = Owner::new(
        &mut scope,
        &specs,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )
    .expect("owner");
    assert_eq!(o.phase(), Phase::Configuring);
    assert_eq!(o.connect(), Err(Error::Busy));
    assert_eq!(o.startup_next(), Ok(true));
    assert_eq!(o.connect(), Err(Error::Busy));
    let (ticket, _, first) = native_spawn(&mut o);
    assert_eq!(first, o.service(0).expect("first"));
    assert_eq!(
        o.spawned(ticket, SpawnOutcome::Failed, 1)
            .expect("actual failed attempt")
            .resource_closures,
        0
    );
    assert_eq!(o.connect(), Err(Error::Busy));
    assert_eq!(o.startup_next(), Ok(true));
    let (ticket, _, second) = native_spawn(&mut o);
    assert_eq!(second, o.service(1).expect("second"));
    assert_eq!(
        o.spawned(ticket, SpawnOutcome::Admitted, 2)
            .expect("actual admitted attempt")
            .resource_closures,
        0
    );
    assert_eq!(o.connect(), Err(Error::Busy));
    assert_eq!(o.startup_next(), Ok(false));
    assert_eq!(o.phase(), Phase::Serving);
    let c = o.connect().expect("only now accepts");
    o.monitor(c).expect("monitor");
    let frame = o.frame().expect("only initial arm dummy");
    let done = frame.ticket;
    assert_eq!(
        frame.bytes,
        &[0, 12, 0, 11, 0, 0, 0, 0, b'a', b'r', b'm', 0]
    );
    o.release_frame(done).expect("actual host handoff");
    assert!(o.frame().is_none());
    assert_eq!(
        o.info(second).expect("source state still retained").status,
        ServiceStatus::STARTED
    );
}
#[test]
fn real_timer_registration_firing_clock_regression_and_cancel_are_distinct() {
    let mut scope = OwnerScope::new();
    let mut services = [ServiceSlot::new(), ServiceSlot::new()];
    let mut clients = [ClientSlot::new()];
    let mut listeners = [];
    let mut a = [0; 128];
    let mut b = [0; 128];
    let mut frames = [FrameSlot::new(&mut a), FrameSlot::new(&mut b)];
    let mut o = Owner::new(
        &mut scope,
        &SPECS,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )
    .expect("owner");
    assert_eq!(o.startup_next(), Ok(false));
    let c = o.connect().expect("client");
    o.start(c, WireId(1), b"first").expect("start");
    let (ticket, child, _) = native_spawn(&mut o);
    assert_eq!(
        o.spawned(ticket, SpawnOutcome::Admitted, 1)
            .expect("actual child")
            .resource_closures,
        0
    );
    assert_eq!(
        o.reaped(child, Exit::Exited(9), 10)
            .expect("actual child wait")
            .resource_closures,
        0
    );
    let immediate = o
        .take_timer()
        .expect("epoch")
        .expect("immediate IDLE request");
    assert_eq!(immediate.action, TimerAction::Arm { at_utc: 10 });
    assert_eq!(
        o.timer_fired(immediate.id),
        Err(Error::Stale),
        "intent alone is not a registered task"
    );
    assert!(o.timer_current(immediate.ticket));
    assert!(o.take_timer().expect("retained lease").is_none());
    o.timer_applied(immediate.ticket)
        .expect("actual registered");
    o.timer_fired(immediate.id).expect("actual fired");
    assert_eq!(o.restart(10), Ok(Some(1010)));
    let future = o.take_timer().expect("epoch").expect("future task");
    assert_ne!(future.id, immediate.id);
    o.timer_applied(future.ticket).expect("actual future task");
    assert_eq!(o.timer_fired(immediate.id), Err(Error::Stale));
    o.timer_fired(future.id)
        .expect("actual task fired although UTC regressed");
    assert_eq!(
        o.restart(5),
        Ok(Some(1010)),
        "source rechecks UTC and schedules remaining time"
    );
    let rearm = o
        .take_timer()
        .expect("epoch")
        .expect("new task after clock regression");
    assert_ne!(future.id, rearm.id);
    o.timer_applied(rearm.ticket).expect("actual rearm");
    o.begin_shutdown(6);
    assert!(!o.timer_drained());
    assert!(o.take_runtime_shutdown().is_none());
    let cancel = o
        .take_timer()
        .expect("cancel uses existing task")
        .expect("cancel");
    assert_eq!(cancel.id, rearm.id);
    assert_eq!(cancel.action, TimerAction::Cancel);
    assert!(o.take_timer().expect("lease").is_none());
    assert_eq!(
        o.timer_aborted(cancel.ticket),
        Err(Error::Stale),
        "cannot abandon actual task cancellation"
    );
    assert!(o.timer_current(cancel.ticket));
    o.timer_applied(cancel.ticket)
        .expect("actual task cancellation");
    assert!(o.timer_drained());
    assert_eq!(o.timer_fired(rearm.id), Err(Error::Stale));
    let final_close = o
        .take_runtime_shutdown()
        .expect("all real resources drained");
    assert!(o.take_runtime_shutdown().is_none());
    assert_ne!(o.phase(), Phase::Closed);
    o.runtime_shutdown_applied(final_close)
        .expect("actual generic runtime close");
    assert_eq!(o.phase(), Phase::Closed);
    assert_eq!(o.runtime_shutdown_applied(final_close), Err(Error::Stale));
}
#[test]
fn foreign_scopes_with_identical_slot_generations_cannot_authorize_other_owner() {
    let mut scope1 = OwnerScope::new();
    let mut scope2 = OwnerScope::new();
    let mut s1 = [ServiceSlot::new(), ServiceSlot::new()];
    let mut s2 = [ServiceSlot::new(), ServiceSlot::new()];
    let mut c1 = [ClientSlot::new()];
    let mut c2 = [ClientSlot::new()];
    let mut l1 = [];
    let mut l2 = [];
    let mut a = [0; 128];
    let mut b = [0; 128];
    let mut f1 = [FrameSlot::new(&mut a)];
    let mut f2 = [FrameSlot::new(&mut b)];
    let mut one = Owner::new(
        &mut scope1,
        &SPECS,
        &mut s1,
        &mut c1,
        &mut l1,
        &mut f1,
        ArmAbi::U64Align8,
    )
    .expect("one");
    let mut two = Owner::new(
        &mut scope2,
        &SPECS,
        &mut s2,
        &mut c2,
        &mut l2,
        &mut f2,
        ArmAbi::U64Align8,
    )
    .expect("two");
    assert_eq!(one.startup_next(), Ok(false));
    assert_eq!(two.startup_next(), Ok(false));
    let first = one.connect().expect("same slot/gen one");
    let second = two.connect().expect("same slot/gen two");
    assert_ne!(first, second);
    let mut set = std::collections::HashSet::new();
    assert!(set.insert(first));
    assert!(set.insert(second));
    assert_eq!(
        set.len(),
        2,
        "Hash/Eq use scope pointer, not identical marker bytes"
    );
    assert_eq!(two.test(first), Err(Error::Stale));
    assert_eq!(two.info(one.service(0).expect("one id")), Err(Error::Stale));
    one.start(first, WireId(1), b"first").expect("one start");
    two.start(second, WireId(1), b"first").expect("two start");
    let (ticket1, child1, _) = native_spawn(&mut one);
    let (ticket2, child2, _) = native_spawn(&mut two);
    assert_ne!(ticket1, ticket2);
    assert_ne!(child1, child2);
    assert_eq!(
        two.spawned(ticket1, SpawnOutcome::Admitted, 1),
        Err(Error::Stale)
    );
    assert_eq!(
        two.spawned(ticket2, SpawnOutcome::Admitted, 1)
            .expect("actual own child")
            .resource_closures,
        0
    );
    assert_eq!(
        one.spawned(ticket1, SpawnOutcome::Admitted, 1)
            .expect("actual other child")
            .resource_closures,
        0
    );
    assert_eq!(two.reaped(child1, Exit::Exited(0), 2), Err(Error::Stale));
    assert_eq!(
        two.info(two.service(0).expect("two service"))
            .expect("still owned running")
            .status,
        ServiceStatus::STARTED
    );
    let old = one.frame().expect("one leased frame").ticket;
    let current = two.frame().expect("two matching slot/gen frame").ticket;
    assert_ne!(old, current);
    assert_eq!(two.release_frame(old), Err(Error::Stale));
    two.release_frame(current).expect("own frame valid");
}
#[test]
fn foreign_readiness_listener_timer_and_runtime_shutdown_leases_are_rejected() {
    let mut scope1 = OwnerScope::new();
    let mut scope2 = OwnerScope::new();
    let mut s1 = [ServiceSlot::new(), ServiceSlot::new()];
    let mut s2 = [ServiceSlot::new(), ServiceSlot::new()];
    let mut c1 = [];
    let mut c2 = [];
    let mut l1 = [ListenerSlot::new()];
    let mut l2 = [ListenerSlot::new()];
    let mut f1 = [];
    let mut f2 = [];
    let mut one = Owner::new(
        &mut scope1,
        &SPECS,
        &mut s1,
        &mut c1,
        &mut l1,
        &mut f1,
        ArmAbi::U64Align8,
    )
    .expect("one");
    let mut two = Owner::new(
        &mut scope2,
        &SPECS,
        &mut s2,
        &mut c2,
        &mut l2,
        &mut f2,
        ArmAbi::U64Align8,
    )
    .expect("two");
    let lid1 = one
        .register_listener(one.service(0).expect("one service"))
        .expect("one actual bound");
    let lid2 = two
        .register_listener(two.service(0).expect("two service"))
        .expect("two actual bound");
    assert_eq!(one.startup_next(), Ok(false));
    assert_eq!(two.startup_next(), Ok(false));
    let arm1 = one.take_listener().expect("epoch").expect("arm one");
    let arm2 = two.take_listener().expect("epoch").expect("arm two");
    assert_eq!(two.listener_applied(arm1.ticket), Err(Error::Stale));
    one.listener_applied(arm1.ticket).expect("actual one arm");
    two.listener_applied(arm2.ticket).expect("actual two arm");
    let ready1 = one
        .readiness(lid1)
        .expect("listener")
        .expect("one registration");
    let ready2 = two
        .readiness(lid2)
        .expect("listener")
        .expect("two registration");
    assert_eq!(two.readiness(lid1), Err(Error::Stale));
    assert_eq!(two.demand(ready1), Err(Error::Stale));
    one.demand(ready1).expect("one actual callback");
    two.demand(ready2).expect("two actual callback");
    let (st1, child1, _) = native_spawn(&mut one);
    let (st2, child2, _) = native_spawn(&mut two);
    assert_eq!(
        one.spawned(st1, SpawnOutcome::Admitted, 1)
            .expect("actual one child")
            .resource_closures,
        0
    );
    assert_eq!(
        two.spawned(st2, SpawnOutcome::Admitted, 1)
            .expect("actual two child")
            .resource_closures,
        0
    );
    assert_eq!(
        one.reaped(child1, Exit::Exited(7), 5)
            .expect("actual one wait")
            .resource_closures,
        0
    );
    assert_eq!(
        two.reaped(child2, Exit::Exited(7), 5)
            .expect("actual two wait")
            .resource_closures,
        0
    );
    let timer1 = one.take_timer().expect("epoch").expect("one IDLE task");
    let timer2 = two.take_timer().expect("epoch").expect("two IDLE task");
    assert_eq!(two.timer_applied(timer1.ticket), Err(Error::Stale));
    one.timer_applied(timer1.ticket).expect("actual task one");
    two.timer_applied(timer2.ticket).expect("actual task two");
    assert_eq!(two.timer_fired(timer1.id), Err(Error::Stale));
    assert!(!two.timer_drained());
    one.begin_shutdown(6);
    two.begin_shutdown(6);
    let cancel1 = one.take_timer().expect("cancel").expect("one cancel");
    let cancel2 = two.take_timer().expect("cancel").expect("two cancel");
    assert_eq!(two.timer_applied(cancel1.ticket), Err(Error::Stale));
    one.timer_applied(cancel1.ticket)
        .expect("actually canceled one");
    two.timer_applied(cancel2.ticket)
        .expect("actually canceled two");
    let close1 = one.take_listener().expect("close").expect("one close");
    let close2 = two.take_listener().expect("close").expect("two close");
    assert_eq!(two.listener_applied(close1.ticket), Err(Error::Stale));
    one.listener_applied(close1.ticket)
        .expect("actually closed one");
    two.listener_applied(close2.ticket)
        .expect("actually closed two");
    let final1 = one.take_runtime_shutdown().expect("one runtime");
    let final2 = two.take_runtime_shutdown().expect("two runtime");
    assert_eq!(two.runtime_shutdown_applied(final1), Err(Error::Stale));
    assert_eq!(two.phase(), Phase::Draining);
    one.runtime_shutdown_applied(final1)
        .expect("actual one runtime shutdown");
    two.runtime_shutdown_applied(final2)
        .expect("actual two runtime shutdown");
}

#[test]
fn empty_configured_service_name_is_not_rejected_by_an_extra_private_policy() {
    let specs = [ServiceSpec {
        name: b"",
        binary: b"b",
        command: b"prepared",
        immediate: false,
        pipe_control: false,
    }];
    let mut scope = OwnerScope::new();
    let mut services = [ServiceSlot::new()];
    let mut clients = [ClientSlot::new()];
    let mut listeners = [];
    let mut bytes = [0; 64];
    let mut frames = [FrameSlot::new(&mut bytes)];
    let mut o = Owner::new(
        &mut scope,
        &specs,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )
    .expect("official configuration API permits empty section name");
    assert_eq!(o.startup_next(), Ok(false));
    let c = o.connect().expect("client");
    let mut request = [0; 17];
    gnunet_arm_core::wire::Request::Start {
        reserved: 0,
        id: WireId(41),
        service: b"",
    }
    .encode(&mut request)
    .expect("final NUL only is a valid START suffix");
    o.receive(c, &request, 0, &mut [])
        .expect("empty name found");
    let (ticket, _, service) = native_spawn(&mut o);
    assert_eq!(o.info(service).expect("source section name").name, b"");
    assert_eq!(
        o.spawned(ticket, SpawnOutcome::Failed, 1)
            .expect("actual host failure input")
            .resource_closures,
        0
    );
    let frame = o.frame().expect("official start-failed reply");
    let reply =
        gnunet_arm_core::wire::ResultReply::decode(ArmAbi::U64Align8, frame.bytes).expect("reply");
    assert_eq!(reply.id, WireId(41));
    assert_eq!(
        reply.result,
        gnunet_arm_core::wire::ResultCode::START_FAILED
    );
}
