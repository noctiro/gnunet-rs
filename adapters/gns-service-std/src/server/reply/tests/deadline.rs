//! Prepared replies retain their hard bounds after original native query retirement.
use super::*;
use crate::{
    Bounds, Close, Manager, Operation, Provider, Shared, Value,
    server::{Call, Event, Peer, Server},
};
use gnunet_service_runtime::{
    clock::{RuntimeClock, SystemClock},
    credentials::UnixAccess,
    service::ServiceOptions,
};
use gnunet_types::AbsoluteTime;
use std::{
    sync::Arc,
    task::{Context, Poll, Waker},
};

enum NoOperation {}

impl Operation for NoOperation {
    type Error = Fault;
    type Report = ();
    fn poll_native_guard(&mut self, _: &mut Context<'_>) -> Option<Fault> {
        match *self {}
    }
    fn poll(&mut self, _: &mut Context<'_>, _: AbsoluteTime) -> Poll<Result<Value, Fault>> {
        match *self {}
    }
    fn begin_close(&mut self) -> Option<Fault> {
        match *self {}
    }
    fn poll_close(&mut self, _: &mut Context<'_>) -> Poll<Close<(), Fault>> {
        match *self {}
    }
}

struct Idle;

impl Provider for Idle {
    type Operation = NoOperation;
    fn start(&mut self, _: &gnunet_gns::EffectKind, _: Bounds) -> Result<NoOperation, Fault> {
        Err(Fault::Unavailable)
    }
    fn poll_native_guard(&mut self, _: &mut Context<'_>) -> Option<Fault> {
        None
    }
    fn poll_shared(&mut self, _: &mut Context<'_>) -> Poll<Shared<Fault>> {
        Poll::Pending
    }
    fn begin_close(&mut self) -> Option<Fault> {
        None
    }
    fn is_closed(&self) -> bool {
        true
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The original prepared result must expire without relying on an older queued frame or a still-owned Manager query"
)]
fn prepared_result_keeps_native_expiry_after_manager_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let mut business = gnunet_gns::Instance::new();
    let mut manager = Manager::new(&mut business, Idle, gnunet_gns::Limits::default())?;
    let mut frontend = crate::server::Instance::new();
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let mut server = Server::new(
        &mut frontend,
        &mut manager,
        clock,
        ServiceOptions::default(),
        UnixAccess::default(),
        crate::server::Limits::default(),
    )?;
    let (connection, mut remote) = connection()?;
    let peer = PeerId {
        owner: server.owner,
        serial: 1,
    };
    server.peers.push(Peer {
        id: peer,
        io: Framed::new(
            connection,
            Limits {
                frame_bytes: 65535,
                ordinary: Budget {
                    frames: 1,
                    bytes: 128,
                },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: 65535,
            },
        )?,
        input_hard: None,
        partial: None,
        cancel_errors: Vec::new(),
        output: Vec::new(),
    });
    server.calls.push(Call {
        peer,
        serial: 1,
        wire: gns::WireId([1; 4]),
        bounds: Bounds::new(
            AbsoluteTime::from_micros(u64::MAX - 1),
            Instant::now() - Duration::from_secs(1),
        )?,
        state: CallState::Ready(ReplyPlan::new(Ok(vec![address()]))),
    });
    let event = server.native_expiry(&mut Context::from_waker(Waker::noop()))?;
    assert!(matches!(
        event,
        Some(Event::Closed {
            cause: Some(crate::server::Error::Protocol(Fault::Timeout)),
            ..
        })
    ));
    assert_eq!(server.peers(), 0);
    assert_eq!(server.calls(), 0);
    assert_eq!(
        remote.read(&mut [0; 1])?,
        0,
        "expired reply closes its original MQ without writing a new frame"
    );
    Ok(())
}
