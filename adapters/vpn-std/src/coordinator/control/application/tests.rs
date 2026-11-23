use super::*;
use gnunet_service_runtime::{
    clock::SystemClock, credentials::UnixAccess, service::ServiceOptions,
};
use provider::{CloseOutcome, PacketCompletion, PacketOutcome, PacketRequest, Provider, RequestId};
use std::{cell::RefCell, rc::Rc, task::Waker};

#[derive(Default)]
struct SettingsPort {
    request: Option<RouteRequest>,
    completion: Option<RouteCompletion>,
    reads: usize,
    closes: usize,
}

struct TestProvider(Rc<RefCell<SettingsPort>>);

impl Provider for TestProvider {
    fn begin_route(&mut self, request: RouteRequest) -> io::Result<()> {
        let mut port = self.0.borrow_mut();
        if port.request.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        port.request = Some(request);
        Ok(())
    }

    fn poll_route(&mut self, _: &mut Context<'_>) -> Poll<RouteCompletion> {
        self.0
            .borrow_mut()
            .completion
            .take()
            .map_or(Poll::Pending, Poll::Ready)
    }

    fn cancel_route(&mut self, _: RequestId) -> RouteOutcome {
        RouteOutcome::Failed {
            error: io::ErrorKind::Interrupted.into(),
            routes_absent: false,
        }
    }

    fn begin_write(&mut self, _: PacketRequest, _: &[u8]) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn poll_write(&mut self, _: &mut Context<'_>) -> Poll<PacketCompletion> {
        Poll::Pending
    }

    fn cancel_write(&mut self, _: RequestId) -> PacketOutcome {
        PacketOutcome::Unknown {
            error: io::ErrorKind::Unsupported.into(),
            exposed: false,
        }
    }

    fn poll_read(&mut self, _: &mut Context<'_>, _: usize) -> Poll<io::Result<Option<Vec<u8>>>> {
        self.0.borrow_mut().reads += 1;
        Poll::Pending
    }

    fn close(&mut self) -> CloseOutcome {
        self.0.borrow_mut().closes += 1;
        CloseOutcome {
            routes_absent: false,
            error: None,
        }
    }
}

#[test]
fn original_install_and_revoke_receipts_control_provider_readiness()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let _runtime = runtime.enter();
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let mut domain = core::Instance::new();
    let mut clients = [core::ClientSlot::new()];
    let mut requests = [core::RequestSlot::new()];
    let mut leases = [core::LeaseSlot::new()];
    let mut flows = [core::FlowSlot::new()];
    let mut slab = [0; 1284];
    let mut packets = [core::PacketSlot::new(&mut slab)];
    let prefix = core::Prefix {
        network: core::Address::V4([192, 0, 2, 0]),
        bits: 24,
        interface: core::Address::V4([192, 0, 2, 1]),
    };
    let engine = core::Engine::new(
        &mut domain,
        core::Storage {
            clients: &mut clients,
            requests: &mut requests,
            leases: &mut leases,
            flows: &mut flows,
            packets: &mut packets,
        },
        core::Limits {
            ipv4: Some(prefix),
            packet_bytes: 1280,
            ..Default::default()
        },
    )?;
    let server = server::Server::new(
        engine,
        clock.clone(),
        Default::default(),
        ServiceOptions::default(),
        UnixAccess::default(),
    )?;
    let mut cadet_domain = cadet::Instance::new();
    let mut ports = [];
    let mut channels = [cadet::ChannelSlot::new()];
    let cadet = cadet::Client::new(
        &mut cadet_domain,
        cadet::EndpointSource::unix_with_clock("unused-cadet".into(), clock),
        &mut ports,
        &mut channels,
        Default::default(),
    )?;
    let profile = PeerProfiles::new(core::AfProfile::native(), [])?;
    let provider = Rc::new(RefCell::new(SettingsPort::default()));
    let device = Device::from_provider(TestProvider(provider.clone()))?;
    let mut coordinator = Coordinator::new(
        Parts {
            server,
            cadet,
            device,
        },
        &[],
        &profile,
        Limits {
            flows: 1,
            ..Default::default()
        },
    )
    .map_err(|failure| failure.error)?;
    let mut cx = Context::from_waker(Waker::noop());
    let mut observe = |_| {};
    if !coordinator.poll_control(&mut cx, &mut observe)? || coordinator.tun_ready()? {
        return Err("queueing provider settings granted readiness".into());
    }
    let _read = coordinator.poll_tun_input(&mut cx, &mut observe)?;
    if provider.borrow().reads != 0 {
        return Err("queued settings enabled application packet reads".into());
    }
    let install = provider
        .borrow_mut()
        .request
        .take()
        .ok_or("original install request missing")?;
    if install.action != core::RouteAction::Install
        || install.ipv4 != Some(prefix)
        || install.mtu != 1280
    {
        return Err("provider received a different install plan".into());
    }
    let mut unrelated =
        Device::from_provider(TestProvider(Rc::new(RefCell::new(SettingsPort::default()))))?;
    let wrong = unrelated
        .io
        .provider_mut()
        .ok_or("wrong device mode")?
        .issue()?;
    provider.borrow_mut().completion = Some(RouteCompletion {
        id: wrong,
        outcome: RouteOutcome::Installed,
    });
    let _consumed = coordinator.poll_control(&mut cx, &mut observe)?;
    if coordinator.tun_ready()? || coordinator.debt().routes != core::RouteState::Absent {
        return Err("another provider's receipt installed this scope".into());
    }
    provider.borrow_mut().completion = Some(RouteCompletion {
        id: install.id,
        outcome: RouteOutcome::Installed,
    });
    let _consumed = coordinator.poll_control(&mut cx, &mut observe)?;
    if !coordinator.tun_ready()? || coordinator.debt().routes != core::RouteState::Present {
        return Err("original provider receipt did not activate this scope".into());
    }
    let _read = coordinator.poll_tun_input(&mut cx, &mut observe)?;
    if provider.borrow().reads != 1 {
        return Err("installed settings did not enable application packet reads".into());
    }

    coordinator.request_shutdown();
    let _consumed = coordinator.poll_control(&mut cx, &mut observe)?;
    let remove = provider
        .borrow_mut()
        .request
        .take()
        .ok_or("original revoke request missing")?;
    if remove.action != core::RouteAction::Remove
        || remove.id.epoch() != install.id.epoch()
        || remove.id.revision() <= install.id.revision()
        || coordinator.tun_ready()?
    {
        return Err(
            "shutdown did not revoke admission using a new revision of the original scope".into(),
        );
    }
    provider.borrow_mut().completion = Some(RouteCompletion {
        id: install.id,
        outcome: RouteOutcome::Removed,
    });
    let _consumed = coordinator.poll_control(&mut cx, &mut observe)?;
    if coordinator.control_released() || coordinator.debt().routes != core::RouteState::Present {
        return Err("stale install ID settled the current revoke".into());
    }
    provider.borrow_mut().completion = Some(RouteCompletion {
        id: remove.id,
        outcome: RouteOutcome::Removed,
    });
    let _consumed = coordinator.poll_control(&mut cx, &mut observe)?;
    if !coordinator.control_released() || coordinator.debt().routes != core::RouteState::Absent {
        return Err("original revoke receipt did not settle route effects".into());
    }
    coordinator.close(&mut observe);
    coordinator.close(&mut observe);
    let closed = coordinator
        .close_report()
        .ok_or("provider close report missing")?;
    if provider.borrow().closes != 1
        || closed.tun.is_some()
        || closed.provider.is_none()
        || closed.routes != core::RouteState::Absent
        || closed.failure.is_some()
        || coordinator.device_info().is_some()
        || coordinator.device_epoch().is_some()
    {
        return Err("provider close did not retain its original route and source outcomes".into());
    }
    Ok(())
}
