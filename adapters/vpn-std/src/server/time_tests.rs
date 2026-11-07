//! Pure port fixtures use the real host activity epoch, without device access.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Focused clock-domain fixtures assert pure lifecycle and actual host admission boundaries"
)]
use super::*;
use gnunet_service_runtime::clock::ClockSample;
use gnunet_vpn::{
    Address, ClientSlot, FlowSlot, Instance, LeaseSlot, Limits as CoreLimits, PacketSlot, Phase,
    Prefix, RequestSlot, Storage, packet,
};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

struct Adjustable {
    absolute: AtomicU64,
    failure: AtomicBool,
    observations: AtomicUsize,
}
impl Adjustable {
    fn new() -> Self {
        Self {
            absolute: AtomicU64::new(1_000),
            failure: AtomicBool::new(false),
            observations: AtomicUsize::new(0),
        }
    }
}
struct Subscription;
impl ClockSubscription for Subscription {
    fn poll_changed(&mut self, _: &mut Context<'_>, _: u64) -> Poll<Result<ClockSample, Fault>> {
        Poll::Pending
    }
}
impl RuntimeClock for Adjustable {
    fn sample(&self) -> Result<ClockSample, Fault> {
        self.observations.fetch_add(1, Ordering::SeqCst);
        if self.failure.load(Ordering::SeqCst) {
            return Err(Fault::Unavailable);
        }
        Ok(ClockSample {
            now: AbsoluteTime::from_micros(self.absolute.load(Ordering::SeqCst)),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        self.observations.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Subscription))
    }
}
fn maintenance(server: &mut Server<'_, '_, '_>) -> Result<(), Error> {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    if let Poll::Ready(Err(error)) = server.poll(&mut cx, &[], None, &mut |_| {}) {
        return Err(error);
    }
    Ok(())
}

#[test]
fn logical_adjustments_preserve_original_native_idle_and_absolute_lease() -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()?;
    runtime.block_on(async {
        let clock = Arc::new(Adjustable::new());
        let mut instance = Instance::new();
        let mut clients = [ClientSlot::new(); 1];
        let mut requests = [RequestSlot::new(); 1];
        let mut leases = [LeaseSlot::new(); 1];
        let mut flows = [FlowSlot::new(); 1];
        let mut bytes = [0; 1284];
        let mut packets = [PacketSlot::new(&mut bytes)];
        let core = Engine::new(
            &mut instance,
            Storage {
                clients: &mut clients,
                requests: &mut requests,
                leases: &mut leases,
                flows: &mut flows,
                packets: &mut packets,
            },
            CoreLimits {
                ipv4: Some(Prefix {
                    network: Address::V4([192, 0, 2, 0]),
                    bits: 29,
                    interface: Address::V4([192, 0, 2, 1]),
                }),
                packet_bytes: 1280,
                idle_micros: 100,
                ..CoreLimits::default()
            },
        )?;
        let mut server = Server::new(
            core,
            clock.clone(),
            Limits::default(),
            ServiceOptions::default(),
            UnixAccess::default(),
        )?;
        // These are explicit pure provider transitions, not native TUN or route
        // receipts. The fixture opens no device, CADET channel or socket.
        let tun = server.engine_mut().attach_tun()?;
        let work = server.engine_mut().routing_request(tun)?.routing;
        server.engine_mut().routing_queued(work)?;
        server.engine_mut().route_applied(work)?;
        let client = server.engine_mut().attach_client()?;
        let (absolute, activity) = server.sample()?;
        let request = server.engine_mut().redirect(
            client,
            WireRequest::Service {
                reserved: 0,
                expires: 1_000_000,
                protocol: u32::from(packet::UDP),
                result_af: 0,
                peer: [1; 32],
                service: [2; 64],
                request_id: [3; 8],
            },
            absolute,
        )?;
        let lease = server
            .engine()
            .request_info(request)?
            .lease
            .ok_or(Fault::NotReady)?;
        let address = server.engine().lease_info(lease)?.address;
        assert_eq!(
            server.engine().lease_info(lease)?.expires,
            AbsoluteTime::from_micros(1_000_000)
        );
        let mut udp = [0; 8];
        udp[..2].copy_from_slice(&50_000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&443u16.to_be_bytes());
        let mut raw = [0; 64];
        let size = packet::build(
            Address::V4([10, 0, 0, 2]),
            address,
            packet::UDP,
            &udp,
            &mut raw,
        )?;
        let flow = server
            .engine_mut()
            .forward_tun(tun, &raw[..size], absolute, activity)?
            .flow;
        assert_eq!(activity, MonoInstant(0));
        clock.absolute.store(9_000_000, Ordering::SeqCst);
        tokio::time::advance(Duration::from_micros(10)).await;
        maintenance(&mut server)?;
        assert_eq!(
            server.engine().lease_info(lease).err(),
            Some(Fault::StaleGeneration)
        );
        assert_eq!(server.engine().flow_info(flow)?.phase, Phase::NeedOpen);
        clock.absolute.store(1, Ordering::SeqCst);
        tokio::time::advance(Duration::from_micros(89)).await;
        let (_, activity) = server.sample()?;
        assert_eq!(activity, MonoInstant(99));
        maintenance(&mut server)?;
        assert_eq!(server.engine().flow_info(flow)?.phase, Phase::NeedOpen);
        assert_eq!(server.engine().flow_info(flow)?.last_used, MonoInstant(0));
        assert_eq!(
            server
                .engine_mut()
                .expire(AbsoluteTime::from_micros(1), MonoInstant(98)),
            Err(Fault::TimeUncertain)
        );
        assert_eq!(server.engine().flow_info(flow)?.phase, Phase::NeedOpen);
        tokio::time::advance(Duration::from_micros(1)).await;
        maintenance(&mut server)?;
        assert_eq!(server.engine().flow_info(flow)?.phase, Phase::Closing);
        assert_eq!(
            server.engine().flow_info(flow)?.failure,
            Some(Fault::Deadline)
        );
        // A real source refusal remains the exact original failure, even though
        // native idle already elapsed. The host fences its IPC scope, never
        // inventing a successful sample or retiring independent TUN ports.
        clock.failure.store(true, Ordering::SeqCst);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(
            server.poll(&mut cx, &[], None, &mut |_| {}),
            Poll::Ready(Err(Error::Protocol(Fault::Unavailable)))
        ));
        assert!(server.ipc_quiescent());
        assert!(server.engine().has_tun_source());
        Ok(())
    })
}

#[test]
fn drained_or_zero_sampled_owner_cannot_restart_its_native_epoch() -> Result<(), Error> {
    for sampled in [false, true] {
        let clock = Arc::new(Adjustable::new());
        let mut instance = Instance::new();
        let mut clients = [ClientSlot::new(); 1];
        let mut requests = [RequestSlot::new(); 1];
        let mut leases = [LeaseSlot::new(); 1];
        let mut flows = [FlowSlot::new(); 1];
        let mut bytes = [0; 1284];
        let mut packets = [PacketSlot::new(&mut bytes)];
        let mut core = Engine::new(
            &mut instance,
            Storage {
                clients: &mut clients,
                requests: &mut requests,
                leases: &mut leases,
                flows: &mut flows,
                packets: &mut packets,
            },
            CoreLimits {
                packet_bytes: 1280,
                ..CoreLimits::default()
            },
        )?;
        if sampled {
            core.expire(AbsoluteTime::from_micros(1_000), MonoInstant(0))?;
        } else {
            let client = core.attach_client()?;
            core.client_lost(client, Fault::Closed)?;
        }
        assert!(!core.is_pristine());
        assert!(matches!(
            Server::new(
                core,
                clock.clone(),
                Limits::default(),
                ServiceOptions::default(),
                UnixAccess::default()
            ),
            Err(Error::Protocol(Fault::InvalidInput))
        ));
        // This synchronous fixture has no Tokio runtime. Refusal must precede
        // source observation/subscription and any native timer construction.
        assert_eq!(clock.observations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
