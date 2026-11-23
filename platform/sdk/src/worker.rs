use crate::{GnNodeSnapshot, config::Options};
use gnunet_node_host::{NetworkChangeNotifier, NetworkChanges, Ready, Upstreams, network_changes};
use gnunet_service_runtime::clock::SystemClock;
use std::{
    error::Error,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, MutexGuard},
    thread::JoinHandle,
};
use tokio::sync::oneshot;

const STARTING: u32 = 0;
const READY: u32 = 1;
const STOPPING: u32 = 2;
const STOPPED: u32 = 3;
const FAILED: u32 = 4;
const ERROR_BYTES: usize = 4096;

struct State {
    snapshot: GnNodeSnapshot,
    error: String,
    stop: Option<oneshot::Sender<()>>,
    network_change: NetworkChangeNotifier,
}

impl State {
    fn ready(&mut self, original: &Ready) {
        if self.snapshot.phase != STARTING {
            return;
        }
        self.snapshot = GnNodeSnapshot {
            phase: READY,
            has_ready: 1,
            peer: original.peer,
            tcp_port: original
                .tcp_addresses
                .first()
                .map_or(0, std::net::SocketAddr::port),
            udp4_port: original
                .udp_addresses
                .iter()
                .find(|addr| addr.is_ipv4())
                .map_or(0, std::net::SocketAddr::port),
            udp6_port: original
                .udp_addresses
                .iter()
                .find(|addr| addr.is_ipv6())
                .map_or(0, std::net::SocketAddr::port),
            quic_port: original.quic_address.map_or(0, |addr| addr.port()),
            http3_port: original.http3_address.map_or(0, |addr| addr.port()),
            unix_mtu: original.unix_mtu.map_or(0, std::num::NonZeroU16::get),
        };
    }

    fn finish(&mut self, result: Result<(), String>) {
        self.stop = None;
        match result {
            Ok(()) => self.snapshot.phase = STOPPED,
            Err(mut error) => {
                let limit = error.floor_char_boundary(ERROR_BYTES);
                error.truncate(limit);
                self.error = error;
                self.snapshot.phase = FAILED;
            }
        }
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) struct Node {
    state: Arc<Mutex<State>>,
    thread: JoinHandle<()>,
}

impl Node {
    pub(crate) fn start(options: Options) -> io::Result<Self> {
        let (stop, stopped) = oneshot::channel();
        let (network_change, changes) = network_changes();
        let state = Arc::new(Mutex::new(State {
            snapshot: GnNodeSnapshot::default(),
            error: String::new(),
            stop: Some(stop),
            network_change,
        }));
        let worker = state.clone();
        let thread = std::thread::Builder::new()
            .name("gnunet-node".into())
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    run(options, &worker, changes, stopped).map_err(|error| error.to_string())
                }))
                .unwrap_or_else(|_| Err("GNUnet node worker panicked".into()));
                lock(&worker).finish(outcome);
            })?;
        Ok(Self { state, thread })
    }

    pub(crate) fn stop(&self) {
        let mut state = lock(&self.state);
        if let Some(stop) = state.stop.take() {
            state.snapshot.phase = STOPPING;
            let _delivered = stop.send(());
        }
    }

    pub(crate) fn notify_network_change(&self) {
        let state = lock(&self.state);
        if matches!(state.snapshot.phase, STARTING | READY) {
            state.network_change.notify();
        }
    }

    pub(crate) fn set_dns_upstreams(&self, upstreams: Upstreams) {
        let state = lock(&self.state);
        if matches!(state.snapshot.phase, STARTING | READY) {
            state.network_change.set_dns_upstreams(upstreams);
        }
    }

    pub(crate) fn snapshot(&self) -> GnNodeSnapshot {
        lock(&self.state).snapshot
    }

    pub(crate) fn with_error<T>(&self, inspect: impl FnOnce(&str) -> T) -> T {
        inspect(&lock(&self.state).error)
    }

    pub(crate) fn join(self) {
        self.stop();
        let _joined = self.thread.join();
    }
}

fn run(
    options: Options,
    state: &Mutex<State>,
    changes: NetworkChanges,
    stopped: oneshot::Receiver<()>,
) -> Result<(), Box<dyn Error>> {
    if lock(state).snapshot.phase == STOPPING {
        return Ok(());
    }
    let node = options.prepare()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    runtime.block_on(node.run(
        Arc::new(SystemClock),
        changes,
        async move { stopped.await.map_err(io::Error::other) },
        |original| {
            lock(state).ready(original);
            Ok(())
        },
    ))?;
    Ok(())
}
