//! Bounded handoff between the VPN coordinator and an application's native queue.

use super::provider::{
    CloseOutcome, PacketCompletion, PacketOutcome, PacketRequest, Provider, RequestId,
    RouteCompletion, RouteOutcome, RouteRequest,
};
use gnunet_vpn::RouteAction;
use std::{
    collections::VecDeque,
    io,
    num::NonZeroU16,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::Duration,
};
#[cfg(unix)]
/// Route mailbox with a native datagram descriptor instead of an app packet queue.
pub mod descriptor;

/// One exclusive command from the original VPN service.
pub enum Command {
    /// The original system settings must be applied or removed.
    Route(RouteRequest),
    /// The original raw IP bytes and their completion token.
    Write(Packet),
    /// The coordinator retired this source. Release its native resources.
    Closed,
}

/// One complete immutable raw IP packet given to the application.
pub struct Packet {
    request: PacketRequest,
    bytes: Vec<u8>,
}

impl Packet {
    /// The original output identity and deadline.
    pub fn request(&self) -> PacketRequest {
        self.request
    }

    /// The original output bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The application retains this endpoint while it owns the platform resource.
/// Dropping it fences submissions and reports unconfirmed settings as unknown.
pub struct Controller(Arc<Shared>);

/// The opposite endpoint, transferred to the VPN coordinator.
pub struct Mailbox(Arc<Shared>);

/// Create a bounded pair with independent command and ingress capacity.
/// No thread, system route, packet source or callback is started here.
pub fn channel(
    maximum_packet: NonZeroU16,
    queued_packets: NonZeroU16,
) -> io::Result<(Controller, Mailbox)> {
    let packet = usize::from(maximum_packet.get());
    let slots = usize::from(queued_packets.get());
    if packet < 20 || packet * slots > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "application VPN packet budget exceeds its bounds",
        ));
    }
    let mut incoming = VecDeque::new();
    incoming
        .try_reserve_exact(slots)
        .map_err(io::Error::other)?;
    let shared = Arc::new(Shared {
        packet,
        slots,
        state: Mutex::new(State {
            incoming,
            routes: Routes::Absent,
            installed: None,
            revocation: None,
            packets_fenced: false,
            route: None,
            write: None,
            close: None,
            stopped: false,
            waker: None,
        }),
        commands: Condvar::new(),
    });
    Ok((Controller(shared.clone()), Mailbox(shared)))
}

struct Shared {
    packet: usize,
    slots: usize,
    state: Mutex<State>,
    commands: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Routes {
    Absent,
    Installed,
    Unknown,
}

struct State {
    incoming: VecDeque<Vec<u8>>,
    routes: Routes,
    installed: Option<RequestId>,
    revocation: Option<RouteCompletion>,
    packets_fenced: bool,
    route: Option<Slot<RouteRequest, (), RouteReceipt>>,
    write: Option<Slot<PacketRequest, Vec<u8>, PacketOutcome>>,
    close: Option<CloseOutcome>,
    stopped: bool,
    waker: Option<Waker>,
}

struct RouteReceipt {
    outcome: RouteOutcome,
    #[cfg(unix)]
    descriptor: Option<std::os::fd::OwnedFd>,
}

impl RouteReceipt {
    fn plain(outcome: RouteOutcome) -> Self {
        Self {
            outcome,
            #[cfg(unix)]
            descriptor: None,
        }
    }
}

impl State {
    fn live(&self) -> io::Result<()> {
        if self.stopped || self.close.is_some() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }

    fn wait<T>(&mut self, cx: &Context<'_>) -> Poll<T> {
        if self
            .waker
            .as_ref()
            .is_none_or(|old| !old.will_wake(cx.waker()))
        {
            self.waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }

    fn forwarding(&self) -> io::Result<()> {
        self.live()?;
        if self.packets_fenced {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self.routes != Routes::Installed || self.installed.is_none() || self.route.is_some() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        Ok(())
    }

    fn has_command(&self) -> bool {
        self.stopped
            || self.close.is_some()
            || self.route.as_ref().is_some_and(|slot| slot.stage.pending())
            || self.write.as_ref().is_some_and(|slot| slot.stage.pending())
    }
}

struct Slot<Q, P, R> {
    request: Q,
    stage: Stage<P, R>,
}

enum Stage<P, R> {
    Pending(P),
    Claimed,
    Cancelled,
    Completed(R),
}

impl<P, R> Stage<P, R> {
    fn pending(&self) -> bool {
        matches!(self, Self::Pending(_))
    }
}

impl<Q: Copy, P, R> Slot<Q, P, R> {
    fn new(request: Q, payload: P) -> Self {
        Self {
            request,
            stage: Stage::Pending(payload),
        }
    }

    fn claim(&mut self) -> Option<(Q, P)> {
        if self.stage.pending()
            && let Stage::Pending(payload) = std::mem::replace(&mut self.stage, Stage::Claimed)
        {
            return Some((self.request, payload));
        }
        None
    }

    fn take_result(slot: &mut Option<Self>) -> Option<(Q, R)> {
        if slot
            .as_ref()
            .is_some_and(|slot| matches!(slot.stage, Stage::Completed(_)))
            && let Some(Self {
                request,
                stage: Stage::Completed(result),
            }) = slot.take()
        {
            return Some((request, result));
        }
        None
    }
}

fn wake(waker: Option<Waker>) {
    if let Some(waker) = waker {
        waker.wake();
    }
}

fn copy(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(io::Error::other)?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn packet_bytes(bytes: &[u8], maximum: usize) -> io::Result<()> {
    if bytes.len() > maximum {
        return Err(io::ErrorKind::InvalidData.into());
    }
    gnunet_tun_host::version(bytes).map_err(io::Error::other)?;
    Ok(())
}

impl Controller {
    /// Claim one exact command on an application worker. This may block for
    /// the supplied duration. Use zero for a nonblocking observation.
    /// One consumer serializes claims and native settings changes.
    pub fn next(&self, timeout: Duration) -> Option<Command> {
        let (mut state, _) = self
            .0
            .commands
            .wait_timeout_while(self.0.lock(), timeout, |state| !state.has_command())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.live().is_err() {
            return Some(Command::Closed);
        }
        let now = tokio::time::Instant::now();
        let absent = state.routes == Routes::Absent;
        let mut expired = false;
        if let Some(slot) = &mut state.route
            && slot.stage.pending()
            && slot.request.deadline <= now
        {
            slot.stage = Stage::Completed(RouteReceipt::plain(RouteOutcome::Failed {
                error: io::ErrorKind::TimedOut.into(),
                routes_absent: absent,
            }));
            expired = true;
        }
        if let Some(slot) = &mut state.write
            && slot.stage.pending()
            && slot.request.deadline <= now
        {
            slot.stage = Stage::Completed(PacketOutcome::Unsent {
                error: io::ErrorKind::TimedOut.into(),
            });
            expired = true;
        }
        let command = if let Some((request, ())) = state.route.as_mut().and_then(Slot::claim) {
            state.routes = Routes::Unknown;
            Some(Command::Route(request))
        } else {
            state
                .write
                .as_mut()
                .and_then(Slot::claim)
                .map(|(request, bytes)| Command::Write(Packet { request, bytes }))
        };
        let waker = if expired { state.waker.take() } else { None };
        drop(state);
        wake(waker);
        command
    }

    /// Submit one whole raw IP packet from the original system source.
    /// WouldBlock leaves the packet with the application. No source admits
    /// packets before the complete route plan is confirmed installed.
    pub fn receive(&self, packet: &[u8]) -> io::Result<()> {
        packet_bytes(packet, self.0.packet)?;
        let mut state = self.0.lock();
        state.forwarding()?;
        if state.incoming.len() == self.0.slots {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        state.incoming.push_back(copy(packet)?);
        let waker = state.waker.take();
        drop(state);
        wake(waker);
        Ok(())
    }

    /// Record the result from the original platform settings operation.
    /// A retired claim may still report its result to settle route knowledge.
    /// Failure to match a claim grants no authority to change another route.
    pub fn complete_route(&self, result: RouteCompletion) -> io::Result<()> {
        self.finish_route(result.id, |_, _| Ok(RouteReceipt::plain(result.outcome)))
    }

    fn finish_route(
        &self,
        id: RequestId,
        receipt: impl FnOnce(RouteRequest, bool) -> io::Result<RouteReceipt>,
    ) -> io::Result<()> {
        let mut state = self.0.lock();
        state.live()?;
        let slot = state
            .route
            .as_mut()
            .filter(|slot| slot.request.id == id)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if !matches!(slot.stage, Stage::Claimed | Stage::Cancelled) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let cancelled = matches!(slot.stage, Stage::Cancelled);
        let receipt = receipt(slot.request, !cancelled)?;
        let routes = match (slot.request.action, &receipt.outcome) {
            (RouteAction::Install, RouteOutcome::Installed) => Routes::Installed,
            (RouteAction::Remove, RouteOutcome::Removed) => Routes::Absent,
            (_, RouteOutcome::Failed { routes_absent, .. }) => {
                if *routes_absent {
                    Routes::Absent
                } else {
                    Routes::Unknown
                }
            }
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        };
        if cancelled {
            state.route = None;
        } else {
            slot.stage = Stage::Completed(receipt);
        }
        state.routes = routes;
        let waker = state.waker.take();
        drop(state);
        wake(waker);
        Ok(())
    }

    /// Record the outcome of the exact immutable packet claimed by the app.
    pub fn complete_write(&self, result: PacketCompletion) -> io::Result<()> {
        let mut state = self.0.lock();
        state.live()?;
        let slot = state
            .write
            .as_mut()
            .filter(|slot| slot.request.id == result.id)
            .ok_or(io::ErrorKind::InvalidInput)?;
        match slot.stage {
            Stage::Claimed => slot.stage = Stage::Completed(result.outcome),
            Stage::Cancelled => state.write = None,
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        }
        let waker = state.waker.take();
        drop(state);
        wake(waker);
        Ok(())
    }

    /// Permanently stop packet admission on this run. An unclaimed write is
    /// unsent. Claimed writes and routing requests keep their original tokens
    /// and can still complete while the application stops the node.
    pub fn fence_packets(&self) {
        let mut state = self.0.lock();
        if std::mem::replace(&mut state.packets_fenced, true) {
            return;
        }
        state.incoming.clear();
        if let Some(slot) = &mut state.write
            && slot.stage.pending()
        {
            slot.stage = Stage::Completed(PacketOutcome::Unsent {
                error: io::ErrorKind::Interrupted.into(),
            });
        }
        let waker = state.waker.take();
        drop(state);
        wake(waker);
    }

    /// Fence ingress and record actual native teardown once. Prove absence only
    /// after the platform has retired its settings and possible late callbacks.
    pub fn revoke(&self, outcome: CloseOutcome) {
        self.seal(outcome);
    }

    fn seal(&self, outcome: CloseOutcome) {
        let mut state = self.0.lock();
        if state.close.is_some() {
            return;
        }
        let absent = outcome.routes_absent || state.routes == Routes::Absent;
        if let Some(id) = state.installed.take() {
            let outcome = if absent {
                RouteOutcome::Removed
            } else {
                RouteOutcome::Failed {
                    error: io::ErrorKind::BrokenPipe.into(),
                    routes_absent: false,
                }
            };
            state.revocation = Some(RouteCompletion { id, outcome });
        }
        state.routes = if absent {
            Routes::Absent
        } else {
            Routes::Unknown
        };
        state.close = Some(CloseOutcome {
            routes_absent: absent,
            ..outcome
        });
        state.incoming.clear();
        if let Some(slot) = &mut state.route
            && matches!(
                slot.stage,
                Stage::Pending(())
                    | Stage::Claimed
                    | Stage::Completed(RouteReceipt {
                        outcome: RouteOutcome::Installed,
                        ..
                    })
            )
        {
            slot.stage = Stage::Completed(RouteReceipt::plain(RouteOutcome::Failed {
                error: io::ErrorKind::BrokenPipe.into(),
                routes_absent: absent,
            }));
        }
        if let Some(slot) = &mut state.write {
            let error = io::ErrorKind::BrokenPipe.into();
            match slot.stage {
                Stage::Pending(_) => slot.stage = Stage::Completed(PacketOutcome::Unsent { error }),
                Stage::Claimed => {
                    slot.stage = Stage::Completed(PacketOutcome::Unknown {
                        error,
                        exposed: true,
                    })
                }
                Stage::Cancelled | Stage::Completed(_) => {}
            }
        }
        let waker = state.waker.take();
        drop(state);
        self.0.commands.notify_all();
        wake(waker);
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.seal(CloseOutcome {
            routes_absent: false,
            error: None,
        });
    }
}

impl Mailbox {
    fn begin_route_with(
        &mut self,
        request: RouteRequest,
        prepare: impl FnOnce(),
    ) -> io::Result<()> {
        if !matches!(request.action, RouteAction::Install | RouteAction::Remove) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if request.action == RouteAction::Install && request.mtu as usize > self.0.packet {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut state = self.0.lock();
        state.live()?;
        if state.route.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        prepare();
        state.incoming.clear();
        state.route = Some(Slot::new(request, ()));
        drop(state);
        self.0.commands.notify_one();
        Ok(())
    }

    fn poll_route_with(
        &mut self,
        cx: &mut Context<'_>,
        apply: impl FnOnce(RouteReceipt) -> RouteOutcome,
    ) -> Poll<RouteCompletion> {
        let mut state = self.0.lock();
        if let Some((request, receipt)) = Slot::take_result(&mut state.route) {
            match receipt.outcome {
                RouteOutcome::Installed => state.installed = Some(request.id),
                RouteOutcome::Removed
                | RouteOutcome::Failed {
                    routes_absent: true,
                    ..
                } => {
                    state.installed = None;
                }
                RouteOutcome::Failed { .. } => {}
            }
            return Poll::Ready(RouteCompletion {
                id: request.id,
                outcome: apply(receipt),
            });
        }
        if let Some(revocation) = state.revocation.take() {
            return Poll::Ready(revocation);
        }
        state.wait(cx)
    }
}

impl Provider for Mailbox {
    fn begin_route(&mut self, request: RouteRequest) -> io::Result<()> {
        self.begin_route_with(request, || {})
    }

    fn poll_route(&mut self, cx: &mut Context<'_>) -> Poll<RouteCompletion> {
        self.poll_route_with(cx, |receipt| receipt.outcome)
    }

    fn cancel_route(&mut self, id: RequestId) -> RouteOutcome {
        let mut state = self.0.lock();
        if let Some(slot) = state.route.as_mut().filter(|slot| slot.request.id == id) {
            if matches!(slot.stage, Stage::Claimed | Stage::Cancelled) {
                slot.stage = Stage::Cancelled;
            } else {
                if let Some((_, outcome)) = Slot::take_result(&mut state.route) {
                    return outcome.outcome;
                }
                state.route = None;
            }
        }
        RouteOutcome::Failed {
            error: io::ErrorKind::Interrupted.into(),
            routes_absent: state.routes == Routes::Absent,
        }
    }

    fn begin_write(&mut self, request: PacketRequest, packet: &[u8]) -> io::Result<()> {
        packet_bytes(packet, self.0.packet)?;
        let mut state = self.0.lock();
        state.forwarding()?;
        if state.write.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        state.write = Some(Slot::new(request, copy(packet)?));
        drop(state);
        self.0.commands.notify_one();
        Ok(())
    }

    fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<PacketCompletion> {
        let mut state = self.0.lock();
        if let Some((request, outcome)) = Slot::take_result(&mut state.write) {
            return Poll::Ready(PacketCompletion {
                id: request.id,
                outcome,
            });
        }
        state.wait(cx)
    }

    fn cancel_write(&mut self, id: RequestId) -> PacketOutcome {
        let mut state = self.0.lock();
        let error = io::ErrorKind::Interrupted.into();
        if let Some(slot) = state.write.as_mut().filter(|slot| slot.request.id == id) {
            if matches!(slot.stage, Stage::Claimed | Stage::Cancelled) {
                slot.stage = Stage::Cancelled;
                return PacketOutcome::Unknown {
                    error,
                    exposed: true,
                };
            }
            if let Some((_, outcome)) = Slot::take_result(&mut state.write) {
                return outcome;
            }
            state.write = None;
            return PacketOutcome::Unsent { error };
        }
        PacketOutcome::Unknown {
            error,
            exposed: false,
        }
    }

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        max_bytes: usize,
    ) -> Poll<io::Result<Option<Vec<u8>>>> {
        let mut state = self.0.lock();
        if state.live().is_err() {
            return Poll::Ready(Ok(None));
        }
        if state.packets_fenced {
            return state.wait(cx);
        }
        if let Some(packet) = state.incoming.pop_front() {
            return if packet.len() <= max_bytes {
                Poll::Ready(Ok(Some(packet)))
            } else {
                Poll::Ready(Err(io::ErrorKind::InvalidData.into()))
            };
        }
        state.wait(cx)
    }

    fn close(&mut self) -> CloseOutcome {
        let mut state = self.0.lock();
        state.stopped = true;
        state.incoming.clear();
        state.waker = None;
        let outcome = state.close.take().unwrap_or(CloseOutcome {
            routes_absent: state.routes == Routes::Absent,
            error: None,
        });
        drop(state);
        self.0.commands.notify_all();
        outcome
    }
}

impl Drop for Mailbox {
    fn drop(&mut self) {
        let _outcome = self.close();
    }
}

#[cfg(test)]
mod tests;
