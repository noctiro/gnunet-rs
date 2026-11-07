//! Explicit same-device administration; no FD replacement or readiness shortcut.
use super::*;
impl<E: Entropy> Driver<'_, '_, '_, E> {
    /// Issue one explicit finite action against the original verified TUN.
    /// No syscall or core forwarding acknowledgement occurs here.
    pub fn plan_tun_action(
        &mut self,
        action: tun::Action,
        until: Instant,
    ) -> io::Result<tun::Effect> {
        self.tun
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "EXIT has no live TUN"))?
            .plan(action, until)
    }
    /// Perform the real supported interface ioctl on the original TUN.
    /// IPv6 address assignment alone does not authorize a DAD-ready claim.
    pub fn apply_tun_action(
        &mut self,
        effect: tun::Effect,
    ) -> Result<tun::NativeApplied, tun::ApplyFailure> {
        match self.tun.as_mut() {
            Some(tun) => tun.apply(effect),
            None => Err(tun::ApplyFailure {
                effect,
                error: io::Error::new(io::ErrorKind::NotConnected, "EXIT has no live TUN"),
                attempted: false,
            }),
        }
    }
    /// Start one original native route transaction. Only its correlated kernel
    /// ACK, never whole request writing, proves the requested route was applied.
    pub fn route_tun_action(
        &mut self,
        effect: tun::Effect,
    ) -> Result<tun::NativeRoute, tun::ApplyFailure> {
        match self.tun.as_mut() {
            Some(tun) => tun.route(effect),
            None => Err(tun::ApplyFailure {
                effect,
                error: io::Error::new(io::ErrorKind::NotConnected, "EXIT has no live TUN"),
                attempted: false,
            }),
        }
    }
    /// Open an actual bounded read-only IPv6 observer for this original device.
    /// Every renewal is a fresh native query owner, never an assumed Ready state.
    pub fn watch_tun_ipv6(
        &self,
        address: Ipv6Addr,
        prefix: u8,
        until: Instant,
        options: tun::Ipv6WatchOptions,
    ) -> io::Result<tun::Ipv6Watch> {
        self.tun
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "EXIT has no live TUN"))?
            .watch_ipv6(address, prefix, until, options)
    }
}
impl<'cfg, 'id, 'slots, E: Entropy> Driver<'cfg, 'id, 'slots, E> {
    /// Original packet owner metadata, not a helper-ready/ownership ACK.
    #[must_use]
    pub fn tun_info(&self) -> Option<&tun::Info> {
        self.tun.as_ref().map(PacketSource::info)
    }
    /// Whether this original packet transport is the actual helper pipes.
    #[must_use]
    pub fn uses_helper(&self) -> bool {
        self.tun.as_ref().is_some_and(PacketSource::is_helper)
    }
    /// Original helper configuration hard, never replaced after native progress.
    #[must_use]
    pub fn helper_initial_deadline(&self) -> Option<Instant> {
        match &self.tun {
            Some(PacketSource::Helper(io)) => Some(io.initial_deadline()),
            _ => None,
        }
    }
    /// Poll only actual helper initial observation, with no new source/entropy.
    pub fn poll_helper_prepare(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match &mut self.tun {
            Some(source) => source.poll_prepare(cx).map_err(Error::from),
            None => Poll::Ready(Err(Fault::Unavailable.into())),
        }
    }
    /// Actual current kernel snapshot, retaining the original helper/native epoch.
    pub fn snapshot_tun(&self, until: Instant) -> Result<tun::NativeSnapshot, tun::AdminFailure> {
        self.tun
            .as_ref()
            .ok_or(tun::AdminFailure::SourceRetired)?
            .snapshot(until)
    }
    /// Actual original read-only route reconciliation; this is never an add ACK.
    pub fn query_tun_route(
        &self,
        destination: std::net::IpAddr,
        prefix: u8,
        gateway: Option<std::net::IpAddr>,
        until: Instant,
    ) -> Result<tun::RouteQuery, tun::AdminFailure> {
        self.tun
            .as_ref()
            .ok_or(tun::AdminFailure::SourceRetired)?
            .query(destination, prefix, gateway, until)
    }
    /// Check/register original helper native hard limits before any logical clock
    /// wait. Real loss retains this same helper for explicit later OS wait.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let event = self.tun.as_mut().and_then(|io| io.poll_native_guard(cx));
        match event {
            Some(tun::ReadEvent::Lost(loss)) => {
                self.tun_loss(loss, observe)?;
                Ok(true)
            }
            Some(tun::ReadEvent::WriteExpired(write)) => self.tun_write(
                tun::WriteEvent::Unsent {
                    write,
                    reason: tun::Unsent::Deadline,
                },
                observe,
            ),
            None => Ok(false),
            _ => Err(Fault::Conflict.into()),
        }
    }
    /// Wait the exact retired helper after physical shutdown. No clock sample or
    /// replacement PID is involved and pipe close alone is never called reap.
    pub async fn reap_helper(&mut self) -> Option<tun::helper::Report> {
        match &mut self.retiring_tun {
            Some(owner) => owner.reap_helper().await,
            None => None,
        }
    }
}
