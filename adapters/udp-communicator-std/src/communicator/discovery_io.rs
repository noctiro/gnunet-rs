//! Optional LAN discovery ownership, per-interface retries and original sends.
use super::*;
use crate::discovery::{Membership, Operation, Pending, Row};

/// Prepared complete interface replacement, exclusively bound to the original
/// discovery state and sockets. Dropping it leaves rows, retry targets, pending
/// announcements and memberships unchanged. Preparation performs no native I/O.
#[must_use = "Commit after all dependent snapshot projections are prepared, or drop to retain the original snapshot"]
pub struct InterfaceUpdate<'communicator> {
    state: &'communicator mut discovery::State,
    sockets: &'communicator mut [DatagramSocket],
    defaults: usize,
    rows: Vec<Row>,
}
impl std::fmt::Debug for InterfaceUpdate<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceUpdate")
            .field("interfaces", &self.rows.len())
            .finish_non_exhaustive()
    }
}
impl InterfaceUpdate<'_> {
    /// Install the prepared rows and revoke only retained announcements whose
    /// original interface is absent. No allocation, syscall, clock sample or
    /// fallible work follows this commit. Membership retirement remains polled.
    pub fn commit(self) {
        let Self {
            state,
            sockets,
            defaults,
            rows,
        } = self;
        state.rows = rows;
        state.cursor = 0;
        for (socket, owner) in sockets.iter_mut().take(defaults).enumerate() {
            let Some(pending) = state.pending[socket] else {
                continue;
            };
            if state
                .rows
                .iter()
                .any(|row| row.interface == pending.interface)
            {
                continue;
            }
            owner.cancel_discovery();
            state.pending[socket] = None;
            state.failures[socket] = Some((
                Operation::Send {
                    interface: pending.interface,
                    target: pending.target,
                },
                Error::StaleGeneration.into(),
            ));
        }
    }
}

fn retry_at(state: &discovery::State, now: u64) -> Result<u64, Error> {
    now.checked_add(state.configuration.interval_us)
        .filter(|value| *value != u64::MAX)
        .ok_or(Error::Overflow)
}
fn isolated(error: &SocketError) -> bool {
    match error {
        SocketError::Core(Error::Deadline) => true,
        SocketError::Io(error) => {
            if gnunet_native::network::isolated_datagram_send_error(error) {
                return true;
            }
            #[cfg(unix)]
            {
                matches!(error.raw_os_error(), Some(libc::ENODEV | libc::ENXIO))
            }
            #[cfg(not(unix))]
            {
                false
            }
        }
        _ => false,
    }
}
// Linux reports EADDRNOTAVAIL only after searching this socket's complete
// IPv6 group/index list and finding no matching membership. Other backends
// retain failed leave debt until a successful leave or original socket close.
fn membership_absent(error: &SocketError) -> bool {
    #[cfg(target_os = "linux")]
    {
        matches!(error, SocketError::Io(error) if error.raw_os_error() == Some(libc::EADDRNOTAVAIL))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _original = error;
        false
    }
}
fn failed(socket: usize, operation: Operation, error: SocketError) -> Activity {
    Activity::DiscoveryFailed {
        socket,
        operation,
        error,
    }
}

impl<'id> Communicator<'id> {
    /// Enable actual LAN presence on these original sockets. Requires a
    /// time-enabled Tokio IO runtime, as does the normal standard PROGRAM.
    /// Caller supplies complete native interface snapshots separately. Current
    /// native source-selection support covers Linux, macOS, FreeBSD and Windows.
    pub fn enable_discovery(
        &mut self,
        configuration: discovery::Configuration,
    ) -> Result<(), Error> {
        if self.closing || self.closed {
            return Err(Error::Closed);
        }
        if self.discovery.is_some() {
            return Err(Error::Conflict);
        }
        self.discovery = Some(discovery::State::new(configuration)?);
        Ok(())
    }
    /// Replace only after an actual complete successful native interface scan.
    /// A failed/incomplete scan must retain the previous snapshot. No IO, key
    /// use or new clock sample occurs here; actual membership/send is polled.
    pub fn update_interfaces(&mut self, interfaces: &[discovery::Interface]) -> Result<(), Error> {
        self.prepare_interfaces(interfaces)?.commit();
        Ok(())
    }
    /// Reserve and validate a complete replacement before any dependent address
    /// publication state is changed. The exclusive guard makes commit infallible.
    pub fn prepare_interfaces(
        &mut self,
        interfaces: &[discovery::Interface],
    ) -> Result<InterfaceUpdate<'_>, Error> {
        if self.closing || self.closed {
            return Err(Error::Closed);
        }
        let rows = self
            .discovery
            .as_ref()
            .ok_or(Error::NotReady)?
            .prepare(interfaces, self.last_clock)?;
        let state = self.discovery.as_mut().ok_or(Error::NotReady)?;
        Ok(InterfaceUpdate {
            state,
            sockets: &mut self.sockets,
            defaults: self.defaults,
            rows,
        })
    }
    /// Consume one bounded signature hint exactly once. Caller must submit it
    /// to the original TRANSPORT Application Validate owner and retain its own
    /// unadmitted hint under backpressure; this grants no authenticated queue.
    pub fn take_discovered(&mut self) -> Option<Discovered> {
        if self.closing || self.closed {
            return None;
        }
        self.discovery.as_mut().and_then(|state| state.hint.take())
    }
    /// Check/register only original discovery-send native deadlines. Call this
    /// before awaiting/reading a canonical clock; it performs no socket syscall,
    /// clock request, signature, encryption or application validation.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Failure> {
        if self.closing || self.closed {
            return None;
        }
        if let Some(failure) = self.burst_native_guard(cx) {
            return Some(failure);
        }
        for index in 0..self.defaults {
            if let Err(error) = self.sockets[index].poll_discovery_guard(cx) {
                self.sockets[index].cancel_discovery();
                let Some(state) = self.discovery.as_mut() else {
                    return Some(Error::Stale.into());
                };
                let Some(pending) = state.pending[index].take() else {
                    return Some(Error::Stale.into());
                };
                if !isolated(&error) {
                    return Some(error.into());
                }
                state.failures[index] = Some((
                    Operation::Send {
                        interface: pending.interface,
                        target: pending.target,
                    },
                    error,
                ));
            }
        }
        None
    }
    pub(super) fn discovery_step(
        &mut self,
        cx: &mut Context<'_>,
        identity: &Identity,
        now: u64,
    ) -> Result<Option<Activity>, Failure> {
        let Some(state) = self.discovery.as_mut() else {
            return Ok(None);
        };
        for index in 0..self.defaults {
            if let Some((operation, error)) = state.failures[index].take() {
                return Ok(Some(failed(index, operation, error)));
            }
            let Some(pending) = state.pending[index] else {
                continue;
            };
            match self.sockets[index].poll_discovery_send(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    self.sockets[index].cancel_discovery();
                    state.pending[index] = None;
                    if isolated(&error) {
                        return Ok(Some(failed(
                            index,
                            Operation::Send {
                                interface: pending.interface,
                                target: pending.target,
                            },
                            error,
                        )));
                    }
                    return Err(error.into());
                }
                Poll::Ready(Ok(sent)) => {
                    state.pending[index] = None;
                    if sent.operation != pending.operation
                        || sent.target != pending.target
                        || sent.bytes != 96
                    {
                        return Err(Error::Stale.into());
                    }
                    return Ok(Some(Activity::DiscoverySent {
                        target: pending.target,
                    }));
                }
            }
        }
        let v6 = self
            .sockets
            .iter()
            .take(self.defaults)
            .position(|socket| socket.profile() == Profile::Ipv6);
        if let Some(socket) = v6 {
            if let Some(at) = state.memberships.iter().position(|membership| {
                now >= membership.retry
                    && !state.rows.iter().any(|row| {
                        row.interface.source.is_ipv6() && row.interface.index == membership.index
                    })
            }) {
                let index = state.memberships[at].index;
                let retry = retry_at(state, now)?;
                match self.sockets[socket].leave_discovery(&discovery::IPV6_GROUP, index) {
                    Ok(()) => {
                        state.memberships.swap_remove(at);
                        return Ok(Some(Activity::Discovery));
                    }
                    Err(error) if isolated(&error) => {
                        if membership_absent(&error) {
                            state.memberships.swap_remove(at);
                        } else {
                            state.memberships[at].retry = retry;
                        }
                        return Ok(Some(failed(
                            socket,
                            Operation::Leave { interface: index },
                            error,
                        )));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if let Some(index) = state
                .rows
                .iter()
                .filter(|row| row.interface.source.is_ipv6() && now >= row.join_due)
                .map(|row| row.interface.index)
                .find(|index| {
                    !state
                        .memberships
                        .iter()
                        .any(|membership| membership.index == *index)
                })
            {
                let retry = retry_at(state, now)?;
                // An unresolved old leave cannot grow the membership table.
                // Defer only this optional join; encrypted queues keep working.
                let result = if state.memberships.len() == state.configuration.interfaces {
                    Err(Error::Capacity.into())
                } else {
                    self.sockets[socket].join_discovery(&discovery::IPV6_GROUP, index)
                };
                match result {
                    Ok(()) => {
                        state.memberships.push(Membership { index, retry: now });
                        return Ok(Some(Activity::Discovery));
                    }
                    Err(error)
                        if isolated(&error)
                            || matches!(error, SocketError::Core(Error::Capacity)) =>
                    {
                        for row in &mut state.rows {
                            if row.interface.source.is_ipv6() && row.interface.index == index {
                                row.join_due = retry;
                            }
                        }
                        return Ok(Some(failed(
                            socket,
                            Operation::Join { interface: index },
                            error,
                        )));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        for offset in 0..state.rows.len() {
            let index = (state.cursor + offset) % state.rows.len();
            if now < state.rows[index].due {
                continue;
            }
            let interface = state.rows[index].interface;
            let Some(socket) = self.sockets.iter().take(self.defaults).position(|socket| {
                matches!(
                    (socket.profile(), interface.source),
                    (Profile::Ipv4, SocketAddr::V4(_)) | (Profile::Ipv6, SocketAddr::V6(_))
                )
            }) else {
                continue;
            };
            if self.sockets[socket].has_pending_send() {
                continue;
            }
            let hard = Instant::now()
                .checked_add(state.configuration.send_lifetime)
                .ok_or(Error::Overflow)?;
            let due = retry_at(state, now)?;
            let operation = state.sequence.checked_add(1).ok_or(Error::Overflow)?;
            let target = interface.target(self.sockets[socket].local_address().port())?;
            let packet = state.packet(index, identity)?;
            // Check the original native budget again after synchronous signing.
            let result = self.sockets[socket].queue_discovery(
                interface.source,
                interface.index,
                target,
                operation,
                packet,
                hard,
            );
            state.rows[index].due = due;
            state.cursor = (index + 1) % state.rows.len();
            match result {
                Ok(()) => {
                    state.sequence = operation;
                    state.pending[socket] = Some(Pending {
                        operation,
                        interface,
                        target,
                    });
                    return Ok(Some(Activity::Discovery));
                }
                Err(error) if isolated(&error) => {
                    return Ok(Some(failed(
                        socket,
                        Operation::Send { interface, target },
                        error,
                    )));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_discovery_keeps_owner_and_resource_failures_terminal() {
        for error in [
            Error::Closed,
            Error::Stale,
            Error::Capacity,
            Error::WouldBlock,
        ] {
            assert!(!isolated(&error.into()));
        }
        for kind in [
            io::ErrorKind::OutOfMemory,
            io::ErrorKind::NotConnected,
            io::ErrorKind::WriteZero,
        ] {
            assert!(!isolated(&io::Error::from(kind).into()));
        }
        assert!(isolated(&Error::Deadline.into()));
        assert!(isolated(
            &io::Error::from(io::ErrorKind::AddrNotAvailable).into()
        ));
    }
}
