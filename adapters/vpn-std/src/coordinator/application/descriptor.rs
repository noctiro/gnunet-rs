//! App-owned route settings with one reactor-owned duplicate of a raw IP descriptor.
use super::{
    CloseOutcome, PacketCompletion, PacketOutcome, PacketRequest, Provider, RequestId,
    RouteCompletion, RouteOutcome, RouteReceipt, RouteRequest,
};
use gnunet_service_runtime::readiness::RegisteredIo;
use gnunet_vpn::RouteAction;
use std::{
    io,
    num::NonZeroU16,
    os::fd::BorrowedFd,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

/// Original route command or final retirement of this descriptor provider.
pub enum Command {
    /// Apply or remove the exact settings.
    Route(RouteRequest),
    /// The coordinator has retired its packet descriptor.
    Closed,
}

/// Platform route owner. Only one logical reader calls `next`. Completions and
/// revocation may run concurrently with that reader.
pub struct Controller(super::Controller);

/// Coordinator packet owner and original route mailbox.
pub struct Mailbox {
    routes: super::Mailbox,
    input: Vec<u8>,
    output: Option<(PacketRequest, Vec<u8>)>,
    fd: Option<RegisteredIo>,
}

/// Create a route-only command channel and a bounded native IP packet owner.
/// The fd must provide nonblocking raw IP packets on whole read/write
/// boundaries. Reactors, sockets and routes are supplied by the caller.
pub fn channel(maximum_packet: NonZeroU16) -> io::Result<(Controller, Mailbox)> {
    let (controller, routes) = super::channel(maximum_packet, NonZeroU16::MIN)?;
    Ok((
        Controller(controller),
        Mailbox {
            routes,
            input: Vec::new(),
            output: None,
            fd: None,
        },
    ))
}

impl Controller {
    /// Wait at most `timeout` for one original route or close command.
    pub fn next(&self, timeout: Duration) -> Option<Command> {
        match self.0.next(timeout)? {
            super::Command::Route(route) => Some(Command::Route(route)),
            super::Command::Closed => Some(Command::Closed),
            super::Command::Write(_) => None,
        }
    }

    /// Record actual installation and borrow the exact nonblocking descriptor.
    /// The provider duplicates it with close-on-exec before this call returns.
    /// Leave nonblocking enabled and delegate all packet I/O on that original
    /// open file description to the coordinator while the provider owns it.
    /// A canceled installation can settle its route claim without a new fd.
    pub fn installed(&self, id: RequestId, fd: BorrowedFd<'_>) -> io::Result<()> {
        self.0.finish_route(id, |request, retain| {
            if request.action != RouteAction::Install {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let descriptor = if retain {
                Some(fd.try_clone_to_owned()?)
            } else {
                None
            };
            Ok(RouteReceipt {
                outcome: RouteOutcome::Installed,
                descriptor,
            })
        })
    }

    /// Settle an original failure or removal at the actual platform boundary.
    pub fn complete_route(&self, result: RouteCompletion) -> io::Result<()> {
        if matches!(result.outcome, RouteOutcome::Installed) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.0.complete_route(result)
    }

    /// Stop all new descriptor packet effects while keeping route retirement live.
    pub fn fence_packets(&self) {
        self.0.fence_packets();
    }

    /// Fence new packet effects and retain the original teardown outcome.
    pub fn revoke(&self, outcome: CloseOutcome) {
        self.0.revoke(outcome);
    }
}

impl Provider for Mailbox {
    fn begin_route(&mut self, request: RouteRequest) -> io::Result<()> {
        if request.action == RouteAction::Install && self.fd.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        self.routes.begin_route_with(request, || {
            // The platform may need its original fd to be the last open
            // handle. Retire this duplicate before publishing Remove.
            if request.action == RouteAction::Remove {
                self.fd = None;
            }
        })
    }

    fn poll_route(&mut self, cx: &mut Context<'_>) -> Poll<RouteCompletion> {
        let receipt = self.routes.poll_route_with(cx, |receipt| {
            if !matches!(receipt.outcome, RouteOutcome::Installed) {
                return receipt.outcome;
            }
            let registered = receipt
                .descriptor
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
                .and_then(|fd| RegisteredIo::new(fd).map_err(|e| e.error));
            match registered {
                Ok(fd) => {
                    self.fd = Some(fd);
                    RouteOutcome::Installed
                }
                Err(error) => RouteOutcome::Failed {
                    error,
                    routes_absent: false,
                },
            }
        });
        if matches!(
            &receipt,
            Poll::Ready(RouteCompletion {
                outcome: RouteOutcome::Removed | RouteOutcome::Failed { .. },
                ..
            })
        ) {
            self.fd = None;
        }
        receipt
    }

    fn cancel_route(&mut self, id: RequestId) -> RouteOutcome {
        self.routes.cancel_route(id)
    }

    fn begin_write(&mut self, request: PacketRequest, packet: &[u8]) -> io::Result<()> {
        super::packet_bytes(packet, self.routes.0.packet)?;
        let state = self.routes.0.lock();
        state.forwarding()?;
        if self.fd.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        if self.output.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.output = Some((request, super::copy(packet)?));
        Ok(())
    }

    fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<PacketCompletion> {
        let Some((request, packet)) = &self.output else {
            return Poll::Pending;
        };
        let id = request.id;
        let state = self.routes.0.lock();
        let result = if Instant::now() >= request.deadline {
            Poll::Ready(Err(io::ErrorKind::TimedOut.into()))
        } else if state.packets_fenced {
            Poll::Ready(Err(io::ErrorKind::Interrupted.into()))
        } else {
            match state
                .forwarding()
                .and_then(|()| self.fd.as_ref().ok_or(io::ErrorKind::BrokenPipe.into()))
            {
                Ok(fd) => fd.poll_write(cx, packet),
                Err(error) => Poll::Ready(Err(error)),
            }
        };
        // The shared route lock orders packet syscalls before or after fencing.
        drop(state);
        let outcome = match result {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(written)) => write_outcome(written, packet.len()),
            Poll::Ready(Err(error)) => PacketOutcome::Unsent { error },
        };
        self.output = None;
        Poll::Ready(PacketCompletion { id, outcome })
    }

    fn cancel_write(&mut self, id: RequestId) -> PacketOutcome {
        let error = io::ErrorKind::Interrupted.into();
        if self
            .output
            .as_ref()
            .is_some_and(|(request, _)| request.id == id)
        {
            self.output = None;
            PacketOutcome::Unsent { error }
        } else {
            PacketOutcome::Unknown {
                error,
                exposed: false,
            }
        }
    }

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        max_bytes: usize,
    ) -> Poll<io::Result<Option<Vec<u8>>>> {
        let mut state = self.routes.0.lock();
        if state.live().is_err() {
            return Poll::Ready(Ok(None));
        }
        if state.forwarding().is_err() {
            return state.wait(cx);
        }
        let fd = self.fd.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let maximum = max_bytes.min(self.routes.0.packet);
        if maximum < 20 {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        let extent = maximum + 1;
        if self.input.len() < extent {
            self.input
                .try_reserve_exact(extent - self.input.len())
                .map_err(io::Error::other)?;
            self.input.resize(extent, 0);
        }
        let result = fd.poll_read(cx, &mut self.input[..extent]);
        drop(state);
        let read = match result {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        };
        if read == 0 {
            return Poll::Ready(Ok(None));
        }
        let packet = self.input.get(..read).ok_or(io::ErrorKind::InvalidData)?;
        super::packet_bytes(packet, maximum)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let mut packet = std::mem::take(&mut self.input);
        packet.truncate(read);
        Poll::Ready(Ok(Some(packet)))
    }

    fn close(&mut self) -> CloseOutcome {
        self.fd = None;
        self.output = None;
        self.routes.close()
    }
}

impl Drop for Mailbox {
    fn drop(&mut self) {
        let _outcome = self.close();
    }
}

fn write_outcome(written: usize, expected: usize) -> PacketOutcome {
    if written == expected {
        PacketOutcome::Written { bytes: written }
    } else if written == 0 {
        PacketOutcome::Unsent {
            error: io::ErrorKind::WriteZero.into(),
        }
    } else {
        PacketOutcome::Unknown {
            error: io::Error::other(format!(
                "native VPN wrote {written} of {expected} raw IP bytes"
            )),
            exposed: true,
        }
    }
}

#[cfg(test)]
mod tests;
