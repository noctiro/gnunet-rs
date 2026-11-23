//! Same original TRANSPORT command, public utility scan and actual socket transfer.
use super::*;
use gnunet_nat_burst_host::{self as native, Burst, ReadyParameters, SelectedSocket, Selection};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::AbsoluteTime;
pub use native::Instance;
pub use native::wire::Endian;
use std::{future::Future, net::IpAddr, pin::Pin, time::Duration};
use tokio::time::Sleep;

mod types;
pub use types::{Failure, Outcome, Policy, Refusal, Report};
mod state;
use state::{Active, Chosen, Command, HeldInput, Phase, Retired};
mod handoff;
mod retirement;
use retirement::isolated;
#[cfg(test)]
mod tests;

fn local_order() -> Endian {
    if cfg!(target_endian = "little") {
        Endian::Little
    } else {
        Endian::Big
    }
}
pub(super) enum Probe {
    Unrelated,
    /// Same original default receipt is retained until the original initial
    /// probe actually writes, never copied or treated as a completed callback.
    Pending,
    Selected,
}
pub(super) struct Port<'id> {
    instance: &'id Instance,
    clock: Arc<dyn RuntimeClock>,
    pub(super) policy: Policy,
    serial: u64,
    active: Option<Active<'id>>,
    report: Option<Report>,
    cancelled: Option<Report>,
    fence: Option<u64>,
    changed: bool,
}
impl Port<'_> {
    fn take_report(&mut self) -> Option<Report> {
        let report = self.report.take().or_else(|| self.cancelled.take());
        self.report = self.cancelled.take();
        report
    }
    fn fail(&mut self) -> Option<Failure> {
        self.active.take().map(|Active { command, phase }| {
            let retired = match phase {
                Phase::Running(owner) => state::ended(owner, None),
                phase => phase.interrupt(Error::Cancelled),
            };
            Failure {
                report: command.report(retired.outcome),
            }
        })
    }
    fn cancel(&mut self) {
        if let Some(Active { command, phase }) = self.active.take() {
            let retired = phase.interrupt(Error::Cancelled);
            let report = command.report(retired.outcome);
            if self.report.is_none() {
                self.report = Some(report);
            } else {
                self.cancelled = Some(report);
            }
            self.changed = true;
        }
    }
}
impl<'id> Communicator<'id> {
    /// Enable the real public burst path before any original registration bytes
    /// are written. Instance and clock are supplied by the actual foreground.
    /// The single-peer Driver remains an explicitly non-burst embedding.
    pub fn enable_burst(
        &mut self,
        instance: &'id Instance,
        clock: Arc<dyn RuntimeClock>,
        policy: Policy,
    ) -> Result<(), super::Failure> {
        if self.closing
            || self.closed
            || self.burst.is_some()
            || self.registered
            || self.io.queued_frames() != 0
            || self.effects.len() != 1
            || !matches!(
                self.effects.front().map(|effect| effect.origin),
                Some(Origin::Register)
            )
            || policy.lifetime.is_zero()
            || policy.lifetime > Duration::from_secs(60)
            || !(1..=512).contains(&policy.scan.sockets)
            || !(1..=1024).contains(&policy.scan.io_budget)
            || policy.scan.send_interval.is_zero()
            || policy.scan.socket_lifetime.is_zero()
        {
            return Err(Error::InvalidInput.into());
        }
        let slots = self
            .defaults
            .checked_add(self.configuration.endpoints)
            .ok_or(Error::Overflow)?;
        self.sockets
            .try_reserve_exact(slots - self.sockets.len())
            .map_err(|_| Error::Capacity)?;
        self.completions
            .try_reserve_exact(slots - self.completions.len())
            .map_err(|_| Error::Capacity)?;
        let frame = frozen(16, |out| transport::register(true, out))?;
        // Same original registration envelope/sequence, still wholly unexposed.
        self.effects.front_mut().ok_or(Error::Stale)?.frame = frame;
        self.burst = Some(Port {
            instance,
            clock,
            policy,
            serial: 0,
            active: None,
            report: None,
            cancelled: None,
            fence: None,
            changed: false,
        });
        Ok(())
    }
    /// Move one actual local terminal report. Completion remains an original
    /// publication ticket, and neither selection nor1254 authenticates the peer.
    pub fn take_burst_report(&mut self) -> Option<Report> {
        // Keep the oldest slot occupied until both earlier outcomes drain, so
        // a newly expired command cannot overtake a source-canceled report.
        self.burst.as_mut().and_then(Port::take_report)
    }
    pub(super) fn cancel_burst(&mut self) {
        if let Some(port) = &mut self.burst {
            port.cancel();
        }
    }
    pub(super) fn transport_lost_burst(&mut self) {
        if let Some(port) = &mut self.burst {
            port.cancel();
            // The original report retains its exact publication ticket; a new
            // source must never wait on or complete this retired MQ fence.
            port.fence = None;
        }
    }
    pub(super) fn burst_command(
        &mut self,
        peer: PeerId,
        rtt: u64,
        ip: IpAddr,
    ) -> Result<Option<Activity>, super::Failure> {
        let port = self.burst.as_ref().ok_or(Error::Unsupported)?;
        let hard = Instant::now()
            .checked_add(port.policy.lifetime)
            .ok_or(Error::Overflow)?;
        if port.report.is_some() && port.cancelled.is_some() {
            return Err(Error::Capacity.into());
        }
        if port
            .active
            .as_ref()
            .is_some_and(|active| !active.phase.input_held())
        {
            // A new real 1253 supersedes its preceding scan, not the socket/MQ.
            self.burst.as_mut().ok_or(Error::Stale)?.cancel();
        }
        let port = self.burst.as_ref().ok_or(Error::Stale)?;
        if let Some(active) = &port.active {
            let command = &active.command;
            if command.peer != peer || command.rtt != rtt || command.remote.ip() != ip {
                return Err(Error::Conflict.into());
            }
        } else {
            if peer == self.configuration.local || rtt == u64::MAX {
                return Err(Error::InvalidInput.into());
            }
            let default = self
                .sockets
                .iter()
                .take(self.defaults)
                .position(|socket| socket.local_address().is_ipv4() == ip.is_ipv4())
                .ok_or(Error::Unsupported)?;
            let remote = SocketAddr::new(ip, self.sockets[default].local_address().port());
            let serial = port.serial.checked_add(1).ok_or(Error::Overflow)?;
            let command = Command {
                serial,
                peer,
                rtt,
                remote,
                default,
                hard,
                alarm: Box::pin(tokio::time::sleep_until(hard.into())),
                ignored: 0,
            };
            let port = self.burst.as_mut().ok_or(Error::Stale)?;
            port.serial = serial;
            port.active = Some(Active {
                command,
                phase: Phase::Waiting(HeldInput),
            });
        }
        let port = self.burst.as_mut().ok_or(Error::Stale)?;
        if port.report.is_some()
            || port.cancelled.is_some()
            || port
                .fence
                .is_some_and(|sequence| sequence > self.written_effect)
        {
            return Ok(None);
        }
        port.fence = None;
        let active = port.active.as_mut().ok_or(Error::Stale)?;
        if matches!(active.phase, Phase::Retired(_)) {
            return self.burst_retired(None);
        }
        if !matches!(active.phase, Phase::Waiting(_)) {
            return Err(Error::Stale.into());
        }
        let command = &active.command;
        if Instant::now() >= command.hard {
            return self.burst_retired(Some(Error::Deadline));
        }
        let sample = port.clock.sample()?;
        if Instant::now() >= command.hard {
            return self.burst_retired(Some(Error::Deadline));
        }
        let remaining = u64::try_from(
            command
                .hard
                .saturating_duration_since(Instant::now())
                .as_micros(),
        )
        .map_err(|_| Error::Overflow)?;
        let until = AbsoluteTime::from_micros(
            sample
                .now
                .as_micros()
                .checked_add(remaining)
                .filter(|value| *value != u64::MAX)
                .ok_or(Error::Overflow)?,
        );
        let parameters = ReadyParameters {
            remote: command.remote,
            public_peer: self.configuration.local,
            local_order: local_order(),
            remote_order: port.policy.remote_order,
            until,
            hard: command.hard,
        };
        let result = Burst::start_ready_with_socket_policy(
            port.instance,
            self.sockets[command.default].shared()?,
            parameters,
            port.policy.scan,
            port.clock.clone(),
            self.sockets[command.default].socket_policy().clone(),
        );
        match result {
            Ok(owner) => {
                // The new owner remains local until the original MQ frame is
                // released. A failed release drops only this new probe owner.
                if !self.io.release_frame() {
                    return Err(Error::Stale.into());
                }
                active.phase = Phase::Running(owner);
                Ok(Some(Activity::Burst))
            }
            Err(error @ native::Error::Fault(Error::Deadline | Error::Capacity)) => {
                let Active { command, phase } = port.active.take().ok_or(Error::Stale)?;
                let Phase::Waiting(input) = phase else {
                    port.active = Some(Active { command, phase });
                    return Err(super::Failure::BurstStart(error));
                };
                port.active = Some(Active {
                    command,
                    phase: Phase::Retired(Retired {
                        outcome: Outcome::Preparation(error),
                        input: Some(input),
                    }),
                });
                self.burst_retired(None)
            }
            Err(error) => Err(super::Failure::BurstStart(error)),
        }
    }
    pub(super) fn burst_probe(
        &mut self,
        socket: usize,
        receipt: Receipt,
    ) -> Result<Probe, super::Failure> {
        let Some(port) = &mut self.burst else {
            return Ok(Probe::Unrelated);
        };
        if receipt.len() != native::wire::MESSAGE_BYTES {
            return Ok(Probe::Unrelated);
        }
        let Some(active) = &mut port.active else {
            return Ok(Probe::Unrelated);
        };
        if socket != active.command.default {
            return Ok(Probe::Unrelated);
        }
        if receipt.address().ip() != active.command.remote.ip() {
            return Ok(Probe::Unrelated);
        }
        let Phase::Running(owner) = &mut active.phase else {
            return Ok(Probe::Unrelated);
        };
        if owner.report().datagrams_written == 0 {
            return Ok(Probe::Pending);
        }
        let id = owner.default_socket();
        let selected = owner
            .on_datagram(id, receipt.address(), self.sockets[socket].bytes(receipt)?)
            .map_err(super::Failure::BurstStart)?;
        if selected == native::Disposition::Selected {
            self.sockets[socket].consume(receipt)?;
            Ok(Probe::Selected)
        } else {
            Ok(Probe::Unrelated)
        }
    }
    pub(super) fn burst_step(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<Option<Activity>, super::Failure> {
        let Some(port) = &mut self.burst else {
            return Ok(None);
        };
        if std::mem::take(&mut port.changed) {
            return Ok(Some(Activity::Burst));
        }
        let Some(active) = &mut port.active else {
            return Ok(None);
        };
        match &mut active.phase {
            Phase::Waiting(_) => return Ok(None),
            Phase::Retired(_) => return self.burst_retired(None),
            Phase::Running(owner) => {
                let mut ignored = 0_u64;
                let step = owner.poll_step(cx, |event| {
                    if matches!(event, native::Event::Datagram { .. }) {
                        ignored = ignored.saturating_add(1);
                    }
                });
                active.command.ignored = active.command.ignored.saturating_add(ignored);
                match step {
                    Poll::Pending => return Ok(None),
                    Poll::Ready(native::Step::Progress) => return Ok(Some(Activity::Burst)),
                    Poll::Ready(native::Step::Stopped) => {
                        let end = owner.end().ok_or(Error::Stale)?;
                        if isolated(&end.cause, active.command.remote.port()) {
                            return self.burst_retired(None);
                        }
                        return Err(super::Failure::Burst(port.fail().ok_or(Error::Stale)?));
                    }
                    Poll::Ready(native::Step::Selected) => self.take_burst_selection()?,
                }
            }
            Phase::Selected(_) => {}
        }
        self.handoff_burst(now, classify)
    }
}
