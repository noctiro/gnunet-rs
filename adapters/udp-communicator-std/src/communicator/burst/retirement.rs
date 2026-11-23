//! Original probe/selection retirement, report backpressure and native guards.
use super::*;
pub(super) fn isolated(cause: &native::Cause, default_port: u16) -> bool {
    match cause {
        native::Cause::Cancelled | native::Cause::Deadline(_) | native::Cause::Exhausted => true,
        native::Cause::Io {
            action,
            port,
            error,
        } => match action {
            native::IoAction::Bind
            | native::IoAction::ReceivePolicy
            | native::IoAction::Nonblocking
            | native::IoAction::Reactor => *port != default_port,
            native::IoAction::Send | native::IoAction::Receive => {
                *port != default_port || gnunet_native::network::isolated_datagram_send_error(error)
            }
            native::IoAction::LocalAddress
            | native::IoAction::PeerAddress
            | native::IoAction::Prepare => false,
        },
        native::Cause::Clock(_) | native::Cause::Partial { .. } | native::Cause::Overflow => false,
        native::Cause::Selected => false,
    }
}

impl<'id> Communicator<'id> {
    pub(super) fn retire_burst(&mut self, admission: Option<Error>) -> Result<bool, Error> {
        let port = self.burst.as_mut().ok_or(Error::Stale)?;
        let Active { command, phase } = port.active.take().ok_or(Error::Stale)?;
        let retired = match (admission, phase) {
            (Some(cause), phase) => phase.interrupt(cause),
            (None, Phase::Retired(retired)) => retired,
            (None, Phase::Running(owner)) if owner.end().is_some() => state::ended(owner, None),
            (_, phase) => {
                port.active = Some(Active { command, phase });
                return Err(Error::NotReady);
            }
        };
        if port.report.is_some() {
            port.active = Some(Active {
                command,
                phase: Phase::Retired(retired),
            });
            return Ok(false);
        }
        if retired.input.is_some() && !self.io.release_frame() {
            port.active = Some(Active {
                command,
                phase: Phase::Retired(retired),
            });
            return Err(Error::Stale);
        }
        port.report = Some(command.report(retired.outcome));
        port.changed = true;
        Ok(true)
    }
    pub(super) fn burst_retired(
        &mut self,
        admission: Option<Error>,
    ) -> Result<Option<Activity>, crate::communicator::Failure> {
        if self.retire_burst(admission)? {
            self.burst.as_mut().ok_or(Error::Stale)?.changed = false;
            Ok(Some(Activity::Burst))
        } else {
            Ok(None)
        }
    }
    pub(in crate::communicator) fn burst_native_guard(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Option<crate::communicator::Failure> {
        let port = self.burst.as_mut()?;
        let active = port.active.as_mut()?;
        if let Phase::Running(owner) = &mut active.phase {
            owner.poll_native_guard(cx);
            if let Some(end) = owner.end()
                && !matches!(end.cause, native::Cause::Selected)
            {
                if !isolated(&end.cause, active.command.remote.port()) {
                    let failure = port.fail()?;
                    self.close();
                    return Some(crate::communicator::Failure::Burst(failure));
                }
                return self.retire_burst(None).err().map(Into::into);
            }
        }
        let expired = Instant::now() >= active.command.hard
            || active.command.alarm.as_mut().poll(cx).is_ready();
        if expired || matches!(active.phase, Phase::Retired(_)) {
            self.retire_burst(expired.then_some(Error::Deadline))
                .err()
                .map(Into::into)
        } else {
            None
        }
    }
}
