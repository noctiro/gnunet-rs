//! Original absolute restart targets and native wake subscriptions.
use super::*;

impl<'view, 'scope, 'spec, 'slots, 'bytes, C: Clock>
    Driver<'view, 'scope, 'spec, 'slots, 'bytes, C>
{
    pub(super) fn timer(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if self.state.pending_timer.is_none() {
            self.state.pending_timer = self.owner.take_timer()?;
        }
        let Some(effect) = self.state.pending_timer else {
            return Ok(false);
        };
        if !self.owner.timer_current(effect.ticket) {
            return Err(Error::Mapping);
        }
        match effect.action {
            TimerAction::Arm { at_utc } => {
                if self.state.timer.is_none() {
                    let now = self.utc()?;
                    let sleep = if at_utc == u64::MAX {
                        None
                    } else {
                        let duration = Duration::from_micros(at_utc.saturating_sub(now));
                        let deadline = Instant::now()
                            .checked_add(duration)
                            .ok_or(Error::Capacity)?;
                        Some(Box::pin(tokio::time::sleep_until(deadline)))
                    };
                    self.state.timer = Some(Timer {
                        id: effect.id,
                        at_utc,
                        sleep,
                    });
                    if let Some(timer) = self.state.timer.as_mut()
                        && let Some(sleep) = timer.sleep.as_mut()
                    {
                        // Poll installs the actual timer entry before acknowledging
                        // the registration. A ready result is still IDLE work.
                        let _readiness = sleep.as_mut().poll(cx);
                    }
                } else if self.state.timer.as_ref().is_none_or(|t| t.id != effect.id) {
                    return Err(Error::Mapping);
                }
            }
            TimerAction::Cancel => {
                if self.state.timer.as_ref().is_some_and(|t| t.id != effect.id) {
                    return Err(Error::Mapping);
                }
                drop(self.state.timer.take());
            }
        }
        self.owner.timer_applied(effect.ticket)?;
        self.state.pending_timer = None;
        Ok(true)
    }
}
