//! Original native/logical guards, including startup.
use super::*;
pub(super) struct Alarm {
    source: Arc<dyn RuntimeClock>,
    hard: Option<Instant>,
    native: Option<Pin<Box<Sleep>>>,
    until: Option<AbsoluteTime>,
    logical: Option<Pin<Box<LogicalDeadline>>>,
    pub(super) startup: Option<gnunet_service_runtime::clock::Bounds>,
}
impl Alarm {
    pub(super) fn new(
        source: Arc<dyn RuntimeClock>,
        initial: gnunet_service_runtime::clock::Bounds,
    ) -> Self {
        Self {
            source,
            hard: None,
            native: None,
            until: None,
            logical: None,
            startup: Some(initial),
        }
    }
    pub(super) fn set(&mut self, deadlines: impl Iterator<Item = Deadline>) -> Result<(), Fault> {
        let mut hard = self.startup.map(|bound| bound.hard());
        let mut until = self
            .startup
            .map(|bound| AbsoluteTime::from_micros(bound.expires()));
        for deadline in deadlines {
            hard = Some(hard.map_or(deadline.hard(), |old: Instant| old.min(deadline.hard())));
            let absolute = AbsoluteTime::from_micros(deadline.expires());
            until = Some(until.map_or(absolute, |old: AbsoluteTime| old.min(absolute)));
        }
        if hard != self.hard {
            self.hard = hard;
            self.native = hard.map(|hard| Box::pin(tokio::time::sleep_until(hard)));
        }
        if hard.is_some_and(|hard| Instant::now() >= hard) {
            return Err(Fault::Timeout);
        }
        if until != self.until {
            self.until = until;
            self.logical = until
                .map(|until| LogicalDeadline::at(self.source.clone(), until).map(Box::pin))
                .transpose()?;
        }
        Ok(())
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Result<bool, Fault> {
        if self.hard.is_some_and(|hard| Instant::now() >= hard)
            || self
                .native
                .as_mut()
                .is_some_and(|t| t.as_mut().poll(cx).is_ready())
        {
            return Ok(true);
        }
        if let Some(logical) = &mut self.logical
            && let Poll::Ready(result) = logical.as_mut().poll(cx)
        {
            result?;
            return Ok(true);
        }
        Ok(false)
    }
}
