//! Logical KEEP_ALIVE intent, independent of every original signed SEND/job.
use crate::{api::Api, clock::Span, types::Intent, *};
use domain::OperationPhase;
use gnunet_types::Error as Fault;

#[derive(Clone, Copy)]
struct Echo<'a> {
    hash: Hash,
    timestamp: u64,
    operation: Operation<'a>,
}
#[derive(Clone, Copy)]
pub(crate) struct SubscriptionIntent<'a> {
    pub room: Room<'a>,
    discourse: ShortHash,
    duration: u64,
    flags: u32,
    // Only an actual echo of the current operation establishes this intent.
    // Until then, every replacement source uses this same first caller bound.
    pending: Option<Span>,
    source: Option<Source<'a>>,
    member: Option<MemberSession<'a>>,
    operation: Option<Operation<'a>>,
    echo: Option<Echo<'a>>,
    attempt_span: Option<Span>,
    next_due: Option<u64>,
    armed: bool,
    automatic: bool,
}
fn renewal_at(timestamp: u64, duration: u64) -> Option<u64> {
    (duration != u64::MAX)
        .then(|| timestamp.saturating_add(duration / 10 * 9 + (duration % 10) * 9 / 10))
}
impl SubscriptionIntent<'_> {
    fn retire_attempt(&mut self) {
        self.source = None;
        self.member = None;
        self.operation = None;
        self.echo = None;
        self.attempt_span = None;
        self.next_due = None;
        self.armed = false;
        self.automatic = false;
    }
    fn confirmed(&mut self, timestamp: u64) {
        self.pending = None;
        self.operation = None;
        self.echo = None;
        self.attempt_span = None;
        self.next_due = renewal_at(timestamp, self.duration);
        self.armed = false;
        self.automatic = false;
    }
}
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    pub(crate) fn subscription_capacity(
        &mut self,
        room: Room<'a>,
        body: wire::body::Body<'_>,
    ) -> Result<(), Error> {
        let wire::body::Body::Subscription {
            discourse, flags, ..
        } = body
        else {
            return Ok(());
        };
        if flags & 1 != 0
            || flags & 2 == 0
            || self
                .subscriptions
                .iter()
                .any(|s| s.room == room && s.discourse == *discourse)
        {
            return Ok(());
        }
        if self.subscriptions.iter().filter(|s| s.room == room).count()
            == self.limits.core.subscriptions_per_room
        {
            return Err(Fault::Capacity.into());
        }
        let maximum = self
            .limits
            .core
            .rooms
            .checked_mul(self.limits.core.subscriptions_per_room)
            .ok_or(Fault::Overflow)?;
        if self.subscriptions.len() >= maximum {
            return Err(Fault::Capacity.into());
        }
        if self.subscriptions.len() == self.subscriptions.capacity() {
            let count = self
                .subscriptions
                .len()
                .checked_add(1)
                .ok_or(Fault::Overflow)?;
            let width = core::mem::size_of::<SubscriptionIntent<'a>>();
            let current = self.retained_overhead()?;
            let ceiling = self.limits.bytes;
            let available = ceiling.checked_sub(current).ok_or(Fault::Capacity)? / width;
            if available < count {
                return Err(Fault::Capacity.into());
            }
            let desired = self
                .subscriptions
                .capacity()
                .checked_mul(2)
                .unwrap_or(maximum)
                .max(4)
                .max(count)
                .min(maximum)
                .min(available);
            // Charge the old and replacement allocations together. Ordinary
            // growth is geometric; a minimal fallback preserves admissions
            // when a larger allocation fails or exceeds actual peak capacity.
            let allocate = |requested| -> Result<Vec<SubscriptionIntent<'a>>, Fault> {
                let mut grown = Vec::new();
                grown
                    .try_reserve_exact(requested)
                    .map_err(|_| Fault::Capacity)?;
                let actual = grown.capacity().checked_mul(width).ok_or(Fault::Overflow)?;
                if current.checked_add(actual).is_none_or(|n| n > ceiling) {
                    return Err(Fault::Capacity);
                }
                Ok(grown)
            };
            let mut grown = match allocate(desired) {
                Ok(grown) => grown,
                Err(Fault::Capacity) if desired > count => allocate(count)?,
                Err(error) => return Err(error.into()),
            };
            grown.extend_from_slice(&self.subscriptions);
            self.subscriptions = grown;
        }
        Ok(())
    }
    pub(crate) fn remember_subscription(
        &mut self,
        room: Room<'a>,
        body: wire::body::Body<'_>,
        source: Source<'a>,
        member: MemberSession<'a>,
        operation: Operation<'a>,
        span: Span,
    ) {
        let wire::body::Body::Subscription {
            discourse,
            time,
            flags,
        } = body
        else {
            return;
        };
        // This library's explicit keep_alive=false helper withdraws local
        // renewal intent too. No signed interval, old job or receipt is erased.
        if flags & 1 != 0 || flags & 2 == 0 {
            self.subscriptions
                .retain(|s| s.room != room || s.discourse != *discourse);
            return;
        }
        let row = SubscriptionIntent {
            room,
            discourse: *discourse,
            duration: time.as_micros(),
            flags,
            pending: Some(span),
            source: Some(source),
            member: Some(member),
            operation: Some(operation),
            echo: None,
            attempt_span: Some(span),
            next_due: None,
            armed: false,
            automatic: false,
        };
        if let Some(old) = self
            .subscriptions
            .iter_mut()
            .find(|s| s.room == room && s.discourse == *discourse)
        {
            *old = row;
        } else {
            // The unique public admission path reserved this bounded slot.
            self.subscriptions.push(row);
        }
        self.wake_domain();
    }
    fn subscription_echo(
        &self,
        row: SubscriptionIntent<'a>,
    ) -> Result<Option<Echo<'a>>, domain::Error> {
        if let Some(echo) = row.echo {
            return Ok(Some(echo));
        }
        let Some(operation) = row.operation else {
            return Ok(None);
        };
        if self.core.operation_phase(operation)? != OperationPhase::Complete {
            return Ok(None);
        }
        let hash = self
            .core
            .operations(row.room)?
            .find_map(|(binding, _)| {
                (binding.operation() == operation).then_some(*binding.message())
            })
            .ok_or(Fault::StaleGeneration)?;
        let message = self.core.message(row.room, &hash)?;
        if !message.local_sent()
            || !matches!(message.origin(), domain::MessageOrigin::Live(source) if Some(source) == row.source)
        {
            return Err(Fault::Authentication.into());
        }
        let wire::body::Body::Subscription {
            discourse,
            time,
            flags,
        } = message.body()?
        else {
            return Err(Fault::Conflict.into());
        };
        if *discourse != row.discourse || time.as_micros() != row.duration || flags != row.flags {
            return Err(Fault::Authentication.into());
        }
        let original = message.original().ok_or(Fault::NotFound)?;
        Ok(Some(Echo {
            hash,
            timestamp: wire::envelope::Envelope::decode(original)?
                .header()?
                .timestamp
                .as_micros(),
            operation,
        }))
    }
    pub(crate) fn observe_subscriptions(
        &mut self,
        now: Option<u64>,
    ) -> Result<(), (Room<'a>, domain::Error)> {
        let mut index = 0;
        while index < self.subscriptions.len() {
            let row = self.subscriptions[index];
            // Observe a real completed echo before considering a later clock.
            if let Some(echo) = self.subscription_echo(row).map_err(|e| (row.room, e))? {
                // Wire completion can precede bounded semantic work. Seal the
                // exact received echo before the caller retires its old Op;
                // waiting here needs neither that Op nor its full raw frame.
                self.subscriptions[index].operation = None;
                self.subscriptions[index].echo = Some(echo);
                let message = self
                    .core
                    .message(row.room, &echo.hash)
                    .map_err(|e| (row.room, e))?;
                if message.semantic_applied() {
                    if !message.local_sent()
                        || !matches!(message.origin(), domain::MessageOrigin::Live(source) if Some(source) == row.source)
                    {
                        return Err((row.room, Fault::Authentication.into()));
                    }
                    self.subscriptions[index].confirmed(echo.timestamp);
                    self.wake_domain();
                }
            } else if let Some(operation) = row.operation
                && matches!(
                    self.core
                        .operation_phase(operation)
                        .map_err(|e| (row.room, e))?,
                    OperationPhase::Failed | OperationPhase::Cancelled
                )
            {
                // Failure retires only this effect. An established logical
                // intent survives; an unconfirmed one still has its first Span.
                self.subscriptions[index].retire_attempt();
            }
            if self.subscriptions[index].attempt_span.is_none()
                && self.subscriptions[index]
                    .pending
                    .is_some_and(|span| span.expired(now))
            {
                self.subscriptions.swap_remove(index);
            } else {
                index += 1;
            }
        }
        Ok(())
    }
    pub(crate) fn retry_subscription_deadline(&self, cause: StopCause<'a>) -> bool {
        let StopCause::Deadline(operation) = cause else {
            return false;
        };
        self.subscriptions.iter().any(|s| {
            s.pending.is_none()
                && s.automatic
                && s.operation.or(s.echo.map(|echo| echo.operation)) == Some(operation)
        })
    }
    pub(crate) fn retire_subscription_attempts(&mut self) {
        for row in &mut self.subscriptions {
            row.retire_attempt();
        }
    }
    pub(crate) fn subscription_hard(&self) -> Option<tokio::time::Instant> {
        self.subscriptions
            .iter()
            .filter_map(|s| s.attempt_span.map(|span| span.hard))
            .min()
    }
    pub(crate) fn subscription_effect_target(&self) -> Option<u64> {
        self.subscriptions
            .iter()
            .filter_map(|s| s.attempt_span.map(|span| span.logical))
            .min()
    }
    pub(crate) fn expired_subscription(&self, now: Option<u64>) -> Option<Operation<'a>> {
        self.subscriptions.iter().find_map(|s| {
            s.attempt_span
                .filter(|span| span.expired(now))
                .and(s.operation.or(s.echo.map(|echo| echo.operation)))
        })
    }
    pub(crate) fn subscription_target(&self) -> Option<u64> {
        if self.domain_blocked
            || self.free_jobs() == 0
            || self.changing.is_some()
            || !self.ready()
            || self.disconnecting
        {
            return None;
        }
        self.subscriptions
            .iter()
            .filter_map(|s| s.armed.then_some(s.next_due).flatten())
            .min()
    }
    pub(crate) fn drive_subscriptions(&mut self, now: u64) -> Result<(), Error> {
        if self.domain_blocked || self.subscriptions.is_empty() {
            self.subscription_scan_remaining = 0;
            return Ok(());
        }
        self.subscription_scan_remaining = self
            .subscription_scan_remaining
            .min(self.subscriptions.len());
        // One global fair scan, not one whole-ledger scan for each room.
        for _ in 0..self.limits.work_per_poll {
            if self.subscription_scan_remaining == 0 || self.free_jobs() == 0 {
                break;
            }
            self.subscription_scan_remaining -= 1;
            let index = self.subscription_cursor % self.subscriptions.len();
            self.subscription_cursor = (index + 1) % self.subscriptions.len();
            let row = self.subscriptions[index];
            if row.operation.is_some() || row.echo.is_some() {
                continue;
            }
            let room = row.room;
            let (_, source, epoch, member) = match self.sending(room) {
                Ok(current) => current,
                Err(Error::Local(Fault::NotReady | Fault::Closed)) => {
                    self.subscriptions[index].armed = false;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let restoring = row.source != Some(source) || row.member != Some(member);
            if !restoring && row.next_due.is_none_or(|at| now < at) {
                self.subscriptions[index].armed = row.pending.is_none();
                continue;
            }
            let span = match row.pending {
                Some(span) => span,
                None => Span::new(now, self.limits.operation_lifetime)?,
            };
            self.admission_bounded(Deadline {
                owner: self.owner,
                span,
            })?;
            let body = wire::body::Body::Subscription {
                discourse: &row.discourse,
                time: gnunet_wire::official::RelativeTime::from_micros(row.duration),
                flags: row.flags,
            };
            let operation = match self
                .core
                .prepare_send(source, member, body, now, span.logical)
            {
                Ok(operation) => operation,
                Err(domain::Error::Protocol(
                    Fault::NotReady | Fault::WouldBlock | Fault::Capacity,
                )) => {
                    self.domain_blocked = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            };
            self.record_job(room, source, epoch, operation, span, Intent::Subscription)?;
            let current = &mut self.subscriptions[index];
            current.source = Some(source);
            current.member = Some(member);
            current.operation = Some(operation);
            current.attempt_span = Some(span);
            current.next_due = None;
            current.armed = false;
            current.automatic = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct NoEntropy;
    impl crypto::Entropy for NoEntropy {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Fault> {
            Err(Fault::EntropyUnavailable)
        }
    }

    // Lifecycle/brand source case only. No provider is polled, and no signed
    // echo, semantic acceptance or native success is fabricated by this fixture.
    // Constructing Api would derive its published anonymous key if run; these
    // source regressions are compiled only in this change's validation scope.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Fallible owner setup with original-span and exact-attempt assertions"
    )]
    fn original_pending_budget_and_established_internal_attempt_are_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?
            .block_on(async {
                let mut core_instance = domain::Instance::new();
                let instance = native::Instance::new();
                let mut api = Api::<NoEntropy, 1024>::anonymous(
                    &mut core_instance,
                    &instance,
                    EndpointSource::unix("/unused-messenger-subscription-fixture".into()),
                    NoEntropy,
                    Limits::default(),
                )?;
                let room = api.core.room([1; 64], None)?;
                let source = api.core.attach_source(
                    room,
                    domain::SourceRole::Client,
                    wire::padding::Decode::Absent,
                    None,
                )?;
                api.core.create_submitted(source)?;
                let original = api.core.open(source, 1_000_000)?;
                let other_room = api.core.room([2; 64], None)?;
                let other_source = api.core.attach_source(
                    other_room,
                    domain::SourceRole::Client,
                    wire::padding::Decode::Absent,
                    None,
                )?;
                api.core.create_submitted(other_source)?;
                let other = api.core.open(other_source, 1_000_000)?;
                let pending = Span {
                    logical: 100,
                    hard: tokio::time::Instant::now() + Duration::from_secs(1),
                };
                api.subscriptions.push(SubscriptionIntent {
                    room,
                    discourse: [9; 32],
                    duration: 10,
                    flags: 2 | 0x80,
                    pending: Some(pending),
                    source: Some(source),
                    member: None,
                    operation: Some(original),
                    echo: None,
                    attempt_span: Some(pending),
                    next_due: None,
                    armed: false,
                    automatic: false,
                });
                api.retire_subscription_attempts();
                let row = api.subscriptions[0];
                assert_eq!(row.pending.map(|s| s.logical), Some(100));
                assert_eq!(row.pending.map(|s| s.hard), Some(pending.hard));
                assert!(row.operation.is_none() && row.source.is_none());
                assert!(!api.retry_subscription_deadline(StopCause::Deadline(original)));
                assert!(api.observe_subscriptions(Some(100)).is_ok());
                assert!(api.subscriptions.is_empty());

                let mut established = row;
                // Test the post-semantic transition separately from its production
                // authentication gate. A source change cannot undo this fact.
                established.confirmed(20);
                established.retire_attempt();
                assert!(established.pending.is_none());
                assert_eq!(established.flags, 2 | 0x80);
                established.operation = Some(original);
                established.attempt_span = Some(pending);
                established.automatic = true;
                api.subscriptions.push(established);
                assert!(api.retry_subscription_deadline(StopCause::Deadline(original)));
                assert!(!api.retry_subscription_deadline(StopCause::Deadline(other)));
                api.subscriptions[0].automatic = false;
                assert!(!api.retry_subscription_deadline(StopCause::Deadline(original)));
                api.subscriptions[0].automatic = true;
                let stopped = api.close();
                assert!(api.subscriptions.is_empty());
                assert!(!api.can_reconnect(&stopped));
                Ok(())
            })
    }
}
