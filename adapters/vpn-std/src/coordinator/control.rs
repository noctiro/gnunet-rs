use super::*;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    New,
    Snapshot,
    Configure(u8),
    Dad,
    Routes(usize),
    Ready,
    Remove(usize),
    Released,
    Failed,
}
struct Route {
    job: tun::NativeRoute,
    index: usize,
    removing: bool,
}
struct Query {
    job: tun::RouteQuery,
    index: usize,
    removing: bool,
}
pub(super) struct Control<'id> {
    phase: Phase,
    plan: Option<core::RoutingRequest<'id>>,
    work: Option<core::Routing<'id>>,
    until: Option<Instant>,
    route: Option<Route>,
    query: Option<Query>,
    watch: Option<tun::Ipv6Watch>,
    sample_at: Option<Instant>,
    pub(super) uncertain: bool,
    pub(super) prior_tun_close_error: Option<io::Error>,
    control_close_error: Option<io::Error>,
    pub(super) unconfirmed_control_closes: u64,
    pub(super) dead: bool,
}
impl Control<'_> {
    pub(super) fn new() -> Self {
        Self {
            phase: Phase::New,
            plan: None,
            work: None,
            until: None,
            route: None,
            query: None,
            watch: None,
            sample_at: None,
            uncertain: false,
            prior_tun_close_error: None,
            control_close_error: None,
            unconfirmed_control_closes: 0,
            dead: false,
        }
    }
}
fn ip(a: core::Address) -> IpAddr {
    match a {
        core::Address::V4(a) => Ipv4Addr::from(a).into(),
        core::Address::V6(a) => Ipv6Addr::from(a).into(),
    }
}
fn prefix(plan: core::RoutingRequest<'_>, i: usize) -> Option<core::Prefix> {
    match i {
        0 => plan.ipv4,
        1 => plan.ipv6,
        _ => None,
    }
}
impl<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
{
    fn control_failed(&mut self, reason: Fault) -> Result<(), Error> {
        if let Some(work) = self.control.work.take() {
            self.server.engine_mut().route_failed(work, reason)?;
        } else if let Some(source) = self.source
            && !self.control.dead
        {
            self.server.engine_mut().route_lost(source, reason)?;
        }
        self.control.phase = Phase::Failed;
        self.request_shutdown();
        Ok(())
    }
    fn retain_control_close(&mut self, error: Option<&io::Error>) {
        if let Some(error) = error {
            self.control.unconfirmed_control_closes =
                self.control.unconfirmed_control_closes.saturating_add(1);
            if self.control.control_close_error.is_none() {
                self.control.control_close_error = Some(match error.raw_os_error() {
                    Some(errno) => io::Error::from_raw_os_error(errno),
                    None => io::Error::new(error.kind(), error.to_string()),
                });
            }
            // Do not keep opening periodic query sockets after uncertain close.
            // Actual ACK/Get/observation outcomes remain their original facts.
            self.request_shutdown();
        }
    }
    fn stop_watch(&mut self, observe: &mut impl FnMut(Event<'id, 'cadet>)) {
        if let Some(mut w) = self.control.watch.take()
            && let tun::Ipv6Progress::Complete(c) = w.cancel()
        {
            self.retain_control_close(c.close_error.as_ref());
            observe(Event::Ipv6Ended(c));
        }
    }
    fn start_query(&mut self, index: usize, removing: bool) -> Result<(), Error> {
        if self.control.unconfirmed_control_closes != 0 {
            return Err(Fault::Io.into());
        }
        let plan = self.control.plan.ok_or(Fault::NotReady)?;
        let p = prefix(plan, index).ok_or(Fault::InvalidInput)?;
        let until = self.control.until.ok_or(Fault::NotReady)?;
        let job = self
            .device
            .io
            .query_route(ip(p.network), p.bits, None, until)?;
        self.control.query = Some(Query {
            job,
            index,
            removing,
        });
        Ok(())
    }
    fn start_route(
        &mut self,
        index: usize,
        removing: bool,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        if self.control.unconfirmed_control_closes != 0 {
            return Err(Fault::Io.into());
        }
        let p = prefix(self.control.plan.ok_or(Fault::NotReady)?, index).ok_or(Fault::NotReady)?;
        let action = tun::Action::Route {
            add: !removing,
            destination: ip(p.network),
            prefix: p.bits,
            gateway: None,
        };
        let effect = self
            .device
            .io
            .plan(action, self.control.until.ok_or(Fault::NotReady)?)?;
        match self.device.io.route(effect) {
            Ok(job) => {
                self.control.route = Some(Route {
                    job,
                    index,
                    removing,
                });
                Ok(())
            }
            Err(e) => {
                observe(Event::ControlFailed(e));
                self.control_failed(Fault::Io)
            }
        }
    }
    fn route_complete(
        &mut self,
        index: usize,
        removing: bool,
        c: tun::RouteCompletion,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        if c.id.epoch() != &self.device.epoch() {
            return Err(Fault::StaleGeneration.into());
        }
        let good = c.timing == tun::Timing::Timely
            && matches!(&c.outcome, tun::RouteOutcome::KernelAck(Ok(())));
        let reconcile = c.timing == tun::Timing::Timely
            && matches!(&c.outcome,tun::RouteOutcome::KernelAck(Err(e)) if (!removing && e.kind()==io::ErrorKind::AlreadyExists) || (removing && e.kind()==io::ErrorKind::NotFound));
        if matches!(&c.outcome, tun::RouteOutcome::Uncertain(_)) {
            self.control.uncertain = true;
        }
        self.retain_control_close(c.close_error.as_ref());
        observe(Event::Route(c));
        if good {
            self.report.route_acks = self.report.route_acks.saturating_add(1);
            self.control.phase = if removing {
                Phase::Remove(index + 1)
            } else {
                Phase::Routes(index + 1)
            };
        } else if reconcile {
            self.start_query(index, removing)?;
        } else {
            self.control_failed(Fault::OutcomeUnknown)?;
        }
        Ok(())
    }
    fn query_complete(
        &mut self,
        index: usize,
        removing: bool,
        c: tun::RouteQueryCompletion,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        if c.target().epoch() != &self.device.epoch() {
            return Err(Fault::StaleGeneration.into());
        }
        let exact = matches!(c.outcome(), tun::RouteQueryOutcome::Exact(_));
        let absent = matches!(c.outcome(), tun::RouteQueryOutcome::Absent);
        self.retain_control_close(c.close_error());
        observe(Event::RouteQuery(c));
        if removing {
            if absent {
                self.control.phase = Phase::Remove(index + 1);
            } else if exact {
                self.start_route(index, true, observe)?;
            } else {
                self.control_failed(Fault::OutcomeUnknown)?;
            }
        } else if exact {
            self.control.phase = Phase::Routes(index + 1);
        } else {
            self.control_failed(if absent {
                Fault::NotFound
            } else {
                Fault::OutcomeUnknown
            })?;
        }
        Ok(())
    }
    fn poll_watch(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        let Some(w) = self.control.watch.as_mut() else {
            return Ok(false);
        };
        let progress = match w.poll(cx) {
            Poll::Pending => return Ok(false),
            Poll::Ready(p) => p,
        };
        match progress {
            tun::Ipv6Progress::Observed(o) => {
                if o.target.epoch() != &self.device.epoch() {
                    return Err(Fault::StaleGeneration.into());
                }
                let ready = o.state == tun::Ipv6State::Ready;
                let wait = matches!(o.state, tun::Ipv6State::Tentative | tun::Ipv6State::Missing);
                observe(Event::Ipv6(o));
                if ready {
                    self.stop_watch(observe);
                    if self.control.phase == Phase::Dad {
                        self.control.phase = Phase::Routes(0);
                    }
                    // A new monitor is scheduled only after this actual ready
                    // sample. Initial unfinished DAD keeps its original deadline.
                    self.control.sample_at = Some(Self::deadline(self.limits.ipv6_watch.interval)?);
                } else if self.control.phase == Phase::Ready || !wait {
                    self.stop_watch(observe);
                    self.control_failed(Fault::Unavailable)?;
                }
            }
            tun::Ipv6Progress::Complete(c) => {
                self.control.watch = None;
                self.retain_control_close(c.close_error.as_ref());
                observe(Event::Ipv6Ended(c));
                self.control_failed(Fault::Unavailable)?;
            }
            tun::Ipv6Progress::Activity { .. } => {}
            tun::Ipv6Progress::Finished => {
                self.control.watch = None;
                return Err(Fault::Conflict.into());
            }
            tun::Ipv6Progress::WaitDeadline => return Ok(false),
        }
        Ok(true)
    }
    fn begin_cleanup(
        &mut self,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        if matches!(
            self.control.phase,
            Phase::New | Phase::Released | Phase::Remove(_)
        ) {
            return Ok(false);
        }
        self.stop_watch(observe);
        if let Some(mut route) = self.control.route.take()
            && let tun::RouteProgress::Complete(c) = route.job.cancel()
        {
            if c.submission != tun::RouteSubmission::Unsent {
                self.control.uncertain = true;
            }
            self.retain_control_close(c.close_error.as_ref());
            observe(Event::Route(c));
        }
        if let Some(mut query) = self.control.query.take()
            && let tun::RouteQueryProgress::Complete(c) = query.job.cancel()
        {
            self.retain_control_close(c.close_error());
            observe(Event::RouteQuery(c));
        }
        if let Some(work) = self.control.work.take() {
            self.server.engine_mut().retire_routing(work)?;
        }
        let Some(source) = self.source else {
            return Ok(false);
        };
        if self.device.provenance != Provenance::Created {
            self.server.engine_mut().release_borrowed_routes(source)?;
            self.control.phase = Phase::Released;
            return Ok(true);
        }
        if self.control.dead {
            return Ok(false);
        }
        let plan = match self.server.engine_mut().route_cleanup_request(source) {
            Ok(p) => p,
            Err(Fault::NotFound) => {
                self.control.phase = Phase::Released;
                return Ok(true);
            }
            Err(e) => return Err(e.into()),
        };
        self.control.work = Some(plan.routing);
        self.control.plan = Some(plan);
        self.server.engine_mut().can_queue_routing(plan.routing)?;
        // Admission into this retained bounded cleanup workflow is the original
        // provider job; subsequent native requests retain the same deadline.
        let target = Self::deadline(self.limits.control_timeout)?;
        self.control.until = Some(
            self.device
                .io
                .initial_deadline()
                .map_or(target, |original| original.min(target)),
        );
        self.server.engine_mut().routing_queued(plan.routing)?;
        self.control.phase = Phase::Remove(0);
        Ok(true)
    }
    pub(super) fn poll_control(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        if self.control.unconfirmed_control_closes != 0 {
            return Err(Fault::Io.into());
        }
        if self.stopping.is_some()
            && !matches!(
                self.control.phase,
                Phase::New | Phase::Released | Phase::Remove(_)
            )
        {
            return self.begin_cleanup(observe);
        }
        if self.control.dead {
            return Ok(false);
        }
        if let Some(mut route) = self.control.route.take() {
            match route.job.poll(cx) {
                Poll::Pending => {
                    self.control.route = Some(route);
                    return Ok(false);
                }
                Poll::Ready(tun::RouteProgress::Complete(c)) => {
                    self.route_complete(route.index, route.removing, c, observe)?;
                    return Ok(true);
                }
                Poll::Ready(tun::RouteProgress::Finished) => return Err(Fault::Conflict.into()),
                Poll::Ready(_) => {
                    self.control.route = Some(route);
                    return Ok(true);
                }
            }
        }
        if let Some(mut query) = self.control.query.take() {
            match query.job.poll(cx) {
                Poll::Pending => {
                    self.control.query = Some(query);
                    return Ok(false);
                }
                Poll::Ready(tun::RouteQueryProgress::Complete(c)) => {
                    self.query_complete(query.index, query.removing, c, observe)?;
                    return Ok(true);
                }
                Poll::Ready(tun::RouteQueryProgress::Finished) => {
                    return Err(Fault::Conflict.into());
                }
                Poll::Ready(_) => {
                    self.control.query = Some(query);
                    return Ok(true);
                }
            }
        }
        if self.control.watch.is_some() {
            return self.poll_watch(cx, observe);
        }
        if !matches!(
            self.control.phase,
            Phase::New | Phase::Ready | Phase::Released | Phase::Failed
        ) && self.control.until.is_some_and(|t| Instant::now() >= t)
        {
            self.control_failed(Fault::Deadline)?;
            return Ok(true);
        }
        match self.control.phase {
            Phase::New => {
                if self.stopping.is_some() {
                    return Ok(false);
                }
                match self.device.io.poll_prepare(cx) {
                    Poll::Pending => return Ok(false),
                    Poll::Ready(Err(error)) => return Err(error.into()),
                    Poll::Ready(Ok(())) => {}
                }
                let source = self.server.engine_mut().attach_tun()?;
                self.source = Some(source);
                let plan = self.server.engine_mut().routing_request(source)?;
                // Retain the original job before any later validation or native
                // deadline can fail, so no issued routing token becomes orphaned.
                self.control.work = Some(plan.routing);
                self.control.plan = Some(plan);
                if plan.ipv6.is_some() && self.limits.mtu < 1280 {
                    return Err(Fault::InvalidInput.into());
                }
                let target = Self::deadline(self.limits.control_timeout)?;
                self.control.until = Some(
                    self.device
                        .io
                        .initial_deadline()
                        .map_or(target, |original| original.min(target)),
                );
                if self.device.provenance != Provenance::Created {
                    self.server
                        .engine_mut()
                        .can_queue_borrowed_routing(plan.routing)?;
                    self.server
                        .engine_mut()
                        .routing_borrowed_queued(plan.routing)?;
                } else {
                    self.server.engine_mut().can_queue_routing(plan.routing)?;
                    self.server.engine_mut().routing_queued(plan.routing)?;
                }
                self.control.phase = Phase::Snapshot;
                Ok(true)
            }
            Phase::Snapshot => {
                let s = self
                    .device
                    .io
                    .snapshot(self.control.until.ok_or(Fault::NotReady)?)?;
                if s.epoch() != &self.device.epoch() {
                    return Err(Fault::StaleGeneration.into());
                }
                let plan = self.control.plan.ok_or(Fault::NotReady)?;
                let v4ok = plan.ipv4.is_none_or(|p| {
                    match (p.interface, s.ipv4_address(), s.ipv4_netmask()) {
                        (
                            core::Address::V4(a),
                            tun::Ipv4Observation::Present(real),
                            tun::Ipv4Observation::Present(mask),
                        ) => real.octets() == a && mask.octets() == v4mask(p.bits),
                        _ => false,
                    }
                });
                let borrowed = self.device.provenance != Provenance::Created;
                let matches =
                    self.device.io.accepts_mtu(s.mtu(), self.limits.mtu) && s.up() && v4ok;
                self.retain_control_close(s.close_error());
                observe(Event::Snapshot(s));
                if borrowed {
                    if !matches {
                        self.control_failed(Fault::Conflict)?;
                        return Ok(true);
                    }
                    self.control.phase = Phase::Dad;
                } else {
                    self.control.phase = Phase::Configure(0);
                }
                Ok(true)
            }
            Phase::Configure(i) => {
                let plan = self.control.plan.ok_or(Fault::NotReady)?;
                let action = native_action(plan, i, self.limits.mtu)?;
                if i >= 5 {
                    self.control.phase = Phase::Dad;
                    return Ok(true);
                }
                if let Some(action) = action {
                    let effect = self
                        .device
                        .io
                        .plan(action, self.control.until.ok_or(Fault::NotReady)?)?;
                    match self.device.io.apply(effect) {
                        Ok(receipt) => {
                            let valid = receipt.timing() == tun::Timing::Timely
                                && receipt.id().epoch() == &self.device.epoch();
                            observe(Event::Applied(receipt));
                            self.report.native_applied =
                                self.report.native_applied.saturating_add(1);
                            if !valid {
                                self.control_failed(Fault::OutcomeUnknown)?;
                                return Ok(true);
                            }
                        }
                        Err(e) => {
                            observe(Event::ControlFailed(e));
                            self.control_failed(Fault::Io)?;
                            return Ok(true);
                        }
                    }
                }
                self.control.phase = Phase::Configure(i + 1);
                Ok(true)
            }
            Phase::Dad => {
                if let Some(p) = self.control.plan.and_then(|p| p.ipv6) {
                    let core::Address::V6(a) = p.interface else {
                        return Err(Fault::InvalidInput.into());
                    };
                    self.control.watch = Some(self.device.io.watch_ipv6(
                        a.into(),
                        p.bits,
                        self.control.until.ok_or(Fault::NotReady)?,
                        self.limits.ipv6_watch,
                    )?);
                } else {
                    self.control.phase = Phase::Routes(0);
                }
                Ok(true)
            }
            Phase::Routes(i) => {
                if i >= 2 {
                    let work = self.control.work.take().ok_or(Fault::NotReady)?;
                    if self.device.provenance != Provenance::Created {
                        self.server.engine_mut().route_borrowed_verified(work)?;
                    } else {
                        self.server.engine_mut().route_applied(work)?;
                    }
                    self.control.phase = Phase::Ready;
                    return Ok(true);
                }
                if prefix(self.control.plan.ok_or(Fault::NotReady)?, i).is_none() {
                    self.control.phase = Phase::Routes(i + 1);
                    return Ok(true);
                }
                if self.device.provenance != Provenance::Created {
                    self.start_query(i, false)?;
                } else {
                    self.start_route(i, false, observe)?;
                }
                Ok(true)
            }
            Phase::Ready => {
                if self.control.plan.and_then(|p| p.ipv6).is_some()
                    && self.control.sample_at.is_none_or(|at| Instant::now() >= at)
                {
                    let p = self
                        .control
                        .plan
                        .and_then(|p| p.ipv6)
                        .ok_or(Fault::NotReady)?;
                    let core::Address::V6(a) = p.interface else {
                        return Err(Fault::InvalidInput.into());
                    };
                    self.control.watch = Some(self.device.io.watch_ipv6(
                        a.into(),
                        p.bits,
                        Self::deadline(self.limits.monitor_timeout)?,
                        self.limits.ipv6_watch,
                    )?);
                    self.control.sample_at = None;
                    return Ok(true);
                }
                Ok(false)
            }
            Phase::Remove(i) => {
                if i >= 2 {
                    let work = self.control.work.take().ok_or(Fault::NotReady)?;
                    if self.control.uncertain {
                        self.server
                            .engine_mut()
                            .route_failed(work, Fault::OutcomeUnknown)?;
                        observe(Event::CleanupUncertain {
                            reason: Fault::OutcomeUnknown,
                        });
                    } else {
                        self.server.engine_mut().route_removed(work)?;
                    }
                    self.control.phase = Phase::Released;
                    return Ok(true);
                }
                if prefix(self.control.plan.ok_or(Fault::NotReady)?, i).is_none() {
                    self.control.phase = Phase::Remove(i + 1);
                    return Ok(true);
                }
                self.start_query(i, true)?;
                Ok(true)
            }
            Phase::Released | Phase::Failed => Ok(false),
        }
    }
    pub(super) fn control_released(&self) -> bool {
        matches!(self.control.phase, Phase::Released | Phase::New)
    }
    pub(super) fn control_deadline(&self) -> Option<Instant> {
        if self.control.phase == Phase::Ready {
            self.control.sample_at
        } else if matches!(
            self.control.phase,
            Phase::Released | Phase::Failed | Phase::New
        ) {
            None
        } else {
            self.control.until
        }
    }
    /// Physically close all local sources independently, without sampling the
    /// logical clock. Original control ambiguity and external jobs remain visible.
    /// Repeated calls retain the original close_report and never close a recycled
    /// descriptor. debt() reports later original external-job retirement.
    pub fn close(&mut self, observe: &mut impl FnMut(Event<'id, 'cadet>)) {
        if self.closed.is_some() {
            return;
        }
        let ipc = self.server.shutdown(|e| observe(Event::Ipc(e)));
        let mut failure = self
            .control
            .prior_tun_close_error
            .as_ref()
            .map(|_| Error::Protocol(Fault::Io));
        self.stop_watch(observe);
        if let Some(mut route) = self.control.route.take()
            && let tun::RouteProgress::Complete(c) = route.job.cancel()
        {
            if c.submission != tun::RouteSubmission::Unsent {
                self.control.uncertain = true;
            }
            self.retain_control_close(c.close_error.as_ref());
            observe(Event::Route(c));
        }
        if let Some(mut query) = self.control.query.take()
            && let tun::RouteQueryProgress::Complete(c) = query.job.cancel()
        {
            self.retain_control_close(c.close_error());
            observe(Event::RouteQuery(c));
        }
        if let Some(work) = self.control.work.take()
            && let Err(e) = self.server.engine_mut().retire_routing(work)
            && failure.is_none()
        {
            failure = Some(e.into());
        }
        let backend = match self.cadet.close() {
            Ok(report) => {
                if let Some(report) = report
                    && let Err(e) = self.backend_lost(report, Fault::Closed, observe)
                    && failure.is_none()
                {
                    failure = Some(e);
                }
                report
            }
            Err(e) => {
                if failure.is_none() {
                    failure = Some(e.into());
                }
                None
            }
        };
        let mut removal_proven = false;
        let device = if !self.control.dead {
            let epoch = self.device.epoch();
            let may_prove = self.device.provenance == Provenance::Created
                && !self.control.uncertain
                && epoch.current();
            let loss = self.device.io.close();
            if (matches!(&loss.cause, tun::LossCause::ShortWrite { bytes, .. } if *bytes > 0)
                || loss
                    .pending
                    .as_ref()
                    .is_some_and(|id| id.helper_accepted_prefix() > 0))
                && let Some(output) = &self.output
                && loss.pending.as_ref() == Some(&output.write)
                && let Err(error) = self.server.engine_mut().exposed(output.effect)
                && failure.is_none()
            {
                failure = Some(error.into());
            }

            removal_proven = may_prove
                && loss.epoch == epoch
                && matches!(&loss.cause, tun::LossCause::Closed)
                && loss.close_error.is_none();
            if loss.close_error.is_some() {
                self.control.uncertain = true;
                if failure.is_none() {
                    failure = Some(Fault::Io.into());
                }
            }
            if !removal_proven
                && self.device.provenance == Provenance::Created
                && let Some(source) = self.source
                && let Err(e) = self
                    .server
                    .engine_mut()
                    .route_lost(source, Fault::OutcomeUnknown)
                && failure.is_none()
            {
                failure = Some(e.into());
            }
            // close() cannot perform a positive write; any earlier positive
            // short-write loss was already delivered by the actual TUN owner.
            if let Some(source) = self.source {
                match self.server.engine_mut().tun_lost(source, Fault::Closed) {
                    Ok(fact) => observe(Event::TunCoreLost(fact)),
                    Err(e) => {
                        if failure.is_none() {
                            failure = Some(e.into());
                        }
                    }
                }
            }
            self.control.dead = true;
            self.output = None;
            self.input = None;
            Some(loss)
        } else {
            None
        };
        if let Some(source) = self.source {
            let state = self.server.engine().route_state(source);
            let result = if self.device.provenance != Provenance::Created {
                match state {
                    Ok(
                        core::RouteState::BorrowedVerified | core::RouteState::BorrowedUnverified,
                    ) => self.server.engine_mut().release_borrowed_routes(source),
                    _ => Ok(()),
                }
            } else if removal_proven {
                // Fresh kernel-allocated nonpersistent interface removal is the
                // platform's owned-device close contract. This does not cover an
                // unresolved exposed route request that may outlive its socket.
                self.server.engine_mut().confirm_routes_absent(source)
            } else {
                Ok(())
            };
            if let Err(e) = result
                && failure.is_none()
            {
                failure = Some(e.into());
            }
        }
        // Finite fixed pools bound this explicit retirement walk. Uncredited
        // incoming data whose peer actually stopped is marked retired by core.
        let budget = self
            .server
            .engine()
            .buffers()
            .count()
            .saturating_add(self.links.len())
            .saturating_add(1);
        for _ in 0..budget {
            match self.release_finished() {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    if failure.is_none() {
                        failure = Some(e);
                    }
                    break;
                }
            }
        }
        let routes = self
            .source
            .and_then(|s| self.server.engine().route_state(s).ok())
            .unwrap_or(core::RouteState::Absent);
        let flows = self.server.engine().flows().count();
        let buffers = self.server.engine().buffers().count();
        let discoveries = self
            .links
            .iter()
            .flatten()
            .filter(|l| l.discovery.is_some_and(|d| d.queued))
            .count();
        if failure.is_none() && self.control.control_close_error.is_some() {
            failure = Some(Fault::Io.into());
        }
        self.closed = Some(Close {
            ipc,
            cadet: backend,
            tun: device,
            prior_tun_close_error: self.control.prior_tun_close_error.take(),
            control_close_error: self.control.control_close_error.take(),
            unconfirmed_control_closes: self.control.unconfirmed_control_closes,
            routes,
            flows,
            buffers,
            discoveries,
            failure,
            report: self.report,
        });
    }
}
fn v4mask(bits: u8) -> [u8; 4] {
    if bits == 0 {
        0u32.to_be_bytes()
    } else {
        (u32::MAX << (32 - u32::from(bits))).to_be_bytes()
    }
}

fn native_action(
    plan: core::RoutingRequest<'_>,
    i: u8,
    mtu: u32,
) -> Result<Option<tun::Action>, Fault> {
    Ok(match i {
        0 => Some(tun::Action::Mtu(mtu)),
        1 => match plan.ipv4 {
            Some(p) => match p.interface {
                core::Address::V4(a) => Some(tun::Action::Ipv4Address(a.into())),
                _ => return Err(Fault::InvalidInput),
            },
            None => None,
        },
        2 => plan
            .ipv4
            .map(|p| tun::Action::Ipv4Netmask(v4mask(p.bits).into())),
        3 => match plan.ipv6 {
            Some(p) => match p.interface {
                core::Address::V6(a) => Some(tun::Action::Ipv6Address {
                    address: a.into(),
                    prefix: p.bits,
                }),
                _ => return Err(Fault::InvalidInput),
            },
            None => None,
        },
        4 => Some(tun::Action::LinkUp(true)),
        _ => None,
    })
}
