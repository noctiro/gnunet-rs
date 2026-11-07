//! Canonical admission and per-original-MQ frame/output/debt ownership.
use super::*;
impl<'id, 'store, 'bytes> Server<'id, 'store, 'bytes> {
    /// Admit an actual canonical Unix/TCP accepted stream. ACL and real Unix
    /// credentials precede pure attach_client. Any rejection closes that source.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<Option<Client<'id>>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for diagnostic in diagnostics {
            observe(Event::Socket(SocketEvent::Diagnostic(diagnostic)));
        }
        let allowed = match address {
            PeerAddress::Tcp(peer) => self.options.access.allows(peer.ip()),
            PeerAddress::Unix => self.unix.allows(&connection)?,
        };
        if !allowed {
            drop(connection);
            observe(Event::Rejected(address));
            return Ok(None);
        }
        if self.shutdown.is_some() {
            drop(connection);
            return Err(Fault::Closed.into());
        }
        let index = self
            .apps
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let mut io = Framed::new(connection, self.framing())?;
        let client = match self.core.attach_client() {
            Ok(c) => c,
            Err(e) => {
                io.retire();
                return Err(e.into());
            }
        };
        self.apps[index] = Some(App {
            client,
            io,
            requests: 0,
            blocked: false,
            held: None,
            queued: None,
            read_hard: None,
            send_hard: None,
            cursor: 0,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client));
        Ok(Some(client))
    }
    fn retire(
        &mut self,
        client: Client<'id>,
        request: Request<'id>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        if self.core.request_client(request)? != client {
            return Err(Fault::StaleGeneration.into());
        }
        let info = self.core.request_info(request)?;
        self.core.retire_request(request)?;
        if let Some(app) = self
            .apps
            .iter_mut()
            .flatten()
            .find(|app| app.client == client)
        {
            app.requests = app.requests.checked_sub(1).ok_or(Fault::Conflict)?;
            if app.requests == 0 {
                app.send_hard = None;
            }
        }
        self.report.retired_requests = self.report.retired_requests.saturating_add(1);
        observe(Event::Retired {
            client,
            request,
            info,
        });
        Ok(())
    }
    pub(super) fn stop(
        &mut self,
        index: usize,
        cause: CloseCause,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let mut app = self.apps[index].take().ok_or(Fault::StaleGeneration)?;
        // Real close before core.client_lost and before original metadata release.
        app.io.retire();
        app.held = None;
        app.queued = None;
        self.accept.client_closed();
        self.report.closed = self.report.closed.saturating_add(1);
        let loss = self.core.client_lost(app.client, cause.fault());
        let mut failure = match loss {
            Ok(_) => None,
            Err(e) => {
                observe(Event::CleanupFailed(e));
                Some(e.into())
            }
        };
        observe(Event::Closed {
            client: app.client,
            cause,
            loss: loss.ok(),
        });
        loop {
            let next = self
                .core
                .requests()
                .find(|request| self.core.request_client(*request) == Ok(app.client));
            let Some(request) = next else {
                break;
            };
            if let Err(error) = self.retire(app.client, request, observe) {
                if failure.is_none() {
                    failure = Some(error);
                }
                break;
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    pub(super) fn hard_limits(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let now = Instant::now();
        for i in 0..self.apps.len() {
            let Some(app) = &self.apps[i] else {
                continue;
            };
            let expired = app.read_hard.is_some_and(|at| now >= at)
                || app.send_hard.is_some_and(|at| now >= at)
                || app.held.as_ref().is_some_and(|h| now >= h.output.hard)
                || app.queued.is_some_and(|q| now >= q.hard);
            let drained = self.shutdown.is_some()
                && app.requests == 0
                && app.held.is_none()
                && app.queued.is_none();
            if expired || drained {
                self.stop(
                    i,
                    if expired {
                        CloseCause::Deadline
                    } else {
                        CloseCause::Shutdown
                    },
                    observe,
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn input(
        &mut self,
        index: usize,
        now: AbsoluteTime,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let app = self.apps[index].as_ref().ok_or(Fault::StaleGeneration)?;
        let Some(bytes) = app.io.frame() else {
            return Ok(false);
        };
        let client = app.client;
        let kind = Frame::decode(bytes)?.header().message_type();
        if self.options.tolerant
            && kind != mt::VPN_CLIENT_REDIRECT_TO_IP
            && kind != mt::VPN_CLIENT_REDIRECT_TO_SERVICE
        {
            let app = self.apps[index].as_mut().ok_or(Fault::StaleGeneration)?;
            if !app.io.release_frame() {
                return Err(Fault::Conflict.into());
            }
            app.read_hard = None;
            return Ok(true);
        }
        let request = match WireRequest::decode_with_profile(bytes, self.core.ipc_af()) {
            Ok(r) => r,
            Err(e) => {
                self.stop(index, CloseCause::Fault(e.into()), observe)?;
                return Ok(true);
            }
        };
        if app.requests >= self.limits.requests_per_client {
            return self.backpressure(index, observe);
        }
        // Core guarantees every Capacity/validation/overflow refusal is before
        // business mutation. Retain this complete original RX while TX drains.
        let send_hard = Self::hard(self.limits.send_timeout)?;
        match self.core.redirect(client, request, now) {
            Ok(request) => {
                let info = self.core.request_info(request)?;
                let app = self.apps[index].as_mut().ok_or(Fault::StaleGeneration)?;
                app.requests = app.requests.checked_add(1).ok_or(Fault::Overflow)?;
                app.send_hard.get_or_insert(send_hard);
                if !app.io.release_frame() {
                    return Err(Fault::Conflict.into());
                }
                app.read_hard = None;
                app.blocked = false;
                self.report.inputs = self.report.inputs.saturating_add(1);
                observe(Event::Input {
                    client,
                    request,
                    request_id: info.request_id,
                });
                Ok(true)
            }
            Err(Fault::Capacity | Fault::WouldBlock) => self.backpressure(index, observe),
            Err(e) => {
                self.stop(index, CloseCause::Fault(e.into()), observe)?;
                Ok(true)
            }
        }
    }
    fn backpressure(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let app = self.apps[index].as_mut().ok_or(Fault::StaleGeneration)?;
        if app.blocked {
            return Ok(false);
        }
        app.blocked = true;
        observe(Event::Backpressured(app.client));
        Ok(true)
    }
    fn output(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let app = self.apps[index].as_ref().ok_or(Fault::StaleGeneration)?;
        let client = app.client;
        if app.queued.is_some() || app.requests == 0 {
            return Ok(false);
        }
        if app.held.is_none() {
            let hard = app.send_hard.ok_or(Fault::Conflict)?;
            let Some(prepared) = self.core.prepare_client(client)? else {
                return Ok(false);
            };
            let effect = prepared.effect;
            let request = effect.request().ok_or(Fault::Conflict)?;
            let frame = match OwnedFrame::copy_from(prepared.bytes) {
                Ok(frame) => frame,
                Err(e) => {
                    self.core.reject_prepared(effect)?;
                    return Err(e.into());
                }
            };
            self.apps[index]
                .as_mut()
                .ok_or(Fault::StaleGeneration)?
                .held = Some(Held {
                frame,
                output: Output {
                    effect,
                    request,
                    hard,
                },
            });
        }
        let held = self.apps[index]
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .held
            .take()
            .ok_or(Fault::Conflict)?;
        match self.core.can_queue(held.output.effect) {
            Ok(()) => {}
            Err(Fault::Closed) => {
                self.core.reject_prepared(held.output.effect)?;
                self.retire(client, held.output.request, observe)?;
                return Ok(true);
            }
            Err(e) => {
                self.apps[index]
                    .as_mut()
                    .ok_or(Fault::StaleGeneration)?
                    .held = Some(held);
                return Err(e.into());
            }
        }
        let output = held.output;
        let app = self.apps[index].as_mut().ok_or(Fault::StaleGeneration)?;
        match app
            .io
            .enqueue_owned(held.frame, output.effect, Class::Ordinary)
        {
            Ok(()) => {
                app.queued = Some(output);
                self.report.queued = self.report.queued.saturating_add(1);
                observe(Event::Queued {
                    client,
                    request: output.request,
                    effect: output.effect,
                });
                self.core.queued(output.effect)?;
                Ok(true)
            }
            Err(rejected) => {
                let error = rejected.reason;
                app.held = Some(Held {
                    frame: rejected.value.0,
                    output,
                });
                if matches!(error, Fault::Capacity | Fault::WouldBlock) {
                    Ok(false)
                } else {
                    Err(error.into())
                }
            }
        }
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let app = self.apps[index].as_mut().ok_or(Fault::StaleGeneration)?;
        let client = app.client;
        let progress = match app.io.poll_write(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.stop(index, CloseCause::Fault(e.into()), observe)?;
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Ok(progress)) => progress,
        };
        let output = app.queued.ok_or(Fault::Conflict)?;
        if progress.origin != output.effect {
            return Poll::Ready(Err(Fault::StaleGeneration.into()));
        }
        self.report.written_bytes = self
            .report
            .written_bytes
            .saturating_add(progress.bytes as u64);
        if progress.complete {
            self.report.written_frames = self.report.written_frames.saturating_add(1);
        }
        observe(Event::Write {
            client,
            request: output.request,
            bytes: progress.bytes,
            complete: progress.complete,
        });
        self.core.exposed(output.effect)?;
        if progress.complete {
            self.core.written(output.effect)?;
            self.apps[index]
                .as_mut()
                .ok_or(Fault::StaleGeneration)?
                .queued = None;
            self.retire(client, output.request, observe)?;
        }
        Poll::Ready(Ok(Progress::Activity))
    }
    fn retired(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let client = self.apps[index]
            .as_ref()
            .ok_or(Fault::StaleGeneration)?
            .client;
        let next = self.core.requests().find(|request| {
            self.core.request_client(*request) == Ok(client)
                && self.core.request_info(*request).is_ok_and(|info| {
                    matches!(
                        info.outcome,
                        Outcome::Written
                            | Outcome::Unsent
                            | Outcome::Canceled
                            | Outcome::Lost { .. }
                    )
                })
        });
        if let Some(request) = next {
            self.retire(client, request, observe)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn app(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        now: AbsoluteTime,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        for n in 0..4 {
            let class = (self.apps[index]
                .as_ref()
                .ok_or(Fault::StaleGeneration)?
                .cursor
                + n)
                % 4;
            let result = match class {
                0 => self.write(cx, index, observe),
                1 => {
                    if self.output(index, observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                2 => {
                    if self.shutdown.is_some() {
                        Poll::Pending
                    } else if self.apps[index]
                        .as_ref()
                        .ok_or(Fault::StaleGeneration)?
                        .io
                        .frame()
                        .is_some()
                    {
                        if self.input(index, now, observe)? {
                            Poll::Ready(Ok(Progress::Activity))
                        } else {
                            Poll::Pending
                        }
                    } else {
                        match self.apps[index]
                            .as_mut()
                            .ok_or(Fault::StaleGeneration)?
                            .io
                            .poll_read(cx)
                        {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Ok(ReadStep::Eof)) => {
                                self.stop(index, CloseCause::Eof, observe)?;
                                Poll::Ready(Ok(Progress::Activity))
                            }
                            Poll::Ready(Err(e)) => {
                                self.stop(index, CloseCause::Fault(e.into()), observe)?;
                                Poll::Ready(Ok(Progress::Activity))
                            }
                            Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                                let hard = Self::hard(self.limits.input_timeout)?;
                                self.apps[index]
                                    .as_mut()
                                    .ok_or(Fault::StaleGeneration)?
                                    .read_hard
                                    .get_or_insert(hard);
                                Poll::Ready(Ok(Progress::Activity))
                            }
                        }
                    }
                }
                _ => {
                    if self.retired(index, observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
            };
            if result.is_ready() {
                if let Some(app) = &mut self.apps[index] {
                    app.cursor = (class + 1) % 4;
                }
                return result;
            }
        }
        Poll::Pending
    }
    pub(super) fn poll_apps(
        &mut self,
        cx: &mut Context<'_>,
        now: AbsoluteTime,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        for n in 0..self.apps.len() {
            let i = (self.app_cursor + n) % self.apps.len();
            if self.apps[i].is_some() {
                let result = self.app(cx, i, now, observe);
                if result.is_ready() {
                    self.app_cursor = (i + 1) % self.apps.len();
                    return result;
                }
            }
        }
        Poll::Pending
    }
}
