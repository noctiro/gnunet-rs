//! Original accepted sources and retained immutable response writes.
use super::*;
impl<'id, 'slots> Server<'id, 'slots> {
    /// Admit an actual initialized source using the standard ACL and kernel
    /// credentials before creating a pure client generation.
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
            PeerAddress::Tcp(ip) => self.options.access.allows(ip.ip()),
            PeerAddress::Unix => self.unix.allows(&connection)?,
        };
        if !allowed {
            drop(connection);
            observe(Event::Rejected(address));
            return Ok(None);
        }
        if self.failed || self.shutdown.is_some() {
            drop(connection);
            return Err(Fault::Closed.into());
        }
        let index = self
            .apps
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let first = Instant::now()
            .checked_add(self.limits.first_input)
            .ok_or(Fault::Overflow)?;
        let mut writes = VecDeque::new();
        writes
            .try_reserve(self.limits.output_frames)
            .map_err(|_| Fault::Capacity)?;
        let mut io = Framed::new(connection, self.framing())?;
        let client = match self.core.attach_client() {
            Ok(client) => client,
            Err(error) => {
                io.retire();
                return Err(error.into());
            }
        };
        self.apps[index] = Some(App {
            client,
            io: Some(io),
            writes,
            first: Some(first),
            partial: None,
            cursor: 0,
            held_now: None,
            detached: false,
            retire_reason: Fault::Closed,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        self.restart_progress();
        observe(Event::Accepted(client));
        Ok(Some(client))
    }
    pub(super) fn stop_app(
        &mut self,
        index: usize,
        cause: CloseCause,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
        if let Some(mut io) = app.io.take() {
            io.retire();
            drop(io);
            self.accept.client_closed();
            app.first = None;
            app.partial = None;
            app.held_now = None;
            app.retire_reason = match &cause {
                CloseCause::Eof => Fault::Closed,
                CloseCause::Shutdown => Fault::Cancelled,
                CloseCause::Deadline => Fault::Deadline,
                CloseCause::Fault(Error::Protocol(error)) => *error,
                CloseCause::Fault(Error::Cadet(cadet::Error::Protocol(error))) => *error,
                CloseCause::Fault(Error::Entropy(_)) => Fault::Unavailable,
                CloseCause::Fault(_) => Fault::Io,
            };
            self.report.closed = self.report.closed.saturating_add(1);
            observe(Event::Closed {
                client: app.client,
                cause,
            });
        }
        self.retire_app(index, observe)
    }
    fn retire_app(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let app = self.apps[index].as_ref().ok_or(Fault::Stale)?;
        if app.io.is_some() {
            return Err(Fault::Conflict.into());
        }
        let client = app.client;
        let reason = app.retire_reason;
        while let Some(write) = self.apps[index]
            .as_ref()
            .ok_or(Fault::Stale)?
            .writes
            .front()
        {
            let (id, admitted, outcome) = (
                write.id,
                write.admitted,
                if write.completed {
                    Completion::Written
                } else if write.written == 0 {
                    Completion::Unsent(reason)
                } else {
                    Completion::Lost(reason)
                },
            );
            self.terminal(id, outcome, admitted, observe)?;
            let _removed = self.apps[index]
                .as_mut()
                .ok_or(Fault::Stale)?
                .writes
                .pop_front();
        }
        if !self.apps[index].as_ref().ok_or(Fault::Stale)?.detached {
            match self.core.detach_client(client) {
                Ok(()) | Err(Fault::StaleGeneration) => {}
                Err(error) => return Err(error.into()),
            }
            self.apps[index].as_mut().ok_or(Fault::Stale)?.detached = true;
        }
        self.apps[index] = None;
        Ok(())
    }
    pub(super) fn reap_apps(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        for i in 0..self.apps.len() {
            if self.apps[i].as_ref().is_some_and(|a| a.io.is_none()) {
                self.retire_app(i, observe)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn app_input(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let app = self.apps[index].as_ref().ok_or(Fault::Stale)?;
        if app.io.as_ref().and_then(|io| io.frame()).is_none() {
            return Ok(false);
        }
        // Freeze the original complete input's logical origin once. Capacity
        // retries retain that same frame, native classification bound and time.
        let now = match app.held_now {
            Some(now) => now,
            None => {
                let now = self.now()?;
                self.apps[index].as_mut().ok_or(Fault::Stale)?.held_now = Some(now);
                now
            }
        };
        let app = self.apps[index].as_ref().ok_or(Fault::Stale)?;
        let frame = app
            .io
            .as_ref()
            .and_then(|io| io.frame())
            .ok_or(Fault::Stale)?;
        let client = app.client;
        let request = match ClientRequest::decode(frame) {
            Ok(request) => request,
            Err(Fault::Unsupported) if self.options.tolerant => {
                if !self.apps[index]
                    .as_mut()
                    .and_then(|a| a.io.as_mut())
                    .ok_or(Fault::Stale)?
                    .release_frame()
                {
                    return Err(Fault::Conflict.into());
                }
                let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
                app.partial = None;
                app.held_now = None;
                return Ok(true);
            }
            Err(error) => {
                self.stop_app(index, CloseCause::Fault(error.into()), observe)?;
                return Ok(true);
            }
        };
        let result = self
            .core
            .client_request(client, request, now, &mut self.ports_provider);
        match result {
            Ok(()) => {
                let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
                if !app.io.as_mut().ok_or(Fault::Closed)?.release_frame() {
                    return Err(Fault::Conflict.into());
                }
                app.first = None;
                app.partial = None;
                app.held_now = None;
                self.report.inputs = self.report.inputs.saturating_add(1);
                observe(Event::Input(client));
                Ok(true)
            }
            Err(Fault::WouldBlock | Fault::NotReady) => Ok(false),
            Err(error) => {
                let error = self
                    .core_result::<()>(Err(error))
                    .err()
                    .ok_or(Fault::Conflict)?;
                self.stop_app(index, CloseCause::Fault(error), observe)?;
                Ok(true)
            }
        }
    }
    pub(super) fn queue_client(
        &mut self,
        id: EffectId<'id>,
        client: Client<'id>,
        frame: OwnedFrame,
        charge: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let Some(index) = self.apps.iter().position(|a| {
            a.as_ref()
                .is_some_and(|a| a.client == client && a.io.is_some())
        }) else {
            self.reject(id, Fault::Closed, observe)?;
            return Ok(true);
        };
        let origin = self.next_output.checked_add(1).ok_or(Fault::Overflow)?;
        let hard = self.hard()?;
        let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
        let retained = app.writes.iter().try_fold(0usize, |sum, w| {
            sum.checked_add(w.charge).ok_or(Fault::Overflow)
        })?;
        if charge < frame.len() {
            return Err(Fault::Conflict.into());
        }
        if charge > self.limits.output_bytes {
            self.stop_app(index, CloseCause::Fault(Fault::Capacity.into()), observe)?;
            return Ok(true);
        }
        if app.writes.len() == self.limits.output_frames
            || retained
                .checked_add(charge)
                .is_none_or(|n| n > self.limits.output_bytes)
            || !app
                .io
                .as_ref()
                .ok_or(Fault::Closed)?
                .capacity(frame.bytes().len(), Class::Ordinary)
        {
            // Temporary output pressure retains the original core effect. The
            // oldest actual queued write keeps its fixed physical hard bound.
            return Ok(false);
        }
        match app
            .io
            .as_mut()
            .ok_or(Fault::Closed)?
            .enqueue_owned(frame, origin, Class::Ordinary)
        {
            Ok(()) => {}
            Err(rejected) => {
                let cause = rejected.reason;
                self.stop_app(index, CloseCause::Fault(cause.into()), observe)?;
                return Ok(true);
            }
        }
        self.next_output = origin;
        app.writes.push_back(Write {
            id,
            origin,
            hard,
            charge,
            written: 0,
            completed: false,
            admitted: false,
        });
        self.core.admit_effect(id)?;
        self.apps[index]
            .as_mut()
            .ok_or(Fault::Stale)?
            .writes
            .back_mut()
            .ok_or(Fault::Stale)?
            .admitted = true;
        observe(Event::Queued { client, effect: id });
        Ok(true)
    }
    fn app_step(
        &mut self,
        index: usize,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        for offset in 0..2 {
            let selected = (self.apps[index].as_ref().ok_or(Fault::Stale)?.cursor + offset) % 2;
            let result = if selected == 0 {
                let result = self.apps[index]
                    .as_mut()
                    .and_then(|a| a.io.as_mut())
                    .ok_or(Fault::Closed)?
                    .poll_write(cx);
                match result {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        self.stop_app(index, CloseCause::Fault(error.into()), observe)?;
                        Poll::Ready(Ok(Progress::Activity))
                    }
                    Poll::Ready(Ok(progress)) => {
                        let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
                        let write = app.writes.front_mut().ok_or(Fault::Stale)?;
                        if write.origin != progress.origin || !write.admitted {
                            return Poll::Ready(Err(Fault::Conflict.into()));
                        }
                        write.written = write
                            .written
                            .checked_add(progress.bytes)
                            .ok_or(Fault::Overflow)?;
                        write.completed = progress.complete;
                        let id = write.id;
                        let client = app.client;
                        self.report.written_bytes = self
                            .report
                            .written_bytes
                            .saturating_add(progress.bytes as u64);
                        observe(Event::Write {
                            client,
                            effect: id,
                            bytes: progress.bytes,
                            complete: progress.complete,
                        });
                        if progress.complete {
                            self.terminal(id, Completion::Written, true, observe)?;
                            let _removed = self.apps[index]
                                .as_mut()
                                .ok_or(Fault::Stale)?
                                .writes
                                .pop_front();
                            self.report.written_frames =
                                self.report.written_frames.saturating_add(1);
                        }
                        Poll::Ready(Ok(Progress::Activity))
                    }
                }
            } else if self.apps[index]
                .as_ref()
                .and_then(|a| a.io.as_ref())
                .is_some_and(|io| io.frame().is_some())
            {
                if self.app_input(index, observe)? {
                    Poll::Ready(Ok(Progress::Activity))
                } else {
                    Poll::Pending
                }
            } else {
                let result = self.apps[index]
                    .as_mut()
                    .and_then(|a| a.io.as_mut())
                    .ok_or(Fault::Closed)?
                    .poll_read(cx);
                match result {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(ReadStep::Eof)) => {
                        self.stop_app(index, CloseCause::Eof, observe)?;
                        Poll::Ready(Ok(Progress::Activity))
                    }
                    Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                        let until = Instant::now()
                            .checked_add(self.limits.partial_input)
                            .ok_or(Fault::Overflow)?;
                        let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
                        // The first-byte phase covers classification/admission,
                        // including a complete held frame under backpressure.
                        if bytes > 0 {
                            app.partial.get_or_insert(until);
                        }
                        Poll::Ready(Ok(Progress::Activity))
                    }
                    Poll::Ready(Err(error)) => {
                        self.stop_app(index, CloseCause::Fault(error.into()), observe)?;
                        Poll::Ready(Ok(Progress::Activity))
                    }
                }
            };
            if result.is_ready() {
                if let Some(app) = &mut self.apps[index] {
                    app.cursor = (selected + 1) % 2;
                }
                return result;
            }
        }
        Poll::Pending
    }
    pub(super) fn poll_apps(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        for offset in 0..self.apps.len() {
            let index = (self.app_cursor + offset) % self.apps.len();
            if self.apps[index].as_ref().is_some_and(|a| a.io.is_some()) {
                let result = self.app_step(index, cx, observe);
                if result.is_ready() {
                    self.app_cursor = (index + 1) % self.apps.len();
                    return result;
                }
            }
        }
        Poll::Pending
    }
}
