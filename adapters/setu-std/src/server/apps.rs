//! Real application sockets, canonical admission and immutable bounded output.
use super::*;
impl<'id, 'slots> Server<'id, 'slots> {
    /// Admit one actual canonically initialized socket after address policy and
    /// kernel Unix credentials. No pure client exists for an unadmitted source.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<Option<CoreClient>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for diagnostic in diagnostics {
            observe(Event::Socket(SocketEvent::Diagnostic(diagnostic)));
        }
        let allowed = match address {
            PeerAddress::Tcp(p) => self.options.access.allows(p.ip()),
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
        let mut writes = VecDeque::new();
        writes
            .try_reserve(self.limits.output_frames)
            .map_err(|_| Fault::Capacity)?;
        let client = match self.core.connect() {
            Ok(c) => c,
            Err(e) => {
                io.retire();
                return Err(e.into());
            }
        };
        self.apps[index] = Some(App {
            client: client.clone(),
            io,
            held: None,
            writes,
            cursor: 0,
            read_hard: None,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client.clone()));
        Ok(Some(client))
    }
    pub(super) fn stop_app(
        &mut self,
        index: usize,
        cause: CloseCause,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let mut app = self.apps[index].take().ok_or(Fault::Stale)?;
        app.io.retire();
        app.held = None;
        app.writes.clear();
        self.accept.client_closed();
        self.core.client_closed(&app.client)?;
        self.report.closed = self.report.closed.saturating_add(1);
        observe(Event::Closed {
            client: app.client,
            cause,
        });
        Ok(())
    }
    fn app_frame(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let Some(app) = &self.apps[index] else {
            return Ok(false);
        };
        let Some(bytes) = app.io.frame() else {
            return Ok(false);
        };
        let client = app.client.clone();
        // Actual CADET has no oversized-element fragmentation protocol. Reject
        // an impossible ADD at its real source before accepting set membership.
        let frame = Frame::decode(bytes)?;
        if frame.header().message_type() == mt::SETU_ADD
            && bytes.len().saturating_sub(8) > MAX_APPLICATION_MESSAGE_SIZE - 8
        {
            self.stop_app(index, CloseCause::Fault(Fault::TooLarge.into()), observe)?;
            return Ok(true);
        }
        let now = self.now()?;
        let expires = self.expires(now)?;
        let result = self.core.receive_client(&client, bytes, now, expires);
        match result {
            Ok(_) => {
                let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
                if !app.io.release_frame() {
                    return Err(Fault::Stale.into());
                }
                self.report.inputs = self.report.inputs.saturating_add(1);
                observe(Event::Input(client));
                Ok(true)
            }
            Err(Fault::Unsupported) if self.options.tolerant => {
                self.apps[index]
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .io
                    .release_frame();
                Ok(true)
            }
            Err(e) => {
                self.stop_app(index, CloseCause::Fault(e.into()), observe)?;
                Ok(true)
            }
        }
    }
    fn app(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        for n in 0..3 {
            let class = (self.apps[index].as_ref().ok_or(Fault::Stale)?.cursor + n) % 3;
            let result = match class {
                0 => {
                    let written = self.apps[index]
                        .as_mut()
                        .ok_or(Fault::Stale)?
                        .io
                        .poll_write(cx);
                    match written {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            self.stop_app(index, CloseCause::Fault(e.into()), observe)?;
                            Poll::Ready(Ok(Progress::Activity))
                        }
                        Poll::Ready(Ok(p)) => {
                            let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
                            if p.complete {
                                let (origin, _) = app.writes.pop_front().ok_or(Fault::Stale)?;
                                if origin != p.origin {
                                    return Poll::Ready(Err(Fault::Stale.into()));
                                }
                                self.report.written_frames =
                                    self.report.written_frames.saturating_add(1);
                            }
                            self.report.written_bytes =
                                self.report.written_bytes.saturating_add(p.bytes as u64);
                            observe(Event::Write {
                                client: app.client.clone(),
                                bytes: p.bytes,
                                complete: p.complete,
                            });
                            Poll::Ready(Ok(Progress::Activity))
                        }
                    }
                }
                1 => {
                    if self.apps[index]
                        .as_ref()
                        .ok_or(Fault::Stale)?
                        .io
                        .frame()
                        .is_some()
                    {
                        if self.app_frame(index, observe)? {
                            Poll::Ready(Ok(Progress::Activity))
                        } else {
                            Poll::Pending
                        }
                    } else {
                        match self.apps[index]
                            .as_mut()
                            .ok_or(Fault::Stale)?
                            .io
                            .poll_read(cx)
                        {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Ok(ReadStep::Progress { complete, .. })) => {
                                let hard = self.hard()?;
                                let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
                                if complete {
                                    app.read_hard = None;
                                } else {
                                    app.read_hard.get_or_insert(hard);
                                }
                                Poll::Ready(Ok(Progress::Activity))
                            }
                            Poll::Ready(Ok(ReadStep::Eof)) => {
                                self.stop_app(index, CloseCause::Eof, observe)?;
                                Poll::Ready(Ok(Progress::Activity))
                            }
                            Poll::Ready(Err(e)) => {
                                self.stop_app(index, CloseCause::Fault(e.into()), observe)?;
                                Poll::Ready(Ok(Progress::Activity))
                            }
                        }
                    }
                }
                _ => {
                    let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
                    if let Some((frame, origin, hard)) = app.held.take() {
                        match app.io.enqueue_owned(frame, origin, Class::Ordinary) {
                            Ok(()) => {
                                app.writes.push_back((origin, hard));
                                observe(Event::Queued(app.client.clone()));
                                Poll::Ready(Ok(Progress::Activity))
                            }
                            Err(rejected) => {
                                let reason = rejected.reason;
                                app.held = Some((rejected.value.0, rejected.value.1, hard));
                                if matches!(reason, Fault::Capacity | Fault::WouldBlock) {
                                    Poll::Pending
                                } else {
                                    return Poll::Ready(Err(reason.into()));
                                }
                            }
                        }
                    } else {
                        Poll::Pending
                    }
                }
            };
            if result.is_ready() {
                if let Some(app) = &mut self.apps[index] {
                    app.cursor = (class + 1) % 3;
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
        for n in 0..self.apps.len() {
            let i = (self.cursor + n) % self.apps.len();
            if self.apps[i].is_some() {
                let p = self.app(cx, i, observe);
                if p.is_ready() {
                    self.cursor = (i + 1) % self.apps.len();
                    return p;
                }
            }
        }
        Poll::Pending
    }
    fn queue_app(
        &mut self,
        client: &CoreClient,
        bytes: Vec<u8>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let Some(index) = self
            .apps
            .iter()
            .position(|a| a.as_ref().is_some_and(|a| a.client == *client))
        else {
            return Ok(());
        };
        let hard = self.hard()?;
        let origin = self.next_output.checked_add(1).ok_or(Fault::Overflow)?;
        self.next_output = origin;
        let app = self.apps[index].as_mut().ok_or(Fault::Stale)?;
        if app.held.is_some() {
            self.stop_app(index, CloseCause::Fault(Fault::Capacity.into()), observe)?;
            return Ok(());
        }
        match app
            .io
            .enqueue_owned(OwnedFrame::new(bytes), origin, Class::Ordinary)
        {
            Ok(()) => {
                app.writes.push_back((origin, hard));
                observe(Event::Queued(client.clone()));
            }
            Err(rejected) => {
                if matches!(rejected.reason, Fault::Capacity | Fault::WouldBlock) {
                    app.held = Some((rejected.value.0, rejected.value.1, hard));
                } else {
                    self.stop_app(index, CloseCause::Fault(rejected.reason.into()), observe)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn results(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        if let Some(incoming) = self.core.next_incoming()? {
            let mut bytes = buffer(self.limits.frame_bytes)?;
            match incoming.encode(&mut bytes) {
                Ok(n) => {
                    bytes.truncate(n);
                    self.queue_app(&incoming.client, bytes, observe)?
                }
                Err(e) => {
                    if let Some(index) = self
                        .apps
                        .iter()
                        .position(|a| a.as_ref().is_some_and(|a| a.client == incoming.client))
                    {
                        self.stop_app(index, CloseCause::Fault(e.into()), observe)?;
                    }
                }
            }
            return Ok(true);
        }
        if let Some(result) = self.core.next_result() {
            let mut bytes = buffer(self.limits.frame_bytes)?;
            match result.encode(&mut bytes) {
                Ok(n) => {
                    bytes.truncate(n);
                    self.queue_app(&result.client, bytes, observe)?
                }
                Err(e) => {
                    // Even terminal output must fail at the real app source if its
                    // official wrapper cannot fit; never send a private fragment.
                    if let Some(index) = self
                        .apps
                        .iter()
                        .position(|a| a.as_ref().is_some_and(|a| a.client == result.client))
                    {
                        self.stop_app(index, CloseCause::Fault(e.into()), observe)?;
                    }
                }
            }
            return Ok(true);
        }
        Ok(false)
    }
}
