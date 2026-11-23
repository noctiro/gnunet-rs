//! Accepted source ownership and retained official frame cursors.
use super::*;

impl<'view, 'scope, 'spec, 'slots, 'bytes, C: Clock>
    Driver<'view, 'scope, 'spec, 'slots, 'bytes, C>
{
    /// Admit one already accepted physical connection after peer policy. This is
    /// also a safe embedding port; it performs no fake listener readiness.
    pub fn admit(&mut self, stream: Connection, peer: PeerAddress) -> Result<bool, Error> {
        if matches!(peer, PeerAddress::Unix)
            && !self.state.unix_access.allows(&stream).map_err(Error::Io)?
        {
            drop(stream);
            return Ok(false);
        }
        if let PeerAddress::Tcp(address) = peer
            && !self.options.access.allows(address.ip())
        {
            drop(stream);
            return Ok(false);
        }
        if self.state.sessions.len() + self.state.persisted.len() >= self.state.limits.clients {
            drop(stream);
            return Err(Error::Capacity);
        }
        let l = self.state.limits;
        let io = FramedConnection::new(stream, l.frame_bytes, l.tx_bytes, l.tx_frames, l.io_slice)
            .map_err(|_| Error::Capacity)?;
        let id = self.owner.connect()?;
        self.state.sessions.push(Session {
            id,
            io,
            send_first: false,
        });
        self.state.counters.accepted = self.state.counters.accepted.saturating_add(1);
        Ok(true)
    }
    pub(super) fn close(&mut self, index: usize, resource: bool) -> Result<(), Error> {
        let session = self.state.sessions.remove(index);
        if self.state.next_session > index {
            self.state.next_session -= 1;
        }
        if self.state.next_session >= self.state.sessions.len() {
            self.state.next_session = 0;
        }
        let persisted = self.owner.client_persisted(session.id)?;
        self.owner.disconnect(session.id)?;
        if persisted {
            // service.c:finish_client_drop frees only the network handle for a
            // persisted requester. Retain its actual descriptor until the
            // enclosing process State ends, without resuming EMFILE acceptance.
            self.state.persisted.push(session.io.into_connection());
        } else {
            drop(session);
            self.state.control_accept.client_closed();
            self.state.counters.closed = self.state.counters.closed.saturating_add(1);
            self.state.counters.resource_closes = self
                .state
                .counters
                .resource_closes
                .saturating_add(u64::from(resource));
        }
        Ok(())
    }
    pub(super) fn handoff(&mut self) -> Result<bool, Error> {
        let Some(frame) = self.owner.frame() else {
            return Ok(false);
        };
        let id = frame.client;
        let ticket = frame.ticket;
        let index = self
            .state
            .sessions
            .iter()
            .position(|session| session.id == id)
            .ok_or(Error::Mapping)?;
        if let Err(error) = self.state.sessions[index].io.enqueue(frame.bytes) {
            self.state.diagnostic(Diagnostic::Peer(error));
            self.close(index, true)?;
        } else {
            self.owner.release_frame(ticket)?;
            self.state.counters.handed_off = self.state.counters.handed_off.saturating_add(1);
            self.owner
                .set_mq_length(id, self.state.sessions[index].io.mq_length())?;
        }
        Ok(true)
    }
    pub(super) fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Error>> {
        if !self.state.control_accept.ready() {
            return Poll::Pending;
        }
        let Some(control) = self.state.control.as_ref() else {
            return Poll::Pending;
        };
        for listener in control.listeners() {
            if let Poll::Ready(result) = listener.poll_canonical_connection(cx) {
                let accepted = match result {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        match self.state.control_accept.failed(error) {
                            SocketEvent::Failed(AcceptError::Initialization(error)) => self
                                .state
                                .diagnostic(Diagnostic::AcceptedSocketFailure(error)),
                            SocketEvent::Failed(error @ AcceptError::Accept(_))
                                if error.is_emfile() => {}
                            SocketEvent::Failed(AcceptError::Accept(error)) => {
                                self.state.diagnostic(Diagnostic::Accept(error))
                            }
                            SocketEvent::Failed(AcceptError::Credentials(error)) => {
                                self.state.diagnostic(Diagnostic::Credentials(error))
                            }
                            SocketEvent::Diagnostic(diagnostic) => self
                                .state
                                .diagnostic(Diagnostic::AcceptedSocket(diagnostic)),
                        }
                        return Poll::Ready(Ok(true));
                    }
                };
                let (stream, peer, diagnostics) = accepted.into_parts();
                for diagnostic in diagnostics {
                    self.state
                        .diagnostic(Diagnostic::AcceptedSocket(diagnostic));
                }
                match self.admit(stream, peer) {
                    Ok(_admitted) => return Poll::Ready(Ok(true)),
                    // In admit, only the original credential query returns Io.
                    Err(Error::Io(error)) => {
                        self.state.diagnostic(Diagnostic::Credentials(error));
                        return Poll::Ready(Ok(true));
                    }
                    Err(
                        Error::Capacity
                        | Error::Core(
                            gnunet_arm_service_core::Error::Capacity
                            | gnunet_arm_service_core::Error::Exhausted,
                        ),
                    ) => return Poll::Ready(Ok(true)),
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        }
        Poll::Pending
    }
    pub(super) fn receive_session(
        &mut self,
        index: usize,
        cx: &mut Context<'_>,
    ) -> Result<bool, Error> {
        let id = self.state.sessions[index].id;
        let now = self.utc()?;
        let buffered = self.state.sessions[index].io.buffered_bytes();
        match self.state.sessions[index].io.poll_receive(cx) {
            Poll::Ready(Ok(Received::Frame(bytes))) => {
                match self.owner.receive(id, bytes, now, self.rows) {
                    Ok(()) => {
                        if let Err(error) = self.state.sessions[index].io.consume_frame() {
                            self.state.diagnostic(Diagnostic::Peer(error));
                            self.close(index, false)?;
                        }
                        self.state.counters.received =
                            self.state.counters.received.saturating_add(1);
                    }
                    Err(gnunet_arm_service_core::Error::Busy) => {
                        return Ok(self.state.sessions[index].io.buffered_bytes() != buffered);
                    }
                    Err(gnunet_arm_service_core::Error::Malformed) => self.close(index, false)?,
                    Err(
                        gnunet_arm_service_core::Error::Capacity
                        | gnunet_arm_service_core::Error::Exhausted,
                    ) => self.close(index, true)?,
                    Err(error) => return Err(error.into()),
                }
                Ok(true)
            }
            Poll::Ready(Ok(Received::Eof { partial })) => {
                if partial {
                    self.state
                        .diagnostic(Diagnostic::Peer(framed::Error::Malformed));
                }
                self.close(index, false)?;
                Ok(true)
            }
            Poll::Ready(Err(error)) => {
                self.state.diagnostic(Diagnostic::Peer(error));
                self.close(index, false)?;
                Ok(true)
            }
            Poll::Pending => Ok(self.state.sessions[index].io.buffered_bytes() != buffered),
        }
    }
    pub(super) fn send_session(
        &mut self,
        index: usize,
        cx: &mut Context<'_>,
    ) -> Result<bool, Error> {
        let id = self.state.sessions[index].id;
        match self.state.sessions[index].io.poll_send(cx) {
            Poll::Ready(Ok(true)) => {
                self.owner
                    .set_mq_length(id, self.state.sessions[index].io.mq_length())?;
                Ok(true)
            }
            Poll::Ready(Err(error)) => {
                self.state.diagnostic(Diagnostic::Peer(error));
                self.close(index, false)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    pub(super) fn poll_sessions(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let count = self.state.sessions.len();
        let first = self.state.next_session;
        for index in (first..count).chain(0..first) {
            let id = self.state.sessions[index].id;
            let send_first = self.state.sessions[index].send_first;
            for receive in [!send_first, send_first] {
                let progress = if receive {
                    self.receive_session(index, cx)?
                } else {
                    self.send_session(index, cx)?
                };
                if progress {
                    let count = self.state.sessions.len();
                    self.state.next_session = if count == 0 {
                        0
                    } else if self.state.sessions.get(index).is_some_and(|s| s.id == id) {
                        self.state.sessions[index].send_first = receive;
                        if index + 1 == count { 0 } else { index + 1 }
                    } else {
                        index % count
                    };
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
