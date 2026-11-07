//! Native FS routing transitions over original owners.
use super::*;
impl PeerReply {
    /// Decode the retained original shape without replacing its raw bytes.
    fn local_input(&self) -> Result<ClientPut<'_>, ProtocolError> {
        match self {
            Self::Local(frame) => {
                let Response::Put(put) = Response::decode(frame.bytes())? else {
                    return Err(ProtocolError::Malformed);
                };
                Ok(put)
            }
            Self::Cadet { frame, metadata } => {
                let reply = fs_cadet::Reply::decode(frame.bytes())?;
                Ok(ClientPut {
                    block_type: reply.block_type,
                    expiration: reply.expiration,
                    // The original peer frame has none of these fields.
                    // Copy only the provider's explicit local observations.
                    last_transmission: metadata.last_transmission,
                    num_transmissions: metadata.num_transmissions,
                    respect_offered: metadata.respect_offered,
                    block: reply.block,
                })
            }
            Self::Gap { frame, metadata } => {
                let reply = gnunet_wire::official::fs_gap::Put::decode(frame.bytes())?;
                Ok(ClientPut {
                    block_type: reply.block_type,
                    expiration: reply.expiration,
                    // The original peer frame has none of these fields.
                    // Copy only the provider's explicit local observations.
                    last_transmission: metadata.last_transmission,
                    num_transmissions: metadata.num_transmissions,
                    respect_offered: metadata.respect_offered,
                    block: reply.block,
                })
            }
        }
    }
}
impl<'id, 'slots, 'seen, S: StorePort, L: LocationSigner, R: PeerRouter>
    Server<'id, 'slots, 'seen, S, L, R>
{
    fn peer_failure(&mut self, error: Arc<Error>, observe: &mut impl FnMut(Event)) {
        // A failed provider cannot remain as an unpolled source owner. Preserve
        // its primary cause independently of any actual physical close refusal.
        let error = match self.router.close() {
            Ok(()) => error,
            Err(cleanup) => {
                let scope = if error.is_fatal() {
                    FailureScope::Service
                } else {
                    FailureScope::Operation
                };
                Arc::new(Error::Route(
                    peers::PeerFailure::new(
                        peers::Backend::Provider,
                        ProviderFailure::new(Box::new(error), scope),
                        Some(cleanup),
                    )
                    .into_failure(),
                ))
            }
        };
        self.report.peer_shutdown = Some(PeerShutdown::Retired);
        self.report.peer_failure = Some(error.clone());
        self.fault(None, error, observe);
        self.peer_failed = true;
        let retained = self.peer_reply.as_ref().map(|(serial, _)| *serial);
        let mut i = 0;
        while i < self.routes.len() {
            let (serial, route) = self.routes[i];
            if retained == Some(serial) {
                self.peer_reply_ended = true;
                i += 1;
                continue;
            }
            self.routes.swap_remove(i);
            if let Err(error) = self.router.cancel(serial) {
                self.fault(
                    Some(route.client().value()),
                    Arc::new(Error::Route(error)),
                    observe,
                );
            }
            if let Err(error) = self.protocol.route_idle(route) {
                self.fault(
                    Some(route.client().value()),
                    Arc::new(Error::Protocol(error)),
                    observe,
                );
            }
        }
    }
    /// Recover the explicit failed provider only after its retained original
    /// result has settled. Recovery never replays an old route or changes IDs.
    pub fn recover_peer_router(
        &mut self,
        recover: impl FnOnce(&mut R) -> Result<(), ProviderFailure>,
    ) -> Result<(), Arc<Error>> {
        if self.closing || !self.peer_failed || !self.routes.is_empty() || self.peer_reply.is_some()
        {
            return Err(Arc::new(Error::Protocol(ProtocolError::WouldBlock)));
        }
        recover(&mut self.router).map_err(|error| Arc::new(Error::Route(error)))?;
        self.peer_failed = false;
        self.peer_shutdown_requested = false;
        self.report.peer_shutdown = None;
        self.tick.as_mut().reset(Instant::now());
        Ok(())
    }
    pub(super) fn poll_routes(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<()> {
        if self.ports_closed {
            return Poll::Pending;
        }
        let mut io_progress = false;
        let deliver = self.peer_reply.is_none();
        if !self.peer_failed {
            match self.router.poll(cx, deliver) {
                Poll::Pending => {}
                Poll::Ready(Ok(PeerProgress::Activity)) => io_progress = true,
                Poll::Ready(Ok(PeerProgress::Reply { route, frame })) if deliver => {
                    if self.routes.iter().any(|(serial, _)| *serial == route) {
                        self.peer_reply = Some((route, PeerReply::Local(frame)));
                        self.peer_reply_ended = false;
                    }
                    io_progress = true;
                }
                Poll::Ready(Ok(PeerProgress::CadetReply {
                    route,
                    frame,
                    metadata,
                })) if deliver => {
                    if self.routes.iter().any(|(serial, _)| *serial == route) {
                        self.peer_reply = Some((route, PeerReply::Cadet { frame, metadata }));
                        self.peer_reply_ended = false;
                    }
                    io_progress = true;
                }
                Poll::Ready(Ok(PeerProgress::GapReply {
                    route,
                    frame,
                    metadata,
                })) if deliver => {
                    if self.routes.iter().any(|(serial, _)| *serial == route) {
                        self.peer_reply = Some((route, PeerReply::Gap { frame, metadata }));
                        self.peer_reply_ended = false;
                    }
                    io_progress = true;
                }
                Poll::Ready(Ok(
                    PeerProgress::Reply { .. }
                    | PeerProgress::CadetReply { .. }
                    | PeerProgress::GapReply { .. },
                )) => {
                    self.peer_failure(Arc::new(Error::Protocol(ProtocolError::Capacity)), observe);
                    io_progress = true;
                }
                Poll::Ready(Ok(PeerProgress::Ended(serial))) => {
                    if self
                        .peer_reply
                        .as_ref()
                        .is_some_and(|(held, _)| *held == serial)
                    {
                        self.peer_reply_ended = true;
                    } else if let Some(i) = self.routes.iter().position(|(id, _)| *id == serial) {
                        let (_, route) = self.routes.swap_remove(i);
                        if let Err(error) = self.protocol.route_idle(route) {
                            self.fault(
                                Some(route.client().value()),
                                Arc::new(Error::Protocol(error)),
                                observe,
                            );
                        }
                    }
                    io_progress = true;
                }
                Poll::Ready(Err(error)) => {
                    self.peer_failure(Arc::new(Error::Route(error)), observe);
                    io_progress = true;
                }
            }
        }
        if !self.closing
            && !self.peer_failed
            && let Some(serial) = self.router.input_needed()
        {
            let result = if let Some((_, route)) = self.routes.iter().find(|(id, _)| *id == serial)
            {
                self.protocol
                    .route_snapshot(*route)
                    .map_err(|e| Arc::new(Error::Protocol(e)))
                    .and_then(|(search, seen)| {
                        self.router
                            .refresh(serial, search, seen)
                            .map_err(|e| Arc::new(Error::Route(e)))
                    })
            } else {
                Err(Arc::new(Error::Protocol(ProtocolError::StaleGeneration)))
            };
            if let Err(error) = result {
                // No current original input means no first admission. Physical
                // retirement preserves the exact provider cause/cleanup and
                // cannot turn a stale request into a different client route.
                self.peer_failure(error, observe);
            }
            io_progress = true;
        }
        if let Some((serial, frame)) = self.peer_reply.take() {
            let Some((_, route)) = self.routes.iter().find(|(id, _)| *id == serial).copied() else {
                self.peer_reply_ended = false;
                return Poll::Ready(());
            };
            if !self.ready(route.client()) {
                self.peer_reply = Some((serial, frame));
                return if io_progress {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                };
            }
            let result = (|| {
                let put = frame
                    .local_input()
                    .map_err(|e| Arc::new(Error::Protocol(e)))?;
                // CADET's reply prefix is 16 bytes; local ClientPut needs 32.
                // Allocate for the actual local result rather than its source.
                let length = Response::Put(put)
                    .encoded_len()
                    .map_err(|e| Arc::new(Error::Protocol(e)))?;
                let mut output = bytes(length)?;
                match self
                    .protocol
                    .prepare_peer(route, put, &mut output, self.now()?)
                    .map_err(|e| Arc::new(Error::Protocol(e)))?
                {
                    PeerResult::Ignored(reason) => observe(Event::Skipped {
                        query: route.query_id().value(),
                        reason,
                    }),
                    PeerResult::Reply(reply) => {
                        output.truncate(reply.bytes());
                        self.queue(reply.client(), OwnedFrame::new(output))?;
                        self.protocol
                            .commit_reply(reply)
                            .map_err(|e| Arc::new(Error::Protocol(e)))?;
                        self.report.peer_results = self.report.peer_results.saturating_add(1);
                        self.release_done(route.query_id(), observe)?;
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                self.fault(Some(route.client().value()), error, observe);
                self.close_client(route.client(), observe);
            }
            if std::mem::replace(&mut self.peer_reply_ended, false)
                && let Some(i) = self.routes.iter().position(|(id, _)| *id == serial)
            {
                let (_, route) = self.routes.swap_remove(i);
                if let Err(error) = self.protocol.route_idle(route) {
                    self.fault(
                        Some(route.client().value()),
                        Arc::new(Error::Protocol(error)),
                        observe,
                    );
                }
            }
            return Poll::Ready(());
        }
        if self.closing || self.peer_failed || self.routes.len() >= self.limits.route_slots {
            return if io_progress {
                Poll::Ready(())
            } else {
                Poll::Pending
            };
        }
        let route = match self.protocol.next_route() {
            Ok(Some(r)) => r,
            Ok(None) => {
                return if io_progress {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                };
            }
            Err(e) => {
                self.fault(None, Arc::new(Error::Protocol(e)), observe);
                self.closing = true;
                return Poll::Ready(());
            }
        };
        let Some(serial) = self.route_serial.checked_add(1) else {
            self.fault(
                None,
                Arc::new(Error::Protocol(ProtocolError::Overflow)),
                observe,
            );
            self.closing = true;
            return Poll::Ready(());
        };
        let result = self
            .protocol
            .seen(route.query_id())
            .map_err(|e| Arc::new(Error::Protocol(e)))
            .and_then(|seen| {
                self.router
                    .start(serial, route.search(), seen)
                    .map_err(|e| Arc::new(Error::Route(e)))
            });
        self.route_serial = serial;
        match result {
            Ok(RouteAdmission::Queued) => self.routes.push((serial, route)),
            Ok(RouteAdmission::Idle | RouteAdmission::Refused) => {
                if let Err(e) = self.protocol.route_idle(route) {
                    self.fault(
                        Some(route.client().value()),
                        Arc::new(Error::Protocol(e)),
                        observe,
                    );
                }
            }
            Err(e) => {
                self.fault(Some(route.client().value()), e, observe);
                if let Err(e) = self.protocol.route_idle(route) {
                    self.fault(
                        Some(route.client().value()),
                        Arc::new(Error::Protocol(e)),
                        observe,
                    );
                }
            }
        }
        Poll::Ready(())
    }
}
