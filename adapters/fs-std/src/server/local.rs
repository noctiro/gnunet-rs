//! Native FS local transitions over original owners.
use super::*;
enum Delivery {
    Done,
    Resolve(Pending),
    Cleanup,
}
impl<'id, 'slots, 'seen, S: StorePort, L: LocationSigner, R: PeerRouter>
    Server<'id, 'slots, 'seen, S, L, R>
{
    fn failed_on_demand(
        &mut self,
        local: LocalPending<'id>,
        error: Arc<Error>,
        observe: &mut impl FnMut(Event),
    ) {
        let remove =
            matches!(error.as_ref(),Error::Index(error) if error.remove_on_demand_record());
        self.fault(Some(local.lookup.client().value()), error, observe);
        if self.live(local.lookup) {
            let result = (|| {
                let StoreResponse::Data(data) = StoreResponse::decode(local.frame.bytes())? else {
                    return Err(ProtocolError::Malformed);
                };
                let advance = self.protocol.skip_local(
                    local.lookup,
                    data.uid,
                    SkipReason::Invalid(ProtocolError::Io),
                )?;
                self.protocol.skip(advance)
            })();
            match result {
                Ok(()) => {
                    if let Err(error) = self.release_done(local.lookup.query_id(), observe) {
                        self.fault(Some(local.lookup.client().value()), error, observe);
                    }
                }
                Err(error) => self.fault(
                    Some(local.lookup.client().value()),
                    Arc::new(Error::Protocol(error)),
                    observe,
                ),
            }
        }
        if remove {
            // Only a previously validated type6 lookup reaches the resolver.
            // Keep exact original bytes even if its initiating client is gone.
            self.cleanup = Some(Cleanup {
                client: local.lookup.client().value(),
                frame: local.frame,
                pending: false,
            });
        }
    }
    fn poll_cleanup(
        &mut self,
        cx: &mut Context<'_>,
        mut cleanup: Cleanup,
        observe: &mut impl FnMut(Event),
    ) -> Poll<()> {
        if !cleanup.pending {
            if self.closing {
                return Poll::Ready(());
            }
            let admitted = (|| {
                let StoreResponse::Data(data) = StoreResponse::decode(cleanup.frame.bytes())
                    .map_err(|e| Arc::new(Error::Protocol(e)))?
                else {
                    return Err(Arc::new(Error::Protocol(ProtocolError::Malformed)));
                };
                self.store
                    .start_remove(data.key, data.value)
                    .map_err(|e| Arc::new(Error::Port(e)))
            })();
            match admitted {
                Ok(()) => {
                    cleanup.pending = true;
                    self.cleanup = Some(cleanup);
                    cx.waker().wake_by_ref();
                }
                Err(error) => {
                    self.report.on_demand_cleanup_failures =
                        self.report.on_demand_cleanup_failures.saturating_add(1);
                    self.fault(Some(cleanup.client), error, observe);
                }
            }
            return Poll::Ready(());
        }
        match self.store.poll(cx) {
            Poll::Pending => {
                self.cleanup = Some(cleanup);
                Poll::Pending
            }
            Poll::Ready(Ok(LookupProgress::Activity)) => {
                self.cleanup = Some(cleanup);
                Poll::Ready(())
            }
            Poll::Ready(Ok(LookupProgress::Removed(reply))) => {
                match reply.response() {
                    Ok(StoreResponse::Status(status)) if status.code == 1 => {
                        self.report.on_demand_removed =
                            self.report.on_demand_removed.saturating_add(1)
                    }
                    Ok(StoreResponse::Status(_)) => {
                        self.report.on_demand_cleanup_failures =
                            self.report.on_demand_cleanup_failures.saturating_add(1);
                        self.fault(
                            Some(cleanup.client),
                            Arc::new(Error::Port(ports::Error::RemoveRefused(reply))),
                            observe,
                        );
                    }
                    _ => {
                        self.report.on_demand_cleanup_failures =
                            self.report.on_demand_cleanup_failures.saturating_add(1);
                        self.fault(
                            Some(cleanup.client),
                            Arc::new(Error::Protocol(ProtocolError::Malformed)),
                            observe,
                        );
                    }
                }
                Poll::Ready(())
            }
            Poll::Ready(Ok(LookupProgress::Complete(_))) => {
                self.report.on_demand_cleanup_failures =
                    self.report.on_demand_cleanup_failures.saturating_add(1);
                self.fault(
                    Some(cleanup.client),
                    Arc::new(Error::Protocol(ProtocolError::Malformed)),
                    observe,
                );
                Poll::Ready(())
            }
            Poll::Ready(Err(error)) => {
                if matches!(
                    error.outcome(),
                    Some(gnunet_datastore_host::Outcome::Status { code: 1, .. })
                ) {
                    self.report.on_demand_removed = self.report.on_demand_removed.saturating_add(1);
                } else {
                    self.report.on_demand_cleanup_failures =
                        self.report.on_demand_cleanup_failures.saturating_add(1);
                }
                self.fault(Some(cleanup.client), Arc::new(Error::Port(error)), observe);
                Poll::Ready(())
            }
        }
    }
    pub(super) fn poll_store(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<()> {
        if let Some(cleanup) = self.cleanup.take() {
            return self.poll_cleanup(cx, cleanup, observe);
        }
        if let Some(mut local) = self.local.take() {
            if !self.live(local.lookup) {
                if let Some(job) = &mut local.resolve {
                    match job.poll(cx) {
                        Poll::Pending => {
                            self.local = Some(local);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => {
                            self.failed_on_demand(local, error, observe);
                            return Poll::Ready(());
                        }
                        Poll::Ready(Ok(_)) => {}
                    }
                }
                return Poll::Ready(());
            }
            if let Some(job) = &mut local.resolve {
                match job.poll(cx) {
                    Poll::Pending => {
                        self.local = Some(local);
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => {
                        local.resolve = None;
                        match result {
                            Ok(Output::Resolved(value)) => local.resolved = Some(value),
                            Ok(_) => {
                                self.fault(
                                    Some(local.lookup.client().value()),
                                    Arc::new(Error::Protocol(ProtocolError::Malformed)),
                                    observe,
                                );
                                self.close_client(local.lookup.client(), observe);
                                return Poll::Ready(());
                            }
                            Err(error) => {
                                self.failed_on_demand(local, error, observe);
                                return Poll::Ready(());
                            }
                        }
                    }
                }
            }
            if !self.ready(local.lookup.client()) {
                self.local = Some(local);
                return Poll::Pending;
            }
            let original = match StoreResponse::decode(local.frame.bytes()) {
                Ok(StoreResponse::Data(data)) => data,
                _ => {
                    self.fault(
                        Some(local.lookup.client().value()),
                        Arc::new(Error::Protocol(ProtocolError::Malformed)),
                        observe,
                    );
                    self.close_client(local.lookup.client(), observe);
                    return Poll::Ready(());
                }
            };
            let data = if let Some(value) = &local.resolved {
                Data {
                    kind: 1,
                    value,
                    ..original
                }
            } else {
                original
            };
            let result = (|| {
                let mut output = bytes(32 + data.value.len())?;
                let prepared = self
                    .protocol
                    .prepare_local(local.lookup, data, &mut output, self.now()?)
                    .map_err(|e| Arc::new(Error::Protocol(e)))?;
                match prepared {
                    LocalResult::Reply(reply) => {
                        output.truncate(reply.bytes());
                        self.queue(reply.client(), OwnedFrame::new(output))?;
                        let query = reply.query_id();
                        self.protocol
                            .commit_reply(reply)
                            .map_err(|e| Arc::new(Error::Protocol(e)))?;
                        self.report.local_results = self.report.local_results.saturating_add(1);
                        self.release_done(query, observe)?;
                        Ok(Delivery::Done)
                    }
                    LocalResult::Skip(advance) => {
                        observe(Event::Skipped {
                            query: advance.query_id().value(),
                            reason: advance.reason(),
                        });
                        let cleanup = data.kind == 6
                            && data.value.len() != 72
                            && local.lookup.block_type().value() == 0
                            && data.key == local.lookup.key()
                            && advance.reason() == SkipReason::Invalid(ProtocolError::Malformed);
                        let query = advance.query_id();
                        self.protocol
                            .skip(advance)
                            .map_err(|e| Arc::new(Error::Protocol(e)))?;
                        self.release_done(query, observe)?;
                        Ok(if cleanup {
                            Delivery::Cleanup
                        } else {
                            Delivery::Done
                        })
                    }
                    LocalResult::OnDemand(_) => {
                        let record: [u8; 72] = data
                            .value
                            .try_into()
                            .map_err(|_| Arc::new(Error::Protocol(ProtocolError::Malformed)))?;
                        let job = self.worker.submit(Task::Resolve {
                            query: *local.lookup.key(),
                            record,
                        })?;
                        Ok(Delivery::Resolve(job))
                    }
                }
            })();
            match result {
                Ok(Delivery::Resolve(job)) => {
                    local.resolve = Some(job);
                    self.local = Some(local);
                    cx.waker().wake_by_ref();
                }
                Ok(Delivery::Done) => {}
                Ok(Delivery::Cleanup) => {
                    self.cleanup = Some(Cleanup {
                        client: local.lookup.client().value(),
                        frame: local.frame,
                        pending: false,
                    });
                    cx.waker().wake_by_ref();
                }
                Err(error) => {
                    self.fault(Some(local.lookup.client().value()), error, observe);
                    self.close_client(local.lookup.client(), observe);
                }
            }
            return Poll::Ready(());
        }
        if let Some(lookup) = self.lookup {
            match self.store.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(LookupProgress::Activity)) => return Poll::Ready(()),
                Poll::Ready(result) => {
                    self.lookup = None;
                    if !self.live(lookup) {
                        return Poll::Ready(());
                    }
                    match result {
                        Ok(LookupProgress::Complete(Some(frame))) => {
                            self.local = Some(LocalPending {
                                lookup,
                                frame,
                                resolve: None,
                                resolved: None,
                            })
                        }
                        Ok(LookupProgress::Complete(None)) => {
                            match self.protocol.local_end(lookup) {
                                Ok(()) => {
                                    if let Err(e) = self.release_done(lookup.query_id(), observe) {
                                        self.fault(Some(lookup.client().value()), e, observe);
                                    }
                                }
                                Err(e) => self.fault(
                                    Some(lookup.client().value()),
                                    Arc::new(Error::Protocol(e)),
                                    observe,
                                ),
                            }
                        }
                        Ok(LookupProgress::Activity) => {}
                        Ok(LookupProgress::Removed(_)) => {
                            self.fault(
                                Some(lookup.client().value()),
                                Arc::new(Error::Protocol(ProtocolError::Malformed)),
                                observe,
                            );
                            self.close_client(lookup.client(), observe);
                        }
                        Err(e) => {
                            self.fault(
                                Some(lookup.client().value()),
                                Arc::new(Error::Port(e)),
                                observe,
                            );
                            match self.protocol.local_unavailable(lookup) {
                                Ok(()) => {
                                    if let Err(e) = self.release_done(lookup.query_id(), observe) {
                                        self.fault(Some(lookup.client().value()), e, observe);
                                    }
                                }
                                Err(e) => self.fault(
                                    Some(lookup.client().value()),
                                    Arc::new(Error::Protocol(e)),
                                    observe,
                                ),
                            }
                        }
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Ready(());
                }
            }
        }
        if self.closing {
            return Poll::Pending;
        }
        // Rotate past output-blocked clients without starting another datastore
        // operation or making their slow socket block all other local queries.
        for _ in 0..self.protocol.query_capacity() {
            let lookup = match self.protocol.next_local() {
                Ok(Some(v)) => v,
                Ok(None) => return Poll::Pending,
                Err(e) => {
                    self.fault(None, Arc::new(Error::Protocol(e)), observe);
                    self.closing = true;
                    return Poll::Ready(());
                }
            };
            if !self.ready(lookup.client()) {
                match self.protocol.local_failed(lookup) {
                    Ok(()) => {}
                    Err(e) => self.fault(
                        Some(lookup.client().value()),
                        Arc::new(Error::Protocol(e)),
                        observe,
                    ),
                }
                continue;
            }
            let query = ports::Lookup {
                key: *lookup.key(),
                kind: lookup.block_type().value(),
                next_uid: lookup.next_uid(),
            };
            match self.store.start(query) {
                Ok(()) => {
                    self.lookup = Some(lookup);
                    cx.waker().wake_by_ref();
                }
                Err(e) => {
                    self.fault(
                        Some(lookup.client().value()),
                        Arc::new(Error::Port(e)),
                        observe,
                    );
                    match self.protocol.local_unavailable(lookup) {
                        Ok(()) => {
                            if let Err(error) = self.release_done(lookup.query_id(), observe) {
                                self.fault(Some(lookup.client().value()), error, observe);
                            }
                        }
                        Err(e) => self.fault(
                            Some(lookup.client().value()),
                            Arc::new(Error::Protocol(e)),
                            observe,
                        ),
                    }
                }
            }
            return Poll::Ready(());
        }
        Poll::Pending
    }
}
