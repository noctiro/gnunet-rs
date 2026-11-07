//! Actual unverified UDP callbacks, same-task TCP fallback, and complete results.
use super::*;
use crate::core::conversion;
use zeroize::Zeroize;
impl<'id> Runtime<'id> {
    pub(super) fn query_outcome(
        &mut self,
        result: &Result<core::Completion, Fault>,
        reason: core::ReadFailure,
    ) {
        if let Ok(result) = result {
            match result.outcome {
                core::Outcome::Retrying => self.metrics.add(2, 1),
                core::Outcome::Failed => self.metrics.add(
                    if matches!(reason, core::ReadFailure::Rcode(_)) {
                        7
                    } else {
                        10
                    },
                    1,
                ),
                _ => {}
            }
        }
    }
    fn read_failed(
        &mut self,
        index: usize,
        mut row: Pending<'id>,
        reason: core::ReadFailure,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        let Native::Query(query) = &mut row.native else {
            self.pending[index] = Some(row);
            return Err(Fault::Conflict.into());
        };
        if let Some(request) = query.request.take() {
            self.dns.resolve_cancel(request)?;
        }
        if let Some(mut tcp) = query.tcp.take() {
            let _original = tcp.cancel();
            self.report.tcp_closed = self.report.tcp_closed.saturating_add(1);
        }
        observe(Event::ReadFailed {
            job: row.job.diagnostic(),
            reason,
        });
        self.metrics.add(6, 1);
        let result = if row.retiring {
            self.core.retired(&row.job, core::Retirement::Unsent)
        } else {
            self.core.dns_failed(&row.job, reason)
        };
        self.query_outcome(&result, reason);
        self.finish_row(index, row, result)
    }
    pub(super) fn poll_udp(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<bool, Error> {
        if self.stopped_dns || self.dns.pending_requests() == 0 {
            return Ok(false);
        }
        let incoming = &mut self.incoming;
        let notice = &mut self.notice;
        let result = {
            let driving = self.dns.drive(None, |event, _context| {
                *notice = Some(match event {
                    gnunet_dnsstub_host::Event::Datagram(packet) => {
                        incoming.bytes.clear();
                        // DnsStub delivered a nontruncated packet no longer than
                        // its configured bound, which this loan pre-reserved.
                        incoming.bytes.extend_from_slice(packet.bytes);
                        incoming.request = Some(packet.request);
                        incoming.server = Some(packet.source);
                        Notice::Datagram
                    }
                    gnunet_dnsstub_host::Event::SocketOpened {
                        result: Err(error), ..
                    }
                    | gnunet_dnsstub_host::Event::ReceiveFailed { error, .. } => Notice::Io {
                        request: None,
                        error,
                    },
                    gnunet_dnsstub_host::Event::Sent {
                        request,
                        result: Err(error),
                        ..
                    } => Notice::Io {
                        request: Some(request),
                        error,
                    },
                    _ => Notice::Activity,
                });
                gnunet_dnsstub_host::Flow::Return
            });
            let mut driving = std::pin::pin!(driving);
            driving.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(error)) => Err(Error::Dns(error)),
            Poll::Ready(Ok(_)) => match self.notice.take() {
                Some(Notice::Io { request, error }) => {
                    self.note_io(request, error, observe);
                    Ok(true)
                }
                Some(Notice::Datagram) => {
                    let request = self.incoming.request.take().ok_or(Fault::StaleGeneration)?;
                    let source = self.incoming.server.take().ok_or(Fault::StaleGeneration)?;
                    let index = self.pending.iter().position(|slot| slot.as_ref().is_some_and(|row| matches!(&row.native, Native::Query(query) if query.request == Some(request))));
                    let result = if let Some(index) = index {
                        if !self.servers.contains(&source) || !self.dns.owns_request(request) {
                            Err(Fault::StaleGeneration.into())
                        } else {
                            // Temporarily move the pre-reserved loan, not a full
                            // response clone. It is returned before the next IO.
                            let bytes = std::mem::replace(
                                &mut self.incoming.bytes,
                                Zeroizing::new(Vec::new()),
                            );
                            let result = self.response(index, &bytes, source, false, observe);
                            self.incoming.bytes = bytes;
                            result
                        }
                    } else {
                        Ok(())
                    }; // An original cancellation may race this raw notification.
                    self.incoming.bytes.zeroize();
                    result.map(|()| true)
                }
                _ => Ok(true),
            },
        }
    }
    fn response(
        &mut self,
        index: usize,
        bytes: &[u8],
        source: SocketAddr,
        from_tcp: bool,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        let mut row = self.pending[index].take().ok_or(Fault::StaleGeneration)?;
        if let Err(error) = row.budget.check(&self.clock) {
            if error == Fault::Deadline {
                return self.read_failed(index, row, core::ReadFailure::Deadline, observe);
            }
            self.pending[index] = Some(row);
            return Err(error.into());
        }
        let now = match self.clock.sample() {
            Ok(now) => now,
            Err(error) => {
                self.pending[index] = Some(row);
                return Err(error.into());
            }
        };
        let Native::Query(query) = &mut row.native else {
            self.pending[index] = Some(row);
            return Err(Fault::Conflict.into());
        };
        if from_tcp && query.tcp_server != Some(source) {
            self.pending[index] = Some(row);
            return Err(Fault::StaleGeneration.into());
        }
        let inspected = self.work.inspect(
            bytes,
            &query.bytes,
            &query.hostname,
            now.absolute,
            self.core.policy(),
            &mut self.names,
        );
        self.metrics
            .add(0, u64::try_from(inspected.expired).unwrap_or(u64::MAX));
        match inspected.result {
            Ok(response::Reply::NeedTcp) if !from_tcp => {
                if let Some(request) = query.request.take() {
                    self.dns.resolve_cancel(request)?;
                }
                query.tcp_server = Some(source);
                // Keep a waiting fallback when the real TCP pool is full. Its
                // original budget is still checked on every enclosing turn.
                observe(Event::TcpFallback {
                    job: row.job.diagnostic(),
                    server: source,
                });
                self.pending[index] = Some(row);
                Ok(())
            }
            Ok(response::Reply::NeedTcp) => {
                self.read_failed(index, row, core::ReadFailure::InvalidResponse, observe)
            }
            Ok(response::Reply::Answer { records, summary }) => {
                if let Err(error) = row.budget.check(&self.clock) {
                    if error == Fault::Deadline {
                        return self.read_failed(index, row, core::ReadFailure::Deadline, observe);
                    }
                    self.pending[index] = Some(row);
                    return Err(error.into());
                }
                if let Some(request) = query.request.take() {
                    self.dns.resolve_cancel(request)?;
                }
                let slot = match self.answers.iter().position(Option::is_none) {
                    Some(slot) => slot,
                    None => {
                        self.pending[index] = Some(row);
                        return Err(Fault::Capacity.into());
                    }
                };
                self.metrics.dns(row.started);
                if summary.empty {
                    self.metrics.add(12, 1);
                }
                match self.core.dns_result(&row.job, summary) {
                    Ok(id) => {
                        self.answers[slot] = Some(Answer { id, records });
                        self.report.completed = self.report.completed.saturating_add(1);
                        observe(Event::Result {
                            job: row.job.diagnostic(),
                            kind: Kind::Query,
                            code: Some(0),
                        });
                        self.resume_deferred()?;
                        Ok(())
                    }
                    Err(error) => {
                        row.native = Native::Settled;
                        self.pending[index] = Some(row);
                        self.stalled = true;
                        Err(error.into())
                    }
                }
            }
            Err(Error::Conversion(reason)) => {
                observe(Event::DnsRejected {
                    job: row.job.diagnostic(),
                    reason,
                });
                match reason {
                    conversion::Failure::Identifier if !from_tcp => {
                        self.metrics.add(8, 1);
                        self.pending[index] = Some(row);
                        Ok(())
                    }
                    conversion::Failure::Question | conversion::Failure::Header if !from_tcp => {
                        self.metrics.add(9, 1);
                        self.pending[index] = Some(row);
                        Ok(())
                    }
                    conversion::Failure::ResponseCode(code) => {
                        self.read_failed(index, row, core::ReadFailure::Rcode(code), observe)
                    }
                    _ => {
                        self.metrics.add(9, 1);
                        self.read_failed(index, row, core::ReadFailure::InvalidResponse, observe)
                    }
                }
            }
            Err(error) => {
                self.pending[index] = Some(row);
                Err(error)
            }
        }
    }
    pub(super) fn poll_tcp(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<bool, Error> {
        let mut active = self
            .pending
            .iter()
            .flatten()
            .filter(|row| matches!(&row.native, Native::Query(query) if query.tcp.is_some()))
            .count();
        for offset in 0..self.pending.len() {
            let index = (self.cursor + offset) % self.pending.len();
            let row = match &mut self.pending[index] {
                Some(row) if !row.retiring => row,
                _ => continue,
            };
            let Native::Query(query) = &mut row.native else {
                continue;
            };
            let Some(server) = query.tcp_server else {
                continue;
            };
            if query.tcp.is_none() && active < self.limits.tcp_requests {
                row.budget.check(&self.clock)?;
                query.tcp = Some(crate::tcp::Exchange::new(
                    server,
                    &query.bytes,
                    row.budget.hard,
                    self.limits.response_bytes,
                    self.limits.io_bytes,
                )?);
                active += 1;
            }
            let Some(tcp) = &mut query.tcp else {
                continue;
            };
            let result = tcp.poll(cx);
            match result {
                Poll::Pending => {}
                Poll::Ready(result) => {
                    self.cursor = (index + 1) % self.pending.len();
                    if let Some(row) = &mut self.pending[index]
                        && let Native::Query(query) = &mut row.native
                    {
                        query.tcp = None;
                    }
                    self.report.tcp_closed = self.report.tcp_closed.saturating_add(1);
                    match result {
                        Ok(bytes) => self.response(index, &bytes, server, true, observe)?,
                        Err(failure) => {
                            let timeout = failure.cause.kind() == io::ErrorKind::TimedOut;
                            self.note_io(None, failure.cause, observe);
                            let row = self.pending[index].take().ok_or(Fault::StaleGeneration)?;
                            self.read_failed(
                                index,
                                row,
                                if timeout {
                                    core::ReadFailure::Deadline
                                } else {
                                    core::ReadFailure::Source
                                },
                                observe,
                            )?;
                        }
                    }
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
