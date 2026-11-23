//! Original DNS callback decisions, source binding and deferred refusal writes.
use super::{Bound, Callback, Counter, Event, Failure, Failures, Fault, Owner, Stage, dns};
use std::{error::Error, fmt};
use tokio::time::Instant;

#[derive(Debug)]
struct SourceLoss {
    stage: Stage,
    cause: dns::Cause,
}
impl fmt::Display for SourceLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original {:?} DNS source lost: {:?}",
            self.stage, self.cause
        )
    }
}
impl Error for SourceLoss {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            dns::Cause::Io(error) => Some(error),
            dns::Cause::Clock(error) | dns::Cause::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Resolution {
    Waiting,
    DropReady,
    Queued,
}

impl<'a, 'slots> Owner<'a, 'slots> {
    pub(super) fn recover_dns_source(
        &mut self,
        stage: Stage,
        cause: dns::Cause,
    ) -> Result<Event, Failure> {
        let mut cleanup = Vec::new();
        if let Err(error) = self.source_lost(stage) {
            cleanup.push(error);
        }
        let reconnect = self
            .dns(stage)
            .and_then(|client| client.reconnect().map_err(Failure::from));
        if let Err(error) = reconnect {
            cleanup.push(error);
        }
        if cleanup.is_empty() {
            Ok(Event::DnsLost { stage, cause })
        } else {
            Err(Box::new(Failures {
                original: Some(Box::new(SourceLoss { stage, cause })),
                cleanup,
            }))
        }
    }

    pub(super) fn on_dns(
        &mut self,
        stage: Stage,
        p: dns::Progress<'a>,
        now: u64,
    ) -> Result<Event, Failure> {
        let port = if stage == Stage::Pre { 1 } else { 2 };
        self.blocked &= !port;
        match p {
            dns::Progress::Connected(epoch) => {
                if self.source(stage).is_some() {
                    return Err(Fault::Conflict.into());
                }
                let replies = self.dns(stage)?.reply_limit();
                let source = self.core.attached(stage, replies)?;
                *self.source_mut(stage) = Some((epoch, source));
                Ok(Event::DnsAttached(stage))
            }
            dns::Progress::InitWritten(_) => Ok(Event::DnsInitWritten(stage)),
            dns::Progress::Request(input) => {
                self.metrics.bump(if stage == Stage::Pre {
                    Counter::RequestsIntercepted
                } else {
                    Counter::RepliesIntercepted
                });

                let (epoch, source) = self.source(stage).ok_or(Fault::Stale)?;
                if input.request().epoch() != epoch {
                    return Err(Fault::Stale.into());
                }
                let bounds = Bound {
                    expires: input.expires(),
                    hard: input.hard(),
                };
                if self.callbacks.len() >= self.callbacks.capacity() {
                    return Err(Fault::Capacity.into());
                }
                let admission = if bounds.live(now) {
                    self.core
                        .admit(source, input.id(), input.dns(), bounds.expires, now)
                } else {
                    Err(Fault::Deadline)
                };
                let accepted = match admission {
                    Ok(request) => Some(request),
                    Err(error) => {
                        if stage == Stage::Pre
                            && matches!(
                                error,
                                Fault::Malformed | Fault::Truncated | Fault::InvalidInput
                            )
                        {
                            self.metrics.bump(Counter::Malformed);
                        }
                        None
                    }
                };
                if stage == Stage::Pre
                    && let Some(request) = accepted
                {
                    let channel = self.channels.iter().any(|c| {
                        c.channel.is_some()
                            && !c.destroying
                            && self.leases.iter().any(|l| {
                                l.peer == c.peer && l.expires > now && Instant::now() < l.hard
                            })
                    });
                    if !channel {
                        self.core.cancel(request)?;
                        self.metrics.bump(Counter::ChannelDown);
                    }
                }
                self.callbacks.push(Callback {
                    stage,
                    native: input.request(),
                    id: input.id(),
                    resolution: if accepted.is_some() {
                        Resolution::Waiting
                    } else {
                        Resolution::DropReady
                    },
                    core: accepted,
                    bounds,
                });
                Ok(Event::DnsRequest {
                    stage,
                    accepted: accepted.is_some(),
                })
            }
            dns::Progress::Dropping(token) => {
                if let Some(row) = self.callbacks.iter_mut().find(|r| r.native == token) {
                    if stage == Stage::Pre && row.resolution != Resolution::Queued {
                        self.metrics.bump(Counter::Timeout);
                    }
                    row.resolution = Resolution::Queued;
                }
                if let Some(row) = self.callbacks.iter().find(|r| r.native == token)
                    && let Some(request) = row.core
                {
                    self.core.cancel(request)?;
                    self.core.reply_queued(request)?;
                    let mut i = 0;
                    while i < self.allocations.len() {
                        if self.allocations[i].request == request {
                            self.cancel_job(i)
                        } else {
                            i += 1
                        }
                    }
                }
                Ok(Event::Admitted)
            }
            dns::Progress::Written(token) => {
                if let Some(i) = self
                    .callbacks
                    .iter()
                    .position(|r| r.native == token && r.stage == stage)
                {
                    let row = self.callbacks.remove(i);
                    if let Some(request) = row.core {
                        let (_, source) = self.source(stage).ok_or(Fault::Stale)?;
                        self.core.reply_written(source, request)?;
                    }
                }
                Ok(Event::DnsReplyWritten(stage))
            }
            dns::Progress::Lost { cause, .. } => self.recover_dns_source(stage, cause),
            dns::Progress::Retry { .. } | dns::Progress::Unavailable(_) => {
                self.blocked |= port;
                self.delay()?;
                Ok(Event::Backpressure)
            }
            dns::Progress::Activity { .. } | dns::Progress::Wait => Ok(Event::Activity),
            dns::Progress::Closed => Err(Fault::Closed.into()),
        }
    }
    pub(super) fn refusals(&mut self, now: u64) -> Result<Option<Event>, Failure> {
        // At most one attempt per original DNS source. A full output budget
        // must still permit that source's existing writes and the other source
        // to make progress; its own IO/deadline supplies the next wake.
        for stage in [Stage::Pre, Stage::Post] {
            let Some(i) = self.callbacks.iter().position(|row| {
                row.stage == stage
                    && row.resolution == Resolution::DropReady
                    && row.bounds.live(now)
            }) else {
                continue;
            };
            let request = self.callbacks[i].native;
            match self.dns(stage)?.reply(request, dns::ipc::Decision::Drop) {
                Ok(()) => {
                    self.callbacks[i].resolution = Resolution::Queued;
                    return Ok(Some(Event::Admitted));
                }
                Err(gnunet_client_host::ConnectError::Protocol(
                    Fault::WouldBlock | Fault::Capacity | Fault::NotReady | Fault::Deadline,
                )) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }
}
