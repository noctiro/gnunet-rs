//! One captured DNS query, its native group and its original flow write.
use crate::{Error, core};
use gnunet_native::dns_proxy::{Datagram, MulticastEvent, MulticastRequest, UdpFlow};
use gnunet_types::Error as Fault;
use std::{
    io, mem,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

enum Phase {
    Resolving,
    Reply(Datagram),
    Writing { stopped: bool },
    Settled,
}

pub(super) enum Progress {
    Activity,
    Refused(Error),
    CloseFlow,
    Written {
        result: io::Result<()>,
        timely: bool,
    },
}

pub(super) struct Exchange {
    until: Instant,
    phase: Phase,
    group_live: bool,
}

impl Exchange {
    pub(super) fn start(
        flow: &mut UdpFlow,
        request: MulticastRequest,
        lifetime: Duration,
    ) -> Result<Self, Error> {
        if request.destination_port()? != 53 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native multicast relay accepts ordinary DNS on port 53",
            )
            .into());
        }
        let until = Instant::from_std(request.received_at())
            .checked_add(lifetime)
            .ok_or(Fault::Overflow)?;
        if Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        core::validate_questioned_query(request.bytes())?;
        if Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        flow.begin_multicast(request)?;
        Ok(Self {
            until,
            phase: Phase::Resolving,
            group_live: true,
        })
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        match self.phase {
            Phase::Resolving | Phase::Reply(_) | Phase::Writing { stopped: false } => {
                Some(self.until)
            }
            Phase::Writing { stopped: true } | Phase::Settled => None,
        }
    }

    pub(super) fn reserves_write(&self) -> bool {
        matches!(self.phase, Phase::Writing { .. })
            || !self.group_live && matches!(self.phase, Phase::Reply(_))
    }

    pub(super) fn owns_write(&self) -> bool {
        matches!(self.phase, Phase::Writing { .. })
    }

    pub(super) fn retired(&self) -> bool {
        !self.group_live && matches!(self.phase, Phase::Settled)
    }

    pub(super) fn stop(&mut self, flow: &mut UdpFlow) {
        flow.cancel_multicast();
        self.phase = if self.owns_write() {
            Phase::Writing { stopped: true }
        } else {
            Phase::Settled
        };
    }

    pub(super) fn poll_guard(
        &mut self,
        flow: &mut UdpFlow,
        cx: &mut Context<'_>,
    ) -> Poll<Progress> {
        if self.deadline().is_some_and(|until| Instant::now() >= until) {
            let writing = self.owns_write();
            self.stop(flow);
            return Poll::Ready(if writing {
                Progress::CloseFlow
            } else {
                Progress::Refused(Fault::Deadline.into())
            });
        }
        if let Phase::Writing { stopped } = self.phase
            && let Poll::Ready(result) = flow.poll_write(cx)
        {
            self.phase = Phase::Settled;
            return Poll::Ready(Progress::Written {
                result: result.unwrap_or_else(|| {
                    Err(io::Error::other("native multicast write result missing"))
                }),
                timely: !stopped && Instant::now() < self.until,
            });
        }
        if self.group_live {
            let event = flow.poll_multicast_completions(cx);
            return self.group_event(flow, event);
        }
        Poll::Pending
    }

    pub(super) fn poll_admission(
        &mut self,
        flow: &mut UdpFlow,
        ordinary_write_busy: bool,
        cx: &mut Context<'_>,
    ) -> Poll<Progress> {
        if self.deadline().is_some_and(|until| Instant::now() >= until) {
            return self.poll_guard(flow, cx);
        }
        if matches!(self.phase, Phase::Resolving) {
            let event = flow.poll_multicast(cx);
            return self.group_event(flow, event);
        }
        if matches!(self.phase, Phase::Reply(_))
            && !ordinary_write_busy
            && flow.writable()
            && !self.group_live
            && let Phase::Reply(reply) = mem::replace(&mut self.phase, Phase::Settled)
        {
            if Instant::now() >= self.until {
                return Poll::Ready(Progress::Refused(Fault::Deadline.into()));
            }
            let (bytes, sender) = reply.into_parts();
            return Poll::Ready(match flow.begin_write(bytes, sender) {
                Ok(()) => {
                    self.phase = Phase::Writing { stopped: false };
                    Progress::Activity
                }
                Err(rejected) => Progress::Refused(rejected.into_error().into()),
            });
        }
        Poll::Pending
    }

    fn group_event(
        &mut self,
        flow: &mut UdpFlow,
        event: Poll<Option<MulticastEvent>>,
    ) -> Poll<Progress> {
        match event {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(MulticastEvent::Sent)) => Poll::Ready(Progress::Activity),
            Poll::Ready(Some(MulticastEvent::Reply(reply))) => {
                if matches!(self.phase, Phase::Resolving)
                    && Instant::now() < self.until
                    && flow.multicast_query().is_some_and(|query| {
                        core::questioned_reply_matches(query, reply.bytes()) == Ok(true)
                    })
                    && Instant::now() < self.until
                {
                    self.phase = Phase::Reply(reply);
                    flow.cancel_multicast();
                }
                Poll::Ready(Progress::Activity)
            }
            Poll::Ready(Some(MulticastEvent::Retired(receipt))) => {
                self.group_live = false;
                match receipt.into_result() {
                    Ok(()) => Poll::Ready(Progress::Activity),
                    Err(error) => {
                        // A failed group can no longer supply reply authority.
                        if !self.owns_write() {
                            self.phase = Phase::Settled;
                        }
                        Poll::Ready(Progress::Refused(error.into()))
                    }
                }
            }
            Poll::Ready(None) => {
                self.group_live = false;
                if !self.owns_write() {
                    self.phase = Phase::Settled;
                }
                Poll::Ready(Progress::Refused(Fault::StaleGeneration.into()))
            }
        }
    }
}
