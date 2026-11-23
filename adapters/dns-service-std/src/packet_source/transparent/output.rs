use super::{
    AdmittedDatagram, Open, REPLY_SOCKETS, ReplyOwner, ReplySocket, State, Transparent,
    probes::Lane,
};
use crate::packet_source::{PacketExposure, PendingOutput, ReplyPermit, SourceEvent, Write};
use crate::{Error, core};
use gnunet_service_runtime::{framing::OwnedFrame, readiness::RegisteredIo};
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    io,
    task::{Context, Poll, ready},
};
use tokio::time::Instant;

pub(super) struct Output<'id> {
    effect: core::Effect<'id>,
    body: OwnedFrame,
    permit: ReplyPermit<'id>,
    until: Instant,
    stop: Option<Fault>,
    probe_submitted: bool,
}

impl<'id> Output<'id> {
    fn stopped(&self, exposure: PacketExposure, reason: Error) -> SourceEvent<'id> {
        SourceEvent::OutputStopped {
            effect: self.effect,
            exposure,
            total: self.body.len(),
            reason,
        }
    }
}

impl<'id> Transparent<'id> {
    #[expect(
        clippy::result_large_err,
        reason = "A refused reply retains its exact original bytes and permit"
    )]
    pub(crate) fn queue(
        &mut self,
        effect: core::Effect<'id>,
        body: OwnedFrame,
        until: Instant,
        permit: ReplyPermit<'id>,
    ) -> Result<(), (Error, OwnedFrame, ReplyPermit<'id>)> {
        if !self.writable() {
            return Err((Fault::WouldBlock.into(), body, permit));
        }
        if Instant::now() >= until {
            return Err((Fault::Deadline.into(), body, permit));
        }
        if !matches!(&permit.owner, ReplyOwner::Transparent(endpoint) if self.accepts(endpoint)) {
            return Err((Fault::StaleGeneration.into(), body, permit));
        }
        let State::Active(active) = &mut self.state else {
            return Err((Fault::WouldBlock.into(), body, permit));
        };
        active.output = Some(Output {
            effect,
            body,
            permit,
            until,
            stop: None,
            probe_submitted: false,
        });
        Ok(())
    }

    pub(crate) fn pending(&self) -> Option<PendingOutput<'id>> {
        match &self.state {
            State::Active(active) => active.output.as_ref().map(|output| PendingOutput {
                effect: output.effect,
                exposure: PacketExposure::UnsubmittedPacket,
                total: output.body.len(),
            }),
            State::Detached { pending, .. } => *pending,
            _ => None,
        }
    }

    pub(crate) fn cancel_output(&mut self, request: core::Request<'id>) -> Result<(), Error> {
        let State::Active(active) = &mut self.state else {
            return Err(Fault::StaleGeneration.into());
        };
        let output = active
            .output
            .as_mut()
            .filter(|output| output.effect.request() == request)
            .ok_or(Fault::StaleGeneration)?;
        output.stop.get_or_insert_with(|| {
            if Instant::now() >= output.until {
                Fault::Deadline
            } else {
                Fault::Cancelled
            }
        });
        Ok(())
    }

    pub(crate) fn poll_guard(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        if let Poll::Ready(retirement) = self.poll_retirement(cx) {
            return Poll::Ready(SourceEvent::Retired(retirement));
        }
        let State::Active(active) = &mut self.state else {
            return self.poll_recovery(cx);
        };
        let Some(session) = &self.session else {
            return Poll::Ready(SourceEvent::Failed(io::ErrorKind::NotConnected.into()));
        };
        if let Some(output) = &active.output {
            let reason = output
                .stop
                .or_else(|| (Instant::now() >= output.until).then_some(Fault::Deadline));
            if let Some(reason) = reason {
                let event = output.stopped(PacketExposure::UnsubmittedPacket, reason.into());
                active
                    .open
                    .probes
                    .abandon(Lane::Output, &mut active.open.ingress);
                active.output = None;
                return Poll::Ready(event);
            }
            self.timer.as_mut().reset(output.until);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        let open = &mut active.open;
        match open.poll_watch(cx, &session.interfaces) {
            Poll::Ready(super::topology::Event::IngressRetired) => {
                open.replies.retain(|reply| reply.io.descriptor().active());
                Poll::Ready(SourceEvent::IngressRetired)
            }
            Poll::Ready(super::topology::Event::Lost(error)) => {
                Poll::Ready(self.topology_lost(error))
            }
            Poll::Ready(super::topology::Event::Failed(error)) => {
                Poll::Ready(SourceEvent::Failed(error))
            }
            Poll::Ready(super::topology::Event::Returning) => {
                active.refresh_requested = true;
                self.poll_refresh(cx)
            }
            Poll::Pending => self.poll_refresh(cx),
        }
    }

    pub(super) fn poll_output(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        let State::Active(active) = &mut self.state else {
            return Poll::Pending;
        };
        let Some(mut output) = active.output.take() else {
            return Poll::Pending;
        };
        let open = &mut active.open;
        let ReplyOwner::Transparent(endpoint) = &output.permit.owner else {
            open.probes.abandon(Lane::Output, &mut open.ingress);
            return Poll::Ready(output.stopped(
                PacketExposure::UnsubmittedPacket,
                Fault::StaleGeneration.into(),
            ));
        };
        if !open.ingress.retains(endpoint.ingress()) {
            open.probes.abandon(Lane::Output, &mut open.ingress);
            return Poll::Ready(output.stopped(
                PacketExposure::UnsubmittedPacket,
                Fault::StaleGeneration.into(),
            ));
        }
        let event = match open.send(
            cx,
            endpoint,
            output.body.bytes(),
            output.until,
            &mut output.probe_submitted,
        ) {
            Poll::Pending => {
                active.output = Some(output);
                return Poll::Pending;
            }
            Poll::Ready(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                // Retry the same unsubmitted reply with a new qualification.
                active.output = Some(output);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Err(error)) => {
                output.stopped(PacketExposure::UnsubmittedPacket, error.into())
            }
            Poll::Ready(Ok(Submission::Expired)) => {
                output.stopped(PacketExposure::UnsubmittedPacket, Fault::Deadline.into())
            }
            Poll::Ready(Ok(Submission::Sent(bytes))) if bytes != output.body.len() => {
                let exposure = if bytes == 0 {
                    PacketExposure::UnsubmittedPacket
                } else {
                    PacketExposure::DatagramPrefix(bytes)
                };
                output.stopped(exposure, io::Error::from(io::ErrorKind::WriteZero).into())
            }
            Poll::Ready(Ok(Submission::Sent(_))) if Instant::now() >= output.until => {
                output.stopped(PacketExposure::DatagramAccepted, Fault::Deadline.into())
            }
            Poll::Ready(Ok(Submission::Sent(bytes))) => SourceEvent::Written {
                effect: output.effect,
                observation: Write::Datagram { bytes },
            },
        };
        open.probes.abandon(Lane::Output, &mut open.ingress);
        Poll::Ready(event)
    }
}

pub(super) struct RegisteredReply {
    io: RegisteredIo<ReplySocket>,
}

enum Submission {
    Expired,
    Sent(usize),
}

impl Open {
    fn send(
        &mut self,
        cx: &mut Context<'_>,
        admitted: &AdmittedDatagram,
        bytes: &[u8],
        until: Instant,
        probe_submitted: &mut bool,
    ) -> Poll<io::Result<Submission>> {
        if Instant::now() >= until {
            return Poll::Ready(Ok(Submission::Expired));
        }
        let present = self
            .replies
            .iter()
            .position(|reply| reply.io.descriptor().route_matches(admitted));
        if !*probe_submitted {
            if !self.probes.available(Lane::Output) {
                return Poll::Pending;
            }
            if let Some(index) = present {
                // Check present writability before spending a link query.
                ready!(self.replies[index].io.poll_write_on(cx, |_| Ok(())))?;
            }
            let request = self.ingress.probe_reply(admitted)?;
            self.probes.submit(Lane::Output, request)?;
            *probe_submitted = true;
        }
        let receipt = ready!(self.probes.poll(cx, Lane::Output));
        *probe_submitted = false;
        if Instant::now() >= until {
            return Poll::Ready(Ok(Submission::Expired));
        }
        if present.is_none() {
            self.ingress.ensure_current_namespace()?;
        }
        let qualification = self.ingress.finish_reply(admitted, receipt)?;
        let socket = if let Some(index) = present {
            self.replies
                .remove(index)
                .ok_or_else(|| io::Error::other("missing UDP reply socket"))?
        } else {
            if self.replies.len() == REPLY_SOCKETS {
                self.replies.pop_front();
            }
            let reply = ReplySocket::bind(&qualification, self.bypass_mark)?;
            let io = RegisteredIo::from_descriptor(reply).map_err(|(_, error)| error)?;
            RegisteredReply { io }
        };
        self.replies.push_back(socket);
        let socket = self
            .replies
            .back()
            .ok_or_else(|| io::Error::other("missing UDP reply socket"))?;
        // The proof is consumed by this attempt, including a stale writable hint.
        socket.io.poll_write_on(cx, |reply| {
            if Instant::now() >= until {
                return Ok(Submission::Expired);
            }
            reply.send(qualification, bytes).map(Submission::Sent)
        })
    }
}
