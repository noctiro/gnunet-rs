//! Original finite readiness/send bounds, independent of DNS retry and wall time.
use super::{Peer, Provider};
use crate::upstream::{Event, Flow, HostError, Progress, SendExpired};
use gnunet_types::Error;
use std::{
    future::Future,
    io,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

pub(super) fn ready(peer: &mut Peer, cx: &mut Context<'_>, bound: Duration) -> io::Result<bool> {
    let observed = match peer.connection.poll_ready(cx) {
        Poll::Ready(Ok(())) => true,
        Poll::Ready(Err(error)) => return Err(error),
        Poll::Pending => false,
    };
    peer.ready = observed;
    readiness(&mut peer.ready_until, observed, Instant::now(), bound)
}
fn readiness(
    until: &mut Option<Instant>,
    observed: bool,
    now: Instant,
    bound: Duration,
) -> io::Result<bool> {
    if until.is_some_and(|until| now >= until) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original DNS peer readiness expired",
        ));
    }
    if observed {
        *until = None;
        return Ok(true);
    }
    if until.is_none() {
        *until = Some(
            now.checked_add(bound)
                .ok_or_else(|| io::Error::other("DNS peer readiness deadline overflow"))?,
        );
    }
    Ok(false)
}

pub(super) fn expire_send(
    peer: &mut Peer,
    completion: Option<io::Result<()>>,
) -> Result<Event<'static>, Error> {
    let send = peer.sending.as_mut().ok_or(Error::StaleGeneration)?;
    if send.until.take().is_none() {
        return Err(Error::StaleGeneration);
    }
    let (request, socket, destination) = (send.request, send.socket, send.destination);
    if completion.is_some() {
        peer.sending = None;
    }
    peer.connection.request_cancel();
    peer.retiring = true;
    peer.ready = false;
    peer.ready_until = None;
    Ok(Event::Sent {
        request,
        socket,
        destination,
        result: Err(io::Error::new(
            io::ErrorKind::TimedOut,
            SendExpired { completion },
        )),
    })
}
impl Provider {
    pub(super) fn native_deadline(&self) -> Option<Instant> {
        self.groups
            .iter()
            .flatten()
            .filter(|group| !group.retiring)
            .flat_map(|group| group.peers.iter().flatten())
            .filter(|peer| !peer.retiring)
            .flat_map(|peer| {
                [
                    peer.ready_until,
                    peer.sending.as_ref().and_then(|send| send.until),
                ]
            })
            .flatten()
            .min()
    }
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        callback: &mut impl FnMut(Event<'_>) -> Flow,
    ) -> Poll<Result<Progress, HostError>> {
        if self.core.is_stopped() {
            return Poll::Pending;
        }
        let mut exhausted = true;
        for _ in 0..32 {
            match self.poll_groups(cx, false, callback)? {
                Some(Flow::Return) => return Poll::Ready(Ok(Progress::Activity)),
                Some(Flow::Continue) => continue,
                None => {
                    exhausted = false;
                    break;
                }
            }
        }
        if let Some(wake) = self.native_deadline() {
            self.timer.as_mut().reset(wake);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        if exhausted {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::readiness;
    use std::{io, time::Duration};
    use tokio::time::Instant;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure deadline policy checks fixed instants without constructing native SDK objects"
    )]
    fn waiting_and_late_ready_never_extend_the_original_interval() -> io::Result<()> {
        let now = Instant::now();
        let bound = Duration::from_secs(5);
        let original = now + bound;
        let mut until = Some(original);
        assert!(!readiness(
            &mut until,
            false,
            now + Duration::from_secs(1),
            bound
        )?);
        assert!(!readiness(
            &mut until,
            false,
            now + Duration::from_secs(4),
            bound
        )?);
        assert_eq!(until, Some(original));
        let late = readiness(&mut until, true, original, bound);
        assert!(late.is_err_and(|error| error.kind() == io::ErrorKind::TimedOut));
        assert_eq!(until, Some(original));
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure readiness transition policy verifies one bounded interval after an actual state change"
    )]
    fn ready_to_waiting_has_one_new_fixed_interval() -> io::Result<()> {
        let now = Instant::now();
        let bound = Duration::from_secs(5);
        let mut until = Some(now + bound);
        assert!(readiness(&mut until, true, now, bound)?);
        assert!(until.is_none());
        assert!(!readiness(&mut until, false, now + bound, bound)?);
        let waiting_until = now + bound + bound;
        assert_eq!(until, Some(waiting_until));
        assert!(!readiness(
            &mut until,
            false,
            waiting_until - Duration::from_secs(1),
            bound
        )?);
        assert_eq!(until, Some(waiting_until));
        assert!(readiness(&mut until, false, waiting_until, bound).is_err());
        Ok(())
    }
}
