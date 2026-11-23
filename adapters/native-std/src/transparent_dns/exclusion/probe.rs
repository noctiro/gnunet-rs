//! Original link queries separated from applying their results to the watch.

use super::{
    AdmittedDatagram, Datagram, IngressObservation, Ingresses, Link, LinkCheckError, LinkQuery,
    Listener, ReplyQualification,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_PROBE_AGE: Duration = Duration::from_millis(50);

/// Native receive outcome before obtaining evidence for the original ingress.
#[derive(Debug)]
pub enum PendingReceive {
    /// One complete UDP body in the supplied buffer, still awaiting qualification.
    Captured(UnqualifiedDatagram),
    /// The consumed datagram did not have valid native metadata.
    Refused(io::Error),
}

/// A consumed datagram associated with its original capture and receive job.
#[derive(Debug)]
pub struct UnqualifiedDatagram {
    datagram: Datagram,
    source: Arc<()>,
    sequence: u64,
}

impl UnqualifiedDatagram {
    /// Length written into the original payload buffer.
    #[must_use]
    pub const fn body_len(&self) -> usize {
        self.datagram.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Purpose {
    Receive(u64),
    Reply(u64),
}

/// One non-clonable check for an original capture operation.
#[derive(Debug)]
pub struct ProbeRequest {
    link: Arc<Link>,
    master: Option<Arc<Link>>,
    purpose: Purpose,
}

/// Original link-query socket for one capture source.
///
/// The caller owns blocking execution and must keep it off the packet reactor.
#[derive(Debug)]
pub struct ProbeSocket {
    query: LinkQuery,
    source: Arc<()>,
}

impl ProbeSocket {
    pub(super) fn new(query: LinkQuery, source: Arc<()>) -> Self {
        Self { query, source }
    }

    /// Perform a link check on the original native descriptors. A result carries
    /// only evidence. The watch owner still must apply it to the current source.
    #[must_use]
    pub fn run(&mut self, request: ProbeRequest) -> ProbeReceipt {
        let started = Instant::now();
        let ProbeRequest {
            link,
            master,
            purpose,
        } = request;
        let result = if !Arc::ptr_eq(&self.source, &link.observation.0.source) {
            Err(CheckError::Refused(foreign()))
        } else if !link.observation.active() {
            Err(CheckError::Refused(retired()))
        } else {
            master
                .map_or(Ok(()), |master| {
                    self.check_link(&master)
                        .and_then(|()| check_probe_age(started).map_err(CheckError::Refused))
                })
                .and_then(|()| self.check_link(&link))
        };
        ProbeReceipt {
            link,
            purpose,
            result,
            started,
        }
    }

    fn check_link(&mut self, link: &Arc<Link>) -> Result<(), CheckError> {
        self.query
            .by_name(&link.name)
            .map_err(LinkCheckError::Native)
            .and_then(|record| link.match_record(record))
            .map_err(|error| CheckError::Failed(Arc::clone(link), error))
    }
}

/// Result of exactly one native check. The consumer must match it to its
/// original operation and reconcile it with watched retirement.
#[derive(Debug)]
pub struct ProbeReceipt {
    link: Arc<Link>,
    purpose: Purpose,
    result: Result<(), CheckError>,
    started: Instant,
}

#[derive(Debug)]
enum CheckError {
    Failed(Arc<Link>, LinkCheckError),
    Refused(io::Error),
}

impl CheckError {
    fn apply(self) -> io::Error {
        match self {
            Self::Failed(link, error) => link.apply(error),
            Self::Refused(error) => error,
        }
    }
}

impl Ingresses {
    /// Reconcile a cancelled operation's native failure with the live watch.
    /// A receipt from another source and a successful check carry no authority here.
    pub fn discard_probe(&mut self, receipt: ProbeReceipt) {
        if self.retains(&receipt.link.observation)
            && let Err(CheckError::Failed(link, failure)) = receipt.result
        {
            let _refusal = link.apply(failure);
            self.validation_retired |= !receipt.link.observation.active();
        }
    }

    /// Transfer the original native query socket to the capture's worker.
    ///
    /// # Errors
    /// Refuses a repeated transfer.
    pub fn take_probe_worker(&mut self) -> io::Result<ProbeSocket> {
        self.probe.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "transparent DNS link probe sockets already transferred",
            )
        })
    }

    /// Receive one datagram from a listener enrolled in this source.
    ///
    /// # Errors
    /// Refuses foreign listeners before reading and preserves native read
    /// errors. Invalid native metadata is reported as a consumed refusal.
    pub fn receive_unqualified(
        &self,
        listener: &Listener,
        payload: &mut [u8],
    ) -> io::Result<PendingReceive> {
        if !Arc::ptr_eq(&self.source, &listener.source) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transparent DNS listener belongs to a different capture source",
            ));
        }
        match listener.recv(payload) {
            Ok(datagram) => Ok(PendingReceive::Captured(UnqualifiedDatagram {
                datagram,
                source: Arc::clone(&self.source),
                sequence: self.next_sequence()?,
            })),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                Ok(PendingReceive::Refused(error))
            }
            Err(error) => Err(error),
        }
    }

    /// Prepare a link check for a datagram captured by this source.
    ///
    /// # Errors
    /// Refuses a foreign capture or an inactive or unconfigured ingress.
    pub fn probe_input(&self, input: &UnqualifiedDatagram) -> io::Result<ProbeRequest> {
        if !Arc::ptr_eq(&self.source, &input.source) {
            return Err(foreign());
        }
        self.packet_probe(
            input.datagram.interface.get(),
            Purpose::Receive(input.sequence),
        )
    }

    /// Join the worker's receipt to its consumed original datagram.
    ///
    /// # Errors
    /// Refuses a mismatched receipt, retired ingress, failed lookup or invalid
    /// address scope. Confirmed link loss revokes prior admissions.
    pub fn admit(
        &mut self,
        input: UnqualifiedDatagram,
        receipt: ProbeReceipt,
    ) -> io::Result<AdmittedDatagram> {
        if !Arc::ptr_eq(&self.source, &input.source) {
            return Err(foreign());
        }
        self.require_receipt(&receipt, Purpose::Receive(input.sequence))?;
        let ingress = self.confirm_packet(receipt)?;
        let datagram = input.datagram;
        let peer_interface = ingress
            .master()
            .map_or(datagram.interface, IngressObservation::index);
        super::super::address::validate(
            datagram.peer,
            datagram.original,
            datagram.interface,
            peer_interface,
        )?;
        Ok(AdmittedDatagram {
            datagram,
            ingress,
            reply_sequence: AtomicU64::new(0),
        })
    }

    /// Prepare a fresh check for a reply on this exact admitted path.
    ///
    /// # Errors
    /// Refuses a retired or foreign binding.
    pub fn probe_reply(&self, admitted: &AdmittedDatagram) -> io::Result<ProbeRequest> {
        if !self.retains(admitted.ingress()) {
            return Err(retired());
        }
        let sequence = self.next_sequence()?;
        let request =
            self.packet_probe(admitted.datagram.interface.get(), Purpose::Reply(sequence))?;
        admitted.reply_sequence.store(sequence, Ordering::Release);
        Ok(request)
    }

    /// Match one reply check to the exact admission and submission attempt.
    ///
    /// # Errors
    /// Refuses mismatched or stale receipts and failed lookups. Confirmed
    /// link loss revokes earlier admissions.
    pub fn finish_reply<'a>(
        &'a mut self,
        admitted: &'a AdmittedDatagram,
        receipt: ProbeReceipt,
    ) -> io::Result<ReplyQualification<'a>> {
        let Purpose::Reply(sequence) = receipt.purpose else {
            return Err(foreign());
        };
        self.require_receipt(&receipt, Purpose::Reply(sequence))?;
        if !receipt.link.observation.same(admitted.ingress()) {
            return Err(foreign());
        }
        admitted
            .reply_sequence
            .compare_exchange(sequence, 0, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| foreign())?;
        let started = receipt.started;
        self.confirm_packet(receipt)?;
        Ok(ReplyQualification { admitted, started })
    }

    fn next_sequence(&self) -> io::Result<u64> {
        self.probe_sequence
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |previous| {
                previous.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| io::Error::other("transparent DNS link probe sequence exhausted"))
    }

    fn packet_probe(&self, ifindex: u32, purpose: Purpose) -> io::Result<ProbeRequest> {
        let ingress = self
            .position(ifindex)
            .map(|index| &self.links[index])
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "packet ingress was not configured")
            })?;
        if !ingress.link.observation.active() {
            return Err(retired());
        }
        Ok(ProbeRequest {
            link: Arc::clone(&ingress.link),
            master: ingress.vrf.clone(),
            purpose,
        })
    }

    fn require_receipt(&self, receipt: &ProbeReceipt, purpose: Purpose) -> io::Result<()> {
        if receipt.purpose == purpose
            && Arc::ptr_eq(&self.source, &receipt.link.observation.0.source)
        {
            Ok(())
        } else {
            Err(foreign())
        }
    }

    fn confirm_packet(&mut self, receipt: ProbeReceipt) -> io::Result<IngressObservation> {
        if !self.retains(&receipt.link.observation) {
            return Err(retired());
        }
        let outcome = receipt.result.map_err(CheckError::apply);
        self.validation_retired |= !receipt.link.observation.active();
        outcome?;
        check_probe_age(receipt.started)?;
        Ok(receipt.link.observation.clone())
    }
}

pub(super) fn check_probe_age(started: Instant) -> io::Result<()> {
    if started.elapsed() >= MAX_PROBE_AGE {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "transparent DNS link probe expired before application",
        ))
    } else {
        Ok(())
    }
}

fn foreign() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "transparent DNS link probe belongs to another operation",
    )
}

fn retired() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "original configured ingress was retired",
    )
}

#[cfg(test)]
mod tests {
    use super::{super::tests::vrf_fixture, *};
    use std::{net::SocketAddr, num::NonZeroU32};

    fn capture(ingress: &Ingresses) -> io::Result<UnqualifiedDatagram> {
        Ok(UnqualifiedDatagram {
            datagram: Datagram {
                bytes: 1,
                peer: SocketAddr::from(([192, 0, 2, 11], 2000)),
                original: SocketAddr::from(([192, 0, 2, 53], 53)),
                interface: NonZeroU32::MIN,
                namespace: ingress.namespace(),
            },
            source: Arc::clone(&ingress.source),
            sequence: ingress.next_sequence()?,
        })
    }

    fn checked(request: ProbeRequest, started: Instant) -> ProbeReceipt {
        ProbeReceipt {
            link: request.link,
            purpose: request.purpose,
            result: Ok(()),
            started,
        }
    }

    #[test]
    fn receipts_match_the_exact_consumed_datagram_and_reply_attempt() -> io::Result<()> {
        let mut ingress = vrf_fixture()?;
        let first = capture(&ingress)?;
        let second = capture(&ingress)?;
        let first_check = ingress.probe_input(&first)?;
        let second_check = ingress.probe_input(&second)?;
        let admitted = ingress.admit(first, checked(first_check, Instant::now()))?;
        let first_attempt = ingress.probe_reply(&admitted)?;
        let second_attempt = ingress.probe_reply(&admitted)?;
        if ingress
            .admit(second, checked(first_attempt, Instant::now()))
            .is_ok()
        {
            return Err(io::Error::other("a reply qualified a different receive"));
        }
        let next = capture(&ingress)?;
        if ingress
            .admit(next, checked(second_check, Instant::now()))
            .is_ok()
        {
            return Err(io::Error::other(
                "one receive receipt admitted another datagram",
            ));
        }
        let earlier = ingress.probe_reply(&admitted)?;
        if ingress
            .finish_reply(&admitted, checked(second_attempt, Instant::now()))
            .is_ok()
        {
            return Err(io::Error::other("a superseded reply attempt remained live"));
        }
        let _qualified = ingress.finish_reply(&admitted, checked(earlier, Instant::now()))?;
        Ok(())
    }

    #[test]
    fn expired_success_refuses_traffic_and_expired_loss_still_retires_the_link() -> io::Result<()> {
        let mut ingress = vrf_fixture()?;
        let old = Instant::now()
            .checked_sub(MAX_PROBE_AGE)
            .ok_or_else(|| io::Error::other("fixture cannot represent an expired probe"))?;
        let input = capture(&ingress)?;
        let receipt = checked(ingress.probe_input(&input)?, old);
        if !matches!(ingress.admit(input, receipt), Err(error) if error.kind() == io::ErrorKind::TimedOut)
            || !ingress.has_active()
        {
            return Err(io::Error::other(
                "an expired success authorized traffic or retired ingress",
            ));
        }
        let input = capture(&ingress)?;
        let mut receipt = checked(ingress.probe_input(&input)?, old);
        receipt.result = Err(CheckError::Failed(
            Arc::clone(&receipt.link),
            LinkCheckError::Changed,
        ));
        if !matches!(ingress.admit(input, receipt), Err(error) if error.kind() == io::ErrorKind::NotFound)
            || ingress.has_active()
            || !ingress.take_validation_retirement()
        {
            return Err(io::Error::other(
                "an expired confirmed loss did not retire the link",
            ));
        }
        Ok(())
    }

    #[test]
    fn discarding_a_cancelled_probe_preserves_confirmed_loss() -> io::Result<()> {
        let mut ingress = vrf_fixture()?;
        let input = capture(&ingress)?;
        let request = ingress.probe_input(&input)?;
        let admitted = ingress.admit(input, checked(request, Instant::now()))?;
        let mut receipt = checked(ingress.probe_reply(&admitted)?, Instant::now());
        receipt.result = Err(CheckError::Failed(
            Arc::clone(&receipt.link),
            LinkCheckError::Changed,
        ));
        let other = vrf_fixture()?;
        let foreign_input = capture(&other)?;
        let mut foreign = checked(other.probe_input(&foreign_input)?, Instant::now());
        foreign.result = Err(CheckError::Failed(
            Arc::clone(&foreign.link),
            LinkCheckError::Changed,
        ));
        ingress.discard_probe(foreign);
        if !ingress.has_active() || ingress.take_validation_retirement() || !other.has_active() {
            return Err(io::Error::other("foreign receipt changed a live link"));
        }
        ingress.discard_probe(receipt);
        if ingress.has_active() || !ingress.take_validation_retirement() {
            return Err(io::Error::other("cancellation hid the confirmed link loss"));
        }
        Ok(())
    }
}
