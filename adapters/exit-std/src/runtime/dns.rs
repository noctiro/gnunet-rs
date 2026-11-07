//! Bounded actual original literal-resolver UDP jobs. Fresh owned sockets avoid
//! reassigning an old query's socket/transaction ID to another job generation.
use super::*;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::ReadBuf;
fn questions(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, Fault> {
    if bytes.len() < 12 {
        return Err(Fault::Truncated);
    }
    let n = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if n > maximum {
        return Err(Fault::Capacity);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(n.checked_mul(259).ok_or(Fault::Overflow)?)
        .map_err(|_| Fault::Capacity)?;
    let limits = gnunet_dns::Limits {
        maximum_packet_bytes: 65535,
        maximum_queries: maximum,
        maximum_records: 0,
        maximum_compression_hops: 33,
        maximum_work: bytes
            .len()
            .checked_mul(8)
            .and_then(|n| n.checked_add(4096))
            .ok_or(Fault::Overflow)?,
        maximum_text_input_bytes: 0,
    };
    let mut reader = gnunet_dns::Reader::at(bytes, 12, bytes.len(), limits)?;
    for _ in 0..n {
        let mut storage = [0; 255];
        let mut arena = gnunet_dns::Arena::new(&mut storage);
        let q = reader.query(&mut arena)?;
        out.extend(q.name.wire().iter().map(u8::to_ascii_lowercase));
        out.extend_from_slice(&q.kind.0.to_be_bytes());
        out.extend_from_slice(&q.class.to_be_bytes());
    }
    Ok(out)
}
fn socket(server: SocketAddr) -> io::Result<UdpSocket> {
    let (domain, local) = match server {
        SocketAddr::V4(_) => (Domain::IPV4, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
        SocketAddr::V6(_) => (Domain::IPV6, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))),
    };
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if server.is_ipv6() {
        s.set_only_v6(true)?;
    }
    s.set_nonblocking(true)?;
    s.bind(&local.into())?;
    let standard: std::net::UdpSocket = s.into();
    UdpSocket::from_std(standard)
}
fn same(a: SocketAddr, b: SocketAddr) -> bool {
    match (a, b) {
        (SocketAddr::V4(a), SocketAddr::V4(b)) => a == b,
        (SocketAddr::V6(a), SocketAddr::V6(b)) => {
            a.ip() == b.ip() && a.port() == b.port() && a.scope_id() == b.scope_id()
        }
        _ => false,
    }
}
impl<'cfg, 'id, 'slots, E: Entropy> Driver<'cfg, 'id, 'slots, E> {
    pub(super) fn dns_start(
        &mut self,
        flow: Flow,
        job: core::Dns,
        query: OwnedFrame,
        expires: MonoInstant,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let prepared = (|| {
            self.resolver.ok_or(Fault::Unavailable)?;
            if query.len() > self.limits.dns_bytes {
                return Err(Fault::TooLarge);
            }
            let question = questions(query.bytes(), self.limits.dns_questions)?;
            let until = self.until(now, expires, None)?;
            let i = self
                .dns_jobs
                .iter()
                .position(Option::is_none)
                .ok_or(Fault::Capacity)?;
            Ok((i, question, until))
        })();
        match prepared {
            Ok((i, question, until)) => {
                self.dns_jobs[i] = Some(DnsJob {
                    job,
                    flow,
                    query,
                    question,
                    socket: None,
                    until,
                    expires,
                    next_send: Instant::now(),
                    written: false,
                    response: None,
                });
                Ok(())
            }
            Err(fault) => {
                self.engine.dns_retired(&job, Some(fault))?;
                observe(Event::DnsFailed {
                    job,
                    error: fault.into(),
                });
                Ok(())
            }
        }
    }
    pub(super) fn cancel_dns(
        &mut self,
        index: usize,
        failure: Option<Error>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let mut d = self.dns_jobs[index].take().ok_or(Fault::Stale)?;
        drop(d.socket.take());
        d.response = None;
        let fault = failure.as_ref().map(|e| match e {
            Error::Core(e) => *e,
            _ => Fault::Io,
        });
        self.engine.dns_retired(&d.job, fault)?;
        if let Some(error) = failure {
            observe(Event::DnsFailed { job: d.job, error });
        }
        Ok(())
    }
    pub(super) fn expire_dns(
        &mut self,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        for i in 0..self.dns_jobs.len() {
            if self.dns_jobs[i]
                .as_ref()
                .is_some_and(|d| now >= d.expires || Instant::now() >= d.until)
            {
                self.cancel_dns(i, Some(Fault::Deadline.into()), observe)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn dns_job(
        &mut self,
        cx: &mut Context<'_>,
        i: usize,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let d = self.dns_jobs[i].as_ref().ok_or(Fault::Stale)?;
        let info = self.engine.info(&d.flow)?;
        if info.closing || (info.peer_closed && d.written) {
            // A gone peer needs only the real original query-write receipt,
            // never a DNS response. Retire this exact socket before admitting
            // another held inner query on the same flow.
            self.cancel_dns(i, None, observe)?;
            return Poll::Ready(Ok(Progress::Activity));
        }
        if d.response.is_some() {
            let d = self.dns_jobs[i].as_ref().ok_or(Fault::Stale)?;
            let result =
                self.engine
                    .dns_reply(&d.job, d.response.as_ref().ok_or(Fault::Stale)?, now);
            match result {
                Ok(_) => {
                    let mut d = self.dns_jobs[i].take().ok_or(Fault::Stale)?;
                    drop(d.socket.take());
                    self.report.dns_replies = self.report.dns_replies.saturating_add(1);
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Err(Fault::WouldBlock) => return Poll::Pending,
                Err(e) => {
                    self.cancel_dns(i, Some(e.into()), observe)?;
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        let resolver = self.resolver.ok_or(Fault::Unavailable)?;
        if self.dns_jobs[i]
            .as_ref()
            .is_some_and(|d| d.socket.is_none())
        {
            match socket(resolver.server) {
                Ok(s) => {
                    let d = self.dns_jobs[i].as_mut().ok_or(Fault::Stale)?;
                    d.socket = Some(s);
                    self.engine.dns_admitted(&d.job)?;
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Err(e) => {
                    self.cancel_dns(i, Some(e.into()), observe)?;
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        let d = self.dns_jobs[i].as_mut().ok_or(Fault::Stale)?;
        let s = d.socket.as_ref().ok_or(Fault::Stale)?;
        // Real responses remain readable before a due retry. A previous query
        // can never select this socket, and endpoint/id/questions are checked.
        let mut read = ReadBuf::new(&mut self.dns_buffer);
        match s.poll_recv_from(cx, &mut read) {
            Poll::Pending => {}
            Poll::Ready(Err(e)) => {
                self.cancel_dns(i, Some(e.into()), observe)?;
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Ok(source)) => {
                let data = read.filled();
                let matches = d.written
                    && data.len() >= 12
                    && data.len() <= self.limits.dns_bytes
                    && same(source, resolver.server)
                    && data[..2] == d.query.bytes()[..2]
                    && data[2] & 0x80 != 0
                    && (data[2] & 0x78) == (d.query.bytes()[2] & 0x78)
                    && questions(data, self.limits.dns_questions).is_ok_and(|q| q == d.question);
                if matches {
                    let mut response = Vec::new();
                    response
                        .try_reserve_exact(data.len())
                        .map_err(|_| Fault::Capacity)?;
                    response.extend_from_slice(data);
                    d.response = Some(response);
                } else {
                    observe(Event::DnsDiscarded {
                        job: d.job.clone(),
                        source,
                    });
                }
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        if Instant::now() >= d.next_send {
            match s.poll_send_to(cx, d.query.bytes(), resolver.server) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    self.cancel_dns(i, Some(e.into()), observe)?;
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(n)) => {
                    if n != d.query.len() {
                        self.cancel_dns(i, Some(Fault::OutcomeUnknown.into()), observe)?;
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                    if !d.written {
                        self.engine.dns_written(&d.job)?;
                        d.written = true;
                    }
                    d.next_send = Instant::now()
                        .checked_add(resolver.retry)
                        .ok_or(Fault::Overflow)?;
                    self.report.dns_written = self.report.dns_written.saturating_add(1);
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
    pub(super) fn poll_dns(
        &mut self,
        cx: &mut Context<'_>,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        for n in 0..self.dns_jobs.len() {
            let i = (self.dns_cursor + n) % self.dns_jobs.len();
            if self.dns_jobs[i].is_some() {
                let r = self.dns_job(cx, i, now, observe);
                if r.is_ready() {
                    self.dns_cursor = (i + 1) % self.dns_jobs.len();
                    return r;
                }
            }
        }
        Poll::Pending
    }
}
