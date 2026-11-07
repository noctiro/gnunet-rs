//! Original official DNS exit193/194. Actual DNS socket operations stay outside
//! this core; transaction IDs and all completions retain original request scope.
use super::*;
impl Engine<'_> {
    pub(super) fn dns_start(
        &mut self,
        index: usize,
        packet: &[u8],
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Input, Error> {
        let r = self.flows[index].as_ref().ok_or(Error::Stale)?;
        if r.target != Target::Dns || !self.config.dns {
            return Err(Error::PermissionDenied);
        }
        if r.dns.is_some() {
            return Err(Error::WouldBlock);
        }
        if packet.len() < 12 || packet.len() > self.limits.dns_bytes || packet[2] & 0x80 != 0 {
            return Err(Error::Malformed);
        }
        let original = [packet[0], packet[1]];
        let mut wire = None;
        for _ in 0..self.limits.entropy_draws {
            let mut id = [0; 2];
            entropy.fill(&mut id)?;
            if !self
                .flows
                .iter()
                .flatten()
                .any(|r| r.dns.as_ref().is_some_and(|d| d.wire == id))
            {
                wire = Some(id);
                break;
            }
        }
        let wire = wire.ok_or(Error::Capacity)?;
        let mut query = copy(packet)?;
        query[..2].copy_from_slice(&wire);
        let job = Dns {
            owner: self.stamp.clone(),
            serial: self.serial()?,
        };
        let input = Input {
            owner: self.stamp.clone(),
            serial: self.serial()?,
        };
        let expires = now
            .checked_add(self.limits.input_lifetime)
            .ok_or(Error::Overflow)?;
        let idle = now.checked_add(self.limits.idle).ok_or(Error::Overflow)?;
        let r = self.flows[index].as_mut().ok_or(Error::Stale)?;
        r.dns = Some(DnsJob {
            id: job,
            query,
            original,
            wire,
            issued: false,
            admitted: false,
            written: false,
            cancelling: false,
            cancel_issued: false,
        });
        r.receipt = Some(Receipt {
            id: input.clone(),
            ready: false,
            issued: false,
            expires,
        });
        r.last = now;
        r.idle = idle;
        Ok(input)
    }
    fn dns_index(&self, job: &Dns) -> Result<usize, Error> {
        if !Rc::ptr_eq(&self.stamp, &job.owner) {
            return Err(Error::Stale);
        }
        self.flows
            .iter()
            .position(|r| {
                r.as_ref()
                    .is_some_and(|r| r.dns.as_ref().is_some_and(|d| d.id == *job))
            })
            .ok_or(Error::Stale)
    }
    /// Actual external socket port admitted this exact immutable query. No write
    /// or response is inferred; cancelling it still requires dns_retired.
    pub fn dns_admitted(&mut self, job: &Dns) -> Result<(), Error> {
        let i = self.dns_index(job)?;
        let d = self.flows[i]
            .as_mut()
            .and_then(|r| r.dns.as_mut())
            .ok_or(Error::Stale)?;
        if !d.issued || d.admitted || d.cancelling {
            return Err(Error::Stale);
        }
        d.admitted = true;
        Ok(())
    }
    /// Actual whole UDP query write on its original socket. Only this completion
    /// makes the original VPN processing receipt ready; no DNS reply is invented.
    pub fn dns_written(&mut self, job: &Dns) -> Result<(), Error> {
        let i = self.dns_index(job)?;
        let r = self.flows[i].as_mut().ok_or(Error::Stale)?;
        let d = r.dns.as_mut().ok_or(Error::Stale)?;
        if !d.admitted || d.written {
            return Err(Error::Stale);
        }
        d.written = true;
        if !r.closing
            && let Some(input) = &mut r.receipt
        {
            input.ready = true;
        }
        Ok(())
    }
    /// Actual original DNS port returned a validated response on the selected
    /// socket/server scope. Only its matching transaction ID is restored.
    /// WouldBlock retains this original result for caller retry, with no replay.
    pub fn dns_reply(&mut self, job: &Dns, packet: &[u8], now: MonoInstant) -> Result<Flow, Error> {
        let i = self.dns_index(job)?;
        let now = self.time(now)?;
        let r = self.flows[i].as_ref().ok_or(Error::Stale)?;
        let d = r.dns.as_ref().ok_or(Error::Stale)?;
        if r.closing || d.cancelling || !d.written {
            return Err(Error::Closed);
        }
        if packet.len() < 12
            || packet.len() > self.limits.dns_bytes
            || packet[..2] != d.wire
            || packet[2] & 0x80 == 0
        {
            return Err(Error::Authentication);
        }
        let flow = r.flow.clone();
        if r.peer_closed {
            // This actual response no longer has a peer consumer. Retire only
            // its original DNS job, leaving earlier held input/forwarding debts
            // intact until the native host reports their real completion.
            self.flows[i].as_mut().ok_or(Error::Stale)?.dns = None;
            return Ok(flow);
        }
        let mut response = copy(packet)?;
        response[..2].copy_from_slice(&d.original);
        self.queue_peer(
            &flow,
            PeerMessage::Dns {
                reply: true,
                packet: &response,
            },
        )?;
        let r = self.flows[i].as_mut().ok_or(Error::Stale)?;
        r.dns = None;
        r.last = now;
        r.idle = now.checked_add(self.limits.idle).ok_or(Error::Overflow)?;
        Ok(flow)
    }
    /// Actual original socket request is now closed/drained. None with no reply
    /// does not manufacture NXDOMAIN or another negative answer.
    pub fn dns_retired(&mut self, job: &Dns, failure: Option<Error>) -> Result<(), Error> {
        let i = self.dns_index(job)?;
        let r = self.flows[i].as_mut().ok_or(Error::Stale)?;
        let d = r.dns.as_ref().ok_or(Error::Stale)?;
        let unprocessed = !d.written;
        r.dns = None;
        if unprocessed || failure.is_some() {
            self.close_index(i, failure.or(Some(Error::Io)));
        }
        Ok(())
    }
}
