//! Client decisions and exact resolver completion for one original request.
use super::{Client, Decision, Destination, Error, OutputPhase, Owner, Phase, Request, Resolve};
use crate::correlation::questions_match;
impl<'id, const C: usize, const R: usize> Owner<'id, '_, C, R> {
    pub(super) fn replace(&mut self, r: Request<'id>, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.limits.payload_bytes {
            return Err(Error::TooLarge);
        }
        gnunet_dns::Header::decode(bytes)?;
        let free = self.free_bytes();
        let old = self.row(r)?.payload.charge();
        let payload = &mut self.rows[r.row].as_mut().ok_or(Error::Conflict)?.payload;
        self.payloads.replace(r.row, payload, free, bytes)?;
        self.used = self.used - old + payload.charge();
        Ok(())
    }
    /// Actual original client REPLY. Unknown stale RID is ignored; wrong client or
    /// premature callback retirement is refused, never retagged onto another query.
    pub fn reply(
        &mut self,
        client: Client<'id>,
        id: [u8; 8],
        decision: Decision<'_>,
    ) -> Result<bool, Error> {
        self.app(client)?;
        let Some(index) = self
            .rows
            .iter()
            .position(|row| row.as_ref().is_some_and(|r| r.id == id))
        else {
            return Ok(false);
        };
        let r = self.handle(index)?;
        let row = self.row(r)?;
        if row.expired {
            return Ok(false);
        }
        let output = row.output.ok_or(Error::PermissionDenied)?;
        if row.current != Some(client)
            || output.effect.destination != Destination::Client(client)
            || output.phase != OutputPhase::Written
        {
            return Err(Error::PermissionDenied);
        }
        let phase = row.phase;
        if let Decision::Answer(bytes) = decision {
            if matches!(phase, Phase::RequestMonitor | Phase::ResponseMonitor) {
                return Err(Error::PermissionDenied);
            }
            self.replace(r, bytes)?;
        }
        let row = self.row_mut(r)?;
        row.eligible &= !(1u64 << client.row);
        row.current = None;
        row.output = None;
        match decision {
            Decision::Drop => row.phase = Phase::Dropped,
            Decision::Forward => {}
            Decision::Answer(_) => {
                if phase == Phase::PreResolution {
                    let answered =
                        gnunet_dns::Header::decode(self.payload(r)?)?.flags.bits() & 0x8000 != 0;
                    if answered {
                        self.enter(r, Phase::PostResolution)?
                    } else {
                        self.enter(r, Phase::Resolver)?
                    }
                }
            }
        }
        Ok(true)
    }
    /// Original resolver operation is admitted only after actual native resolve()
    /// returned its real ID; native owner retains that exact mapping externally.
    pub fn resolving(&mut self, r: Request<'id>) -> Result<Resolve<'id>, Error> {
        let row = self.row(r)?;
        if row.phase != Phase::Resolver || row.resolver.is_some() || row.expired {
            return Err(Error::NotReady);
        }
        let job = Resolve {
            request: r,
            serial: self.scope.domain.allocate()?,
        };
        self.row_mut(r)?.resolver = Some(job);
        Ok(job)
    }
    /// Submit checked original actual resolver payload. No signature/DNSSEC or
    /// application-success assertion is made by matching DNS header/question data.
    pub fn resolved(&mut self, job: Resolve<'id>, bytes: &[u8]) -> Result<(), Error> {
        let row = self.row(job.request)?;
        if row.resolver != Some(job) || row.expired {
            return Err(Error::StaleGeneration);
        }
        if !questions_match(self.payload(job.request)?, bytes)? {
            return Err(Error::Authentication);
        }
        self.replace(job.request, bytes)?;
        self.row_mut(job.request)?.resolver = None;
        self.enter(job.request, Phase::PostResolution)
    }
    /// Exact native cancellation/eviction/failure has retired callback authority.
    /// It is not cached socket close or remote request revocation evidence.
    pub fn resolve_stopped(&mut self, job: Resolve<'id>) -> Result<(), Error> {
        if self.row(job.request)?.resolver != Some(job) {
            return Err(Error::StaleGeneration);
        }
        let row = self.row_mut(job.request)?;
        row.resolver = None;
        row.phase = Phase::Dropped;
        Ok(())
    }
}
