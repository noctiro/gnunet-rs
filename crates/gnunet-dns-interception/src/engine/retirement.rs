//! Original source/client loss, deadlines and resource retirement.
use super::{Client, Destination, Effect, Error, OutputPhase, Owner, Phase, Request, Source};
impl<'id, const C: usize, const R: usize> Owner<'id, '_, C, R> {
    /// Actual physical client owner stopped: clear only original callback effects
    /// and phase snapshots. Other clients and intercepted requests continue.
    pub fn client_lost(&mut self, client: Client<'id>) -> Result<(), Error> {
        self.app(client)?;
        self.apps[client.row] = None;
        for row in self.rows.iter_mut().flatten() {
            row.eligible &= !(1u64 << client.row);
            if row.current == Some(client) {
                row.current = None;
                row.output = None;
            }
        }
        Ok(())
    }
    /// Actual physical native source closed. All its original outputs and resolver
    /// jobs remain explicitly canceled/retired; no payload is replayed to a new one.
    pub fn source_lost(&mut self, source: Source<'id>) -> Result<(), Error> {
        if self.source != Some(source) {
            return Err(Error::StaleGeneration);
        }
        self.source = None;
        for row in self.rows.iter_mut().flatten() {
            if row.source == source {
                row.phase = Phase::Dropped;
                if row
                    .output
                    .is_some_and(|out| out.effect.destination == Destination::Source(source))
                {
                    row.output = None;
                }
                // Source loss does not physically stop an application MQ.
                // Preserve that callback debt until its original MQ is retired.
                row.expired = true;
            }
        }
        Ok(())
    }
    /// Original native hard target expired or owner explicitly canceled. This
    /// leaves real external output/resolver debts until their actual retirement.
    pub fn abort(&mut self, request: Request<'id>) -> Result<(), Error> {
        let row = self.row_mut(request)?;
        row.expired = true;
        row.phase = Phase::Dropped;
        Ok(())
    }
    /// Logical expiry does not pretend to cancel a partial MQ or DNSSTUB job.
    pub fn expire(&mut self, now: u64) {
        for row in self.rows.iter_mut().flatten() {
            if now >= row.until {
                row.expired = true;
                row.phase = Phase::Dropped;
            }
        }
    }
    /// Original rows, for caller-driven fair bounded work scheduling.
    pub fn requests(&self) -> impl Iterator<Item = Request<'id>> + '_ {
        self.rows.iter().enumerate().filter_map(|(i, row)| {
            row.as_ref().map(|r| Request {
                scope: self.scope,
                row: i,
                serial: r.serial,
            })
        })
    }
    /// Release only an actual terminal row with all original external debts settled.
    pub fn retire(&mut self, r: Request<'id>) -> Result<(), Error> {
        let row = self.row(r)?;
        if row.phase != Phase::Dropped || row.output.is_some() || row.resolver.is_some() {
            return Err(Error::WouldBlock);
        }
        let payload = &self.rows[r.row].as_ref().ok_or(Error::Conflict)?.payload;
        let used = self
            .used
            .checked_sub(payload.charge())
            .ok_or(Error::Conflict)?;
        self.payloads.release(r.row, payload)?;
        self.rows[r.row] = None;
        self.used = used;
        Ok(())
    }
    /// Exact configured local-MQ ceiling, for native construction consistency.
    pub const fn client_capacity(&self) -> usize {
        self.limits.clients
    }
    /// Exact maximum DNS bytes accepted by this original owner.
    pub const fn payload_limit(&self) -> usize {
        self.limits.payload_bytes
    }
    /// Fixed table ceiling for fair O(capacity) native scheduling, no nth rescans.
    pub const fn request_capacity(&self) -> usize {
        self.limits.requests
    }
    /// One original table row, checked only as read-only scheduling metadata.
    pub fn request_at(&self, index: usize) -> Option<Request<'id>> {
        self.rows.get(index)?.as_ref().map(|row| Request {
            scope: self.scope,
            row: index,
            serial: row.serial,
        })
    }
    /// All original callbacks on this still-current client, before its actual
    /// physical source loss is applied. Read-only facts grant no new authority.
    pub fn client_outputs(
        &self,
        client: Client<'id>,
    ) -> Result<impl Iterator<Item = (Effect<'id>, OutputPhase)> + '_, Error> {
        self.app(client)?;
        Ok(self.rows.iter().flatten().filter_map(move |r| {
            r.output
                .filter(|o| o.effect.destination == Destination::Client(client))
                .map(|o| (o.effect, o.phase))
        }))
    }
    /// Actual outstanding original callback metadata for this live MQ. INIT or a
    /// different RID cannot reset the oldest callback's native hard deadline.
    pub fn pending_client(&self, client: Client<'id>) -> Result<bool, Error> {
        self.app(client)?;
        Ok(self.rows.iter().flatten().any(|r| {
            r.output
                .is_some_and(|o| o.effect.destination == Destination::Client(client))
        }))
    }
    /// Active payload bytes in fixed storage, or retained payload capacity on the heap.
    pub const fn payload_bytes(&self) -> usize {
        self.used
    }
}
