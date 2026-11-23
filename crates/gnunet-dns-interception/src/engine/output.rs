//! Original client/source output preparation, exposure and completion.
use super::{
    Client, Destination, Effect, Error, Output, OutputPhase, Owner, Phase, PreparedReply, Request,
    wire,
};
impl<'id, const C: usize, const R: usize> Owner<'id, '_, C, R> {
    /// Encode one original callback, then reserve its immutable effect. Native
    /// allocation/queue failure must reject_prepared before it changes MQ ownership.
    pub fn prepare_client(
        &mut self,
        r: Request<'id>,
        client: Client<'id>,
        out: &mut [u8],
    ) -> Result<(Effect<'id>, usize), Error> {
        self.app(client)?;
        let row = self.row(r)?;
        if row.output.is_some() || row.current != Some(client) || row.expired {
            return Err(Error::NotReady);
        }
        let n = wire::Response {
            id: row.id,
            dns: self.payload(r)?,
        }
        .encode(out)?;
        let effect = Effect {
            request: r,
            serial: self.scope.domain.allocate()?,
            destination: Destination::Client(client),
        };
        self.row_mut(r)?.output = Some(Output {
            effect,
            phase: OutputPhase::Prepared,
        });
        Ok((effect, n))
    }
    /// Prepare the original DNS response without copying its payload. The
    /// returned borrow prevents mutation/retirement while native encoding reads
    /// it. Native admission, exposure and completion remain separate effects.
    ///
    /// # Errors
    /// Refuses a foreign/stale request, a non-output phase, an existing output,
    /// expired work or allocation-serial exhaustion without preparing an effect.
    pub fn prepare_source(&mut self, r: Request<'id>) -> Result<PreparedReply<'_, 'id>, Error> {
        let row = self.row(r)?;
        if row.phase != Phase::Output || row.output.is_some() || row.expired {
            return Err(Error::NotReady);
        }
        let effect = Effect {
            request: r,
            serial: self.scope.domain.allocate()?,
            destination: Destination::Source(row.source),
        };
        self.row_mut(r)?.output = Some(Output {
            effect,
            phase: OutputPhase::Prepared,
        });
        Ok(PreparedReply {
            effect,
            dns: self.payload(r)?,
        })
    }
    fn output_mut(&mut self, e: Effect<'id>) -> Result<&mut Output<'id>, Error> {
        let o = self
            .row_mut(e.request)?
            .output
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if o.effect != e {
            return Err(Error::StaleGeneration);
        }
        Ok(o)
    }
    /// Actual immutable frame entered that destination's queue.
    pub fn queued(&mut self, e: Effect<'id>) -> Result<(), Error> {
        let o = self.output_mut(e)?;
        if o.phase != OutputPhase::Prepared {
            return Err(Error::Conflict);
        }
        o.phase = OutputPhase::Queued;
        Ok(())
    }
    /// Actual positive local exposure, not a remote acknowledgement.
    pub fn exposed(&mut self, e: Effect<'id>) -> Result<(), Error> {
        let o = self.output_mut(e)?;
        if !matches!(o.phase, OutputPhase::Queued | OutputPhase::Exposed) {
            return Err(Error::Conflict);
        }
        o.phase = OutputPhase::Exposed;
        Ok(())
    }
    /// Complete original local output. The native owner retains its transport
    /// observation; no variant establishes remote DNS/application delivery.
    pub fn written(&mut self, e: Effect<'id>) -> Result<(), Error> {
        let o = self.output_mut(e)?;
        if !matches!(o.phase, OutputPhase::Queued | OutputPhase::Exposed) {
            return Err(Error::Conflict);
        }
        if matches!(e.destination, Destination::Source(_)) {
            self.row_mut(e.request)?.output = None;
            self.row_mut(e.request)?.phase = Phase::Dropped;
        } else {
            o.phase = OutputPhase::Written;
        }
        Ok(())
    }
    /// Retire one original source output after its native operation has actually
    /// stopped, without claiming delivery or closing other requests' source.
    /// The caller retains its unsent/unknown/accepted exposure observation.
    pub fn source_stopped(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        if !matches!(effect.destination, Destination::Source(_)) {
            return Err(Error::InvalidInput);
        }
        if !matches!(
            self.output_mut(effect)?.phase,
            OutputPhase::Queued | OutputPhase::Exposed
        ) {
            return Err(Error::Conflict);
        }
        let row = self.row_mut(effect.request)?;
        row.output = None;
        row.expired = true;
        row.phase = Phase::Dropped;
        Ok(())
    }
    /// Native never-admitted output allocation failed, with no exposed bytes.
    pub fn reject_prepared(&mut self, e: Effect<'id>) -> Result<(), Error> {
        if self.output_mut(e)?.phase != OutputPhase::Prepared {
            return Err(Error::Conflict);
        }
        self.row_mut(e.request)?.output = None;
        Ok(())
    }
}
