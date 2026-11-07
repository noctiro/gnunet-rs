//! Authenticated OPEN metadata awaiting an actual local listener.
//! No payload buffer, wire authority, worker or per-packet allocation lives here.
use gnunet_cadet::tunnel::context;
use gnunet_types::{Error, MonoInstant};
use std::time::Duration;
use tokio::time::Instant;

/// Official incoming closed-port lifetime. Duplicate OPEN never changes it.
const CLOSED_PORT_MICROS: u64 = 30_000_000;

#[derive(Clone, Copy)]
pub(super) struct Waiting<'node> {
    pub(super) tunnel: usize,
    pub(super) scope: context::Scope<'node>,
    pub(super) channel: u32,
    pub(super) challenge: [u8; 64],
    pub(super) expires: MonoInstant,
    pub(super) hard: Instant,
}
impl<'node> Waiting<'node> {
    pub(super) fn new(
        tunnel: usize,
        scope: context::Scope<'node>,
        channel: u32,
        challenge: [u8; 64],
        now: MonoInstant,
    ) -> Result<Self, Error> {
        if !scope.is_live() {
            return Err(Error::StaleGeneration);
        }
        let expires = MonoInstant(
            now.0
                .checked_add(CLOSED_PORT_MICROS)
                .ok_or(Error::Overflow)?,
        );
        let hard = Instant::now()
            .checked_add(Duration::from_micros(CLOSED_PORT_MICROS))
            .ok_or(Error::Overflow)?;
        Ok(Self {
            tunnel,
            scope,
            channel,
            challenge,
            expires,
            hard,
        })
    }
    pub(super) fn expired(&self, now: MonoInstant) -> bool {
        now >= self.expires || Instant::now() >= self.hard
    }
}

/// One fixed metadata slab, shared with the Node's CTN claim limit.
/// Empty slots are reusable; admission never increases its length or capacity.
pub(super) struct Loose<'node> {
    pub(super) rows: Vec<Option<Waiting<'node>>>,
}
impl<'node> Loose<'node> {
    pub(super) fn new(limit: usize) -> Result<Self, Error> {
        if limit == 0 {
            return Err(Error::InvalidInput);
        }
        limit
            .checked_mul(core::mem::size_of::<Option<Waiting<'node>>>())
            .ok_or(Error::Overflow)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(limit).map_err(|_| Error::Capacity)?;
        rows.resize_with(limit, || None);
        Ok(Self { rows })
    }
    pub(super) fn position(&self, scope: context::Scope<'node>, channel: u32) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| row.is_some_and(|row| row.scope == scope && row.channel == channel))
    }
    pub(super) fn admit(&mut self, original: Waiting<'node>) -> Result<(), Error> {
        if self.position(original.scope, original.channel).is_some() {
            return Err(Error::Conflict);
        }
        let slot = self
            .rows
            .iter_mut()
            .find(|row| row.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some(original);
        Ok(())
    }
    pub(super) fn contains(&self, scope: context::Scope<'node>) -> bool {
        self.rows.iter().flatten().any(|row| row.scope == scope)
    }
    pub(super) fn next_deadline(&self) -> Option<MonoInstant> {
        self.rows.iter().flatten().map(|row| row.expires).min()
    }
    pub(super) fn native_deadline(&self) -> Option<Instant> {
        self.rows.iter().flatten().map(|row| row.hard).min()
    }
}
