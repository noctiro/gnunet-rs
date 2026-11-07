//! Active v0.29.1 TESTBED resource ownership. There is no active controller IPC.
//! Socket availability and filesystem completion come from explicit native ports.
#![no_std]
#![forbid(unsafe_code)]
use core::{cell::Cell, fmt, ptr};
use gnunet_types::Error;
/// Official default inclusive low and exclusive high port bounds.
pub const DEFAULT_LOW_PORT: u16 = 12000;
/// Official default exclusive upper port bound.
pub const DEFAULT_HIGH_PORT: u16 = 56000;
/// Caller-owned single-thread allocation domain, no hidden global identity.
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// No native, random or cryptographic operation.
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
    fn allocate(&self) -> Result<u64, Error> {
        let n = self.next.get().checked_add(1).ok_or(Error::Overflow)?;
        self.next.set(n);
        Ok(n)
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Scope<'a> {
    domain: &'a Instance,
    allocation: u64,
}
impl PartialEq for Instance {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self, other)
    }
}
impl Eq for Instance {}
impl fmt::Debug for Scope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestbedScope")
            .field("allocation", &self.allocation)
            .finish_non_exhaustive()
    }
}
/// Original one-time socket-probe candidate; it is not an availability proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Probe<'a> {
    scope: Scope<'a>,
    row: usize,
    serial: u64,
    port: u16,
}
impl Probe<'_> {
    /// Actual candidate number, not a future service-ready fact.
    pub const fn port(self) -> u16 {
        self.port
    }
}
/// Logical reservation after actual native availability observation. No FD or
/// future availability is asserted by this token; check native handoff semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reservation<'a> {
    probe: Probe<'a>,
}
impl Reservation<'_> {
    /// Exact reserved port number.
    pub const fn port(self) -> u16 {
        self.probe.port
    }
}
/// Never-reused configuration home counter within an original system.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathId<'a> {
    scope: Scope<'a>,
    number: u64,
}
impl PathId<'_> {
    /// Exact counter, suitable for a numeric owned child path.
    pub const fn number(self) -> u64 {
        self.number
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Free,
    Probing,
    Reserved,
}
/// Caller-fixed reservation metadata. No per-port heap or full generation array.
pub struct PortSlot {
    serial: u64,
    port: u16,
    phase: Phase,
}
impl PortSlot {
    /// Empty caller storage.
    pub const fn empty() -> Self {
        Self {
            serial: 0,
            port: 0,
            phase: Phase::Free,
        }
    }
}
impl Default for PortSlot {
    fn default() -> Self {
        Self::empty()
    }
}
/// Original explicit native probe outcome. The native adapter binds actual TCP
/// and UDP sockets for every supported selected IP family before reporting Free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Availability {
    /// All supported selected socket kinds bound at that moment.
    Free,
    /// One supported selected socket failed to bind; do not reuse this session.
    Busy,
}
/// One bounded system. The bitmap records reserved/busy candidates, while
/// caller slots distinguish original operations and stale releases.
pub struct System<'id, 'slots> {
    scope: Scope<'id>,
    slots: &'slots mut [PortSlot],
    used: [u32; 2048],
    low: u16,
    high: u16,
    cursor: u32,
    path: u64,
    closed: bool,
}
impl<'id, 'slots> System<'id, 'slots> {
    /// Explicit actual persisted path high-water is supplied by the native owner.
    pub fn new(
        instance: &'id Instance,
        slots: &'slots mut [PortSlot],
        low: u16,
        high: u16,
        path_high_water: u64,
    ) -> Result<Self, Error> {
        if low == 0
            || low >= high
            || slots.is_empty()
            || slots.iter().any(|s| s.phase != Phase::Free)
        {
            return Err(Error::InvalidInput);
        }
        let scope = Scope {
            domain: instance,
            allocation: instance.allocate()?,
        };
        Ok(Self {
            scope,
            slots,
            used: [0; 2048],
            low,
            high,
            cursor: u32::from(low),
            path: path_high_water,
            closed: false,
        })
    }
    /// Allocation identity for uniquely named owned native resources; no authority.
    pub const fn allocation(&self) -> u64 {
        self.scope.allocation
    }
    /// Persist this next unused path counter before publishing the original path.
    pub const fn path_high_water(&self) -> u64 {
        self.path
    }
    fn live(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn set(&mut self, port: u16, value: bool) {
        let p = usize::from(port);
        let bit = 1u32 << (p % 32);
        if value {
            self.used[p / 32] |= bit
        } else {
            self.used[p / 32] &= !bit
        }
    }
    fn used(&self, port: u16) -> bool {
        let p = usize::from(port);
        self.used[p / 32] & (1u32 << (p % 32)) != 0
    }
    /// Allocate a real original bounded native probe job. Busy ports are scanned
    /// once until explicit release, including the exact inclusive low bound.
    pub fn probe(&mut self) -> Result<Probe<'id>, Error> {
        self.live()?;
        let row = self
            .slots
            .iter()
            .position(|s| s.phase == Phase::Free)
            .ok_or(Error::Capacity)?;
        let count = u32::from(self.high) - u32::from(self.low);
        let mut found = None;
        for _ in 0..count {
            let port = u16::try_from(self.cursor).map_err(|_| Error::Overflow)?;
            self.cursor += 1;
            if self.cursor >= u32::from(self.high) {
                self.cursor = u32::from(self.low)
            }
            if !self.used(port) {
                found = Some(port);
                break;
            }
        }
        let port = found.ok_or(Error::Capacity)?;
        let serial = self.scope.domain.allocate()?;
        self.set(port, true);
        self.slots[row] = PortSlot {
            serial,
            port,
            phase: Phase::Probing,
        };
        Ok(Probe {
            scope: self.scope,
            row,
            serial,
            port,
        })
    }
    fn check(&self, p: Probe<'id>, phase: Phase) -> Result<(), Error> {
        self.live()?;
        if p.scope != self.scope {
            return Err(Error::StaleGeneration);
        }
        let s = self.slots.get(p.row).ok_or(Error::StaleGeneration)?;
        if s.serial != p.serial || s.port != p.port || s.phase != phase {
            return Err(Error::StaleGeneration);
        }
        Ok(())
    }
    /// Admit only the outcome of this exact native probe. Busy candidates stay in
    /// the bitmap, matching the active library's per-system exclusion policy.
    pub fn probed(
        &mut self,
        p: Probe<'id>,
        availability: Availability,
    ) -> Result<Option<Reservation<'id>>, Error> {
        self.check(p, Phase::Probing)?;
        match availability {
            Availability::Free => {
                self.slots[p.row].phase = Phase::Reserved;
                Ok(Some(Reservation { probe: p }))
            }
            Availability::Busy => {
                self.slots[p.row].phase = Phase::Free;
                Ok(None)
            }
        }
    }
    /// Cancel an original probe that did not yield an availability observation.
    pub fn cancel_probe(&mut self, p: Probe<'id>) -> Result<(), Error> {
        self.check(p, Phase::Probing)?;
        self.slots[p.row].phase = Phase::Free;
        self.set(p.port, false);
        Ok(())
    }
    /// Release only this original logical reservation; stale copies never release
    /// a later reservation of the same numeric port. No process stop is asserted.
    pub fn release(&mut self, r: Reservation<'id>) -> Result<(), Error> {
        self.check(r.probe, Phase::Reserved)?;
        self.slots[r.probe.row].phase = Phase::Free;
        self.set(r.port(), false);
        Ok(())
    }
    /// Check exact original reservation metadata without native readiness claims.
    pub fn reserved(&self, r: Reservation<'id>) -> Result<(), Error> {
        self.check(r.probe, Phase::Reserved)
    }
    /// Burn a path number permanently before any external filesystem effect.
    pub fn allocate_path(&mut self) -> Result<PathId<'id>, Error> {
        self.live()?;
        let number = self.path;
        self.path = self.path.checked_add(1).ok_or(Error::Overflow)?;
        Ok(PathId {
            scope: self.scope,
            number,
        })
    }
    /// Check an issued original path; old systems cannot name a replacement scope.
    pub fn check_path(&self, id: PathId<'id>) -> Result<(), Error> {
        self.live()?;
        if id.scope != self.scope || id.number >= self.path {
            return Err(Error::StaleGeneration);
        }
        Ok(())
    }
    /// Stop logical admission. Native owner separately closes real resources and
    /// reports actual removal; this call is not filesystem/process cleanup proof.
    pub fn close(&mut self) {
        self.closed = true;
        for slot in self.slots.iter_mut() {
            slot.phase = Phase::Free
        }
    }
}
impl Drop for System<'_, '_> {
    fn drop(&mut self) {
        self.close()
    }
}

#[cfg(test)]
mod model;
