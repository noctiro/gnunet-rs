use super::{Lookup, LookupResult, MAX_NAME_BYTES, Parameters, WireId};
use gnunet_types::Error;

/// Nonzero-sized identity storage for one original GNS client lifetime.
///
/// ```compile_fail
/// use gnunet_client::gns::{Client, Instance};
/// let mut storage = Instance::new();
/// let mut first = Client::<1, 8>::new(&mut storage).unwrap();
/// let old = first.begin_connection().unwrap();
/// drop(first);
/// let mut replacement = Client::<1, 8>::new(&mut storage).unwrap();
/// replacement.lost(old).unwrap();
/// ```
#[derive(Debug)]
pub struct Instance {
    _private: u8,
}
impl Instance {
    /// Fresh owner identity without allocation or global counters.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: 0 }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! token {
    ($name:ident, $doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy, Debug)]
        pub struct $name<'a> {
            owner: &'a Instance,
            serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, rhs: &Self) -> bool {
                core::ptr::eq(self.owner, rhs.owner) && self.serial == rhs.serial
            }
        }
        impl Eq for $name<'_> {}
        impl $name<'_> {
            /// Diagnostic serial; it cannot reconstruct authority or wire IDs.
            #[must_use]
            pub const fn diagnostic(self) -> u64 {
                self.serial
            }
        }
    };
}
token!(
    Epoch,
    "Original physical GNS MQ, independent of logical lookup lifetimes."
);
token!(
    QueryId,
    "Original logical GNS lookup; never a raw four-byte wire ID."
);
token!(
    AttemptId,
    "Original immutable request write attempt on one physical MQ."
);

/// Immutable official request retained through partial and canceled native I/O.
/// Dropping it does not authorize recreating that attempt on the same MQ.
#[must_use = "retain the original frame until full writing or retirement of its original MQ"]
pub struct Outbound<'a> {
    epoch: Epoch<'a>,
    query: QueryId<'a>,
    attempt: AttemptId<'a>,
    bytes: [u8; super::LOOKUP_HEADER_LEN + gnunet_gnsrecord::ZONE_WIRE_LEN + MAX_NAME_BYTES + 1],
    len: usize,
}
impl<'a> Outbound<'a> {
    /// Original physical service connection.
    #[must_use]
    pub const fn epoch(&self) -> Epoch<'a> {
        self.epoch
    }
    /// Original logical request, possibly canceled after admission.
    #[must_use]
    pub const fn query(&self) -> QueryId<'a> {
        self.query
    }
    /// Original local write completion capability.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId<'a> {
        self.attempt
    }
    /// Exact original frame; no local owner/generation fields are serialized.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
/// One validated response from an original physical service connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Received<'id, 'wire> {
    /// Well-formed response for no currently submitted original lookup.
    Unmatched,
    /// Terminal observation; the logical query is retired before returning it.
    Answer {
        /// Retired original query capability.
        query: QueryId<'id>,
        /// Structurally decoded, service-supplied records; not block authentication.
        result: LookupResult<'wire>,
    },
}
#[derive(Clone, Copy)]
enum Phase {
    Queued,
    Leased { epoch: u64, attempt: u64 },
    Written { epoch: u64 },
    Canceled { epoch: u64, attempt: u64 },
}
#[derive(Clone, Copy)]
struct State<const N: usize> {
    serial: u64,
    wire: WireId,
    parameters: Parameters,
    name: [u8; N],
    len: usize,
    phase: Phase,
}
/// Allocation-free bounded logical query owner with explicit physical attempts.
///
/// Lookup intent survives physical MQ loss. Canceling an admitted frame suppresses
/// its callback but retains the original write debt until full writing or loss.
/// Retry timing, actual socket writing and framing belong to the native adapter.
pub struct Client<'a, const R: usize, const N: usize> {
    owner: &'a Instance,
    slots: [Option<State<N>>; R],
    epoch: Option<u64>,
    last_epoch: u64,
    last_query: u64,
    last_attempt: u64,
    next_wire: Option<u32>,
    closed: bool,
}
impl<'a, const R: usize, const N: usize> Client<'a, R, N> {
    /// Borrow identity storage and select explicit query/name capacities.
    pub fn new(owner: &'a mut Instance) -> Result<Self, Error> {
        if R == 0 || N > MAX_NAME_BYTES {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            owner,
            slots: [None; R],
            epoch: None,
            last_epoch: 0,
            last_query: 0,
            last_attempt: 0,
            next_wire: Some(0),
            closed: false,
        })
    }
    /// Attach a new original physical MQ. Retire any prior MQ through `lost` first.
    pub fn begin_connection(&mut self) -> Result<Epoch<'a>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.epoch.is_some() {
            return Err(Error::NotReady);
        }
        let serial = self.last_epoch.checked_add(1).ok_or(Error::Overflow)?;
        self.last_epoch = serial;
        self.epoch = Some(serial);
        Ok(Epoch {
            owner: self.owner,
            serial,
        })
    }
    /// Current original physical MQ, if one is attached.
    #[must_use]
    pub fn epoch(&self) -> Option<Epoch<'a>> {
        self.epoch.map(|serial| Epoch {
            owner: self.owner,
            serial,
        })
    }
    /// Exact next original request size, for fallible native storage preflight.
    /// This neither leases an attempt nor allocates or changes query order.
    #[must_use]
    pub fn next_size(&self) -> Option<usize> {
        self.slots
            .iter()
            .flatten()
            .filter(|s| matches!(s.phase, Phase::Queued))
            .min_by_key(|s| s.serial)
            .map(|s| super::LOOKUP_HEADER_LEN + gnunet_gnsrecord::ZONE_WIRE_LEN + s.len + 1)
    }
    fn validate_epoch(&self, epoch: Epoch<'_>) -> Result<(), Error> {
        if core::ptr::eq(epoch.owner, self.owner) && self.epoch == Some(epoch.serial) {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    /// Admit a logical lookup with its unchanged name and parameters.
    /// Empty/default names are retained for the service to interpret.
    pub fn lookup(&mut self, parameters: Parameters, name: &[u8]) -> Result<QueryId<'a>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        Lookup::new(WireId([0; 4]), parameters, name)?;
        if name.len() > N {
            return Err(Error::TooLarge);
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::WouldBlock)?;
        let serial = self.last_query.checked_add(1).ok_or(Error::Overflow)?;
        let wire = self.next_wire.ok_or(Error::Overflow)?;
        let mut stored = [0; N];
        stored[..name.len()].copy_from_slice(name);
        self.slots[index] = Some(State {
            serial,
            wire: WireId::from_counter(wire),
            parameters,
            name: stored,
            len: name.len(),
            phase: Phase::Queued,
        });
        self.last_query = serial;
        self.next_wire = wire.checked_add(1);
        Ok(QueryId {
            owner: self.owner,
            serial,
        })
    }
    fn index(&self, query: QueryId<'_>) -> Result<usize, Error> {
        if !core::ptr::eq(query.owner, self.owner) {
            return Err(Error::Stale);
        }
        self.slots
            .iter()
            .position(|s| {
                s.as_ref().is_some_and(|s| {
                    s.serial == query.serial && !matches!(s.phase, Phase::Canceled { .. })
                })
            })
            .ok_or(Error::Stale)
    }
    /// Whether this exact original logical lookup is still pending.
    #[must_use]
    pub fn live(&self, query: QueryId<'_>) -> bool {
        self.index(query).is_ok()
    }
    /// Cancel only the original logical request. No invented cancel wire is sent.
    pub fn cancel(&mut self, query: QueryId<'_>) -> Result<(), Error> {
        let index = self.index(query)?;
        match self.slots[index].as_ref().ok_or(Error::Stale)?.phase {
            Phase::Leased { epoch, attempt } => {
                self.slots[index].as_mut().ok_or(Error::Stale)?.phase =
                    Phase::Canceled { epoch, attempt };
            }
            _ => self.slots[index] = None,
        }
        Ok(())
    }
    /// Lease the oldest queued lookup as one owned immutable frame.
    /// A lost/dropped write cannot be regenerated until its MQ is retired.
    pub fn outbound(&mut self, epoch: Epoch<'a>) -> Result<Option<Outbound<'a>>, Error> {
        self.validate_epoch(epoch)?;
        let index = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                s.as_ref()
                    .filter(|s| matches!(s.phase, Phase::Queued))
                    .map(|s| (i, s.serial))
            })
            .min_by_key(|(_, s)| *s)
            .map(|(i, _)| i);
        let Some(index) = index else {
            return Ok(None);
        };
        let attempt = self.last_attempt.checked_add(1).ok_or(Error::Overflow)?;
        let state = self.slots[index].as_ref().ok_or(Error::Stale)?;
        let mut output = Outbound {
            epoch,
            query: QueryId {
                owner: self.owner,
                serial: state.serial,
            },
            attempt: AttemptId {
                owner: self.owner,
                serial: attempt,
            },
            bytes: [0; super::LOOKUP_HEADER_LEN
                + gnunet_gnsrecord::ZONE_WIRE_LEN
                + MAX_NAME_BYTES
                + 1],
            len: 0,
        };
        output.len = Lookup::new(state.wire, state.parameters, &state.name[..state.len])?
            .encode(&mut output.bytes)?;
        self.slots[index].as_mut().ok_or(Error::Stale)?.phase = Phase::Leased {
            epoch: epoch.serial,
            attempt,
        };
        self.last_attempt = attempt;
        Ok(Some(output))
    }
    /// Report full local writing of exactly the original frame. This is not a
    /// resolution result, service acceptance or authenticated record observation.
    pub fn written(&mut self, attempt: AttemptId<'_>) -> Result<(), Error> {
        if !core::ptr::eq(attempt.owner, self.owner) {
            return Err(Error::Stale);
        }
        let (index, epoch, canceled) = self
            .slots
            .iter()
            .enumerate()
            .find_map(|(i, s)| match s.as_ref()?.phase {
                Phase::Leased { epoch, attempt: a } if a == attempt.serial => {
                    Some((i, epoch, false))
                }
                Phase::Canceled { epoch, attempt: a } if a == attempt.serial => {
                    Some((i, epoch, true))
                }
                _ => None,
            })
            .ok_or(Error::Stale)?;
        if self.epoch != Some(epoch) {
            return Err(Error::Stale);
        }
        if canceled {
            self.slots[index] = None;
        } else {
            self.slots[index].as_mut().ok_or(Error::Stale)?.phase = Phase::Written { epoch };
        }
        Ok(())
    }
    /// Consume one complete structural reply on its original physical MQ.
    /// Stale/foreign epochs are refused before parsing or changing any lookup.
    pub fn receive<'wire>(
        &mut self,
        epoch: Epoch<'_>,
        bytes: &'wire [u8],
        maximum_records: usize,
    ) -> Result<Received<'a, 'wire>, Error> {
        self.validate_epoch(epoch)?;
        let result = LookupResult::decode(bytes, maximum_records)?;
        let found = self.slots.iter().enumerate().find_map(|(i, s)| {
            s.as_ref()
                .filter(|s| {
                    s.wire == result.id()
                        && matches!(s.phase,Phase::Written { epoch:e } if e==epoch.serial)
                })
                .map(|s| (i, s.serial))
        });
        let Some((index, serial)) = found else {
            return Ok(Received::Unmatched);
        };
        self.slots[index] = None;
        Ok(Received::Answer {
            query: QueryId {
                owner: self.owner,
                serial,
            },
            result,
        })
    }
    /// Retire exactly the lost physical MQ and its attempts; live logical lookups
    /// return to queued state. Canceled writes are discarded and never replayed.
    pub fn lost(&mut self, epoch: Epoch<'_>) -> Result<(), Error> {
        self.validate_epoch(epoch)?;
        for slot in &mut self.slots {
            match slot {
                Some(s) if matches!(s.phase, Phase::Canceled { .. }) => *slot = None,
                Some(s) => s.phase = Phase::Queued,
                None => {}
            }
        }
        self.epoch = None;
        Ok(())
    }
    /// Permanently retire this owner; closing cannot resubscribe or reconnect.
    pub fn close(&mut self) {
        self.slots.fill(None);
        self.epoch = None;
        self.closed = true;
    }
    /// Number of live logical lookups, excluding canceled write debt.
    #[must_use]
    pub fn pending_queries(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| {
                s.as_ref()
                    .is_some_and(|s| !matches!(s.phase, Phase::Canceled { .. }))
            })
            .count()
    }
    /// Number of original admitted frames still awaiting full writing or MQ loss.
    #[must_use]
    pub fn pending_writes(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| {
                s.as_ref().is_some_and(|s| {
                    matches!(s.phase, Phase::Leased { .. } | Phase::Canceled { .. })
                })
            })
            .count()
    }
}
