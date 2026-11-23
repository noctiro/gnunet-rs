//! Allocation-free SETU on one original ordered, authenticated channel.

#![expect(
    clippy::result_large_err,
    reason = "refusal returns caller-owned spans without allocating transient storage"
)]

use crate::{
    Codec, element_hash,
    ibf::{Cell, Key, Order},
    mode::{Choice, choose, validate_options},
    strata::{self, Strata},
    wire::{self, Abi, Element, Options, Peer},
};
use core::{cell::Cell as Generation, ptr};
use gnunet_types::Error;

/// Fixed local workspace reused for each official estimator rotation.
pub const ESTIMATOR_CELLS: usize = strata::CELLS_PER_ESTIMATOR;
/// Exact raw bytes for a transmitted one-estimator prefix and the minimum
/// caller workspace for receiving all supported counts with a streaming codec.
pub const ESTIMATOR_BYTES: usize = strata::WIRE_BYTES_PER_ESTIMATOR;
/// Exact receiver subtraction/peeling scratch.
pub const PEEL_CELLS: usize = strata::BUCKETS;
const FULL_PADDING: [u8; 16] = [0; 16];

mod differential;
mod estimate;
pub use differential::{Differential, RemoteEntry};

#[cfg(all(test, any(feature = "fixed-zlib", feature = "zlib")))]
mod tests;

/// A caller's stable original element snapshot. An append-only source may
/// retain just its original count. Each originally named position must remain
/// the same type and bytes until the exchange retires.
pub trait ElementSource {
    /// Number of original elements in the retained scope.
    fn len(&self) -> Result<usize, Error>;
    /// Whether the original set is empty.
    fn is_empty(&self) -> Result<bool, Error> {
        self.len().map(|len| len == 0)
    }
    /// Borrow or render one exact original typed element in caller scratch.
    fn element<'view>(
        &'view self,
        index: usize,
        scratch: &'view mut [u8],
    ) -> Result<Element<'view>, Error>;
}

impl<S: ElementSource + ?Sized> ElementSource for &S {
    fn len(&self) -> Result<usize, Error> {
        S::len(self)
    }

    fn element<'view>(
        &'view self,
        index: usize,
        scratch: &'view mut [u8],
    ) -> Result<Element<'view>, Error> {
        S::element(self, index, scratch)
    }
}

impl ElementSource for [Element<'_>] {
    fn len(&self) -> Result<usize, Error> {
        Ok(<[Element<'_>]>::len(self))
    }

    fn element<'view>(
        &'view self,
        index: usize,
        _: &'view mut [u8],
    ) -> Result<Element<'view>, Error> {
        self.get(index).copied().ok_or(Error::Stale)
    }
}

/// Original-set index slot. Hosts provide one per admitted local element.
#[derive(Clone, Copy)]
pub struct LocalEntry {
    hash: [u8; 64],
    key: Key,
    index: usize,
    seen: bool,
    offer: differential::Offer,
}

impl LocalEntry {
    /// Empty caller arena slot.
    pub const EMPTY: Self = Self {
        hash: [0; 64],
        key: Key(0),
        index: 0,
        seen: false,
        offer: differential::Offer::Idle,
    };
}

/// Caller arenas for one bounded channel. Large memory stays in these lent
/// slices. A host can reuse the same arenas after the original owner retires.
pub struct Buffers<'a> {
    /// Original local snapshot index and presence marks.
    pub local: &'a mut [LocalEntry],
    /// Exact uniqueness index for peer elements.
    pub remote: &'a mut [RemoteEntry],
    /// One current original outbound frame, retained until `sent`/retirement.
    pub frame: &'a mut [u8],
    /// One caller-generated local element, unused by an already borrowed set.
    pub element: &'a mut [u8],
    /// Local cells for any one estimator rotation.
    pub estimator: &'a mut [Cell],
    /// One stratum's difference work.
    pub peel: &'a mut [Cell],
    /// Raw bytes for the transmitted local prefix and receiving workspace.
    pub raw: &'a mut [u8],
    /// Bounded physical compressed SEC member, excluding the 13-byte header.
    pub compressed: &'a mut [u8],
    /// Optional differential owner. It reuses the estimator cells and raw
    /// workspace once the mode decision no longer needs strata.
    pub differential: Option<&'a mut Differential>,
}

/// Finite wire and result admission for this original channel.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Maximum total elements announced or transmitted by the peer.
    pub remote_elements: usize,
    /// Maximum typed element body in either direction.
    pub element_bytes: usize,
}

/// Explicit original native ABI, negotiated policy and runner bounds.
#[derive(Clone, Copy)]
pub struct Config {
    /// Native ABI of the selected compatible peer profile.
    pub abi: Abi,
    /// Actual official union selection and optional Byzantine bounds.
    pub options: Options,
    /// Caller-admitted remote element capacities.
    pub limits: Limits,
}

/// One already-authenticated CADET channel identity. It is not a wire token.
#[derive(Debug)]
pub struct Instance {
    generation: Generation<u64>,
}

impl Instance {
    /// Establish a stable owner for original channel generations.
    pub const fn new() -> Self {
        Self {
            generation: Generation::new(0),
        }
    }
}

impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}

/// Opening data from the exact authenticated application port.
#[derive(Clone, Copy)]
pub struct Incoming<'a> {
    count: Option<u32>,
    context: Option<&'a [u8]>,
}

impl<'a> Incoming<'a> {
    /// Decode the first original frame on this selected CADET port. The pinned
    /// C initiator leaves the operation fields zeroed, so zero app and count
    /// defer exact membership bounds to subsequent peer evidence.
    pub fn decode(frame: &'a [u8], abi: Abi, selected_port: &[u8; 64]) -> Result<Self, Error> {
        let Peer::Operation {
            count,
            app,
            context,
        } = Peer::decode(frame, abi)?
        else {
            return Err(Error::Malformed);
        };
        let omitted = app == [0; 64];
        if !omitted && &app != selected_port {
            return Err(Error::Authentication);
        }
        Ok(Self {
            count: (!omitted || count != 0).then_some(count),
            context,
        })
    }

    /// Original announced count, deferred on the pinned C zero-header path.
    #[must_use]
    pub const fn announced(self) -> Option<u32> {
        self.count
    }

    /// Exact nested application envelope, if the peer supplied one.
    #[must_use]
    pub const fn context(self) -> Option<&'a [u8]> {
        self.context
    }
}

/// Terminal settlement of the exact original native channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Full exchange ended and physical retirement was confirmed.
    Complete,
    /// Explicit caller cancellation, followed by original retirement.
    Cancelled,
    /// Original protocol or native retirement failure.
    Failed(Error),
}

/// Receipt authority for a single original physical output.
#[derive(Clone, Copy, Debug)]
pub struct Transmission<'scope> {
    scope: &'scope Instance,
    generation: u64,
    serial: u64,
}

impl PartialEq for Transmission<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.scope, other.scope)
            && self.generation == other.generation
            && self.serial == other.serial
    }
}

impl Eq for Transmission<'_> {}

/// Refused construction, preserving exclusive ownership of every caller arena.
pub struct Rejected<'memory> {
    /// Actual admission error.
    pub error: Error,
    /// Original buffers available for another physical channel generation.
    pub buffers: Buffers<'memory>,
}

/// Exact immutable frame staged until its original native admission settles.
pub struct Outbound<'scope, 'view> {
    /// The actual original receipt token.
    pub transmission: Transmission<'scope>,
    /// Complete official peer frame.
    pub bytes: &'view [u8],
    /// Element for a symmetric ADD_REMOTE notification after this original
    /// frame is admitted. The embedding owns notification backpressure.
    pub add_remote: Option<Element<'view>>,
}

#[derive(Clone, Copy)]
enum Direction {
    All,
    Missing,
}

#[derive(Clone, Copy)]
enum FullDecision {
    SendFirst,
    ReceiveFirst,
}

enum Start<'a> {
    Initiate {
        app: [u8; 64],
        context: Option<&'a [u8]>,
    },
    Accept {
        announced: Option<u32>,
    },
}

#[derive(Clone, Copy)]
enum Phase {
    Opening,
    SendingEstimator,
    ExpectEstimator,
    ExpectDecision,
    Differential,
    Signal {
        decision: FullDecision,
        remote_diff: u32,
        local_diff: u32,
    },
    Sending {
        direction: Direction,
        cursor: usize,
    },
    Receiving(Direction),
    Complete {
        request_close: bool,
    },
    Failed(Error),
    Cancelled,
    Retired(Outcome),
}

struct Pending {
    bytes: u16,
    next: Phase,
    lent: bool,
    adds_remote: bool,
}

/// Original full-set or differential channel with one retained element source.
/// The embedding owns its endpoint, timeout, admission receipts and policy.
pub struct Session<'scope, 'memory, S: ElementSource> {
    scope: &'scope Instance,
    generation: u64,
    buffers: Buffers<'memory>,
    source: S,
    config: Config,
    order: Order,
    size: u32,
    average: u64,
    announced: Option<u32>,
    peer_count: Option<u32>,
    received: usize,
    serial: u64,
    pending: Option<Pending>,
    phase: Phase,
}

impl<'scope, 'memory, S: ElementSource> Session<'scope, 'memory, S> {
    /// Bind a local original to an outgoing CADET channel for this app.
    pub fn initiate(
        scope: &'scope Instance,
        source: S,
        buffers: Buffers<'memory>,
        config: Config,
        app: [u8; 64],
        context: Option<&[u8]>,
    ) -> Result<Self, Rejected<'memory>> {
        let width = match (Peer::Operation {
            count: 0,
            app,
            context,
        }
        .encoded_len())
        {
            Ok(width) => width,
            Err(error) => return Err(Rejected { error, buffers }),
        };
        if width > buffers.frame.len() {
            return Err(Rejected {
                error: Error::Capacity,
                buffers,
            });
        }
        Self::new(
            scope,
            source,
            buffers,
            config,
            Start::Initiate { app, context },
        )
    }

    /// Bind an accepted original, after the app has authorized its context.
    pub fn accept(
        scope: &'scope Instance,
        source: S,
        buffers: Buffers<'memory>,
        config: Config,
        original: Incoming<'_>,
    ) -> Result<Self, Rejected<'memory>> {
        Self::new(
            scope,
            source,
            buffers,
            config,
            Start::Accept {
                announced: original.count,
            },
        )
    }

    fn new(
        scope: &'scope Instance,
        source: S,
        mut buffers: Buffers<'memory>,
        config: Config,
        start: Start<'_>,
    ) -> Result<Self, Rejected<'memory>> {
        let announced = match &start {
            Start::Initiate { .. } => None,
            Start::Accept { announced } => *announced,
        };
        let (size, average, order, generation) =
            match Self::prepare(scope, &source, &mut buffers, config, announced) {
                Ok(prepared) => prepared,
                Err(error) => return Err(Rejected { error, buffers }),
            };
        let (phase, pending) = match start {
            Start::Initiate { app, context } => {
                let bytes = match (Peer::Operation {
                    count: size,
                    app,
                    context,
                })
                .encode(config.abi, buffers.frame)
                .and_then(|bytes| u16::try_from(bytes).map_err(|_| Error::TooLarge))
                {
                    Ok(bytes) => bytes,
                    Err(error) => return Err(Rejected { error, buffers }),
                };
                (
                    Phase::Opening,
                    Some(Pending {
                        bytes,
                        next: Phase::ExpectEstimator,
                        lent: false,
                        adds_remote: false,
                    }),
                )
            }
            Start::Accept { .. } => (Phase::SendingEstimator, None),
        };
        scope.generation.set(generation);
        Ok(Self {
            scope,
            generation,
            buffers,
            source,
            config,
            order,
            size,
            average,
            announced,
            peer_count: None,
            received: 0,
            serial: u64::from(pending.is_some()),
            pending,
            phase,
        })
    }

    fn prepare(
        scope: &Instance,
        source: &S,
        buffers: &mut Buffers<'_>,
        config: Config,
        announced: Option<u32>,
    ) -> Result<(u32, u64, Order, u64), Error> {
        config.abi.validate()?;
        validate_options(config.options)?;
        if config.options.force_delta != 0 && buffers.differential.is_none() {
            return Err(Error::Unsupported);
        }
        let count = source.len()?;
        let size = u32::try_from(count).map_err(|_| Error::Capacity)?;
        let maximum = config
            .limits
            .element_bytes
            .checked_add(8)
            .ok_or(Error::Overflow)?;
        if let Some(announced) = announced {
            check_count(config, u64::from(announced))?;
        }
        if buffers.frame.len() < maximum.max(32)
            || buffers.compressed.is_empty()
            || buffers.estimator.len() < ESTIMATOR_CELLS
            || buffers.peel.len() < PEEL_CELLS
            || buffers.raw.len() < ESTIMATOR_BYTES
        {
            return Err(Error::Capacity);
        }
        let order = match config.abi.order {
            wire::Order::Little => Order::Little,
            wire::Order::Big => Order::Big,
        };
        let mut estimator = Strata::clear_prefix(buffers.estimator, 1, order)?;
        let entries = buffers.local.get_mut(..count).ok_or(Error::Capacity)?;
        let mut total = 0u64;
        for (index, entry) in entries.iter_mut().enumerate() {
            let element = source.element(index, buffers.element)?;
            if element.data.len() > config.limits.element_bytes {
                return Err(Error::TooLarge);
            }
            let hash = element_hash(element, config.abi)?;
            let key = Key::from_element_hash(&hash, order)?;
            estimator.insert(key)?;
            total += element.data.len() as u64;
            *entry = LocalEntry {
                hash,
                key,
                index,
                seen: false,
                offer: differential::Offer::Idle,
            };
        }
        entries.sort_unstable_by_key(|entry| entry.hash);
        if entries.windows(2).any(|pair| pair[0].hash == pair[1].hash) {
            return Err(Error::Conflict);
        }
        if buffers.remote.len() < config.limits.remote_elements {
            return Err(Error::Capacity);
        }
        if let Some(delta) = buffers.differential.as_deref_mut() {
            delta.reset(buffers.estimator.len())?;
        }
        let generation = scope
            .generation
            .get()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        Ok((
            size,
            total.checked_div(u64::from(size)).unwrap_or(0),
            order,
            generation,
        ))
    }

    /// Inspect or prepare at most one original physical output. Repeated
    /// borrows before native admission retain the exact same frame and token.
    pub fn outbound(
        &mut self,
        codec: &mut impl Codec,
    ) -> Result<Option<Outbound<'scope, '_>>, Error> {
        if self.pending.is_none() {
            let next = match self.build_output(codec) {
                Ok(Some(next)) => next,
                Ok(None) => return Ok(None),
                Err(error) => {
                    self.abort(error);
                    return Err(error);
                }
            };
            self.serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
            let adds_remote = self.config.options.symmetric != 0
                && match self.phase {
                    Phase::Differential => self
                        .buffers
                        .differential
                        .as_ref()
                        .is_some_and(|delta| delta.staged_element()),
                    Phase::Sending {
                        direction: Direction::Missing,
                        ..
                    } => matches!(
                        next.1,
                        Phase::Sending {
                            direction: Direction::Missing,
                            ..
                        }
                    ),
                    _ => false,
                };
            self.pending = Some(Pending {
                bytes: next.0,
                next: next.1,
                lent: false,
                adds_remote,
            });
        }
        let pending = self.pending.as_mut().ok_or(Error::Conflict)?;
        let bytes = &self.buffers.frame[..usize::from(pending.bytes)];
        let add_remote = if pending.adds_remote {
            match Peer::decode(bytes, self.config.abi)? {
                Peer::Element(element) | Peer::FullElement(element) => Some(element),
                _ => return Err(Error::Conflict),
            }
        } else {
            None
        };
        pending.lent = true;
        Ok(Some(Outbound {
            transmission: Transmission {
                scope: self.scope,
                generation: self.generation,
                serial: self.serial,
            },
            bytes,
            add_remote,
        }))
    }

    fn build_output(&mut self, codec: &mut impl Codec) -> Result<Option<(u16, Phase)>, Error> {
        if matches!(self.phase, Phase::Differential) {
            return self.build_differential();
        }
        let (peer, next) = match self.phase {
            Phase::SendingEstimator => {
                let length = Strata::view(self.buffers.estimator, 1, self.order)?
                    .write_raw(1, self.buffers.raw)?;
                let packed = self
                    .buffers
                    .compressed
                    .len()
                    .min(self.buffers.frame.len() - 13);
                let length = codec.compress(
                    &self.buffers.raw[..length],
                    &mut self.buffers.compressed[..packed],
                )?;
                let data = self
                    .buffers
                    .compressed
                    .get(..length)
                    .filter(|data| !data.is_empty() && length <= packed)
                    .ok_or(Error::Malformed)?;
                (
                    Peer::Strata {
                        compressed: true,
                        count: 1,
                        set_size: u64::from(self.size),
                        data,
                    },
                    Phase::ExpectDecision,
                )
            }
            Phase::Signal {
                decision,
                remote_diff,
                local_diff,
            } => {
                let (request, next) = match decision {
                    FullDecision::SendFirst => (
                        false,
                        Phase::Sending {
                            direction: Direction::All,
                            cursor: 0,
                        },
                    ),
                    FullDecision::ReceiveFirst => (true, Phase::Receiving(Direction::All)),
                };
                (
                    Peer::Full {
                        request,
                        remote_difference: remote_diff,
                        remote_size: self.size,
                        local_difference: local_diff,
                        padding: &FULL_PADDING,
                    },
                    next,
                )
            }
            Phase::Sending { direction, cursor } => {
                let next = self.buffers.local[..self.size as usize]
                    .iter()
                    .enumerate()
                    .skip(cursor)
                    .find(|(_, entry)| matches!(direction, Direction::All) || !entry.seen);
                if let Some((cursor, entry)) = next {
                    let element = self.source.element(entry.index, self.buffers.element)?;
                    if element_hash(element, self.config.abi)? != entry.hash {
                        return Err(Error::Authentication);
                    }
                    (
                        Peer::FullElement(element),
                        Phase::Sending {
                            direction,
                            cursor: cursor + 1,
                        },
                    )
                } else {
                    (
                        Peer::FullDone,
                        match direction {
                            Direction::All => Phase::Receiving(Direction::Missing),
                            Direction::Missing => Phase::Complete {
                                request_close: false,
                            },
                        },
                    )
                }
            }
            _ => return Ok(None),
        };
        let bytes = peer.encode(self.config.abi, self.buffers.frame)?;
        let bytes = u16::try_from(bytes).map_err(|_| Error::TooLarge)?;
        Ok(Some((bytes, next)))
    }

    /// Admit the exact named original frame from the port. Output lifecycle
    /// does not imply peer processing or successful reconciliation.
    pub fn sent(&mut self, original: Transmission<'_>) -> Result<(), Error> {
        if !ptr::eq(original.scope, self.scope)
            || original.generation != self.generation
            || original.serial != self.serial
            || self.pending.as_ref().is_none_or(|pending| !pending.lent)
        {
            return Err(Error::Stale);
        }
        let admitted = self.pending.take().ok_or(Error::Conflict)?;
        if !matches!(
            self.phase,
            Phase::Failed(_) | Phase::Cancelled | Phase::Retired(_)
        ) {
            if matches!(self.phase, Phase::Differential) {
                self.admit_differential()?;
            }
            self.phase = admitted.next;
        }
        Ok(())
    }

    /// Receive one exact frame. ADD_LOCAL is lent only for new elements. The
    /// application must finish synchronous admission or return `WouldBlock`
    /// without side effects so the host can retry the same original frame.
    pub fn receive(
        &mut self,
        frame: &[u8],
        codec: &mut impl Codec,
        learn: impl FnOnce(Element<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let result = self.receive_frame(frame, codec, learn);
        if let Err(error) = result
            && error != Error::WouldBlock
        {
            self.abort(error);
        }
        result
    }

    fn receive_frame(
        &mut self,
        frame: &[u8],
        codec: &mut impl Codec,
        learn: impl FnOnce(Element<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if matches!(
            self.phase,
            Phase::Failed(_) | Phase::Cancelled | Phase::Retired(_)
        ) {
            return Err(Error::Closed);
        }
        if frame.len() > self.buffers.frame.len() {
            return Err(Error::TooLarge);
        }
        let incoming = Peer::decode(frame, self.config.abi)?;
        match (self.phase, incoming) {
            (Phase::Differential, peer) => self.receive_differential(peer, learn),
            (
                Phase::ExpectEstimator,
                Peer::Strata {
                    count,
                    compressed,
                    set_size,
                    data,
                },
            ) => self.decide(
                set_size,
                estimate::Remote {
                    count,
                    compressed,
                    data,
                },
                codec,
            ),
            (
                Phase::ExpectDecision,
                Peer::Full {
                    request,
                    remote_size,
                    remote_difference,
                    local_difference,
                    padding,
                },
            ) => {
                if self.config.options.force_delta == 1 {
                    return Err(Error::Unsupported);
                }
                if !matches!(padding.len(), 0 | 16) {
                    return Err(Error::Malformed);
                }
                check_count(self.config, u64::from(remote_size))?;
                if self
                    .announced
                    .is_some_and(|original| original != remote_size)
                {
                    return Err(Error::Authentication);
                }
                check_differences(
                    self.config,
                    self.size,
                    u64::from(remote_size),
                    u64::from(remote_difference),
                    u64::from(local_difference),
                )?;
                self.peer_count = Some(remote_size);
                self.phase = if request {
                    Phase::Sending {
                        direction: Direction::All,
                        cursor: 0,
                    }
                } else {
                    Phase::Receiving(Direction::All)
                };
                Ok(())
            }
            (Phase::Receiving(direction), Peer::FullElement(element)) => {
                self.receive_element(direction, element, learn)
            }
            (Phase::Receiving(Direction::All), Peer::FullDone) => {
                let count = self.peer_count.ok_or(Error::Conflict)?;
                if self.received != count as usize {
                    return Err(Error::Authentication);
                }
                self.phase = Phase::Sending {
                    direction: Direction::Missing,
                    cursor: 0,
                };
                Ok(())
            }
            (Phase::Receiving(Direction::Missing), Peer::FullDone) => {
                self.phase = Phase::Complete {
                    request_close: true,
                };
                Ok(())
            }
            (
                Phase::Complete {
                    request_close: false,
                },
                Peer::Over,
            ) => {
                self.phase = Phase::Complete {
                    request_close: true,
                };
                Ok(())
            }
            (Phase::ExpectDecision, peer @ Peer::Ibf { .. }) => {
                if self.config.options.force_full == 1 || self.buffers.differential.is_none() {
                    return Err(Error::Unsupported);
                }
                self.peer_count = self.announced;
                self.phase = Phase::Differential;
                self.receive_differential(peer, learn)
            }
            (_, Peer::Operation { .. }) => Err(Error::Replay),
            _ => Err(Error::Malformed),
        }
    }

    fn decide(
        &mut self,
        set_size: u64,
        remote: estimate::Remote<'_>,
        codec: &mut impl Codec,
    ) -> Result<(), Error> {
        check_count(self.config, set_size)?;
        let sizing = remote.estimate(&mut self.buffers, self.size as usize, self.order, codec)?;
        let (remote_diff, local_diff) = match (self.size, set_size) {
            (0, _) => (set_size, 0),
            (_, 0) => (0, u64::from(self.size)),
            _ => (sizing.positive, sizing.negative),
        };
        check_differences(self.config, self.size, set_size, local_diff, remote_diff)?;
        self.peer_count = Some(u32::try_from(set_size).map_err(|_| Error::Capacity)?);
        let decision = match choose(
            self.average,
            u64::from(self.size),
            set_size,
            remote_diff,
            local_diff,
            self.config.options,
        )? {
            Choice::SendFull => FullDecision::SendFirst,
            Choice::RequestFull => FullDecision::ReceiveFirst,
            Choice::Differential => return self.start_differential(remote_diff, local_diff),
        };
        self.phase = Phase::Signal {
            decision,
            remote_diff: u32::try_from(local_diff).map_err(|_| Error::Capacity)?,
            local_diff: u32::try_from(remote_diff).map_err(|_| Error::Capacity)?,
        };
        Ok(())
    }

    fn receive_element(
        &mut self,
        direction: Direction,
        element: Element<'_>,
        learn: impl FnOnce(Element<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let expected = self.peer_count.ok_or(Error::Conflict)? as usize;
        if self.received >= expected || self.received >= self.buffers.remote.len() {
            return Err(Error::Capacity);
        }
        if element.data.len() > self.config.limits.element_bytes {
            return Err(Error::TooLarge);
        }
        let hash = element_hash(element, self.config.abi)?;
        if self.buffers.remote[..self.received]
            .iter()
            .any(|entry| entry.hash == hash)
        {
            return Err(Error::Replay);
        }
        if let Ok(at) =
            self.buffers.local[..self.size as usize].binary_search_by_key(&hash, |entry| entry.hash)
        {
            if matches!(direction, Direction::Missing) {
                return Err(Error::Malformed);
            }
            let original = self
                .source
                .element(self.buffers.local[at].index, self.buffers.element)?;
            if original != element {
                return Err(Error::Authentication);
            }
            self.buffers.local[at].seen = true;
        } else {
            learn(element)?;
        }
        self.buffers.remote[self.received] = RemoteEntry::full(hash);
        self.received += 1;
        Ok(())
    }

    /// Whether the embedding must close this exact physical channel.
    #[must_use]
    pub const fn close_needed(&self) -> bool {
        matches!(
            self.phase,
            Phase::Complete {
                request_close: true
            } | Phase::Failed(_)
                | Phase::Cancelled
        )
    }

    /// Fail this operation without inventing retirement or replacing its lease.
    pub fn abort(&mut self, error: Error) {
        if !matches!(
            self.phase,
            Phase::Retired(_) | Phase::Cancelled | Phase::Failed(_)
        ) {
            self.discard_unlent();
            self.phase = Phase::Failed(error);
        }
    }

    /// Request cancellation of this original channel. Any already lent output
    /// remains unchanged until admission or physical retirement.
    pub fn cancel(&mut self) {
        if !matches!(self.phase, Phase::Retired(_)) {
            self.discard_unlent();
            self.phase = Phase::Cancelled;
        }
    }

    fn discard_unlent(&mut self) {
        if self.pending.as_ref().is_some_and(|pending| !pending.lent) {
            self.pending = None;
        }
    }

    /// Settle actual original channel retirement. A read/write error or early
    /// close cannot become an affirmative result.
    pub fn retired(&mut self, result: Result<(), Error>) {
        if matches!(self.phase, Phase::Retired(_)) {
            return;
        }
        let outcome = match (self.phase, result) {
            (Phase::Complete { .. }, Ok(())) if self.pending.is_none() => Outcome::Complete,
            (Phase::Differential, Ok(()))
                if self.pending.is_none()
                    && self
                        .buffers
                        .differential
                        .as_ref()
                        .is_some_and(|delta| delta.awaiting_close()) =>
            {
                Outcome::Complete
            }
            (Phase::Cancelled, Ok(())) => Outcome::Cancelled,
            (_, Err(error)) | (Phase::Failed(error), _) => Outcome::Failed(error),
            _ => Outcome::Failed(Error::Closed),
        };
        self.phase = Phase::Retired(outcome);
        self.pending = None;
    }

    /// Definitive result after actual native retirement, if observed.
    #[must_use]
    pub const fn outcome(&self) -> Option<Outcome> {
        if let Phase::Retired(outcome) = self.phase {
            Some(outcome)
        } else {
            None
        }
    }

    /// Return this original's caller arenas. Settle physical retirement first
    /// when an original channel has already adopted the operation.
    pub fn into_buffers(self) -> Buffers<'memory> {
        self.buffers
    }
}

fn check_count(config: Config, count: u64) -> Result<(), Error> {
    if count > config.limits.remote_elements as u64 || count > u64::from(u32::MAX) {
        return Err(Error::Capacity);
    }
    if config.options.byzantine == 1
        && !(u64::from(config.options.lower_bound)..=config.options.upper_bound).contains(&count)
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn check_differences(
    config: Config,
    local: u32,
    remote: u64,
    remote_diff: u64,
    local_diff: u64,
) -> Result<(), Error> {
    if config.options.byzantine == 1
        && (remote
            .checked_add(remote_diff)
            .is_none_or(|maximum| maximum > config.options.upper_bound)
            || u64::from(local)
                .checked_add(local_diff)
                .is_none_or(|maximum| maximum > config.options.upper_bound))
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
