//! Active v0.29.1 multi-strata estimator with caller-owned cells and peel scratch.
//! Estimates choose reconciliation work; they never establish equal element sets.
use crate::ibf::{BUCKET_WIRE_BYTES, Cell, Decode, Ibf, Key, Order};
use gnunet_types::Error;
/// Reference allocates eight independently rotated estimators.
pub const ESTIMATORS: usize = 8;
/// Each estimator has32 nested strata.
pub const STRATA: usize = 32;
/// The active source uses79 buckets for every stratum, not the outdated prime comment.
pub const BUCKETS: usize = 79;
/// Active source hashes each key into3 unique buckets.
pub const HASHES: u8 = 3;
/// Caller cells for one actual estimator.
pub const CELLS_PER_ESTIMATOR: usize = STRATA * BUCKETS;
/// Caller cells to retain every active local estimator.
pub const ALL_CELLS: usize = ESTIMATORS * CELLS_PER_ESTIMATOR;
/// Actual uncompressed bytes per estimator, including source20-byte bucket stride.
pub const WIRE_BYTES_PER_ESTIMATOR: usize = CELLS_PER_ESTIMATOR * BUCKET_WIRE_BYTES;
pub(crate) const WIRE_BYTES_PER_STRATUM: usize = BUCKETS * BUCKET_WIRE_BYTES;
/// One heuristic directional difference, not a verified result/element count.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Estimate {
    /// +1 keys recovered from first estimator minus second. The C IBF names this
    /// `remote_decoded_count`; the actual operation role must map it explicitly.
    pub positive: u64,
    /// -1 keys recovered from the subtracted estimator. C calls this local.
    pub negative: u64,
    /// Actual1/2/4/8 estimator average used.
    pub estimators: u8,
    /// At least one failed/budget-limited stratum required power-of-two extrapolation.
    pub extrapolated: bool,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Directional {
    pub(crate) positive: u64,
    pub(crate) negative: u64,
}

impl Directional {
    pub(crate) fn add(self, other: Self) -> Result<Self, Error> {
        Ok(Self {
            positive: self
                .positive
                .checked_add(other.positive)
                .ok_or(Error::Overflow)?,
            negative: self
                .negative
                .checked_add(other.negative)
                .ok_or(Error::Overflow)?,
        })
    }

    pub(crate) fn multiply(self, factor: u64) -> Result<Self, Error> {
        Ok(Self {
            positive: self.positive.checked_mul(factor).ok_or(Error::Overflow)?,
            negative: self.negative.checked_mul(factor).ok_or(Error::Overflow)?,
        })
    }
}

fn peel_row(mut diff: Ibf<'_>) -> Result<Option<Directional>, Error> {
    let mut recovered = Directional::default();
    // Source allows at most 80 successful items for a 79-cell stratum before
    // refusing a continuing/cyclic decoder. A stalled row contributes nothing.
    for _ in 0..=BUCKETS + 1 {
        match diff.peel()? {
            Decode::Empty => return Ok(Some(recovered)),
            Decode::Stalled => break,
            Decode::Item { side: 1, .. } => recovered.positive += 1,
            Decode::Item { side: -1, .. } => recovered.negative += 1,
            Decode::Item { .. } => return Err(Error::Malformed),
        }
    }
    Ok(None)
}
/// Number of estimators selected by the active total-byte threshold policy.
/// Multiplication overflow is explicit instead of choosing a wrapped small profile.
pub fn estimators_for_size(average_element_bytes: u64, elements: u64) -> Result<u8, Error> {
    let bytes = average_element_bytes
        .checked_mul(elements)
        .ok_or(Error::Overflow)?;
    Ok(if bytes < 4221 * 16 {
        1
    } else if bytes < 4221 * 64 {
        2
    } else if bytes < 4221 * 256 {
        4
    } else {
        8
    })
}
fn valid_count(count: u8) -> bool {
    matches!(count, 1 | 2 | 4 | 8)
}
/// One local or received actual strata shape. No heap/worker/runtime is created.
pub struct Strata<'a> {
    cells: &'a mut [Cell],
    estimators: u8,
    order: Order,
}
impl<'a> Strata<'a> {
    /// Initialize all eight local estimators in caller storage. Shape refusal
    /// preserves the storage; no large arrays are placed on the stack.
    pub fn clear(cells: &'a mut [Cell], order: Order) -> Result<Self, Error> {
        Self::clear_prefix(cells, ESTIMATORS as u8, order)
    }

    /// Initialize an exact transmitted estimator prefix in caller storage.
    pub fn clear_prefix(
        cells: &'a mut [Cell],
        estimators: u8,
        order: Order,
    ) -> Result<Self, Error> {
        let cells = cells
            .get_mut(..Self::cell_count(estimators)?)
            .ok_or(Error::Capacity)?;
        cells.fill(Cell::default());
        Ok(Self {
            cells,
            estimators,
            order,
        })
    }
    /// Borrow an already populated1/2/4/8 estimator prefix without clearing it.
    /// Received storage need contain only the actual transmitted prefix.
    pub fn view(cells: &'a mut [Cell], estimators: u8, order: Order) -> Result<Self, Error> {
        let required = Self::cell_count(estimators)?;
        let cells = cells.get_mut(..required).ok_or(Error::Capacity)?;
        Ok(Self {
            cells,
            estimators,
            order,
        })
    }
    /// Actual active prefix, independent of backing allocator capacity.
    #[must_use]
    pub const fn estimators(&self) -> u8 {
        self.estimators
    }
    /// Explicit reference native order used by key hashing/serialization.
    #[must_use]
    pub const fn order(&self) -> Order {
        self.order
    }
    /// Read the actual logical cells, not a Rust-layout wire representation.
    #[must_use]
    pub fn cells(&self) -> &[Cell] {
        self.cells
    }
    /// Required caller cells for one valid transmitted prefix.
    pub fn cell_count(estimators: u8) -> Result<usize, Error> {
        if !valid_count(estimators) {
            return Err(Error::InvalidInput);
        }
        Ok(usize::from(estimators) * CELLS_PER_ESTIMATOR)
    }
    /// Exact uncompressed source representation size. Compression framing belongs
    /// to the caller's real zlib port; these bytes are not a compressed packet.
    pub fn wire_len(estimators: u8) -> Result<usize, Error> {
        if !valid_count(estimators) {
            return Err(Error::InvalidInput);
        }
        Ok(usize::from(estimators) * WIRE_BYTES_PER_ESTIMATOR)
    }
    fn check_prefix(&self, estimators: u8) -> Result<(), Error> {
        if !valid_count(estimators) || estimators > self.estimators {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    fn modify(&mut self, key: Key, side: i8, apply: bool) -> Result<(), Error> {
        for estimator in 0..usize::from(self.estimators) {
            let salted = key.salted((estimator as u32) * 8);
            // The active C inserts inside the trailing-one loop: every one of
            // these nested low strata gets the key, not just one selected layer.
            // Bound the rare all-one prefix to actual32-layer storage instead of
            // following the reference's unchecked out-of-bounds access.
            let layers = (salted.0.trailing_ones() as usize).min(STRATA);
            for layer in 0..layers {
                let at = (estimator * STRATA + layer) * BUCKETS;
                let mut ibf = Ibf::view(&mut self.cells[at..at + BUCKETS], HASHES, self.order)?;
                if apply {
                    if side == 1 {
                        ibf.insert(salted)?;
                    } else {
                        ibf.remove(salted)?;
                    }
                } else {
                    ibf.check_change(salted, side)?;
                }
            }
        }
        Ok(())
    }
    /// Insert a real reconciliation key into each active source rotation.
    /// Deterministic indices and every overflow/work bound preflight before mutation.
    pub fn insert(&mut self, key: Key) -> Result<(), Error> {
        self.modify(key, 1, false)?;
        self.modify(key, 1, true)
    }
    /// Actual inverse of insertion for live set removal. This deliberately uses
    /// the same salts as insert; C's unused remove function incorrectly unsalts.
    /// Valid serialized estimators equal rebuilding from the remaining element set.
    pub fn remove(&mut self, key: Key) -> Result<(), Error> {
        self.modify(key, -1, false)?;
        self.modify(key, -1, true)
    }
    /// Encode the exact raw source layout, including each stratum's20*N stride.
    /// Counters use the active reference's low8-bit estimator approximation;
    /// nonnegative counts above255 truncate exactly as C pack_counter(width8).
    /// Padding is deterministically zeroed; reference readers ignore its bytes.
    pub fn write_raw(&mut self, estimators: u8, output: &mut [u8]) -> Result<usize, Error> {
        self.check_prefix(estimators)?;
        let len = Self::wire_len(estimators)?;
        let cells = Self::cell_count(estimators)?;
        if output.len() < len {
            return Err(Error::Capacity);
        }
        if self.cells[..cells].iter().any(|cell| cell.count < 0) {
            return Err(Error::InvalidInput);
        }
        let stride = WIRE_BYTES_PER_STRATUM;
        for row in 0..usize::from(estimators) * STRATA {
            let at = row * BUCKETS;
            let ibf = Ibf::view(&mut self.cells[at..at + BUCKETS], HASHES, self.order)?;
            ibf.encode_estimator_slice(0, BUCKETS, &mut output[row * stride..(row + 1) * stride])?;
        }
        Ok(len)
    }
    /// Decode one actual uncompressed prefix with exact length and no allocator.
    /// Caller must perform bounded real decompression before calling this method.
    /// Invalid prefix/length is refused before any cell changes; all packed
    /// width8 counts are structurally representable and padding is ignored.
    pub fn read_raw(&mut self, estimators: u8, input: &[u8]) -> Result<(), Error> {
        self.check_prefix(estimators)?;
        if input.len() != Self::wire_len(estimators)? {
            return Err(Error::Malformed);
        }
        let stride = WIRE_BYTES_PER_STRATUM;
        for row in 0..usize::from(estimators) * STRATA {
            let at = row * BUCKETS;
            let mut ibf = Ibf::view(&mut self.cells[at..at + BUCKETS], HASHES, self.order)?;
            ibf.read_slice(0, BUCKETS, 8, &input[row * stride..(row + 1) * stride])?;
        }
        self.estimators = estimators;
        Ok(())
    }
    /// Exact source heuristic over fresh scratch: scan strata31 down to0,
    /// accumulate fully peeled directional counts, and on stalled/budgeted
    /// decoding multiply the prior accumulator by2^(stratum+1). Average the
    /// requested1/2/4/8 estimators. Partial failed-stratum counts do not commit.
    /// Caller scratch is exactly one79-cell work filter; source cells are unchanged.
    pub fn estimate_difference(
        &self,
        other: &Strata<'_>,
        estimators: u8,
        scratch: &mut [Cell],
    ) -> Result<Estimate, Error> {
        self.check_prefix(estimators)?;
        other.check_prefix(estimators)?;
        if self.order != other.order {
            return Err(Error::InvalidInput);
        }
        self.estimate_using(estimators, scratch, |at, scratch| {
            scratch.copy_from_slice(&self.cells[at..at + BUCKETS]);
            Ibf::view(scratch, HASHES, self.order)?.subtract_cells(&other.cells[at..at + BUCKETS])
        })
    }

    /// Estimate remote-minus-local directly from the exact uncompressed wire
    /// prefix, using one stratum of work rather than a second decoded prefix.
    pub fn estimate_remote_raw(
        &self,
        estimators: u8,
        input: &[u8],
        scratch: &mut [Cell],
    ) -> Result<Estimate, Error> {
        self.check_prefix(estimators)?;
        if input.len() != Self::wire_len(estimators)? {
            return Err(Error::Malformed);
        }
        self.estimate_using(estimators, scratch, |at, scratch| {
            let start = at * BUCKET_WIRE_BYTES;
            let end = start + WIRE_BYTES_PER_STRATUM;
            self.subtract_remote_row(at, &input[start..end], scratch)
        })
    }

    pub(crate) fn peel_remote_row(
        &self,
        layer: usize,
        input: &[u8],
        scratch: &mut [Cell],
    ) -> Result<Option<Directional>, Error> {
        let scratch = scratch.get_mut(..BUCKETS).ok_or(Error::Capacity)?;
        if layer >= STRATA || input.len() != WIRE_BYTES_PER_STRATUM {
            return Err(Error::Malformed);
        }
        self.subtract_remote_row(layer * BUCKETS, input, scratch)?;
        peel_row(Ibf::view(scratch, HASHES, self.order)?)
    }

    fn subtract_remote_row(
        &self,
        at: usize,
        input: &[u8],
        scratch: &mut [Cell],
    ) -> Result<(), Error> {
        let mut diff = Ibf::view(scratch, HASHES, self.order)?;
        diff.read_slice(0, BUCKETS, 8, input)?;
        diff.subtract_cells(&self.cells[at..at + BUCKETS])
    }

    fn estimate_using(
        &self,
        estimators: u8,
        scratch: &mut [Cell],
        mut subtract: impl FnMut(usize, &mut [Cell]) -> Result<(), Error>,
    ) -> Result<Estimate, Error> {
        let scratch = scratch.get_mut(..BUCKETS).ok_or(Error::Capacity)?;
        let mut total = Directional::default();
        let mut extrapolated = false;
        for estimator in 0..usize::from(estimators) {
            let mut recovered = Directional::default();
            for layer in (0..STRATA).rev() {
                let at = (estimator * STRATA + layer) * BUCKETS;
                subtract(at, scratch)?;
                if let Some(row) = peel_row(Ibf::view(scratch, HASHES, self.order)?)? {
                    recovered = recovered.add(row)?;
                } else {
                    recovered = recovered.multiply(1u64 << (layer + 1))?;
                    extrapolated = true;
                    break;
                }
            }
            total = total.add(recovered)?;
        }
        Ok(Estimate {
            positive: total.positive / u64::from(estimators),
            negative: total.negative / u64::from(estimators),
            estimators,
            extrapolated,
        })
    }
}
