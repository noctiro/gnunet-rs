use super::{Buffers, ESTIMATOR_BYTES, LocalEntry};
use crate::{
    Codec,
    ibf::{Cell, Order},
    strata::{Directional, STRATA, Strata, WIRE_BYTES_PER_STRATUM as ROW_BYTES},
};
use gnunet_types::Error;

pub(super) struct Remote<'a> {
    pub(super) count: u8,
    pub(super) compressed: bool,
    pub(super) data: &'a [u8],
}

impl Remote<'_> {
    pub(super) fn estimate(
        self,
        buffers: &mut Buffers<'_>,
        local_count: usize,
        order: Order,
        codec: &mut impl Codec,
    ) -> Result<Directional, Error> {
        let expected = Strata::wire_len(self.count)?;
        if self.count == 1 {
            return self.estimate_one(buffers, order, codec);
        }
        let mut prefix = Prefix {
            local: &buffers.local[..local_count],
            cells: buffers.estimator,
            peel: buffers.peel,
            order,
            used: 0,
            rows: 0,
            recovered: Directional::default(),
            scale: 1,
            total: Directional::default(),
        };
        let (partial, history) = buffers.raw.split_at_mut(ROW_BYTES);
        if self.compressed {
            let mut remaining = expected;
            let written = codec.visit_decompressed(self.data, history, expected, &mut |chunk| {
                remaining = remaining.checked_sub(chunk.len()).ok_or(Error::Capacity)?;
                prefix.visit(partial, chunk)
            })?;
            if written != expected || remaining != 0 {
                return Err(Error::Malformed);
            }
        } else {
            if self.data.len() != expected {
                return Err(Error::Malformed);
            }
            prefix.visit(partial, self.data)?;
        }
        if prefix.used != 0 || prefix.rows != usize::from(self.count) * STRATA {
            return Err(Error::Malformed);
        }
        Ok(Directional {
            positive: prefix.total.positive / u64::from(self.count),
            negative: prefix.total.negative / u64::from(self.count),
        })
    }

    fn estimate_one(
        self,
        buffers: &mut Buffers<'_>,
        order: Order,
        codec: &mut impl Codec,
    ) -> Result<Directional, Error> {
        let raw = if self.compressed {
            let raw = &mut buffers.raw[..ESTIMATOR_BYTES];
            if codec.decompress(self.data, raw)? != ESTIMATOR_BYTES {
                return Err(Error::Malformed);
            }
            &*raw
        } else {
            self.data
        };
        let local = Strata::view(buffers.estimator, 1, order)?;
        let estimate = local.estimate_remote_raw(1, raw, buffers.peel)?;
        Ok(Directional {
            positive: estimate.positive,
            negative: estimate.negative,
        })
    }
}

/// The member is decoded in ascending wire order, with one row crossing a
/// window boundary at a time. Only the highest failed peel matters to the C
/// estimator. On failure discard all lower rows and move the multiplier.
struct Prefix<'a> {
    local: &'a [LocalEntry],
    cells: &'a mut [Cell],
    peel: &'a mut [Cell],
    order: Order,
    used: usize,
    rows: usize,
    recovered: Directional,
    scale: u64,
    total: Directional,
}

impl Prefix<'_> {
    fn visit(&mut self, partial: &mut [u8], mut input: &[u8]) -> Result<(), Error> {
        if self.used != 0 {
            let take = input.len().min(ROW_BYTES - self.used);
            partial[self.used..self.used + take].copy_from_slice(&input[..take]);
            self.used += take;
            if self.used != ROW_BYTES {
                return Ok(());
            }
            self.row(partial)?;
            input = &input[take..];
        }
        let (rows, tail) = input.as_chunks::<ROW_BYTES>();
        for row in rows {
            self.row(row)?;
        }
        partial[..tail.len()].copy_from_slice(tail);
        self.used = tail.len();
        Ok(())
    }

    fn row(&mut self, row: &[u8]) -> Result<(), Error> {
        let layer = self.rows % STRATA;
        if layer == 0 {
            let rotation = u32::try_from(self.rows / STRATA).map_err(|_| Error::Overflow)?;
            let mut estimator = Strata::clear_prefix(self.cells, 1, self.order)?;
            for entry in self.local {
                estimator.insert(entry.key.salted(rotation * 8))?;
            }
        }
        let local = Strata::view(self.cells, 1, self.order)?;
        if let Some(decoded) = local.peel_remote_row(layer, row, self.peel)? {
            self.recovered = self.recovered.add(decoded)?;
        } else {
            self.recovered = Directional::default();
            self.scale = 1u64 << (layer + 1);
        }
        if layer + 1 == STRATA {
            self.total = self.total.add(self.recovered.multiply(self.scale)?)?;
            self.recovered = Directional::default();
            self.scale = 1;
        }
        self.rows += 1;
        Ok(())
    }
}
