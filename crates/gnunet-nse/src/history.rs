//! Exact64-sample weighted West arithmetic and source transmission delay formula.
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    nse::{Double, Estimate},
};

/// Official history size, independent of native storage/scheduling shape.
pub const HISTORY_SIZE: usize = 64;
/// Normal source interval, one hour in microseconds.
pub const INTERVAL_MICROS: u64 = 3_600_000_000;

/// Public result of the source's weighted arithmetic.
#[derive(Clone, Copy, Debug)]
pub struct Summary {
    /// Mean matching-bit claim, before correction/peer floor.
    pub mean: f64,
    /// Sample standard deviation; one sample legitimately yields NaN.
    pub deviation: f64,
    /// Corrected logarithmic estimate, floored by connected peer count.
    pub log2_size: f64,
}
impl Summary {
    /// Checked optional linear statistics projection. Overflow is explicit rather than
    /// reproducing the reference's out-of-range floating-to-uint conversion.
    pub fn linear_count(self) -> Result<u64, Error> {
        let value = libm::pow(2.0, self.log2_size);
        if !value.is_finite() || value < 0.0 || value >= u64::MAX as f64 {
            return Err(Error::Overflow);
        }
        Ok(value as u64)
    }
    /// Encode an official client snapshot at the host's logical time sample.
    #[must_use]
    pub const fn estimate(self, now: u64) -> Estimate {
        Estimate {
            timestamp: AbsoluteTime::from_micros(now),
            log2_size: Double::from_value(self.log2_size),
            deviation: Double::from_value(self.deviation),
        }
    }
}

/// Source-order arithmetic over newest-first claims. No signature authority is implied.
pub fn summarize(newest: &[u32], peer_count: usize) -> Result<Summary, Error> {
    if newest.len() > HISTORY_SIZE {
        return Err(Error::Capacity);
    }
    let mut mean = 0.0;
    let mut sum = 0.0;
    let mut sumweight = 0.0;
    for (i, &value) in newest.iter().enumerate() {
        let weight = (newest.len() + 1 - i) as f64;
        let temp = weight + sumweight;
        let q = f64::from(value) - mean;
        let r = q * weight / temp;
        mean += r;
        sum += sumweight * q * r;
        sumweight = temp;
    }
    let variance = if newest.is_empty() {
        0.0
    } else {
        (sum / sumweight) * newest.len() as f64 / (newest.len() as f64 - 1.0)
    };
    let deviation = if variance >= 0.0 {
        libm::sqrt(variance)
    } else {
        variance
    };
    let floor = libm::log(peer_count.max(1) as f64) / libm::log(2.0);
    let corrected = mean - 0.332747;
    Ok(Summary {
        mean,
        deviation,
        log2_size: if corrected > floor { corrected } else { floor },
    })
}

/// Distance delay before caller-provided jitter. Uses the source formula and pure libm.
pub fn matching_delay(interval: u64, matching: u32, mean: f64) -> Result<f64, Error> {
    if interval == 0 || !mean.is_finite() {
        return Err(Error::InvalidInput);
    }
    let f = interval as f64;
    let result = f / 2.0 - (f / core::f64::consts::PI) * libm::atan(f64::from(matching) - mean);
    if !result.is_finite() || result < 0.0 || result >= u64::MAX as f64 {
        return Err(Error::Overflow);
    }
    Ok(result)
}
