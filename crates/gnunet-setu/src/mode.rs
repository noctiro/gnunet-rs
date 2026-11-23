use crate::wire::Options;
use gnunet_types::Error;

pub(crate) fn validate_options(options: Options) -> Result<(), Error> {
    if options.force_delta != 0 && options.force_full != 0
        || options.hashes == 0
        || options.hashes > 255
        || options.bucket_factor == 0
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

pub(crate) fn initial_buckets(remote: u64, local: u64, factor: u64) -> Result<usize, Error> {
    let size = remote
        .checked_add(local)
        .and_then(|difference| difference.checked_mul(factor))
        .ok_or(Error::Overflow)?;
    usize::try_from(size.max(37) | 1).map_err(|_| Error::Capacity)
}

pub(crate) fn retry_buckets(previous: usize, decoded: usize, factor: u64) -> Result<usize, Error> {
    let removed = usize::try_from(factor)
        .map_err(|_| Error::Overflow)?
        .checked_mul(decoded)
        .ok_or(Error::Overflow)?;
    let next = previous
        .checked_mul(2)
        .ok_or(Error::Overflow)?
        .saturating_sub(removed)
        .max(previous.checked_add(2).ok_or(Error::Overflow)?)
        .max(37);
    Ok(next | 1)
}
/// Internal source cost alternatives; no new wire negotiation field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Choice {
    /// Actual delta protocol.
    Differential,
    /// Local full set goes first.
    SendFull,
    /// Request remote full set first.
    RequestFull,
}
/// Source's byte/RTT mode model with checked finite Rust arithmetic. An undefined
/// negative C float-to-u64 counter estimate conservatively selects valid delta.
pub fn choose(
    avg: u64,
    local: u64,
    remote: u64,
    remote_diff: u64,
    local_diff: u64,
    options: Options,
) -> Result<Choice, Error> {
    validate_options(options)?;
    if options.force_delta == 1 {
        return Ok(Choice::Differential);
    }
    if local == 0 {
        return Ok(Choice::RequestFull);
    }
    if remote == 0 {
        return Ok(Choice::SendFull);
    }
    let diff = remote_diff.checked_add(local_diff).ok_or(Error::Overflow)?;
    let full_local = (avg.checked_add(8).ok_or(Error::Overflow)? as f64)
        * (remote_diff.checked_add(local).ok_or(Error::Overflow)? as f64)
        + 8.0
        + 2.0 * (options.bandwidth_latency_tradeoff as f64);
    let full_remote = (avg.checked_add(8).ok_or(Error::Overflow)? as f64)
        * (local_diff.checked_add(remote).ok_or(Error::Overflow)? as f64)
        + 12.0
        + 2.5 * (options.bandwidth_latency_tradeoff as f64);
    let buckets = libm::fmax(37.0, (diff as f64) * (options.bucket_factor as f64));
    let counter = libm::fmin(
        2.0 * libm::log2((local as f64) / buckets),
        libm::log2(local as f64),
    );
    if counter < 0.0 && options.force_full != 1 {
        return Ok(Choice::Differential);
    }
    let ibf = (16.0 * libm::ceil(buckets / 3276.0)
        + buckets * (12.0 + libm::ceil(libm::fmax(counter, 0.0)) / 8.0))
        * 1.2;
    let differential = ((avg + 8) as f64) * (diff as f64)
        + 4.0
        + 152.0 * (diff as f64)
        + libm::ceil(ibf)
        + 3.65145 * (options.bandwidth_latency_tradeoff as f64);
    if options.force_full == 1 || libm::fmin(full_local, full_remote) < differential {
        Ok(if full_local < full_remote {
            Choice::SendFull
        } else {
            Choice::RequestFull
        })
    } else {
        Ok(Choice::Differential)
    }
}
