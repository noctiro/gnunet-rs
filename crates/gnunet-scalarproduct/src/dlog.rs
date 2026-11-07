use crate::crypto::{signed, validate_point};
use alloc::vec::Vec;
use core::mem::size_of;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint};
use gnunet_types::Error;
use zeroize::Zeroize;

/// Explicit finite discrete-log search and retained allocation profile.
#[derive(Clone, Copy, Debug)]
pub struct DlogLimits {
    /// Inclusive signed result magnitude, below i32::MAX.
    pub max_result: u32,
    /// Table's positive/negative giant-step count; 1024 in the C default.
    pub memory: u32,
    /// Actual table capacity plus this job's fixed metadata limit.
    pub max_retained_bytes: usize,
}
impl Default for DlogLimits {
    fn default() -> Self {
        Self {
            max_result: 1024 * 1024,
            memory: 1024,
            max_retained_bytes: 1024 * 1024,
        }
    }
}
impl DlogLimits {
    /// Check finite arithmetic/range without executing elliptic-curve work.
    pub fn validate(self) -> Result<(), Error> {
        if self.max_result == 0
            || self.max_result >= i32::MAX as u32
            || self.memory == 0
            || self.memory > self.max_result
            || self.max_retained_bytes == 0
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Entry {
    point: [u8; 32],
    multiple: i32,
}
#[derive(Clone, Copy)]
enum Phase {
    Build,
    Heap(usize),
    Sort(usize),
    Scan(u32),
    Verify,
    Done,
}

/// Incremental real Edwards25519 discrete logarithm, using the reference
/// giant-step table. A unit performs one group step or a bounded logarithmic
/// heap/search operation. No unbounded sorting/allocation occurs in step().
pub struct Dlog {
    limits: DlogLimits,
    table: Vec<Entry>,
    target: EdwardsPoint,
    query: EdwardsPoint,
    build: EdwardsPoint,
    stride: EdwardsPoint,
    k: u32,
    phase: Phase,
    candidate: Option<i32>,
    result: Option<DlogProgress>,
}

/// A job's actual state; an absent logarithm is never represented by zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DlogProgress {
    /// More explicitly budgeted CPU work is required.
    Pending,
    /// Verified logarithm inside the configured inclusive signed range.
    Done(i32),
    /// No verified in-range logarithm exists for this point.
    OutOfRange,
}

impl Dlog {
    /// Validate a canonical prime-subgroup input and reserve one bounded table.
    pub fn new(target: [u8; 32], limits: DlogLimits) -> Result<Self, Error> {
        limits.validate()?;
        let target = validate_point(&target)?;
        let k = limits.max_result.div_ceil(limits.memory);
        let count = usize::try_from(limits.memory)
            .map_err(|_| Error::TooLarge)?
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?;
        let wanted = count
            .checked_mul(size_of::<Entry>())
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .ok_or(Error::Overflow)?;
        if wanted > limits.max_retained_bytes {
            return Err(Error::Capacity);
        }
        let mut table = Vec::new();
        table
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        let actual = table
            .capacity()
            .checked_mul(size_of::<Entry>())
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .ok_or(Error::Overflow)?;
        if actual > limits.max_retained_bytes {
            return Err(Error::Capacity);
        }
        let first = -i64::from(limits.memory) * i64::from(k);
        Ok(Self {
            limits,
            table,
            target,
            query: target,
            build: ED25519_BASEPOINT_POINT * signed(first),
            stride: ED25519_BASEPOINT_POINT * signed(i64::from(k)),
            k,
            phase: Phase::Build,
            candidate: None,
            result: None,
        })
    }
    /// Actual retained table capacity and fixed job metadata.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.table
            .capacity()
            .checked_mul(size_of::<Entry>())
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .ok_or(Error::Overflow)
    }
    fn sift(&mut self, mut root: usize, end: usize) {
        while let Some(mut child) = root.checked_mul(2).and_then(|n| n.checked_add(1)) {
            if child >= end {
                break;
            }
            if child + 1 < end && self.table[child].point < self.table[child + 1].point {
                child += 1;
            }
            if self.table[root].point >= self.table[child].point {
                break;
            }
            self.table.swap(root, child);
            root = child;
        }
    }
    /// Perform at most the requested finite work units. Zero budget is rejected.
    /// The construction/search is variable-time and makes no side-channel or
    /// measured performance claim.
    pub fn step(&mut self, work_units: usize) -> Result<DlogProgress, Error> {
        if work_units == 0 {
            return Err(Error::InvalidInput);
        }
        if let Some(result) = self.result {
            return Ok(result);
        }
        let count = self.limits.memory as usize * 2 + 1;
        for _ in 0..work_units {
            match self.phase {
                Phase::Build => {
                    if self.table.len() == count {
                        self.phase = Phase::Heap(count / 2);
                        continue;
                    }
                    let index = i32::try_from(self.table.len()).map_err(|_| Error::Overflow)?
                        - self.limits.memory as i32;
                    self.table.push(Entry {
                        point: self.build.compress().to_bytes(),
                        multiple: index,
                    });
                    self.build += self.stride;
                }
                Phase::Heap(root) => {
                    if root == 0 {
                        self.phase = Phase::Sort(count);
                    } else {
                        self.sift(root - 1, count);
                        self.phase = Phase::Heap(root - 1);
                    }
                }
                Phase::Sort(end) => {
                    if end <= 1 {
                        self.phase = Phase::Scan(0);
                    } else {
                        self.table.swap(0, end - 1);
                        self.sift(0, end - 1);
                        self.phase = Phase::Sort(end - 1);
                    }
                }
                Phase::Scan(j) => {
                    if j >= self.k {
                        self.phase = Phase::Verify;
                        continue;
                    }
                    let bytes = self.query.compress().to_bytes();
                    if let Ok(index) = self.table.binary_search_by_key(&bytes, |entry| entry.point)
                    {
                        let value = i64::from(self.table[index].multiple) * i64::from(self.k)
                            - i64::from(j);
                        if value >= -i64::from(self.limits.max_result)
                            && value <= i64::from(self.limits.max_result)
                        {
                            self.candidate =
                                Some(i32::try_from(value).map_err(|_| Error::Overflow)?);
                        }
                    }
                    self.query += ED25519_BASEPOINT_POINT;
                    self.phase = Phase::Scan(j + 1);
                }
                Phase::Verify => {
                    let result = match self.candidate {
                        Some(value)
                            if ED25519_BASEPOINT_POINT * signed(i64::from(value))
                                == self.target =>
                        {
                            DlogProgress::Done(value)
                        }
                        _ => DlogProgress::OutOfRange,
                    };
                    self.result = Some(result);
                    self.phase = Phase::Done;
                    return Ok(result);
                }
                Phase::Done => return self.result.ok_or(Error::Conflict),
            }
        }
        Ok(DlogProgress::Pending)
    }
}
impl Drop for Dlog {
    fn drop(&mut self) {
        self.target.zeroize();
        self.query.zeroize();
        self.build.zeroize();
        self.stride.zeroize();
        self.candidate.zeroize();
        if let Some(DlogProgress::Done(value)) = self.result.as_mut() {
            value.zeroize();
        }
    }
}
