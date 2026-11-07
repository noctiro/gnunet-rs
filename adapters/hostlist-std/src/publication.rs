//! Shared immutable response bodies. Bytes owns the quota charge through the
//! final actual Hyper write-buffer reference, including retired revisions.
use crate::{Core, Error, Fault};
use bytes::Bytes;
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use zeroize::Zeroizing;

/// Current/publication and retained historical response memory bounds.
#[derive(Clone, Copy, Debug)]
pub struct PublicationLimits {
    /// Maximum binary publication body, official default 500000.
    pub binary_bytes: usize,
    /// Maximum JSON publication body including escaping.
    pub json_bytes: usize,
    /// Aggregate charged body capacity across current and in-flight revisions.
    pub retained_bytes: usize,
    /// Maximum cache rows visited in one bounded publication pass.
    pub entries: usize,
}
impl Default for PublicationLimits {
    fn default() -> Self {
        Self {
            binary_bytes: 500_000,
            json_bytes: 2_000_000,
            retained_bytes: 12_000_000,
            entries: 4096,
        }
    }
}
struct Budget {
    used: AtomicUsize,
    maximum: usize,
}
struct Charge {
    budget: Arc<Budget>,
    bytes: usize,
}
impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}
struct BodyOwner {
    data: Zeroizing<Vec<u8>>,
    _charge: Arc<Charge>,
}
impl AsRef<[u8]> for BodyOwner {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
#[derive(Clone)]
pub(crate) struct Published {
    pub revision: u64,
    pub observed: u64,
    pub expires: u64,
    pub binary: Bytes,
    pub json: Bytes,
}
pub(crate) type View = Rc<RefCell<Option<Published>>>;
pub(crate) struct Publisher {
    pub view: View,
    budget: Arc<Budget>,
    limits: PublicationLimits,
}
fn escaped(input: &[u8]) -> Result<usize, Error> {
    input.iter().try_fold(2usize, |n, b| {
        n.checked_add(match b {
            b'"' | b'\\' => 2,
            0..=31 => 6,
            _ => 1,
        })
        .ok_or_else(|| Fault::Overflow.into())
    })
}
fn string(input: &[u8], output: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push(b'"');
    for b in input {
        match b {
            b'"' => output.extend_from_slice(b"\\\""),
            b'\\' => output.extend_from_slice(b"\\\\"),
            0..=31 => {
                output.extend_from_slice(b"\\u00");
                output.push(HEX[usize::from(*b >> 4)]);
                output.push(HEX[usize::from(*b & 15)]);
            }
            _ => output.push(*b),
        }
    }
    output.push(b'"');
}
impl Publisher {
    pub fn new(limits: PublicationLimits) -> Result<Self, Error> {
        if limits.binary_bytes == 0
            || limits.binary_bytes > gnunet_hostlist::BODY_BYTES
            || limits.json_bytes == 0
            || limits.retained_bytes < limits.binary_bytes
            || limits.entries == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        Ok(Self {
            view: Rc::new(RefCell::new(None)),
            budget: Arc::new(Budget {
                used: AtomicUsize::new(0),
                maximum: limits.retained_bytes,
            }),
            limits,
        })
    }
    pub fn clear(&self) {
        *self.view.borrow_mut() = None
    }
    pub fn revision(&self) -> Option<u64> {
        self.view.borrow().as_ref().map(|p| p.revision)
    }
    pub fn publish(&mut self, core: &Core, now: u64) -> Result<bool, Error> {
        if core.hello_count() > self.limits.entries {
            return Err(Fault::Capacity.into());
        }
        if self
            .view
            .borrow()
            .as_ref()
            .is_some_and(|p| p.revision == core.revision() && p.observed <= now && now < p.expires)
        {
            return Ok(false);
        }
        let mut binary_len = 0usize;
        let mut json_len = b"{\"hellos\":[".len() + 2;
        let mut count = 0usize;
        let mut expires = u64::MAX;
        for frame in core.hellos(now) {
            if frame.bytes().len() > self.limits.binary_bytes.saturating_sub(binary_len) {
                continue;
            }
            let cost = escaped(frame.uri())?
                .checked_add(usize::from(count != 0))
                .ok_or(Fault::Overflow)?;
            if cost > self.limits.json_bytes.saturating_sub(json_len) {
                continue;
            }
            binary_len += frame.bytes().len();
            json_len += cost;
            count += 1;
            expires = expires.min(frame.expires());
        }
        let estimated = binary_len.checked_add(json_len).ok_or(Fault::Overflow)?;
        self.budget
            .used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(estimated)
                    .filter(|n| *n <= self.budget.maximum)
            })
            .map_err(|_| Fault::Capacity)?;
        let mut charge = Charge {
            budget: self.budget.clone(),
            bytes: estimated,
        };
        let mut binary = Zeroizing::new(Vec::new());
        binary
            .try_reserve_exact(binary_len)
            .map_err(|_| Fault::Capacity)?;
        let mut json = Zeroizing::new(Vec::new());
        json.try_reserve_exact(json_len)
            .map_err(|_| Fault::Capacity)?;
        let actual = binary
            .capacity()
            .checked_add(json.capacity())
            .ok_or(Fault::Overflow)?;
        if actual > estimated {
            let extra = actual - estimated;
            self.budget
                .used
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    used.checked_add(extra)
                        .filter(|n| *n <= self.budget.maximum)
                })
                .map_err(|_| Fault::Capacity)?;
            charge.bytes = actual;
        }
        json.extend_from_slice(b"{\"hellos\":[");
        let mut count = 0usize;
        for frame in core.hellos(now) {
            if frame.bytes().len() > self.limits.binary_bytes.saturating_sub(binary.len()) {
                continue;
            }
            let cost = escaped(frame.uri())?
                .checked_add(usize::from(count != 0))
                .ok_or(Fault::Overflow)?;
            if cost > self.limits.json_bytes.saturating_sub(json.len() + 2) {
                continue;
            }
            binary.extend_from_slice(frame.bytes());
            if count != 0 {
                json.push(b',')
            }
            string(frame.uri(), &mut json);
            count += 1;
        }
        json.extend_from_slice(b"]}");
        let charge = Arc::new(charge);
        let published = Published {
            revision: core.revision(),
            observed: now,
            expires,
            binary: Bytes::from_owner(BodyOwner {
                data: binary,
                _charge: charge.clone(),
            }),
            json: Bytes::from_owner(BodyOwner {
                data: json,
                _charge: charge,
            }),
        };
        *self.view.borrow_mut() = Some(published);
        Ok(true)
    }
}
