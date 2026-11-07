//! Fixed-capacity FIFO ownership transfer.
use gnunet_types::{Error, Rejected};

/// A finite FIFO; rejection always returns ownership and successful admission transfers it.
pub struct BoundedQueue<T, const N: usize> {
    entries: [Option<T>; N],
    head: usize,
    len: usize,
}

impl<T, const N: usize> Default for BoundedQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> BoundedQueue<T, N> {
    /// Create an empty queue with exactly `N` slots.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            head: 0,
            len: 0,
        }
    }
    /// Current occupied slot count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }
    /// Whether every slot is available.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Whether admission would fail, including a zero-capacity queue.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == N
    }
    /// Total number of slots reserved by this queue.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }
    /// Transfer ownership into this queue, or return it unchanged on backpressure.
    pub fn try_push(&mut self, value: T) -> Result<(), Rejected<T>> {
        if self.len == N {
            return Err(Rejected {
                value,
                reason: Error::Capacity,
            });
        }
        let Some(offset) = self.head.checked_add(self.len) else {
            return Err(Rejected {
                value,
                reason: Error::Overflow,
            });
        };
        let tail = offset % N;
        self.entries[tail] = Some(value);
        self.len += 1;
        Ok(())
    }
    /// Transfer ownership of the oldest entry back to the caller.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let value = self.entries[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        value
    }
    /// Borrow the oldest entry without changing ownership.
    #[must_use]
    pub fn front(&self) -> Option<&T> {
        self.entries.get(self.head).and_then(Option::as_ref)
    }
    /// Borrow entries in FIFO order for the duration of this call.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries[self.head..]
            .iter()
            .chain(self.entries[..self.head].iter())
            .filter_map(Option::as_ref)
            .take(self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_queue_returns_ownership_and_zero_capacity_is_safe() {
        let mut queue = BoundedQueue::<u8, 1>::new();
        assert!(queue.try_push(9).is_ok());
        assert_eq!(
            queue.try_push(8),
            Err(Rejected {
                value: 8,
                reason: Error::Capacity
            })
        );
        assert_eq!(queue.pop(), Some(9));
        let mut empty = BoundedQueue::<u8, 0>::new();
        assert!(empty.try_push(1).is_err());
        assert_eq!(empty.pop(), None);
        assert_eq!(empty.iter().count(), 0);
    }
}
