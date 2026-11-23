//! Fixed-capacity cyclic queue of original owned values.

pub(super) struct Queue<T, const N: usize> {
    slots: [Option<T>; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<T, const N: usize> Queue<T, N> {
    pub(super) const fn new() -> Self {
        Self {
            slots: [const { None }; N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    pub(super) const fn len(&self) -> usize {
        self.len
    }

    pub(super) fn push(&mut self, entry: T) -> Result<(), T> {
        if self.len == N {
            return Err(entry);
        }
        self.slots[self.tail] = Some(entry);
        self.tail = next::<N>(self.tail);
        self.len += 1;
        Ok(())
    }

    pub(super) fn front(&self) -> Option<&T> {
        self.slots.get(self.head)?.as_ref()
    }

    pub(super) fn pop(&mut self) -> Option<T> {
        let entry = self.slots.get_mut(self.head)?.take()?;
        self.head = next::<N>(self.head);
        self.len -= 1;
        Some(entry)
    }
}

fn next<const N: usize>(index: usize) -> usize {
    if index + 1 == N { 0 } else { index + 1 }
}
