//! One packet handle and one original creator; refresh never builds a handle chain.
pub(super) struct Owners<T> {
    pub packet: T,
    creator: Option<Box<T>>,
}
impl<T> Owners<T> {
    pub fn new(packet: T) -> Self {
        Self {
            packet,
            creator: None,
        }
    }
    pub fn creator(&self) -> Option<&T> {
        self.creator.as_deref()
    }
    pub fn refresh(self, packet: T, created: bool) -> Self {
        let Self {
            packet: previous,
            creator,
        } = self;
        let creator = match creator {
            Some(original) => {
                drop(previous);
                Some(original)
            }
            None if created => Some(Box::new(previous)),
            None => {
                drop(previous);
                None
            }
        };
        Self { packet, creator }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    struct Probe {
        name: usize,
        closed: Rc<RefCell<Vec<usize>>>,
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            self.closed.borrow_mut().push(self.name);
        }
    }
    #[test]
    fn refresh_keeps_one_original_creator_until_after_the_last_packet_handle() {
        let closed = Rc::new(RefCell::new(Vec::new()));
        let probe = |name| Probe {
            name,
            closed: closed.clone(),
        };
        let mut owners = Owners::new(probe(0));
        owners = owners.refresh(probe(1), true);
        for generation in 2..65 {
            owners = owners.refresh(probe(generation), false);
            assert_eq!(owners.creator().map(|original| original.name), Some(0));
            assert_eq!(closed.borrow().len(), generation - 1);
            assert!(!closed.borrow().contains(&0));
        }
        drop(owners);
        let closed = closed.borrow();
        assert_eq!(&closed[closed.len() - 2..], &[64, 0]);
        assert_eq!(closed.len(), 65);
    }
    #[test]
    fn opened_handles_never_acquire_a_creator() {
        let closed = Rc::new(RefCell::new(Vec::new()));
        let probe = |name| Probe {
            name,
            closed: closed.clone(),
        };
        let owners = Owners::new(probe(0)).refresh(probe(1), false);
        assert!(owners.creator().is_none());
        assert_eq!(&*closed.borrow(), &[0]);
        drop(owners);
        assert_eq!(&*closed.borrow(), &[0, 1]);
    }
}
