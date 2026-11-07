//! Stable element indices, shared immutable payloads and sparse disagreement ballots.
use crate::{Error, Limits};
use alloc::vec::Vec;
use core::mem::size_of;
use gnunet_wire::official::set::Abi;
pub(crate) fn reserve<T>(
    v: &mut Vec<T>,
    additional: usize,
    max: usize,
    available: &mut usize,
) -> Result<(), Error> {
    let need = v.len().checked_add(additional).ok_or(Error::Overflow)?;
    if need > max {
        return Err(Error::Capacity);
    }
    if need <= v.capacity() {
        return Ok(());
    }
    let target = v
        .capacity()
        .max(2)
        .checked_mul(2)
        .ok_or(Error::Overflow)?
        .min(max)
        .max(need);
    if target.checked_mul(size_of::<T>()).ok_or(Error::Overflow)? > *available {
        return Err(Error::Capacity);
    }
    let mut next = Vec::new();
    next.try_reserve_exact(target)
        .map_err(|_| Error::Capacity)?;
    let new = next
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(Error::Overflow)?;
    if next.capacity() > max || new > *available {
        return Err(Error::Capacity);
    }
    let old = v
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(Error::Overflow)?;
    *available = available
        .checked_sub(new)
        .and_then(|n| n.checked_add(old))
        .ok_or(Error::Overflow)?;
    next.append(v);
    *v = next;
    Ok(())
}
pub(crate) fn bytes(size: usize, available: &mut usize) -> Result<Vec<u8>, Error> {
    if size > *available {
        return Err(Error::Capacity);
    }
    let mut v = Vec::new();
    v.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
    if v.capacity() > *available {
        return Err(Error::Capacity);
    }
    *available -= v.capacity();
    v.resize(size, 0);
    Ok(v)
}
pub(crate) fn charge<T>(v: &Vec<T>) -> Result<usize, Error> {
    v.capacity()
        .checked_mul(size_of::<T>())
        .ok_or(Error::Overflow)
}
pub(crate) struct Element {
    pub raw: Vec<u8>,
}
pub(crate) struct Pool {
    pub elements: Vec<Element>,
    index: Vec<([u8; 64], u32)>,
    payload: usize,
}
impl Pool {
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
            index: Vec::new(),
            payload: 0,
        }
    }
    fn location(&self, raw: &[u8], abi: Abi) -> Result<([u8; 64], Result<u32, usize>), Error> {
        let prefix = gnunet_wire::official::set::Element {
            element_type: 25,
            data: raw,
        }
        .fingerprint_prefix(abi.order)?;
        let hash = gnunet_crypto::hash512_parts(&[&prefix, raw]);
        let found = match self.index.binary_search_by_key(&hash, |e| e.0) {
            Ok(i) => {
                let id = self.index[i].1;
                if self.elements[id as usize].raw != raw {
                    return Err(Error::Authentication);
                }
                Ok(id)
            }
            Err(i) => Err(i),
        };
        Ok((hash, found))
    }
    fn insert_owned(
        &mut self,
        data: Vec<u8>,
        hash: [u8; 64],
        at: usize,
        limits: Limits,
        available: &mut usize,
    ) -> Result<u32, Error> {
        if self.elements.len() >= limits.elements
            || data.len() > limits.element_bytes.checked_add(3).ok_or(Error::Overflow)?
        {
            return Err(Error::Capacity);
        }
        let payload = self
            .payload
            .checked_add(data.capacity())
            .ok_or(Error::Overflow)?;
        if payload > limits.payload_bytes {
            return Err(Error::Capacity);
        }
        reserve(&mut self.elements, 1, limits.elements, available)?;
        reserve(&mut self.index, 1, limits.elements, available)?;
        let id = u32::try_from(self.elements.len()).map_err(|_| Error::Overflow)?;
        self.elements.push(Element { raw: data });
        self.index.insert(at, (hash, id));
        self.payload = payload;
        Ok(id)
    }
    pub fn intern(
        &mut self,
        raw: &[u8],
        abi: Abi,
        limits: Limits,
        available: &mut usize,
    ) -> Result<u32, Error> {
        let (hash, at) = self.location(raw, abi)?;
        let at = match at {
            Ok(id) => return Ok(id),
            Err(at) => at,
        };
        if raw.len() > limits.payload_bytes.saturating_sub(self.payload) {
            return Err(Error::Capacity);
        }
        let mut data = bytes(raw.len(), available)?;
        data.copy_from_slice(raw);
        self.insert_owned(data, hash, at, limits, available)
    }
    pub fn intern_owned(
        &mut self,
        data: Vec<u8>,
        abi: Abi,
        limits: Limits,
        available: &mut usize,
    ) -> Result<u32, Error> {
        let (hash, at) = self.location(&data, abi)?;
        match at {
            Ok(id) => {
                *available = available
                    .checked_add(data.capacity())
                    .ok_or(Error::Overflow)?;
                Ok(id)
            }
            Err(at) => self.insert_owned(data, hash, at, limits, available),
        }
    }
    pub fn charged(&self) -> Result<usize, Error> {
        self.payload
            .checked_add(charge(&self.elements)?)
            .and_then(|n| charge(&self.index).ok().and_then(|m| n.checked_add(m)))
            .ok_or(Error::Overflow)
    }
}
pub(crate) struct Members {
    pub ids: Vec<u32>,
}
impl Members {
    pub fn new() -> Self {
        Self { ids: Vec::new() }
    }
    pub fn copy(&self, available: &mut usize) -> Result<Self, Error> {
        if self
            .ids
            .len()
            .checked_mul(size_of::<u32>())
            .ok_or(Error::Overflow)?
            > *available
        {
            return Err(Error::Capacity);
        }
        let mut ids = Vec::new();
        ids.try_reserve_exact(self.ids.len())
            .map_err(|_| Error::Capacity)?;
        let n = charge(&ids)?;
        if n > *available {
            return Err(Error::Capacity);
        }
        *available -= n;
        ids.extend_from_slice(&self.ids);
        Ok(Self { ids })
    }
    pub fn contains(&self, id: u32) -> bool {
        self.ids.binary_search(&id).is_ok()
    }
    pub fn prepare_add(
        &mut self,
        id: u32,
        limits: Limits,
        available: &mut usize,
    ) -> Result<Option<usize>, Error> {
        if let Err(at) = self.ids.binary_search(&id) {
            reserve(&mut self.ids, 1, limits.elements, available)?;
            Ok(Some(at))
        } else {
            Ok(None)
        }
    }
    pub fn commit_add(&mut self, id: u32, at: Option<usize>) {
        if let Some(at) = at {
            self.ids.insert(at, id);
        }
    }
    pub fn add(&mut self, id: u32, limits: Limits, available: &mut usize) -> Result<(), Error> {
        if let Err(at) = self.ids.binary_search(&id) {
            reserve(&mut self.ids, 1, limits.elements, available)?;
            self.ids.insert(at, id);
        }
        Ok(())
    }
    pub fn remove(&mut self, id: u32) {
        if let Ok(at) = self.ids.binary_search(&id) {
            self.ids.remove(at);
        }
    }
    pub fn charged(&self) -> Result<usize, Error> {
        charge(&self.ids)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Change {
    Stay,
    Add,
    Remove,
}
pub(crate) struct Vote {
    pub element: u32,
    pub proposal: Change,
    yes: Vec<u8>,
}
pub(crate) struct Ballot {
    pub votes: Vec<Vote>,
    committed: Vec<u8>,
    contested: Vec<u8>,
    peers: usize,
    vote_bytes: usize,
}
fn mark(b: &mut [u8], peer: usize) {
    b[peer / 8] |= 1u8 << (peer % 8);
}
impl Ballot {
    pub fn new(peers: usize, local: usize, available: &mut usize) -> Result<Self, Error> {
        let n = peers.div_ceil(8);
        let mut committed = bytes(n, available)?;
        let contested = bytes(n, available)?;
        mark(&mut committed, local);
        Ok(Self {
            votes: Vec::new(),
            committed,
            contested,
            peers,
            vote_bytes: 0,
        })
    }
    pub fn uncommit(&mut self, peer: usize) -> Result<(), Error> {
        if peer >= self.peers {
            return Err(Error::InvalidInput);
        }
        self.committed[peer / 8] &= !(1u8 << (peer % 8));
        Ok(())
    }
    pub fn commit(&mut self, peer: usize) -> Result<(), Error> {
        if peer >= self.peers {
            return Err(Error::InvalidInput);
        }
        mark(&mut self.committed, peer);
        Ok(())
    }
    pub fn contest(&mut self, peer: usize) -> Result<(), Error> {
        if peer >= self.peers {
            return Err(Error::InvalidInput);
        }
        mark(&mut self.contested, peer);
        Ok(())
    }
    pub fn noncontested(&self) -> usize {
        self.committed
            .iter()
            .zip(&self.contested)
            .map(|(a, b)| (a & !b).count_ones() as usize)
            .sum()
    }
    pub fn count(&self) -> usize {
        self.committed.iter().map(|b| b.count_ones() as usize).sum()
    }
    pub fn record(
        &mut self,
        element: u32,
        proposal: Change,
        peer: usize,
        limits: Limits,
        available: &mut usize,
    ) -> Result<(), Error> {
        if peer >= self.peers || proposal == Change::Stay {
            return Err(Error::InvalidInput);
        }
        let at = match self.votes.binary_search_by_key(&element, |v| v.element) {
            Ok(i) => {
                if self.votes[i].proposal != proposal {
                    return Err(Error::Authentication);
                }
                i
            }
            Err(i) => {
                let yes = bytes(self.peers.div_ceil(8), available)?;
                reserve(&mut self.votes, 1, limits.elements, available)?;
                let vote_bytes = self
                    .vote_bytes
                    .checked_add(yes.capacity())
                    .ok_or(Error::Overflow)?;
                self.votes.insert(
                    i,
                    Vote {
                        element,
                        proposal,
                        yes,
                    },
                );
                self.vote_bytes = vote_bytes;
                i
            }
        };
        mark(&mut self.votes[at].yes, peer);
        Ok(())
    }
    fn tally(&self, v: &Vote, exclude_contested: bool) -> (usize, usize) {
        self.committed.iter().zip(&self.contested).zip(&v.yes).fold(
            (0, 0),
            |(yes, count), ((committed, contested), votes)| {
                let eligible = if exclude_contested {
                    committed & !contested
                } else {
                    *committed
                };
                (
                    yes + (eligible & votes).count_ones() as usize,
                    count + eligible.count_ones() as usize,
                )
            },
        )
    }
    fn decide(v: &Vote, yes: usize, count: usize) -> (Change, usize) {
        if yes > count / 2 {
            (v.proposal, yes)
        } else {
            (Change::Stay, count - yes)
        }
    }
    pub fn majority(&self, v: &Vote) -> (Change, usize) {
        let (yes, count) = self.tally(v, false);
        Self::decide(v, yes, count)
    }
    // A contested confirmation represents bottom, not a set whose membership
    // may be counted. The original committed bit is still required for each
    // eligible peer, so a marker or partial SET result cannot create a vote.
    pub fn confirmation_majority(&self, v: &Vote) -> (Change, usize) {
        let (yes, count) = self.tally(v, true);
        Self::decide(v, yes, count)
    }
    // The final candidate contains elements supported by at least ceil(n'/2)
    // nonzero-grade leaders. Resolve membership independently of our base:
    // an Add tie includes the element, while a Remove tie retains it. No
    // eligible votes (0:0) provide neither a proposal nor positive support.
    pub fn union_majority(&self, v: &Vote) -> (Change, usize) {
        let (yes, count) = self.tally(v, false);
        if count != 0 && v.proposal == Change::Add && yes == count - yes {
            (Change::Add, yes)
        } else {
            Self::decide(v, yes, count)
        }
    }
    pub fn charged(&self) -> Result<usize, Error> {
        charge(&self.votes)?
            .checked_add(self.committed.capacity())
            .and_then(|n| n.checked_add(self.contested.capacity()))
            .and_then(|n| n.checked_add(self.vote_bytes))
            .ok_or(Error::Overflow)
    }
}
