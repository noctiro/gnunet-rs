//! Allocation-free official regex state block construction.
use crate::{Hash, MAX_BLOCK_BYTES};
use gnunet_types::Error;
/// One raw official edge token and its exact destination proof key.
#[derive(Clone, Copy, Debug)]
pub struct BlockEdge<'a> {
    /// Destination state's SHA-512 key.
    pub destination: Hash,
    /// Original non-NUL token bytes. No synthetic terminator is encoded.
    pub label: &'a [u8],
}
/// Stable borrowed indexed edges, allowing noalloc caller-owned arrays.
pub trait EdgeSource {
    /// Original edge count; must remain fixed throughout a call.
    fn len(&self) -> usize;
    /// Exact edge at index; must remain fixed throughout a call.
    fn edge(&self, index: usize) -> Option<BlockEdge<'_>>;
    /// Whether this source contains no edges.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl EdgeSource for [BlockEdge<'_>] {
    fn len(&self) -> usize {
        <[BlockEdge<'_>]>::len(self)
    }
    fn edge(&self, index: usize) -> Option<BlockEdge<'_>> {
        self.get(index).copied()
    }
}
fn get(edges: &(impl EdgeSource + ?Sized), index: usize) -> Result<BlockEdge<'_>, Error> {
    edges.edge(index).ok_or(Error::InvalidInput)
}
fn first(edges: &(impl EdgeSource + ?Sized), index: usize) -> Result<usize, Error> {
    let key = get(edges, index)?.destination;
    for i in 0..index {
        if get(edges, i)?.destination == key {
            return Ok(i);
        }
    }
    Ok(index)
}
fn unique_before(edges: &(impl EdgeSource + ?Sized), end: usize) -> Result<usize, Error> {
    let mut count = 0;
    for i in 0..end {
        if first(edges, i)? == i {
            count += 1;
        }
    }
    Ok(count)
}
/// Measure one official deduplicated destination table, EdgeInfo table, proof
/// and token bytes. Limits/invalid input are checked before any output changes.
pub fn state_block_len(proof: &[u8], edges: &(impl EdgeSource + ?Sized)) -> Result<usize, Error> {
    u16::try_from(proof.len()).map_err(|_| Error::TooLarge)?;
    u16::try_from(edges.len()).map_err(|_| Error::TooLarge)?;
    if proof.contains(&0) {
        return Err(Error::InvalidInput);
    }
    let mut len = 8usize.checked_add(proof.len()).ok_or(Error::Overflow)?;
    let minimum = edges
        .len()
        .checked_mul(4)
        .and_then(|n| n.checked_add(len))
        .ok_or(Error::Overflow)?;
    if minimum >= MAX_BLOCK_BYTES {
        return Err(Error::TooLarge);
    }
    for i in 0..edges.len() {
        let edge = get(edges, i)?;
        if edge.label.contains(&0) {
            return Err(Error::InvalidInput);
        }
        u16::try_from(edge.label.len()).map_err(|_| Error::TooLarge)?;
        len = len
            .checked_add(4)
            .and_then(|n| n.checked_add(edge.label.len()))
            .ok_or(Error::Overflow)?;
        if first(edges, i)? == i {
            len = len.checked_add(64).ok_or(Error::Overflow)?;
        }
        if len >= MAX_BLOCK_BYTES {
            return Err(Error::TooLarge);
        }
    }
    if len >= MAX_BLOCK_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(len)
}
/// Encode exactly the official network byte layout, including destination
/// deduplication in original edge order. This is pure construction, not a PUT.
/// EdgeSource must obey its stable indexed contract; normal validation/capacity
/// refusal leaves output unchanged.
pub fn encode_state(
    proof: &[u8],
    accepting: bool,
    edges: &(impl EdgeSource + ?Sized),
    output: &mut [u8],
) -> Result<usize, Error> {
    let size = state_block_len(proof, edges)?;
    if output.len() < size {
        return Err(Error::Capacity);
    }
    let destinations = unique_before(edges, edges.len())?;
    output[..2].copy_from_slice(&(proof.len() as u16).to_be_bytes());
    output[2..4].copy_from_slice(&u16::from(accepting).to_be_bytes());
    output[4..6].copy_from_slice(&(edges.len() as u16).to_be_bytes());
    output[6..8].copy_from_slice(&(destinations as u16).to_be_bytes());
    let rows = 8 + destinations * 64;
    let data = rows + edges.len() * 4;
    output[data..data + proof.len()].copy_from_slice(proof);
    let mut dst = 8;
    let mut at = data + proof.len();
    for i in 0..edges.len() {
        let edge = get(edges, i)?;
        let first = first(edges, i)?;
        if first == i {
            output[dst..dst + 64].copy_from_slice(&edge.destination);
            dst += 64;
        }
        let mut index = 0;
        while index < destinations
            && output[8 + index * 64..8 + (index + 1) * 64] != edge.destination
        {
            index += 1;
        }
        if index == destinations {
            return Err(Error::Malformed);
        }
        output[rows + i * 4..rows + i * 4 + 2].copy_from_slice(&(index as u16).to_be_bytes());
        output[rows + i * 4 + 2..rows + i * 4 + 4]
            .copy_from_slice(&(edge.label.len() as u16).to_be_bytes());
        output[at..at + edge.label.len()].copy_from_slice(edge.label);
        at += edge.label.len();
    }
    Ok(size)
}
