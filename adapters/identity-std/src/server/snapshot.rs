//! Private Rust body codec, independent of public official IPC and C storage.
use gnunet_identity::{Ego, SecretKey, Snapshot};
use gnunet_types::Error;
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"GIDCORE1";
pub(crate) fn encode(snapshot: &Snapshot, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut len = 12usize;
    for ego in snapshot.egos() {
        u16::try_from(ego.name().len()).map_err(|_| Error::Capacity)?;
        len = len
            .checked_add(2 + 36)
            .and_then(|n| n.checked_add(ego.name().len()))
            .ok_or(Error::Overflow)?;
    }
    if len > limit {
        return Err(Error::Capacity);
    }
    let count = u32::try_from(snapshot.egos().len()).map_err(|_| Error::Capacity)?;
    let mut body = Zeroizing::new(Vec::new());
    body.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&count.to_be_bytes());
    for ego in snapshot.egos() {
        body.extend_from_slice(&(ego.name().len() as u16).to_be_bytes());
        body.extend_from_slice(ego.name());
        body.extend_from_slice(ego.key().expose_serialized());
    }
    Ok(body)
}
pub(crate) fn decode(
    body: Zeroizing<Vec<u8>>,
    limits: gnunet_identity::Limits,
) -> Result<Vec<Ego>, Error> {
    if body.is_empty() {
        return Ok(Vec::new());
    }
    if body.len() < 12 || &body[..8] != MAGIC {
        return Err(Error::Storage);
    }
    let count = u32::from_be_bytes(body[8..12].try_into().map_err(|_| Error::Storage)?) as usize;
    if count > limits.egos {
        return Err(Error::Capacity);
    }
    let mut egos = Vec::new();
    egos.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
    let mut at = 12usize;
    for _ in 0..count {
        let prefix_end = at.checked_add(2).ok_or(Error::Overflow)?;
        let n = body.get(at..prefix_end).ok_or(Error::Storage)?;
        let len = usize::from(u16::from_be_bytes([n[0], n[1]]));
        at = prefix_end;
        if len > limits.name_bytes {
            return Err(Error::Capacity);
        }
        let end = at.checked_add(len).ok_or(Error::Overflow)?;
        let bytes = body.get(at..end).ok_or(Error::Storage)?;
        let mut name = Vec::new();
        name.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
        name.extend_from_slice(bytes);
        at = end;
        let end = at.checked_add(36).ok_or(Error::Overflow)?;
        let key = SecretKey::from_serialized(body.get(at..end).ok_or(Error::Storage)?)?;
        egos.push(Ego::new(name, key)?);
        at = end;
    }
    if at != body.len() {
        return Err(Error::Storage);
    }
    Ok(egos)
}
