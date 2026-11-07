//! Exact original wire frames and separately issued purpose6 signing work.
use super::{Job, JobKind, Peer, PutFrameLimit};
use alloc::vec::Vec;
use gnunet_crypto::hash512;
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    dht::{GetMessage, PATH_ELEMENT_LEN, Path, PutMessage, ResultMessage, RouteOptions},
};

pub(super) struct Pending<'id> {
    pub job: Job<'id>,
    pub kind: JobKind,
    pub peer: Peer<'id>,
    pub frame: Vec<u8>,
    pub until: u64,
    pub signing: Option<Signing>,
    pub issued: bool,
    pub retiring: bool,
    pub query: Option<super::super::QueryId<'id>>,
    pub put: Option<super::PutId<'id>>,
    // Full original first-child Job identifies one observed P2P fanout.
    pub monitor: Option<Job<'id>>,
}
pub(super) struct Signing {
    pub material: [u8; crate::path::SIGNED_LEN],
    pub offset: usize,
}
impl<'id> Pending<'id> {
    pub fn get(
        job: Job<'id>,
        peer: Peer<'id>,
        message: GetMessage<'_>,
        until: u64,
    ) -> Result<Self, Error> {
        let mut frame = super::bytes(message.encoded_len()?)?;
        message.encode(&mut frame)?;
        Ok(Self {
            job,
            kind: JobKind::Get,
            peer,
            frame,
            until,
            signing: None,
            issued: false,
            retiring: false,
            query: None,
            put: None,
            monitor: None,
        })
    }
    pub fn put(
        job: Job<'id>,
        peer: Peer<'id>,
        recipient: &[u8; 32],
        message: PutMessage<'_>,
        limit: PutFrameLimit,
        until: u64,
    ) -> Result<Self, Error> {
        let zero = [0; 64];
        let tracking = message.options.contains(RouteOptions::RECORD_ROUTE);
        let message = fit_put(
            PutMessage {
                sender_signature: tracking.then_some(&zero),
                ..message
            },
            limit,
        )?;
        // The same selected borrowed fields are used for size preflight,
        // wire bytes and the original PILS material below. No stale quote.
        let mut frame = super::bytes(message.encoded_len()?)?;
        message.encode(&mut frame)?;
        let signing = if tracking {
            Some(Signing {
                material: crate::path::region(
                    &hash512(message.payload),
                    message.expiration.as_micros(),
                    &predecessor(message.put_path, Path::empty(), message.truncated_peer)?,
                    recipient,
                ),
                offset: frame.len() - message.payload.len() - 64,
            })
        } else {
            None
        };
        Ok(Self {
            job,
            kind: JobKind::Put,
            peer,
            frame,
            until,
            signing,
            issued: false,
            retiring: false,
            query: None,
            put: None,
            monitor: None,
        })
    }
    pub fn result(
        job: Job<'id>,
        peer: Peer<'id>,
        recipient: &[u8; 32],
        message: ResultMessage<'_>,
        until: u64,
    ) -> Result<Self, Error> {
        let zero = [0; 64];
        let tracking = message.options.contains(RouteOptions::RECORD_ROUTE);
        let message = ResultMessage {
            sender_signature: tracking.then_some(&zero),
            ..message
        };
        let mut frame = super::bytes(message.encoded_len()?)?;
        message.encode(&mut frame)?;
        let signing = if tracking {
            Some(Signing {
                material: crate::path::region(
                    &hash512(message.payload),
                    message.expiration.as_micros(),
                    &predecessor(message.put_path, message.get_path, message.truncated_peer)?,
                    recipient,
                ),
                offset: frame.len() - message.payload.len() - 64,
            })
        } else {
            None
        };
        Ok(Self {
            job,
            kind: JobKind::Result,
            peer,
            frame,
            until,
            signing,
            issued: false,
            retiring: false,
            query: None,
            put: None,
            monitor: None,
        })
    }
}
// Fit the already validated metadata and unchanged payload before allocating
// a frame or asking PILS to sign. The original path need not fit u16 first.
fn fit_put(message: PutMessage<'_>, limit: PutFrameLimit) -> Result<PutMessage<'_>, Error> {
    let fixed = PutMessage {
        put_path: Path::empty(),
        ..message
    }
    .encoded_len()?;
    let full = fixed
        .checked_add(message.put_path.as_bytes().len())
        .ok_or(Error::Overflow)?;
    if full <= limit.bytes() {
        return Ok(message);
    }
    if !message.options.contains(RouteOptions::RECORD_ROUTE) {
        return Err(Error::TooLarge);
    }
    // A newly truncated path needs its own 32-byte boundary even if no
    // signed elements remain. An existing boundary is replaced, not doubled.
    let overhead = if message.truncated_peer.is_some() {
        0
    } else {
        32
    };
    let fixed = fixed.checked_add(overhead).ok_or(Error::Overflow)?;
    let available = limit.bytes().checked_sub(fixed).ok_or(Error::TooLarge)?;
    let keep = available / PATH_ELEMENT_LEN;
    let removed = message
        .put_path
        .len()
        .checked_sub(keep)
        .filter(|count| *count != 0)
        .ok_or(Error::InvalidInput)?;
    let cut = removed
        .checked_mul(PATH_ELEMENT_LEN)
        .ok_or(Error::Overflow)?;
    let path = message.put_path.as_bytes();
    // Path entries are signature64 || signer32. Retaining the last removed
    // signer preserves the first retained signature's original predecessor;
    // with zero retained entries it preserves the new sender's predecessor.
    let boundary: &[u8; 32] = path
        .get(cut.checked_sub(32).ok_or(Error::InvalidInput)?..cut)
        .ok_or(Error::InvalidInput)?
        .try_into()
        .map_err(|_| Error::InvalidInput)?;
    let suffix = Path::new(path.get(cut..).ok_or(Error::InvalidInput)?)?;
    Ok(PutMessage {
        options: message.options | RouteOptions::TRUNCATED,
        truncated_peer: Some(boundary),
        put_path: suffix,
        ..message
    })
}
fn predecessor(
    put: Path<'_>,
    get: Path<'_>,
    truncated: Option<&[u8; 32]>,
) -> Result<[u8; 32], Error> {
    let last = get.elements().last().or_else(|| put.elements().last());
    match last {
        Some(entry) => entry
            .predecessor()
            .try_into()
            .map_err(|_| Error::InvalidInput),
        None => Ok(truncated.copied().unwrap_or([0; 32])),
    }
}
pub(super) struct Block<'a> {
    // Opaque current RESULT field, preserved only while forwarding that result.
    // New replies synthesized from local/cache blocks use zero explicitly.
    pub reserved: u16,
    pub kind: u32,
    pub options: RouteOptions,
    pub expiration: u64,
    pub payload: &'a [u8],
    pub truncated: Option<&'a [u8; 32]>,
    pub put: Path<'a>,
    pub get: Path<'a>,
}
impl Block<'_> {
    pub fn result<'a>(&'a self, requested: &'a [u8; 64]) -> ResultMessage<'a> {
        ResultMessage {
            block_type: self.kind,
            reserved: self.reserved,
            options: self.options,
            expiration: AbsoluteTime::from_micros(self.expiration),
            key: requested,
            truncated_peer: self.truncated,
            put_path: self.put,
            get_path: self.get,
            sender_signature: None,
            payload: self.payload,
        }
    }
}

// One original observation, not one payload copy per network destination.
// Every frame was encoded/preflighted before accepting the P2P transition.
pub(super) struct MonitorFanout<'id> {
    pub original: Option<Job<'id>>,
    pub remaining: usize,
    pub ready: bool,
    pub event: u8,
    pub kind: u32,
    pub key: [u8; 64],
    pub options: u32,
    pub frames: Vec<super::super::Output<'id>>,
}
impl MonitorFanout<'_> {
    pub fn conclude(&mut self, last_hop: bool) {
        if self.ready {
            return;
        }
        let bit = u32::from(RouteOptions::LAST_HOP.bits());
        let options = self.options | if last_hop { bit } else { 0 };
        for frame in &mut self.frames {
            // GET148 and PUT151 both encode their u32 options immediately
            // after the common header. Only those validated frames enter here.
            frame.bytes[4..8].copy_from_slice(&options.to_be_bytes());
        }
        self.ready = true;
    }
    pub fn terminal(&mut self, admitted: bool) {
        if self.ready {
            return;
        }
        if admitted {
            self.conclude(false);
        } else {
            self.remaining -= 1;
            if self.remaining == 0 {
                self.conclude(true);
            }
        }
    }
}
