//! Bounded copied DNS data paired with an unforgeable original native endpoint.
use super::{
    multicast::{self, MulticastRequest},
    sdk::{self, Endpoint},
};
use objc2::{rc::Retained, runtime::AnyObject};
use objc2_foundation::{NSArray, NSData, NSError};
use std::{
    fmt, io,
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

/// Largest DNS body accepted by the official interception IPC envelope.
pub const MAX_DATAGRAM_BYTES: usize = 65_519;
static NEXT_FLOW: AtomicU64 = AtomicU64::new(1);

/// Unique, non-reused original flow identity within this process.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowId(NonZeroU64);
impl FlowId {
    pub(super) fn next() -> io::Result<Self> {
        let value = NEXT_FLOW
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| io::Error::other("DNS native flow identity exhausted"))?;
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| io::Error::other("invalid native flow identity"))
    }
}

/// Finite per-read admission bounds, checked before starting the native read.
#[derive(Clone, Copy, Debug)]
pub struct ReadLimits {
    /// Maximum copied datagrams in a single completion, between 1 and 1024.
    pub datagrams: usize,
    /// Maximum bytes in one DNS datagram, at most 65519.
    pub datagram_bytes: usize,
    /// Maximum total retained DNS byte-buffer capacity in the completion.
    pub batch_bytes: usize,
}
impl ReadLimits {
    pub(super) fn validate(self) -> io::Result<Self> {
        if self.datagrams == 0
            || self.datagram_bytes == 0
            || self.datagram_bytes > MAX_DATAGRAM_BYTES
            || self.batch_bytes < self.datagram_bytes
            || self.datagrams > 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid native DNS read bounds",
            ));
        }
        Ok(self)
    }
}

/// One native reply capability, retained beside its original flow identity.
/// It cannot be cloned or constructed from address/port observations.
pub struct ReplyEndpoint {
    pub(super) flow: FlowId,
    pub(super) endpoint: Endpoint,
}
impl ReplyEndpoint {
    /// Original owning flow; equal network tuples do not share this identity.
    pub const fn flow_id(&self) -> FlowId {
        self.flow
    }
}
impl fmt::Debug for ReplyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplyEndpoint")
            .field("flow", &self.flow)
            .finish_non_exhaustive()
    }
}

/// Copied DNS bytes and the matching original endpoint from one native read.
pub struct Datagram {
    bytes: Zeroizing<Vec<u8>>,
    endpoint: ReplyEndpoint,
}
impl Datagram {
    pub(super) fn reply(bytes: Zeroizing<Vec<u8>>, endpoint: ReplyEndpoint) -> Self {
        Self { bytes, endpoint }
    }
    /// Borrow the exact DNS datagram without an IP or helper envelope.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Original flow identity without consuming its reply authority.
    pub const fn flow_id(&self) -> FlowId {
        self.endpoint.flow
    }
    /// Transfer the allocation and native reply authority together.
    /// The caller assumes responsibility for wiping the returned DNS allocation.
    pub fn into_parts(mut self) -> (Vec<u8>, ReplyEndpoint) {
        (std::mem::take(&mut *self.bytes), self.endpoint)
    }
}
impl fmt::Debug for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Datagram")
            .field("bytes", &self.bytes.len())
            .field("flow", &self.flow_id())
            .finish()
    }
}

/// One payload and the route actually observed by the original native read.
#[derive(Debug)]
pub enum ReadDatagram {
    /// An ordinary DNS datagram with a usable reply source.
    Unicast(Datagram),
    /// A group destination that requires a native relay and an actual reply sender.
    Multicast(MulticastRequest),
}

/// A read completion or the end of this original flow's datagrams.
#[derive(Debug)]
pub enum Read {
    /// No more datagrams can be read from this original flow.
    End,
    /// Bounded accepted data plus explicit refusals from the same SDK batch.
    Datagrams(ReadBatch),
}
/// Accepted native data and observable batch-capacity or endpoint refusals.
#[derive(Debug)]
pub struct ReadBatch {
    datagrams: Vec<ReadDatagram>,
    refused: usize,
    first_refusal: Option<io::Error>,
}
impl ReadBatch {
    /// Transfer accepted datagrams, refused count and first original cause.
    pub fn into_parts(self) -> (Vec<ReadDatagram>, usize, Option<io::Error>) {
        (self.datagrams, self.refused, self.first_refusal)
    }
}

pub(super) struct Reservation {
    datagrams: Vec<ReadDatagram>,
    limits: ReadLimits,
    destinations: Destinations,
}

#[derive(Clone, Copy)]
pub(super) enum Destinations {
    Unicast,
    UnicastAndMulticast,
}

impl Reservation {
    pub(super) fn new(limits: ReadLimits, destinations: Destinations) -> io::Result<Self> {
        let limits = limits.validate()?;
        let mut datagrams = Vec::new();
        datagrams
            .try_reserve_exact(limits.datagrams)
            .map_err(|_| io::Error::other("native DNS batch reservation refused"))?;
        Ok(Self {
            datagrams,
            limits,
            destinations,
        })
    }
    pub(super) fn complete(
        self,
        flow: FlowId,
        local: Option<&Endpoint>,
        data: *mut NSArray<NSData>,
        endpoints: *mut NSArray<AnyObject>,
        error: *mut NSError,
    ) -> io::Result<Read> {
        sdk::error_result(error)?;
        sdk::with_arrays(data, endpoints, |data, endpoints| {
            self.copy_batch(flow, local, data, endpoints)
        })
    }
    fn copy_batch(
        mut self,
        flow: FlowId,
        local: Option<&Endpoint>,
        data: &NSArray<NSData>,
        endpoints: &NSArray<AnyObject>,
    ) -> io::Result<Read> {
        let count = data.count();
        if count != endpoints.count() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native DNS datagram/endpoint counts differ",
            ));
        }
        if count == 0 {
            return Ok(Read::End);
        }
        let mut bytes = 0usize;
        let mut refused = 0usize;
        let mut first_refusal = None;
        for index in 0..count.min(self.limits.datagrams) {
            let item = data.objectAtIndex(index);
            let endpoint = endpoints.objectAtIndex(index);
            let admitted = self.admit(flow, local, &item, endpoint, &mut bytes);
            match admitted {
                Ok(datagram) => self.datagrams.push(datagram),
                Err(error) => {
                    refused += 1;
                    first_refusal.get_or_insert(error);
                }
            }
        }
        if count > self.limits.datagrams {
            refused += count - self.limits.datagrams;
            first_refusal.get_or_insert_with(|| {
                io::Error::other("native DNS batch datagram bound exceeded")
            });
        }
        Ok(Read::Datagrams(ReadBatch {
            datagrams: self.datagrams,
            refused,
            first_refusal,
        }))
    }
    fn admit(
        &self,
        flow: FlowId,
        local: Option<&Endpoint>,
        data: &NSData,
        endpoint: Retained<AnyObject>,
        bytes: &mut usize,
    ) -> io::Result<ReadDatagram> {
        let length = data.length();
        if length > self.limits.datagram_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native DNS datagram exceeds admission bound",
            ));
        }
        let endpoint = Endpoint::from_retained(endpoint)?;
        let group = matches!(self.destinations, Destinations::UnicastAndMulticast)
            && multicast::is_multicast_destination(&endpoint)?;
        if !group {
            endpoint.qualify_flow_peer(sdk::EndpointRole::UdpReply, local)?;
        }
        let available = self
            .limits
            .batch_bytes
            .checked_sub(*bytes)
            .ok_or_else(|| io::Error::other("native DNS batch accounting overflow"))?;
        if length > available {
            return Err(io::Error::other("native DNS batch byte bound exceeded"));
        }
        let mut output = Zeroizing::new(Vec::new());
        output
            .try_reserve_exact(length)
            .map_err(|_| io::Error::other("native DNS datagram allocation refused"))?;
        if output.capacity() > available {
            return Err(io::Error::other(
                "native DNS allocation capacity exceeds bound",
            ));
        }
        *bytes += output.capacity();
        sdk::copy_data(data, &mut output);
        if group {
            Ok(ReadDatagram::Multicast(MulticastRequest {
                flow,
                group: endpoint,
                bytes: output,
                reply_limit: self.limits.datagram_bytes,
                received_at: std::time::Instant::now(),
            }))
        } else {
            Ok(ReadDatagram::Unicast(Datagram::reply(
                output,
                ReplyEndpoint { flow, endpoint },
            )))
        }
    }
}
