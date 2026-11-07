//! Actual caller-owned DV fixed slots and shared zeroizing byte loans. No
//! Source, nonce, key, signature, Provider, worker or IO is constructed here.
//! Source/Instance owners must live OUTSIDE and longer than these slot types.
use gnunet_transport::dv::{
    self,
    routes::{ProbeSlot, RouteSlot, SourceSlot},
};
use gnunet_transport_dv_crypto::{
    cache::{ReceiveSlot, SendSlot},
    replay::{NonceSlot, PeerSlot},
};
use gnunet_transport_dv_runtime_host::Storage;
use gnunet_types::Error;
use std::{fmt, mem::size_of};
use zeroize::Zeroizing;

/// Absolute helper-only reported-capacity ceiling, independent of a caller's
/// lower configured pool budget. Excludes separately bounded Runtime/PILS/IO.
pub const MAX_POOL_BYTES: usize = 64 * 1024 * 1024;
/// Absolute total fixed-slot count bound, independently of struct layout.
pub const MAX_METADATA_ROWS: usize = 350_000;
/// Maximum shared plaintext loan count, unrelated to the number of peers.
pub const MAX_PLAINTEXT_BUFFERS: usize = 64;

/// Explicit finite allocation policy. Payload buffers are shared by all peers;
/// no peer/channel receives a preallocated maximum-payload vector of its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Empty route rows, at most8192.
    pub routes: usize,
    /// Empty original probe rows, at most1024.
    pub probes: usize,
    /// Empty source watermark rows, at most16384.
    pub sources: usize,
    /// Empty reusable sender-material slots, at most1024.
    pub send_materials: usize,
    /// Empty reusable recipient-material slots, at most1024.
    pub receive_materials: usize,
    /// Empty live replay peer rows, at most16384.
    pub replay_peers: usize,
    /// Empty exact live replay nonce rows, at most262144.
    pub replay_nonces: usize,
    /// Shared plaintext loans, nonzero/at most64; default4.
    pub plaintext_buffers: usize,
    /// Complete official DV frame ceiling,194..=65535. Scratch uses this size;
    /// each plaintext loan uses frame_bytes-BOX_PREFIX-PAYLOAD_PREFIX.
    pub frame_bytes: usize,
    /// Aggregate reported-capacity admission budget including inline pool
    /// metadata and the original loan-handle vector; at most64MiB.
    pub max_total_bytes: usize,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            routes: 192,
            probes: 8,
            sources: 64,
            send_materials: 16,
            receive_materials: 16,
            replay_peers: 128,
            replay_nonces: 4096,
            plaintext_buffers: 4,
            frame_bytes: 65535,
            max_total_bytes: 8 * 1024 * 1024,
        }
    }
}
/// One independently accounted memory class. Reported capacity is actual
/// Vec::capacity()*element_size, not an invented RSS/allocator overhead measure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Initialized logical content requested by the policy.
    pub requested: usize,
    /// Actual Rust-reported element capacity reserved for this class.
    pub reserved: usize,
}
/// Architecture-specific capacity snapshot at construction or successful loan
/// creation. It is not automatically updated when a moved handle Vec drops.
/// This intentionally excludes
/// allocator bookkeeping/rounding not exposed by Vec, transient stack locals,
/// runtime-owned packet queues/metadata, PILS and the actual persistent Provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    /// Fixed route/cache/replay element arrays and plaintext-vector headers.
    pub metadata: Usage,
    /// Whole shared zeroizing plaintext byte allocations.
    pub plaintext: Usage,
    /// One shared zeroizing AEAD/signature work allocation.
    pub scratch: Usage,
    /// Original Vec of borrowed fat-slice handles moved into Storage/Runtime;
    /// reserved is zero before lending and its actual capacity afterwards.
    pub loan_handles: Usage,
    /// Inline Pools struct bytes, including Vec headers/policy/this observation.
    pub inline_bytes: usize,
    /// Sum of requested classes plus inline bytes, checked for overflow.
    pub requested_bytes: usize,
    /// Sum of actual reported class capacities plus inline bytes.
    pub reserved_bytes: usize,
    /// Admission charge also includes the loan-vector allowance before storage
    /// is lent: inline+all reserved except max(requested,reserved) for handles.
    pub charged_bytes: usize,
    /// Observed live allocation count at this snapshot, including loan handles
    /// at successful lending. This is no allocator bookkeeping byte estimate.
    pub allocations: usize,
    /// Whether the one original Storage loan has actually been issued.
    pub lent: bool,
}
struct Layout {
    metadata: usize,
    plaintext: usize,
    scratch: usize,
    handles: usize,
    inline: usize,
    total: usize,
    inner: usize,
}
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Overflow)
}
fn bytes<T>(n: usize) -> Result<usize, Error> {
    mul(n, size_of::<T>())
}
fn sum(values: &[usize]) -> Result<usize, Error> {
    values.iter().try_fold(0, |n, v| add(n, *v))
}
impl Policy {
    fn layout(self) -> Result<Layout, Error> {
        let counts = [
            self.routes,
            self.probes,
            self.sources,
            self.send_materials,
            self.receive_materials,
            self.replay_peers,
            self.replay_nonces,
        ];
        if counts.contains(&0)
            || self.routes > 8192
            || self.probes > 1024
            || self.sources > 16384
            || self.send_materials > 1024
            || self.receive_materials > 1024
            || self.replay_peers > 16384
            || self.replay_nonces > 262144
            || self.plaintext_buffers == 0
            || self.plaintext_buffers > MAX_PLAINTEXT_BUFFERS
            || self.frame_bytes < dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + 4
            || self.frame_bytes > u16::MAX as usize
            || self.max_total_bytes == 0
            || self.max_total_bytes > MAX_POOL_BYTES
        {
            return Err(Error::InvalidInput);
        }
        if sum(&counts)? > MAX_METADATA_ROWS {
            return Err(Error::Capacity);
        }
        // Lifetimes affect borrow checking, not layout; no 'static value, source
        // reference or secret is created by these size_of type expressions.
        let metadata = sum(&[
            bytes::<RouteSlot>(self.routes)?,
            bytes::<ProbeSlot>(self.probes)?,
            bytes::<SourceSlot>(self.sources)?,
            bytes::<SendSlot<'static, 'static>>(self.send_materials)?,
            bytes::<ReceiveSlot<'static, 'static>>(self.receive_materials)?,
            bytes::<PeerSlot<'static>>(self.replay_peers)?,
            bytes::<NonceSlot<'static>>(self.replay_nonces)?,
            bytes::<Zeroizing<Vec<u8>>>(self.plaintext_buffers)?,
        ])?;
        let inner = self
            .frame_bytes
            .checked_sub(dv::BOX_PREFIX + dv::PAYLOAD_PREFIX)
            .ok_or(Error::InvalidInput)?;
        let plaintext = mul(inner, self.plaintext_buffers)?;
        let scratch = self.frame_bytes;
        let handles = bytes::<&mut [u8]>(self.plaintext_buffers)?;
        let inline = size_of::<Pools<'static, 'static>>();
        let total = sum(&[metadata, plaintext, scratch, handles, inline])?;
        if total > self.max_total_bytes {
            return Err(Error::Capacity);
        }
        Ok(Layout {
            metadata,
            plaintext,
            scratch,
            handles,
            inline,
            total,
            inner,
        })
    }
    /// Validate all counts, products and the aggregate BEFORE any allocation.
    /// Returned bytes are a request/charge estimate, not measured live memory.
    pub fn requested_bytes(self) -> Result<usize, Error> {
        Ok(self.layout()?.total)
    }
    /// Actual fixed capacity of each shared inner-message loan; not per peer.
    pub fn plaintext_bytes(self) -> Result<usize, Error> {
        Ok(self.layout()?.inner)
    }
}
fn slots<T>(count: usize, make: impl FnMut() -> T) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
    out.resize_with(count, make);
    Ok(out)
}
fn buffer(count: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
    out.resize(count, 0);
    Ok(out)
}
/// Caller-owned allocations. `'source`/`'id` refer ONLY to external Source and
/// Instance owners eventually borrowed by real material/replay slots. There is
/// no reference to self and no internal Source/Instance constructor.
/// Storage is issued once; recreating an epoch never silently clears old replay
/// or source state or claims an old native/worker obligation has terminated.
#[must_use = "lend in an outer session scope; drop actual Runtime/loans only after real cleanup"]
pub struct Pools<'source, 'id> {
    policy: Policy,
    routes: Vec<RouteSlot>,
    probes: Vec<ProbeSlot>,
    sources: Vec<SourceSlot>,
    send: Vec<SendSlot<'source, 'id>>,
    receive: Vec<ReceiveSlot<'source, 'id>>,
    replay_peers: Vec<PeerSlot<'id>>,
    replay_nonces: Vec<NonceSlot<'id>>,
    plaintext: Vec<Zeroizing<Vec<u8>>>,
    scratch: Zeroizing<Vec<u8>>,
    observed: Observation,
    lent: bool,
}
impl fmt::Debug for Pools<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DvPools")
            .field("policy", &self.policy)
            .field("memory", &self.observed)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
impl<'source, 'id> Pools<'source, 'id> {
    /// Fallibly allocate only bounded metadata and shared zeroizing buffers.
    /// No key/nonce/source/crypto, worker, timer, entropy or IO is invoked.
    pub fn new(policy: Policy) -> Result<Self, Error> {
        let layout = policy.layout()?;
        let routes = slots(policy.routes, RouteSlot::empty)?;
        let probes = slots(policy.probes, ProbeSlot::empty)?;
        let sources = slots(policy.sources, SourceSlot::empty)?;
        let send = slots(policy.send_materials, SendSlot::new)?;
        let receive = slots(policy.receive_materials, ReceiveSlot::new)?;
        let replay_peers = slots(policy.replay_peers, PeerSlot::new)?;
        let replay_nonces = slots(policy.replay_nonces, NonceSlot::new)?;
        let mut plaintext = Vec::new();
        plaintext
            .try_reserve_exact(policy.plaintext_buffers)
            .map_err(|_| Error::Capacity)?;
        for _ in 0..policy.plaintext_buffers {
            plaintext.push(buffer(layout.inner)?);
        }
        let scratch = buffer(policy.frame_bytes)?;
        let metadata_reserved = sum(&[
            bytes::<RouteSlot>(routes.capacity())?,
            bytes::<ProbeSlot>(probes.capacity())?,
            bytes::<SourceSlot>(sources.capacity())?,
            bytes::<SendSlot<'source, 'id>>(send.capacity())?,
            bytes::<ReceiveSlot<'source, 'id>>(receive.capacity())?,
            bytes::<PeerSlot<'id>>(replay_peers.capacity())?,
            bytes::<NonceSlot<'id>>(replay_nonces.capacity())?,
            bytes::<Zeroizing<Vec<u8>>>(plaintext.capacity())?,
        ])?;
        let plaintext_reserved = plaintext.iter().try_fold(0, |n, b| add(n, b.capacity()))?;
        let reserved = sum(&[
            layout.inline,
            metadata_reserved,
            plaintext_reserved,
            scratch.capacity(),
        ])?;
        let charged = add(reserved, layout.handles)?;
        if charged > policy.max_total_bytes {
            return Err(Error::Capacity);
        }
        let allocations = add(policy.plaintext_buffers, 9)?; // 7 slot Vecs + buffer-header Vec + scratch
        let observed = Observation {
            metadata: Usage {
                requested: layout.metadata,
                reserved: metadata_reserved,
            },
            plaintext: Usage {
                requested: layout.plaintext,
                reserved: plaintext_reserved,
            },
            scratch: Usage {
                requested: layout.scratch,
                reserved: scratch.capacity(),
            },
            loan_handles: Usage {
                requested: layout.handles,
                reserved: 0,
            },
            inline_bytes: layout.inline,
            requested_bytes: layout.total,
            reserved_bytes: reserved,
            charged_bytes: charged,
            allocations,
            lent: false,
        };
        Ok(Self {
            policy,
            routes,
            probes,
            sources,
            send,
            receive,
            replay_peers,
            replay_nonces,
            plaintext,
            scratch,
            observed,
            lent: false,
        })
    }
    /// Explicit immutable policy; no stored source/key value is exposed.
    pub const fn policy(&self) -> Policy {
        self.policy
    }
    /// Last construction/lending capacity snapshot; no private slot/payload
    /// data is exposed. After Runtime/handle drop this remains historical, not
    /// a new live-allocation measurement. storage_observed returns it directly.
    pub const fn observation(&self) -> Observation {
        self.observed
    }
    /// Lend all actual empty caller fields directly to the real Runtime.
    /// The returned lifetime borrows self; Runtime/proof loans must end before
    /// these allocations can move/drop. No buffer body is moved into self-ref.
    pub fn storage(&mut self) -> Result<Storage<'_, 'source, 'id, '_>, Error> {
        self.storage_observed().map(|(storage, _)| storage)
    }
    /// Same actual storage plus a Copy capacity observation available while the
    /// Runtime holds its exclusive borrow. All fallible checks/handle reserve
    /// happen BEFORE any caller-slice loan is issued.
    pub fn storage_observed(
        &mut self,
    ) -> Result<(Storage<'_, 'source, 'id, '_>, Observation), Error> {
        if self.lent {
            return Err(Error::Conflict);
        }
        let mut loans = Vec::new();
        loans
            .try_reserve_exact(self.plaintext.len())
            .map_err(|_| Error::Capacity)?;
        let handles = bytes::<&mut [u8]>(loans.capacity())?;
        let base = self.observed.reserved_bytes;
        let reserved = add(base, handles)?;
        let charged = add(base, self.observed.loan_handles.requested.max(handles))?;
        if charged > self.policy.max_total_bytes {
            return Err(Error::Capacity);
        }
        let mut observed = self.observed;
        observed.loan_handles.reserved = handles;
        observed.reserved_bytes = reserved;
        observed.charged_bytes = charged;
        observed.allocations = add(observed.allocations, 1)?;
        observed.lent = true;
        self.observed = observed;
        self.lent = true;
        for body in &mut self.plaintext {
            loans.push(body.as_mut_slice());
        }
        Ok((
            Storage {
                routes: self.routes.as_mut_slice(),
                probes: self.probes.as_mut_slice(),
                sources: self.sources.as_mut_slice(),
                send: self.send.as_mut_slice(),
                receive: self.receive.as_mut_slice(),
                replay_peers: self.replay_peers.as_mut_slice(),
                replay_nonces: self.replay_nonces.as_mut_slice(),
                plaintext: loans,
                scratch: self.scratch.as_mut_slice(),
            },
            observed,
        ))
    }
}
