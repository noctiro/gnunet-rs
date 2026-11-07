//! quic- address profile: naked32-byte initiator peer proposal followed by
//! existing GNUnet frames on bidirectional stream4. This is not HTTP/3.
use crate::{ClaimedPeer, Epoch, Instance, Role, Scope, frame};
use gnunet_types::{Error, MonoInstant};
/// Canonical original producer's application stream.
pub const STREAM_ID: u64 = 4;
/// Exact ALPN values advertised by the pinned quiche producer. Names are
/// historical; application bytes contain no HTTP/0.9 request line.
pub const ALPNS: [&[u8]; 5] = [b"hq-interop", b"hq-29", b"hq-28", b"hq-27", b"http/0.9"];
/// Canonical TLS ALPN wire vector from the pinned public producer.
pub const ALPN_VECTOR: &[u8] = b"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9";
/// Address prefix, independent of raw UDP or other communicator profiles.
pub const ADDRESS_PREFIX: &str = "quic";
/// Original C advertised communicator queue MTU (not UDP datagram MTU).
pub const ADVERTISED_MTU: usize = 1000;
/// Result after preserving the caller's exact unconsumed suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    /// Exact original stream bytes consumed this call.
    pub consumed: usize,
    /// One newly completed peer proposal; no authentication implied.
    pub claim: Option<ClaimedPeer>,
    /// One complete application frame is held for its actual consumer.
    pub frame: bool,
}
/// Explicit original role/local public identity/source bounds.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Original local public PILS identity, never a secret.
    pub local: [u8; 32],
    /// Original initiator or acceptor intent.
    pub role: Role,
    /// Fixed source deadline, not renewed per stream.
    pub until: MonoInstant,
    /// Caller frame and scratch budget.
    pub max_frame: usize,
}
/// One caller-buffer bounded raw profile connection, without a QUIC engine.
/// Initiator is known from original dial intent; acceptor learns the raw claim.
pub struct Connection<'id, 'buf> {
    scope: Scope<'id>,
    role: Role,
    peer: Option<ClaimedPeer>,
    local: [u8; 32],
    identity_accepted: usize,
    claim: [u8; 32],
    claim_used: usize,
    decoder: frame::Decoder<'buf>,
    fin: bool,
}
impl<'id, 'buf> Connection<'id, 'buf> {
    /// Validate the actually negotiated ALPN and bind the original role and
    /// finite source deadline. This does not validate a TLS certificate or PID.
    pub fn new(
        instance: &'id Instance,
        alpn: &[u8],
        now: MonoInstant,
        buffer: &'buf mut [u8],
        options: Options,
    ) -> Result<Self, Error> {
        Self::new_in(instance, alpn, now, &mut Some(buffer), options)
    }
    /// Recoverable caller-loan admission. Original Option, ALPN, buffer bounds
    /// and finite source deadline are checked before source allocation. Only
    /// the last successful step takes storage; no later assembly can fail.
    pub fn new_in(
        instance: &'id Instance,
        alpn: &[u8],
        now: MonoInstant,
        loan: &mut Option<&'buf mut [u8]>,
        options: Options,
    ) -> Result<Self, Error> {
        let Options {
            role,
            local,
            until,
            max_frame,
        } = options;
        let bytes = loan.as_ref().ok_or(Error::InvalidInput)?.len();
        if !ALPNS.contains(&alpn) {
            return Err(Error::Unsupported);
        }
        frame::Decoder::validate(bytes, max_frame)?;
        let scope = Scope::new(instance, until, now)?;
        let peer = match role {
            Role::Initiator { expected } => Some(ClaimedPeer(expected)),
            Role::Acceptor => None,
        };
        match loan.take() {
            Some(buffer) => Ok(Self {
                scope,
                role,
                peer,
                local,
                identity_accepted: 0,
                claim: [0; 32],
                claim_used: 0,
                decoder: frame::Decoder::validated(buffer, max_frame),
                fin: false,
            }),
            None => Err(Error::InvalidInput),
        }
    }
    /// Exact original local connection source.
    pub const fn epoch(&self) -> Epoch<'id> {
        self.scope.epoch
    }
    /// Remaining original raw32 peer proposal for the initiator. Only actual
    /// QUIC plaintext admission may advance identity_accepted; no stream FIN.
    pub fn identity_suffix(&self, now: MonoInstant) -> Result<&[u8], Error> {
        if self.fin {
            return Err(Error::Closed);
        }
        self.scope.live(now)?;
        if self.role == Role::Acceptor {
            return Err(Error::Unsupported);
        }
        Ok(&self.local[self.identity_accepted..])
    }
    /// Record an actual partial provider admission of the original proposal.
    /// Full acceptance grants local protocol ordering, never peer authentication.
    /// FIN does not erase a late real provider-acceptance receipt. New send
    /// authorization separately fails Closed through may_send/identity_suffix.
    pub fn identity_accepted(&mut self, count: usize) -> Result<bool, Error> {
        if self.scope.closed {
            return Err(Error::Closed);
        }
        if self.role == Role::Acceptor || count == 0 {
            return Err(Error::InvalidInput);
        }
        let next = self
            .identity_accepted
            .checked_add(count)
            .ok_or(Error::Overflow)?;
        if next > 32 {
            return Err(Error::InvalidInput);
        }
        self.identity_accepted = next;
        Ok(next == 32)
    }
    /// Original requested or received public peer metadata. A mature runtime
    /// must separately enforce all actual TLS/channel and communicator policy.
    pub const fn peer(&self) -> Option<ClaimedPeer> {
        self.peer
    }
    /// Local profile ordering for queue admission, not physical QueueSetup ACK.
    pub fn may_send(&self, now: MonoInstant) -> Result<bool, Error> {
        if self.fin {
            return Err(Error::Closed);
        }
        self.scope.live(now)?;
        Ok(self.peer.is_some() && (self.role == Role::Acceptor || self.identity_accepted == 32))
    }
    /// Incremental original stream bytes. Partial32-byte identity, split GNUnet
    /// headers/bodies and concatenated reads all preserve the original cursor.
    pub fn push(&mut self, stream: u64, input: &[u8], now: MonoInstant) -> Result<Progress, Error> {
        self.scope.live(now)?;
        if stream != STREAM_ID {
            return Err(Error::Unsupported);
        }
        if self.fin {
            return Err(Error::Closed);
        }
        let mut consumed = 0;
        let mut claim = None;
        if self.peer.is_none() {
            let count = (32 - self.claim_used).min(input.len());
            self.claim[self.claim_used..self.claim_used + count].copy_from_slice(&input[..count]);
            self.claim_used += count;
            consumed += count;
            if self.claim_used == 32 {
                let peer = ClaimedPeer(self.claim);
                self.peer = Some(peer);
                claim = Some(peer);
            }
            // Return the new claim before processing its same-read frame suffix,
            // so downstream can actually admit its source/queue first.
            return Ok(Progress {
                consumed,
                claim,
                frame: false,
            });
        }
        let step = self.decoder.push(input)?;
        consumed += step.consumed;
        Ok(Progress {
            consumed,
            claim,
            frame: step.ready,
        })
    }
    /// One exact held GNUnet frame; release only after actual consumer admission.
    pub fn frame(&self, now: MonoInstant) -> Result<&[u8], Error> {
        self.scope.live(now)?;
        self.decoder.frame()
    }
    /// Reclaim only the original held frame; returned size is not wire FC/ACK.
    pub fn release_frame(&mut self) -> Result<usize, Error> {
        self.decoder.release()
    }
    /// Actual FIN of canonical stream4. C closes the whole connection on FIN;
    /// caller must enact that lifecycle. Truncated proposals/frames fail.
    pub fn finish(&mut self, stream: u64) -> Result<(), Error> {
        if stream != STREAM_ID {
            return Err(Error::Unsupported);
        }
        if self.peer.is_none() {
            return Err(Error::Truncated);
        }
        self.decoder.finish()?;
        self.fin = true;
        Ok(())
    }
    /// Actual original stream ended; a held final frame is still caller-owned.
    pub const fn finished(&self) -> bool {
        self.fin
    }
    /// Consume this local profile authorization and return its wiped complete
    /// caller loan. Host may recycle only after actual original connection,
    /// driver and IO debts retire; this method fabricates none of those facts.
    pub fn recycle(mut self) -> &'buf mut [u8] {
        self.scope.closed = true;
        self.decoder.recycle()
    }
    /// Clock-free source retirement. No physical QUIC close is claimed here.
    pub fn retire(&mut self) {
        self.scope.closed = true;
        self.decoder.clear();
        self.claim.fill(0);
    }
}
