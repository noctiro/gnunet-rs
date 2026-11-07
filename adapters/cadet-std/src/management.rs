//! Bounded official CADET management snapshots and original MQ/query effects.
//! A snapshot provider supplies real directory facts; no missing-provider END,
//! private query RID, application credit or channel payload is synthesized.
use gnunet_cadet::service::Client;
use gnunet_types::Error;
use gnunet_wire::official::{
    MessageHeader,
    cadet::{PeerIdentities, Request, Response},
};
use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
};

/// Official independent-MQ operation. GetChannel is deliberately unsupported:
/// the pinned official service registers no producer/handler for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// All actually known peers, terminated by PeersEnd.
    Peers,
    /// All actually allocated tunnels, terminated by TunnelsEnd.
    Tunnels,
    /// Known indirect paths to the requested peer, terminated by PathsEnd.
    Paths([u8; 32]),
}
impl Kind {
    pub(crate) fn request(request: Request<'_>) -> Option<Self> {
        match request {
            Request::ListPeers => Some(Self::Peers),
            Request::ListTunnels => Some(Self::Tunnels),
            Request::GetPath { peer } => Some(Self::Paths(peer)),
            _ => None,
        }
    }
    fn end(self) -> Response<'static> {
        match self {
            Self::Peers => Response::PeersEnd,
            Self::Tunnels => Response::TunnelsEnd,
            Self::Paths(_) => Response::PathsEnd,
        }
    }
}
pub(crate) fn decode_query(bytes: &[u8]) -> Result<Option<Kind>, Error> {
    use gnunet_wire::official::message_type as mt;
    let header = MessageHeader::decode(bytes)?;
    if matches!(
        header.message_type(),
        mt::CADET_LOCAL_REQUEST_INFO_PEERS
            | mt::CADET_LOCAL_REQUEST_INFO_TUNNELS
            | mt::CADET_LOCAL_REQUEST_INFO_PATH
    ) {
        return Ok(Kind::request(Request::decode(bytes)?));
    }
    Ok(None)
}
/// Explicit whole-query and directory bounds. Temporary directory storage is
/// bounded by records/path_identities; frozen wire storage by snapshot_bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum classified management MQs, each with at most one active query.
    pub queries: usize,
    /// Maximum regular directory rows and emitted response entries, including END.
    pub records: usize,
    /// Total peer identities retained across distinct oriented paths.
    pub path_identities: usize,
    /// Maximum complete frozen official response bytes for one query.
    pub snapshot_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            queries: 4,
            records: 4096,
            path_identities: 8192,
            snapshot_bytes: 262_144,
        }
    }
}
impl Limits {
    /// Validate only actual finite local bounds; this grants no snapshot.
    pub fn validate(self) -> Result<(), Error> {
        if self.queries == 0
            || !(1..=65535).contains(&self.records)
            || self.path_identities == 0
            || self.snapshot_bytes < 4
        {
            return Err(Error::InvalidInput);
        }
        self.path_identities
            .checked_mul(32)
            .ok_or(Error::Overflow)?;
        Ok(())
    }
}
#[derive(Clone, Copy)]
struct Peer {
    id: [u8; 32],
    tunnel: bool,
    channels: u32,
    connections: u32,
    encryption: u16,
    paths: u16,
    last_counted_path: u16,
}
#[derive(Clone, Copy)]
struct Path {
    start: usize,
    length: usize,
    same_hash: Option<usize>,
}
fn reserve<T>(values: &mut Vec<T>, additional: usize, limit: usize) -> Result<(), Error> {
    let needed = values
        .len()
        .checked_add(additional)
        .ok_or(Error::Overflow)?;
    if needed > limit {
        return Err(Error::Capacity);
    }
    if needed > values.capacity() {
        let target = values.capacity().saturating_mul(2).max(needed).min(limit);
        values
            .try_reserve_exact(target - values.len())
            .map_err(|_| Error::Capacity)?;
    }
    Ok(())
}
/// Explicit trusted provider's bounded public metadata directory. Native Node
/// builds it synchronously from its actual Book/Controllers/channel owners.
/// User-constructed facts are not themselves authentication or native evidence.
/// Record/identity limits also bound both indexes; all new-entry allocations are
/// fallible. Hashes are lookup accelerators, never identity/path equality proofs.
pub struct Directory {
    local: [u8; 32],
    limits: Limits,
    peers: Vec<Peer>,
    peer_index: HashMap<[u8; 32], usize>,
    paths: Vec<Path>,
    path_index: HashMap<u64, usize>,
    path_hash: RandomState,
    identities: Vec<[u8; 32]>,
}
impl Directory {
    /// Start one actual provider capture. No END is queued by construction.
    pub fn new(local: [u8; 32], limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self {
            local,
            limits,
            peers: Vec::new(),
            peer_index: HashMap::new(),
            paths: Vec::new(),
            path_index: HashMap::new(),
            path_hash: RandomState::new(),
            identities: Vec::new(),
        })
    }
    fn peer(&mut self, id: [u8; 32]) -> Result<usize, Error> {
        if id == self.local {
            return Err(Error::InvalidInput);
        }
        if let Some(index) = self.peer_index.get(&id) {
            return Ok(*index);
        }
        reserve(&mut self.peers, 1, self.limits.records)?;
        self.peer_index
            .try_reserve(1)
            .map_err(|_| Error::Capacity)?;
        let index = self.peers.len();
        self.peers.push(Peer {
            id,
            tunnel: false,
            channels: 0,
            connections: 0,
            encryption: 0,
            paths: 0,
            last_counted_path: u16::MAX,
        });
        let _previous = self.peer_index.insert(id, index);
        Ok(index)
    }
    /// Observe one actually known peer even if it currently has no path/tunnel.
    pub fn known_peer(&mut self, id: [u8; 32]) -> Result<(), Error> {
        self.peer(id).map(|_| ())
    }
    /// Add a real oriented path excluding the local peer. A direct neighbor is
    /// a one-identity path. Equal paths shared by several CIDs are deduplicated.
    pub fn path(&mut self, peers: &[[u8; 32]]) -> Result<(), Error> {
        if peers.is_empty() || peers.contains(&self.local) {
            return Err(Error::InvalidInput);
        }
        // Hashing selects only a collision chain. Equal original identity
        // sequences are still compared in full, so a collision never merges paths.
        let hash = self.path_hash.hash_one(peers);
        let first = self.path_index.get(&hash).copied();
        let mut candidate = first;
        while let Some(index) = candidate {
            let path = self.paths[index];
            if &self.identities[path.start..path.start + path.length] == peers {
                return Ok(());
            }
            candidate = path.same_hash;
        }
        reserve(&mut self.paths, 1, self.limits.records)?;
        reserve(
            &mut self.identities,
            peers.len(),
            self.limits.path_identities,
        )?;
        if first.is_none() {
            self.path_index
                .try_reserve(1)
                .map_err(|_| Error::Capacity)?;
        }
        // All fallible insertions precede path/count admission. A failed
        // capture can retain newly known peers, as before, but no phantom path.
        for id in peers {
            self.peer(*id)?;
        }
        let number = self.paths.len();
        // Existing path count is strictly below records <= u16::MAX, so the
        // sentinel can never identify an admitted path.
        let marker = u16::try_from(number).map_err(|_| Error::Overflow)?;
        for id in peers {
            let index = *self.peer_index.get(id).ok_or(Error::StaleGeneration)?;
            let peer = &mut self.peers[index];
            if peer.last_counted_path != marker {
                // number < records <= 65535; each peer counts a path once even
                // if an explicit custom provider repeats that identity in it.
                peer.paths += 1;
                peer.last_counted_path = marker;
            }
        }
        let start = self.identities.len();
        self.identities.extend_from_slice(peers);
        self.paths.push(Path {
            start,
            length: peers.len(),
            same_hash: first,
        });
        let _previous = self.path_index.insert(hash, number);
        Ok(())
    }
    /// Observe one actual non-retired endpoint connection to this peer.
    pub fn connection(&mut self, id: [u8; 32]) -> Result<(), Error> {
        let i = self.peer(id)?;
        self.peers[i].connections = self.peers[i]
            .connections
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        Ok(())
    }
    /// Observe one actual retained tunnel and its exact current channel count
    /// and official diagnostic encryption-state mapping. cstate stays the C
    /// producer's informational zero; no connected/delivery proof is implied.
    pub fn tunnel(
        &mut self,
        id: [u8; 32],
        channels: u32,
        encryption_state: u16,
    ) -> Result<(), Error> {
        let i = self.peer(id)?;
        let p = &mut self.peers[i];
        if p.tunnel {
            return Err(Error::Conflict);
        }
        p.tunnel = true;
        p.channels = channels;
        p.encryption = encryption_state;
        Ok(())
    }
    /// Freeze the complete actual capture into official record bytes plus its
    /// matching END. Failure returns no usable snapshot and emits no partial END.
    pub fn snapshot(mut self, kind: Kind) -> Result<Snapshot, Error> {
        // Admission indexes are no longer needed, so they do not overlap the
        // growing frozen wire snapshot. Only the consumed capture is sorted.
        drop(self.peer_index);
        drop(self.path_index);
        if matches!(kind, Kind::Peers | Kind::Tunnels) {
            self.peers.sort_unstable_by_key(|peer| peer.id);
        }
        let mut snapshot = Snapshot {
            kind,
            bytes: Vec::new(),
            entries: 0,
        };
        match kind {
            Kind::Peers => {
                for peer in &self.peers {
                    snapshot.append(
                        Response::PeerInfo {
                            paths: peer.paths,
                            tunnel: if peer.tunnel { 1 } else { 0 },
                            best_path_length: 0,
                            peer: peer.id,
                        },
                        self.limits,
                    )?;
                }
            }
            Kind::Tunnels => {
                for peer in self.peers.iter().filter(|p| p.tunnel) {
                    snapshot.append(
                        Response::TunnelInfo {
                            channels: peer.channels,
                            peer: peer.id,
                            connections: peer.connections,
                            encryption_state: peer.encryption,
                            connection_state: 0,
                        },
                        self.limits,
                    )?;
                }
            }
            Kind::Paths(peer) => {
                for path in &self.paths {
                    let peers = &self.identities[path.start..path.start + path.length];
                    if let Some(offset) = peers.iter().position(|id| *id == peer)
                        && offset != 0
                    {
                        snapshot.append(
                            Response::PathInfo {
                                offset: u32::try_from(offset).map_err(|_| Error::Overflow)?,
                                peers: PeerIdentities::new(peers),
                            },
                            self.limits,
                        )?;
                    }
                }
            }
        }
        snapshot.append(kind.end(), self.limits)?;
        Ok(snapshot)
    }
}
/// Complete immutable owned wire snapshot. There is no raw constructor or
/// empty-success default. It is created only by a completed provider capture.
pub struct Snapshot {
    kind: Kind,
    bytes: Vec<u8>,
    entries: usize,
}
impl Snapshot {
    fn append(&mut self, response: Response<'_>, limits: Limits) -> Result<(), Error> {
        if self.entries >= limits.records {
            return Err(Error::Capacity);
        }
        let len = response.encoded_len()?;
        let old = self.bytes.len();
        let end = old.checked_add(len).ok_or(Error::Overflow)?;
        if end > limits.snapshot_bytes {
            return Err(Error::Capacity);
        }
        if end > self.bytes.capacity() {
            // Amortized growth stays inside the explicit frozen-byte budget;
            // large peer lists do not copy the whole prefix for every record.
            let target = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(end)
                .min(limits.snapshot_bytes);
            self.bytes
                .try_reserve_exact(target - old)
                .map_err(|_| Error::Capacity)?;
        }
        self.bytes.resize(end, 0);
        response.encode(&mut self.bytes[old..end])?;
        self.entries += 1;
        Ok(())
    }
    /// Exact original query kind represented by these complete bytes.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    /// Number of frozen official frames, including the one matching END.
    #[must_use]
    pub const fn records(&self) -> usize {
        self.entries
    }
    /// Total explicitly bounded captured wire bytes.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes.len()
    }
    fn frame(&self, cursor: usize) -> Result<&[u8], Error> {
        let remaining = self.bytes.get(cursor..).ok_or(Error::StaleGeneration)?;
        let len = MessageHeader::decode(remaining)?.size();
        remaining.get(..len).ok_or(Error::Truncated)
    }
}
/// One actual original accepted-MQ query. No public constructor and no wire RID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Query<'id> {
    client: Client<'id>,
    serial: u64,
    kind: Kind,
}
impl<'id> Query<'id> {
    pub(crate) const fn new(client: Client<'id>, serial: u64, kind: Kind) -> Self {
        Self {
            client,
            serial,
            kind,
        }
    }
    /// Original actual accepted MQ generation.
    #[must_use]
    pub const fn client(self) -> Client<'id> {
        self.client
    }
    /// Local diagnostic operation serial, never encoded in a request/response.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
    /// Actual original decoded official query kind.
    #[must_use]
    pub const fn kind(self) -> Kind {
        self.kind
    }
}
/// One original immutable response frame, minted only by its actual query stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output<'id> {
    query: Query<'id>,
    cursor: usize,
    length: usize,
    last: bool,
}
impl<'id> Output<'id> {
    /// Original query and actual MQ provenance.
    #[must_use]
    pub const fn query(self) -> Query<'id> {
        self.query
    }
    /// Whether this exact response is the matching END.
    #[must_use]
    pub const fn is_end(self) -> bool {
        self.last
    }
}
/// Actual original local output classification; END written is not a claim
/// that the remote inspector consumed it or performed application work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// Actual operation still owns work.
    Pending,
    /// Its actual matching END completed local writing.
    EndWritten,
    /// Physical stop occurred before matching END completed writing.
    Interrupted,
}
/// Immutable actual partial progress of an original query, including loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report<'id> {
    /// Exact original accepted-MQ query.
    pub query: Query<'id>,
    /// A real completed provider snapshot was bound to the query.
    pub snapshot: bool,
    /// Original nonterminal frames fully written locally.
    pub entries: u64,
    /// Actual positive native response bytes across partial/full writes.
    pub written_bytes: u64,
    /// Exact current original output, if any.
    pub pending: Option<Output<'id>>,
    /// Actual positive exposure of that pending original frame.
    pub exposed: bool,
    /// Actual local terminal state, never inferred from queue admission/EOF.
    pub terminal: Terminal,
}
/// Synchronous observations after committed original management effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'id> {
    /// Actual query accepted; no snapshot or END was fabricated.
    Requested(Query<'id>),
    /// Original immutable record retained for actual output.
    Queued(Output<'id>),
    /// Actual positive write on this original frame, with committed report.
    Write {
        /// Exact original immutable record.
        output: Output<'id>,
        /// Positive bytes written by the actual syscall.
        bytes: usize,
        /// Actual complete-frame write fact.
        complete: bool,
        /// Committed exact-query progress.
        report: Report<'id>,
    },
    /// Original physical MQ stopped. Its matching Closed event retains the
    /// actual native cause; client/query identity joins these two observations.
    Stopped(Report<'id>),
}
pub(crate) struct Stream<'id> {
    query: Option<Query<'id>>,
    snapshot: Option<Snapshot>,
    cursor: usize,
    pending: Option<Output<'id>>,
    frame_written: usize,
    report: Option<Report<'id>>,
}
impl<'id> Stream<'id> {
    pub(crate) fn new() -> Self {
        Self {
            query: None,
            snapshot: None,
            cursor: 0,
            pending: None,
            frame_written: 0,
            report: None,
        }
    }
    pub(crate) fn active(&self) -> bool {
        self.query.is_some()
    }
    pub(crate) fn request(&mut self, query: Query<'id>) -> Result<(), Error> {
        if self.active() {
            return Err(Error::WouldBlock);
        }
        self.query = Some(query);
        self.snapshot = None;
        self.cursor = 0;
        self.pending = None;
        self.frame_written = 0;
        self.report = Some(Report {
            query,
            snapshot: false,
            entries: 0,
            written_bytes: 0,
            pending: None,
            exposed: false,
            terminal: Terminal::Pending,
        });
        Ok(())
    }
    pub(crate) fn awaiting(&self) -> Option<Query<'id>> {
        self.query.filter(|_| self.snapshot.is_none())
    }
    pub(crate) fn bind(&mut self, query: Query<'id>, snapshot: Snapshot) -> Result<(), Error> {
        if self.query != Some(query) || self.snapshot.is_some() || snapshot.kind() != query.kind {
            return Err(Error::StaleGeneration);
        }
        self.snapshot = Some(snapshot);
        if let Some(r) = self.report.as_mut() {
            r.snapshot = true;
        }
        Ok(())
    }
    pub(crate) fn next_len(&self) -> Result<Option<usize>, Error> {
        if self.pending.is_some() {
            return Ok(None);
        }
        let Some(snapshot) = &self.snapshot else {
            return Ok(None);
        };
        Ok(Some(snapshot.frame(self.cursor)?.len()))
    }
    pub(crate) fn prepare(&mut self, out: &mut [u8]) -> Result<Output<'id>, Error> {
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let query = self.query.ok_or(Error::NotReady)?;
        let snapshot = self.snapshot.as_ref().ok_or(Error::NotReady)?;
        let frame = snapshot.frame(self.cursor)?;
        let bytes = out.get_mut(..frame.len()).ok_or(Error::Capacity)?;
        bytes.copy_from_slice(frame);
        let output = Output {
            query,
            cursor: self.cursor,
            length: frame.len(),
            last: self.cursor + frame.len() == snapshot.bytes.len(),
        };
        self.pending = Some(output);
        self.frame_written = 0;
        if let Some(r) = self.report.as_mut() {
            r.pending = Some(output);
            r.exposed = false;
        }
        Ok(output)
    }
    pub(crate) fn written(
        &mut self,
        output: Output<'id>,
        bytes: usize,
        complete: bool,
    ) -> Result<Report<'id>, Error> {
        if self.pending != Some(output) || self.query != Some(output.query) || bytes == 0 {
            return Err(Error::StaleGeneration);
        }
        let total = self
            .frame_written
            .checked_add(bytes)
            .ok_or(Error::Overflow)?;
        if total > output.length || complete != (total == output.length) {
            return Err(Error::InvalidInput);
        }
        let r = self.report.as_mut().ok_or(Error::NotReady)?;
        r.written_bytes = r
            .written_bytes
            .checked_add(u64::try_from(bytes).map_err(|_| Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        r.exposed = true;
        self.frame_written = total;
        if complete {
            self.cursor = self
                .cursor
                .checked_add(output.length)
                .ok_or(Error::Overflow)?;
            self.pending = None;
            r.pending = None;
            r.exposed = false;
            if output.last {
                r.terminal = Terminal::EndWritten;
                self.query = None;
                self.snapshot = None;
            } else {
                r.entries = r.entries.checked_add(1).ok_or(Error::Overflow)?;
            }
        }
        Ok(*r)
    }
    pub(crate) fn report(&self) -> Option<Report<'id>> {
        self.report
    }
    pub(crate) fn stopped(&self) -> Option<Report<'id>> {
        self.report.map(|mut r| {
            if r.terminal == Terminal::Pending {
                r.terminal = Terminal::Interrupted;
            }
            r
        })
    }
}
