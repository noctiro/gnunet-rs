//! Rust-owned durable replay/address storage with an actual process writer fence.
//!
//! This server implements the official STORE and iterator subset consumed by the
//! TCP communicator. PEERSTORE monitor/plugin/expiry administration remain separate
//! required service work. It never delegates storage to a C service.
use crate::{AddressStore, framed::Framed};
use gnunet_service_runtime::connection::Connection;
use gnunet_transport::PeerId;
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader, MessageType};
use std::task::{Context, Poll};
#[cfg(test)]
use std::{fs, path::PathBuf};
mod journal;
pub use journal::{
    HelloProfiles, Journal, JournalFailure, ManagedAddress, ManagedQuota,
    Transaction as JournalTransaction,
};
#[derive(Clone)]
struct Record {
    peer: PeerId,
    subsystem: Vec<u8>,
    key: Vec<u8>,
    value: Vec<u8>,
    expiry: u64,
}
fn number<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<usize, Error> {
    Ok(usize::from(u16::from_be_bytes(number(bytes, offset)?)))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(number(bytes, offset)?))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(number(bytes, offset)?))
}
fn frame(kind: u16, size: usize) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; size];
    MessageHeader::from_total_size(MessageType::new(kind), size)?.encode(&mut out)?;
    Ok(out)
}
fn cstring(bytes: &[u8]) -> Result<&[u8], Error> {
    if bytes.is_empty() || bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(Error::Malformed);
    }
    Ok(&bytes[..bytes.len() - 1])
}
impl AddressStore for Journal {
    fn validated(&mut self, peer: PeerId, address: &[u8], until: u64) -> Result<(), Error> {
        if address.contains(&0) {
            return Err(Error::InvalidInput);
        }
        let mut value = address.to_vec();
        value.push(0);
        self.store(
            Record {
                peer,
                subsystem: b"transport".to_vec(),
                key: b"transport-communicator-url".to_vec(),
                value,
                expiry: until,
            },
            false,
        )
    }
}
fn decode_record(bytes: &[u8]) -> Result<Record, Error> {
    Frame::decode(bytes)?;
    let key = u16_at(bytes, 52)?;
    let value = u16_at(bytes, 54)?;
    let subsystem = u16_at(bytes, 56)?;
    if bytes.len()
        != 60usize
            .checked_add(key)
            .and_then(|n| n.checked_add(value))
            .and_then(|n| n.checked_add(subsystem))
            .ok_or(Error::Overflow)?
        || u16_at(bytes, 58)? != 0
    {
        return Err(Error::Malformed);
    }
    Ok(Record {
        peer: PeerId(number(bytes, 4)?),
        expiry: u64_at(bytes, 36)?,
        subsystem: cstring(&bytes[60..60 + subsystem])?.to_vec(),
        key: cstring(&bytes[60 + subsystem..60 + subsystem + key])?.to_vec(),
        value: bytes[60 + subsystem + key..].to_vec(),
    })
}
fn encode_record(record: &Record, rid: u32, kind: u16) -> Result<Vec<u8>, Error> {
    let ss = record.subsystem.len() + 1;
    let ks = record.key.len() + 1;
    let size = 60 + ss + ks + record.value.len();
    let mut out = frame(kind, size)?;
    out[4..36].copy_from_slice(&record.peer.0);
    out[36..44].copy_from_slice(&record.expiry.to_be_bytes());
    out[44..48].copy_from_slice(&rid.to_be_bytes());
    for (offset, length) in [(52, ks), (54, record.value.len()), (56, ss)] {
        out[offset..offset + 2].copy_from_slice(
            &u16::try_from(length)
                .map_err(|_| Error::TooLarge)?
                .to_be_bytes(),
        );
    }
    out[60..60 + ss - 1].copy_from_slice(&record.subsystem);
    out[60 + ss..60 + ss + ks - 1].copy_from_slice(&record.key);
    out[60 + ss + ks..].copy_from_slice(&record.value);
    Ok(out)
}
struct Iteration {
    rid: u32,
    records: Vec<Record>,
    next: usize,
}
struct PendingFrames(std::vec::IntoIter<Vec<u8>>);
impl Default for PendingFrames {
    fn default() -> Self {
        Self(Vec::new().into_iter())
    }
}
impl Drop for PendingFrames {
    fn drop(&mut self) {
        for bytes in self.0.as_mut_slice() {
            zeroize::Zeroize::zeroize(bytes);
        }
    }
}
fn queue_pending(client: &mut Client) -> Result<bool, Error> {
    while let Some(bytes) = client.pending.0.as_slice().first() {
        match client.io.reserve(bytes.len()) {
            Ok(()) => {}
            // Keep this original committed reply, but let the existing TX queue
            // drain. Retrying admission before TX without yielding would deadlock.
            Err(Error::WouldBlock) => return Ok(false),
            Err(error) => return Err(error),
        }
        let bytes = client.pending.0.next().ok_or(Error::Stale)?;
        // Body and metadata ownership were reserved before consuming this reply.
        client.io.queue_owned(bytes)?;
    }
    Ok(true)
}
struct Client {
    io: Framed,
    iterations: Vec<Iteration>,
    pending: PendingFrames,
}
/// Official replay-store IPC server, owned by the same node supervisor as Journal.
/// Each iterator snapshots its original records, preventing scan/replace feedback.
pub struct Server {
    clients: Vec<Client>,
    cursor: usize,
    maximum: usize,
    requests: u64,
}
impl Server {
    /// Reserve a bounded set of physical internal/public client connections.
    pub fn new(maximum: usize) -> Result<Self, Error> {
        if maximum == 0 {
            return Err(Error::InvalidInput);
        }
        let mut clients = Vec::new();
        clients
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            clients,
            cursor: 0,
            maximum,
            requests: 0,
        })
    }
    /// Admit one actual socket; no C backend or detached database worker is used.
    pub fn admit(&mut self, connection: Connection) -> Result<(), Error> {
        if self.clients.len() == self.maximum {
            return Err(Error::Capacity);
        }
        self.clients.push(Client {
            io: Framed::new(connection, 1024 * 1024)?,
            iterations: Vec::new(),
            pending: PendingFrames::default(),
        });
        Ok(())
    }
    /// Current admitted physical public/internal IPC owners.
    #[must_use]
    pub fn clients(&self) -> usize {
        self.clients.len()
    }
    /// Number of complete official requests actually handled.
    #[must_use]
    pub fn requests(&self) -> u64 {
        self.requests
    }
    /// Poll one fair actual socket/request direction. Fatal commit uncertainty stops
    /// the whole node; closing an IPC stream alone never proves database rollback.
    pub fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        journal: &mut Journal,
        now: u64,
    ) -> Poll<Result<(), Error>> {
        for client in &mut self.clients {
            let _all_queued = queue_pending(client)?;
        }
        let count = self.clients.len() * 2;
        if count == 0 {
            return Poll::Pending;
        }
        for _ in 0..count {
            let slot = self.cursor % count;
            self.cursor = (self.cursor + 1) % count;
            let index = slot / 2;
            if slot.is_multiple_of(2) {
                if journal.transaction_pending() {
                    continue;
                }
                // Do not dispatch another request over an unqueued original
                // reply. TX and other clients retain their normal fair turns.
                if !self.clients[index].pending.0.as_slice().is_empty() {
                    continue;
                }
                let Client { io, iterations, .. } = &mut self.clients[index];
                if let Some(bytes) = io.frame() {
                    let result = handle(iterations, journal, bytes, now);
                    io.release();
                    self.requests = self.requests.checked_add(1).ok_or(Error::Overflow)?;
                    match result {
                        Ok(outputs) => {
                            self.clients[index].pending = PendingFrames(outputs.into_iter());
                            let _all_queued = queue_pending(&mut self.clients[index])?;
                        }
                        Err(Error::Storage | Error::OutcomeUnknown) => {
                            return Poll::Ready(result.map(|_| ()));
                        }
                        Err(_) => {
                            self.clients.remove(index);
                        }
                    }
                    return Poll::Ready(Ok(()));
                }
                match self.clients[index].io.poll_read(cx) {
                    Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                    Poll::Ready(Err(_)) => {
                        self.clients.remove(index);
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => {}
                }
            } else {
                match self.clients[index].io.poll_write(cx) {
                    Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                    Poll::Ready(Err(_)) => {
                        self.clients.remove(index);
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => {}
                }
            }
        }
        Poll::Pending
    }
    /// Physically close every original stream; this actor has no deferred commits.
    pub fn shutdown(&mut self) {
        self.clients.clear();
    }
}
fn result(kind: u16, rid: u32, status: u32) -> Result<Vec<u8>, Error> {
    let mut out = frame(kind, 12)?;
    out[4..8].copy_from_slice(&rid.to_be_bytes());
    out[8..12].copy_from_slice(&status.to_be_bytes());
    Ok(out)
}
fn iterate(
    iterations: &mut Vec<Iteration>,
    index: usize,
    limit: u64,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut output = Vec::new();
    let n = limit.min(64);
    for _ in 0..n {
        if let Some(record) = iterations[index].records.get(iterations[index].next) {
            output.push(encode_record(record, iterations[index].rid, 822)?);
            iterations[index].next += 1;
        } else {
            output.push(result(823, iterations[index].rid, 1)?);
            iterations.remove(index);
            break;
        }
    }
    Ok(output)
}
fn handle(
    iterations: &mut Vec<Iteration>,
    journal: &mut Journal,
    bytes: &[u8],
    now: u64,
) -> Result<Vec<Vec<u8>>, Error> {
    match Frame::decode(bytes)?.header().message_type().value() {
        820 => {
            let rid = u32_at(bytes, 44)?;
            let option = u32_at(bytes, 48)?;
            if option > 1 {
                return Err(Error::Unsupported);
            }
            let record = decode_record(bytes)?;
            match journal.store(record, option == 1) {
                Ok(()) => Ok(vec![result(827, rid, 1)?]),
                Err(Error::Replay) => Ok(vec![result(827, rid, u32::MAX)?]),
                Err(error) => Err(error),
            }
        }
        821 => {
            let peer = PeerId(number(bytes, 4)?);
            let rid = u32_at(bytes, 36)?;
            let peer_set = u16_at(bytes, 40)?;
            let ss = u16_at(bytes, 42)?;
            let ks = u16_at(bytes, 46)?;
            if peer_set > 1
                || u16_at(bytes, 44)? != 0
                || bytes.len() != 48 + ss + ks
                || iterations.len() >= 128
                || iterations.iter().any(|i| i.rid == rid)
            {
                return Err(Error::Malformed);
            }
            let sub = if ss == 0 {
                None
            } else {
                Some(cstring(&bytes[48..48 + ss])?)
            };
            let key = if ks == 0 {
                None
            } else {
                Some(cstring(&bytes[48 + ss..])?)
            };
            let records = journal
                .records()
                .filter(|r| {
                    r.expiry > now
                        && (peer_set == 0 || r.peer == peer)
                        && sub.is_none_or(|s| s == r.subsystem)
                        && key.is_none_or(|k| k == r.key)
                })
                .cloned()
                .collect();
            iterations.push(Iteration {
                rid,
                records,
                next: 0,
            });
            iterate(iterations, iterations.len() - 1, 1)
        }
        828 => {
            if bytes.len() != 16 {
                return Err(Error::Malformed);
            }
            let limit = u64_at(bytes, 4)?;
            if limit == 0 {
                return Err(Error::Malformed);
            }
            let rid = u32_at(bytes, 12)?;
            let index = iterations
                .iter()
                .position(|i| i.rid == rid)
                .ok_or(Error::Stale)?;
            iterate(iterations, index, limit)
        }
        829 => {
            if bytes.len() != 8 {
                return Err(Error::Malformed);
            }
            let rid = u32_at(bytes, 4)?;
            let index = iterations
                .iter()
                .position(|i| i.rid == rid)
                .ok_or(Error::Stale)?;
            iterations.remove(index);
            Ok(Vec::new())
        }
        _ => Err(Error::Unsupported),
    }
}

#[cfg(test)]
mod framing_resource_tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Actual queue liveness assertions with fallible setup"
    )]
    use super::*;
    use std::{future::poll_fn, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn pending_original_reply_drains_after_full_queue_without_replaying_a_request()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
            let root = std::env::temp_dir().join(format!("gnunet-ps-framing-{}", std::process::id()));
            fs::create_dir_all(&root)?;
            let mut journal = Journal::open(root.join("journal"))?;
            let (stream, mut peer) = tokio::net::UnixStream::pair()?;
            let mut server = Server::new(1)?;
            server.admit(Connection::from_unix(stream))?;
            let capacity = 1024 * 1024;
            let mut expected = Vec::with_capacity(capacity + 12);
            for _ in 0..16 {
                let bytes = frame(822, 65535)?;
                expected.extend_from_slice(&bytes);
                server.clients[0].io.queue_owned(bytes)?;
            }
            let last = frame(823, 16)?;
            expected.extend_from_slice(&last);
            server.clients[0].io.queue_owned(last)?;
            assert_eq!(expected.len(), capacity);
            let original = result(827, 17, 1)?;
            expected.extend_from_slice(&original);
            // Read a genuine STORE over this same MQ, but leave dispatch to
            // Server after the TX budget is already full. The durable effect
            // must happen once even while its original reply awaits capacity.
            let request = encode_record(&Record {
                peer: PeerId([7; 32]), subsystem: b"framing".to_vec(),
                key: b"key".to_vec(), value: b"original".to_vec(), expiry: 999,
            }, 17, 820)?;
            peer.write_all(&request).await?;
            while server.clients[0].io.frame().is_none() {
                poll_fn(|cx| server.clients[0].io.poll_read(cx)).await?;
            }
            let expected_len = expected.len();
            let driver = async {
                poll_fn(|cx| {
                    for _ in 0..64 {
                        match server.poll_step(cx, &mut journal, 1) {
                            Poll::Ready(Ok(())) => {}
                            Poll::Ready(Err(error)) => return Poll::Ready(Err::<(), _>(error)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }).await
            };
            let read = async {
                let mut actual = vec![0; expected_len];
                peer.read_exact(&mut actual).await?;
                Ok::<_, std::io::Error>(actual)
            };
            let actual = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::select! {
                    result = driver => Err(std::io::Error::other(format!("driver stopped: {result:?}"))),
                    result = read => result,
                }
            }).await??;
            assert_eq!(actual, expected);
            assert!(server.clients[0].pending.0.as_slice().is_empty());
            assert_eq!(server.requests(), 1);
            assert_eq!(journal.commits(), 1);
            server.shutdown();
            let mut tail = [0; 1];
            assert_eq!(peer.read(&mut tail).await?, 0);
            drop(journal);
            fs::remove_dir_all(root)?;
            Ok(())
        })
    }
}

struct DiscoveryScan<'a> {
    position: usize,
    start: usize,
    work: usize,
    quantum: usize,
    visitor: &'a mut dyn FnMut(&[u8]) -> Result<crate::discovery::VisitControl, Error>,
}
impl DiscoveryScan<'_> {
    fn offer(&mut self, address: &[u8]) -> Result<bool, Error> {
        if self.position < self.start {
            self.position = self.position.checked_add(1).ok_or(Error::Overflow)?;
            return Ok(true);
        }
        if self.work == self.quantum {
            return Ok(false);
        }
        self.work += 1;
        if (self.visitor)(address)? == crate::discovery::VisitControl::Pause {
            return Ok(false);
        }
        self.position = self.position.checked_add(1).ok_or(Error::Overflow)?;
        Ok(true)
    }
}
impl crate::discovery::AddressSource for Journal {
    fn visit(
        &mut self,
        peer: PeerId,
        utc: u64,
        start: usize,
        quantum: core::num::NonZeroUsize,
        visitor: &mut dyn FnMut(&[u8]) -> Result<crate::discovery::VisitControl, Error>,
    ) -> Result<crate::discovery::Visit, Error> {
        use crate::discovery::Visit;
        let mut scan = DiscoveryScan {
            position: 0,
            start,
            work: 0,
            quantum: quantum.get(),
            visitor,
        };
        // The journal itself bounds all retained records to4096 and4MiB.
        // At most quantum address callbacks are made in this scheduling pass.
        let mut scratch = [0; 8192];
        for record in self.records() {
            if record.peer != peer || record.expiry <= utc {
                continue;
            }
            if record.subsystem == b"transport" && record.key == b"transport-communicator-url" {
                if let Ok(address) = cstring(&record.value)
                    && !scan.offer(address)?
                {
                    return Ok(Visit {
                        cursor: scan.position,
                        finished: false,
                    });
                }
            } else if record.subsystem == b"peerstore" && record.key == b"peerstore-peer-hello-uri"
            {
                let parsed = gnunet_hello::Hello::parse_message(
                    &record.value,
                    None,
                    &mut scratch,
                    gnunet_hello::Limits {
                        maximum_input_bytes: 65535,
                        maximum_address_bytes: 8192,
                        maximum_addresses: 128,
                    },
                );
                let Ok(hello) = parsed else {
                    continue;
                };
                if hello.peer().as_bytes() != &peer.0
                    || hello
                        .verify_at(
                            self.hello_profiles().discovery,
                            gnunet_hello::AbsoluteTime::from_micros(utc),
                        )
                        .is_err()
                {
                    continue;
                }
                // Even a profile that signs the address set only supplies hints
                // for full communicator/signed validation.
                for address in hello.addresses() {
                    let address = address.as_bytes();
                    let Some(split) = address.windows(3).position(|w| w == b"://") else {
                        continue;
                    };
                    if split == 0 {
                        continue;
                    }
                    let n = address.len().checked_sub(2).ok_or(Error::Overflow)?;
                    let mut converted = Vec::new();
                    converted
                        .try_reserve_exact(n)
                        .map_err(|_| Error::Capacity)?;
                    converted.extend_from_slice(&address[..split]);
                    converted.push(b'-');
                    converted.extend_from_slice(&address[split + 3..]);
                    if !scan.offer(&converted)? {
                        return Ok(Visit {
                            cursor: scan.position,
                            finished: false,
                        });
                    }
                }
            }
        }
        Ok(Visit {
            cursor: scan.position,
            finished: true,
        })
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check real bounded journal discovery and original sources"
)]
mod discovery_tests {
    use super::*;
    use crate::discovery::{AddressSource, VisitControl};
    use core::num::NonZeroUsize;
    use gnunet_crypto::EddsaPrivateKey;
    use gnunet_hello::{AbsoluteTime, HelloBuilder, SignatureProfile};
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }
    fn directory() -> Result<Cleanup, Error> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| Error::Entropy)?;
        let p = std::env::temp_dir().join(format!(
            "gnunet-rs-discovery-{:032x}",
            u128::from_ne_bytes(random)
        ));
        fs::create_dir(&p).map_err(|_| Error::Storage)?;
        Ok(Cleanup(p))
    }
    fn record(peer: PeerId, subsystem: &[u8], key: &[u8], value: Vec<u8>, expiry: u64) -> Record {
        Record {
            peer,
            subsystem: subsystem.to_vec(),
            key: key.to_vec(),
            value,
            expiry,
        }
    }
    #[test]
    fn actual_journal_lookup_filters_original_peer_and_resumes_past_unsupported_candidates()
    -> Result<(), Error> {
        let d = directory()?;
        let mut j = Journal::open(d.0.join("db"))?;
        let peer = PeerId([9; 32]);
        j.store(
            record(
                PeerId([8; 32]),
                b"transport",
                b"transport-communicator-url",
                b"tcp-foreign\0".to_vec(),
                999,
            ),
            false,
        )?;
        j.store(
            record(
                peer,
                b"transport",
                b"transport-communicator-url",
                b"tcp-expired\0".to_vec(),
                100,
            ),
            false,
        )?;
        j.store(
            record(
                peer,
                b"transport",
                b"transport-communicator-url",
                b"udp-first\0".to_vec(),
                999,
            ),
            false,
        )?;
        j.store(
            record(
                peer,
                b"transport",
                b"transport-communicator-url",
                b"tcp-second\0".to_vec(),
                999,
            ),
            false,
        )?;
        let mut seen = Vec::new();
        let one = j.visit(peer, 100, 0, NonZeroUsize::MIN, &mut |a| {
            seen.push(a.to_vec());
            Ok(VisitControl::Continue)
        })?;
        assert_eq!(seen, [b"udp-first".to_vec()]);
        assert_eq!((one.cursor, one.finished), (1, false));
        let two = j.visit(peer, 100, one.cursor, NonZeroUsize::MIN, &mut |a| {
            seen.push(a.to_vec());
            Ok(VisitControl::Continue)
        })?;
        assert_eq!(seen, [b"udp-first".to_vec(), b"tcp-second".to_vec()]);
        assert_eq!((two.cursor, two.finished), (2, true));
        Ok(())
    }
    #[test]
    fn actual_hello_metadata_is_checked_but_addresses_remain_untrusted_hints() -> Result<(), Error>
    {
        let d = directory()?;
        let mut j = Journal::open(d.0.join("db"))?;
        let key = EddsaPrivateKey::from_seed([9; 32]);
        let peer = PeerId(*key.public_key().as_bytes());
        j.store(
            record(
                peer,
                b"peerstore",
                b"peerstore-peer-hello-uri",
                vec![0, 255],
                999,
            ),
            false,
        )?;
        let mut scratch = [0; 1024];
        let limits = gnunet_hello::Limits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 1024,
            maximum_addresses: 16,
        };
        let mut builder = HelloBuilder::new(&mut scratch, limits);
        builder.add_address(b"tcp://127.0.0.1:42")?;
        builder.add_address(b"udp://127.0.0.1:43")?;
        let hello = builder.sign(
            &key,
            AbsoluteTime::from_micros(999),
            SignatureProfile::Gnunet029,
        )?;
        let mut bytes = vec![0; hello.message_len()?];
        hello.encode_message(&mut bytes)?;
        j.store(
            record(
                PeerId([2; 32]),
                b"peerstore",
                b"peerstore-peer-hello-uri",
                bytes.clone(),
                999,
            ),
            false,
        )?;
        let mut invalid = bytes.clone();
        invalid[8] ^= 1;
        j.store(
            record(
                peer,
                b"peerstore",
                b"peerstore-peer-hello-uri",
                invalid,
                999,
            ),
            false,
        )?;
        j.store(
            record(peer, b"peerstore", b"peerstore-peer-hello-uri", bytes, 999),
            false,
        )?;
        let mut seen = Vec::new();
        let result = j.visit(
            peer,
            100,
            0,
            NonZeroUsize::new(8).ok_or(Error::InvalidInput)?,
            &mut |a| {
                seen.push(a.to_vec());
                Ok(VisitControl::Continue)
            },
        )?;
        assert!(result.finished);
        seen.sort();
        assert_eq!(
            seen,
            [b"tcp-127.0.0.1:42".to_vec(), b"udp-127.0.0.1:43".to_vec()]
        );
        Ok(())
    }
    #[test]
    fn pause_does_not_consume_original_source_position() -> Result<(), Error> {
        let d = directory()?;
        let mut j = Journal::open(d.0.join("db"))?;
        let peer = PeerId([9; 32]);
        j.validated(peer, b"tcp-original", 999)?;
        let one = j.visit(peer, 100, 0, NonZeroUsize::MIN, &mut |_| {
            Ok(VisitControl::Pause)
        })?;
        assert_eq!((one.cursor, one.finished), (0, false));
        let mut seen = Vec::new();
        let two = j.visit(peer, 100, one.cursor, NonZeroUsize::MIN, &mut |a| {
            seen.push(a.to_vec());
            Ok(VisitControl::Continue)
        })?;
        assert!(two.finished);
        assert_eq!(seen, [b"tcp-original".to_vec()]);
        Ok(())
    }
}
