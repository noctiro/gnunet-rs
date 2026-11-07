//! Real local Unix peers exercise the normal command router. These fixtures
//! prove local IPC behavior, not official C interoperability or remote deletion.
use super::super::{RecordData, RecordFlags, RecordType, SecretKey, gnsrecord};
use gnunet::wire::{MessageHeader, identity as id, namestore as ns};
use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::DirBuilderExt,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn check(condition: bool, message: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn key(seed: u8) -> io::Result<SecretKey> {
    let mut bytes = Zeroizing::new([seed; id::KEY_LEN]);
    bytes[..4].copy_from_slice(&id::KeyType::Eddsa.value().to_be_bytes());
    SecretKey::from_serialized(&bytes[..]).map_err(io::Error::other)
}

struct Fixture {
    directory: PathBuf,
    stop: Arc<AtomicBool>,
    returned: Arc<AtomicBool>,
    peers: Vec<JoinHandle<io::Result<()>>>,
}
impl Fixture {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        loop {
            let directory = std::env::temp_dir().join(format!(
                "gnunet-orphans-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => {
                    return Ok(Self {
                        directory,
                        stop: Arc::new(AtomicBool::new(false)),
                        returned: Arc::new(AtomicBool::new(false)),
                        peers: Vec::new(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }
    fn socket(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }
    fn listener(&self, name: &str) -> io::Result<UnixListener> {
        let listener = UnixListener::bind(self.socket(name))?;
        listener.set_nonblocking(true)?;
        Ok(listener)
    }
    fn args(&self, action: &str) -> Vec<OsString> {
        vec![
            action.into(),
            self.socket("namestore").into_os_string(),
            "--identity-socket".into(),
            self.socket("identity").into_os_string(),
            "--timeout-ms".into(),
            "1000".into(),
        ]
    }
    fn spawn(
        &mut self,
        listener: UnixListener,
        actor: impl FnOnce(Peer, UnixListener) -> io::Result<()> + Send + 'static,
    ) {
        let stop = self.stop.clone();
        let returned = self.returned.clone();
        self.peers.push(thread::spawn(move || {
            actor(
                Peer {
                    stop,
                    returned,
                    until: Instant::now() + Duration::from_secs(3),
                },
                listener,
            )
        }));
    }
    fn run(&self, args: &[OsString], output: &mut impl Write) -> Result {
        let result = super::super::run(args, output);
        self.returned.store(true, Ordering::SeqCst);
        result
    }
    fn finish(&mut self) -> io::Result<()> {
        let mut failure = None;
        for peer in self.peers.drain(..) {
            let result = match peer.join() {
                Ok(result) => result,
                Err(_) => Err(io::Error::other("local orphan peer panicked")),
            };
            if let Err(error) = result
                && failure.is_none()
            {
                failure = Some(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for peer in self.peers.drain(..) {
            let _joined = peer.join();
        }
        let _removed = fs::remove_dir_all(&self.directory);
    }
}
struct Peer {
    stop: Arc<AtomicBool>,
    returned: Arc<AtomicBool>,
    until: Instant,
}
impl Peer {
    fn guard(&self) -> io::Result<()> {
        if self.stop.load(Ordering::SeqCst) || Instant::now() >= self.until {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local orphan peer bound",
            ))
        } else {
            Ok(())
        }
    }
    fn accept(&self, listener: &UnixListener) -> io::Result<UnixStream> {
        loop {
            self.guard()?;
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_millis(20)))?;
                    stream.set_write_timeout(Some(Duration::from_millis(20)))?;
                    return Ok(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn read(&self, stream: &mut UnixStream, output: &mut [u8]) -> io::Result<usize> {
        loop {
            self.guard()?;
            match stream.read(output) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(1))
                }
                result => return result,
            }
        }
    }
    fn exact(&self, stream: &mut UnixStream, mut output: &mut [u8]) -> io::Result<()> {
        while !output.is_empty() {
            let read = self.read(stream, output)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "partial local orphan frame",
                ));
            }
            output = &mut output[read..];
        }
        Ok(())
    }
    fn frame(&self, stream: &mut UnixStream) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut header = [0; 4];
        self.exact(stream, &mut header)?;
        let size = MessageHeader::decode(&header)
            .map_err(io::Error::other)?
            .size();
        let mut bytes = Zeroizing::new(vec![0; size]);
        bytes[..4].copy_from_slice(&header);
        self.exact(stream, &mut bytes[4..])?;
        Ok(bytes)
    }
    fn write(&self, stream: &mut UnixStream, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            self.guard()?;
            match stream.write(bytes) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "local orphan peer write",
                    ));
                }
                Ok(written) => bytes = &bytes[written..],
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn identity(&self, stream: &mut UnixStream, response: id::Response<'_>) -> io::Result<()> {
        let mut bytes = Zeroizing::new(vec![0; response.encoded_len().map_err(io::Error::other)?]);
        response.encode(&mut bytes).map_err(io::Error::other)?;
        self.write(stream, &bytes)
    }
    fn namestore(&self, stream: &mut UnixStream, response: ns::Response<'_>) -> io::Result<()> {
        let mut bytes = Zeroizing::new(vec![0; response.encoded_len().map_err(io::Error::other)?]);
        response.encode(&mut bytes).map_err(io::Error::other)?;
        self.write(stream, &bytes)
    }
    fn eof(&self, stream: &mut UnixStream) -> io::Result<()> {
        match self.read(stream, &mut [0]) {
            Ok(0) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::other(
                "unexpected write after original local completion",
            )),
        }
    }
    fn no_connection(&self, listener: &UnixListener) -> io::Result<()> {
        let until = Instant::now() + Duration::from_millis(30);
        while Instant::now() < until {
            self.guard()?;
            match listener.accept() {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(error) => return Err(error),
                Ok(_) => return Err(io::Error::other("unexpected extra NAMESTORE connection")),
            }
        }
        Ok(())
    }
    fn no_replay(&self, listener: &UnixListener) -> io::Result<()> {
        loop {
            self.guard()?;
            match listener.accept() {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if self.returned.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(io::Error::other(
                        "unexpected NAMESTORE replay before command return",
                    ));
                }
            }
        }
    }
}
fn identity_start(peer: &Peer, stream: &mut UnixStream, egos: &[(u8, &[u8])]) -> io::Result<()> {
    let bytes = peer.frame(stream)?;
    check(
        matches!(
            id::Request::decode(&bytes).map_err(io::Error::other)?,
            id::Request::Start
        ),
        "missing actual IDENTITY START",
    )?;
    for &(seed, name) in egos {
        let key = key(seed)?;
        peer.identity(
            stream,
            id::Response::Update {
                name: Some(name),
                key: key.view().map_err(io::Error::other)?,
            },
        )?;
    }
    peer.identity(stream, id::Response::EndOfList)
}
fn identities(fixture: &mut Fixture, egos: Vec<(u8, &'static [u8])>) -> io::Result<()> {
    let listener = fixture.listener("identity")?;
    fixture.spawn(listener, move |peer, listener| {
        let mut stream = peer.accept(&listener)?;
        identity_start(&peer, &mut stream, &egos)?;
        peer.eof(&mut stream)
    });
    Ok(())
}
fn start(peer: &Peer, stream: &mut UnixStream, selected: Option<u8>) -> io::Result<u32> {
    let bytes = peer.frame(stream)?;
    let ns::Request::IterateStart { rid, zone, filter } =
        ns::Request::decode(&bytes).map_err(io::Error::other)?
    else {
        return Err(io::Error::other("missing actual iteration START"));
    };
    check(
        filter == 0,
        "management iteration changed its original unfiltered selection",
    )?;
    match (zone, selected) {
        (None, None) => {}
        (Some(zone), Some(seed)) => check(
            key(seed)?.constant_time_eq(
                &SecretKey::from_serialized(zone.expose_serialized()).map_err(io::Error::other)?,
            ),
            "wrong selected iteration authority",
        )?,
        _ => {
            return Err(io::Error::other(
                "wrong all-zone versus selected-zone iteration",
            ));
        }
    }
    Ok(rid)
}
fn next(peer: &Peer, stream: &mut UnixStream, rid: u32) -> io::Result<()> {
    let bytes = peer.frame(stream)?;
    check(
        matches!(ns::Request::decode(&bytes).map_err(io::Error::other)?, ns::Request::IterateNext { rid: actual, limit: 1 } if actual == rid),
        "missing original iteration credit",
    )
}
fn retired_iteration(peer: &Peer, stream: &mut UnixStream, rid: u32) -> io::Result<()> {
    let mut first = [0];
    match peer.read(stream, &mut first) {
        Ok(0) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => return Ok(()),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let mut header = [0; 4];
    header[0] = first[0];
    peer.exact(stream, &mut header[1..])?;
    let mut bytes = Zeroizing::new(vec![
        0;
        MessageHeader::decode(&header)
            .map_err(io::Error::other)?
            .size()
    ]);
    bytes[..4].copy_from_slice(&header);
    peer.exact(stream, &mut bytes[4..])?;
    check(
        matches!(ns::Request::decode(&bytes).map_err(io::Error::other)?, ns::Request::IterateStop { rid: actual } if actual == rid),
        "refused scan sent a mutation",
    )?;
    peer.eof(stream)
}
fn record(
    peer: &Peer,
    stream: &mut UnixStream,
    rid: u32,
    seed: u8,
    label: &[u8],
) -> io::Result<()> {
    let key = key(seed)?;
    let record = [RecordData {
        expiration_time: u64::MAX,
        record_type: RecordType::TXT,
        flags: RecordFlags::NONE,
        data: b"orphan fixture",
    }];
    let mut bytes = Zeroizing::new(vec![
        0;
        gnsrecord::serialized_len(&record)
            .map_err(io::Error::other)?
    ]);
    gnsrecord::serialize(&record, &mut bytes).map_err(io::Error::other)?;
    peer.namestore(
        stream,
        ns::Response::Records {
            rid,
            zone: key.view().map_err(io::Error::other)?,
            label: ns::CString::new(label).map_err(io::Error::other)?,
            expires: gnunet_types::AbsoluteTime::NEVER,
            records: ns::Records::new(&bytes, 1).map_err(io::Error::other)?,
        },
    )
}
fn empty_store(peer: &Peer, stream: &mut UnixStream, seed: u8, label: &[u8]) -> io::Result<u32> {
    let bytes = peer.frame(stream)?;
    let ns::Request::Store {
        rid,
        zone,
        single_tx,
        reserved,
        sets,
    } = ns::Request::decode(&bytes).map_err(io::Error::other)?
    else {
        return Err(io::Error::other("expected one actual STORE"));
    };
    check(
        single_tx == 1 && reserved == 0 && sets.count() == 1,
        "STORE must retain one atomic label",
    )?;
    check(
        key(seed)?.constant_time_eq(
            &SecretKey::from_serialized(zone.expose_serialized()).map_err(io::Error::other)?,
        ),
        "STORE changed original authority",
    )?;
    let set = sets
        .iter()
        .next()
        .ok_or_else(|| io::Error::other("missing deletion set"))?
        .map_err(io::Error::other)?;
    check(
        set.label.bytes() == label && set.records.count() == 0 && set.records.bytes().is_empty(),
        "STORE must delete exactly the selected label",
    )?;
    Ok(rid)
}
fn contains(bytes: &[u8], part: &[u8]) -> bool {
    bytes.windows(part.len()).any(|window| window == part)
}
fn event<'a>(output: &'a [u8], name: &'a [u8]) -> impl Iterator<Item = &'a [u8]> + 'a {
    output.split(|byte| *byte == b'\n').filter(move |line| {
        let marker = b"\"event\":\"";
        let Some(start) = line
            .windows(marker.len())
            .position(|window| window == marker)
        else {
            return false;
        };
        let value = &line[start + marker.len()..];
        value.starts_with(name) && value.get(name.len()) == Some(&b'"')
    })
}
fn recovered(line: &[u8]) -> io::Result<SecretKey> {
    let marker = b"\"private_key\":\"";
    let start = line
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or_else(|| io::Error::other("missing deliberate private-key export"))?
        + marker.len();
    let tail = &line[start..];
    let end = tail
        .iter()
        .position(|byte| *byte == b'"')
        .ok_or_else(|| io::Error::other("unterminated private-key export"))?;
    let mut bytes = Zeroizing::new([0; id::KEY_LEN]);
    check(
        gnsrecord::decode_base32(&tail[..end], &mut bytes[..]).map_err(io::Error::other)?
            == id::KEY_LEN,
        "typed private-key export length changed",
    )?;
    SecretKey::from_serialized(&bytes[..]).map_err(io::Error::other)
}

#[test]
fn list_routes_after_identity_end_and_exports_only_recoverable_orphan_keys() -> Result {
    let mut fixture = Fixture::new()?;
    let listener = fixture.listener("namestore")?;
    let before_end = listener.try_clone()?;
    let identity_listener = fixture.listener("identity")?;
    fixture.spawn(identity_listener, move |peer, listener| {
        let mut stream = peer.accept(&listener)?;
        let bytes = peer.frame(&mut stream)?;
        check(
            matches!(
                id::Request::decode(&bytes).map_err(io::Error::other)?,
                id::Request::Start
            ),
            "missing actual IDENTITY START",
        )?;
        let owned = key(1)?;
        peer.identity(
            &mut stream,
            id::Response::Update {
                name: Some(b"owned"),
                key: owned.view().map_err(io::Error::other)?,
            },
        )?;
        // A nonempty partial initial enumeration grants no all-zone scan yet.
        peer.no_connection(&before_end)?;
        peer.identity(&mut stream, id::Response::EndOfList)?;
        peer.eof(&mut stream)
    });
    fixture.spawn(listener, |peer, listener| {
        let mut stream = peer.accept(&listener)?;
        let rid = start(&peer, &mut stream, None)?;
        for (seed, label) in [
            (1, b"owned-label".as_slice()),
            (2, b"first"),
            (3, b"second"),
        ] {
            record(&peer, &mut stream, rid, seed, label)?;
            next(&peer, &mut stream, rid)?;
        }
        peer.namestore(&mut stream, ns::Response::End { rid })?;
        peer.eof(&mut stream)?;
        peer.no_replay(&listener)
    });
    let mut output = Zeroizing::new(Vec::new());
    let result = fixture.run(&fixture.args("list-orphans"), &mut *output);
    fixture.finish()?;
    result?;
    let rows = event(&output, b"namestore_orphan_records").collect::<Vec<_>>();
    check(
        rows.len() == 2,
        "owned ego was listed or orphan row was lost",
    )?;
    for (row, seed) in rows.iter().zip([2, 3]) {
        let restored = recovered(row)?;
        let original = key(seed)?;
        check(
            restored.constant_time_eq(&original)
                && restored.public_key()? == original.public_key()?,
            "exported typed orphan key cannot be recovered",
        )?;
    }
    check(
        contains(&output, b"\"natural_end\":true")
            && contains(&output, b"namestore_management_complete"),
        "list did not consume actual natural END",
    )?;
    Ok(())
}

#[test]
fn purge_waits_for_natural_end_then_acknowledges_each_exact_empty_label() -> Result {
    let mut fixture = Fixture::new()?;
    identities(&mut fixture, vec![(1, b"owned")])?;
    let listener = fixture.listener("namestore")?;
    fixture.spawn(listener, |peer, listener| {
        let mut stream = peer.accept(&listener)?;
        let rid = start(&peer, &mut stream, None)?;
        for label in [b"alpha".as_slice(), b"beta"] {
            record(&peer, &mut stream, rid, 2, label)?;
            next(&peer, &mut stream, rid)?;
        }
        peer.no_connection(&listener)?;
        peer.namestore(&mut stream, ns::Response::End { rid })?;
        let mut writer = peer.accept(&listener)?;
        for label in [b"alpha".as_slice(), b"beta"] {
            let rid = empty_store(&peer, &mut writer, 2, label)?;
            peer.namestore(&mut writer, ns::Response::Generic { rid, code: 0 })?;
        }
        peer.eof(&mut writer)?;
        peer.eof(&mut stream)?;
        peer.no_replay(&listener)
    });
    let mut output = Zeroizing::new(Vec::new());
    let result = fixture.run(&fixture.args("purge-orphans"), &mut *output);
    fixture.finish()?;
    result?;
    let closed = event(&output, b"namestore_management_closed")
        .next()
        .ok_or("missing actual cleanup report")?;
    check(
        event(&output, b"namestore_management_delete_result").count() == 2
            && contains(closed, b"\"successful_deletions\":2")
            && contains(&output, b"namestore_management_complete"),
        "successful purge receipts were lost",
    )?;
    Ok(())
}

#[test]
fn incomplete_identity_iteration_or_limit_never_admits_a_deletion() -> Result {
    for profile in [0u8, 1, 2] {
        let mut fixture = Fixture::new()?;
        let close_identity = Arc::new(AtomicBool::new(false));
        let closed_identity = Arc::new(AtomicBool::new(false));
        let listener = fixture.listener("identity")?;
        let requested = close_identity.clone();
        let closed = closed_identity.clone();
        fixture.spawn(listener, move |peer, listener| {
            let mut stream = peer.accept(&listener)?;
            identity_start(&peer, &mut stream, &[(1, b"owned")])?;
            if profile == 1 {
                while !requested.load(Ordering::SeqCst) {
                    peer.guard()?;
                    thread::sleep(Duration::from_millis(1));
                }
                drop(stream);
                closed.store(true, Ordering::SeqCst);
                Ok(())
            } else {
                peer.eof(&mut stream)
            }
        });
        let listener = fixture.listener("namestore")?;
        fixture.spawn(listener, move |peer, listener| {
            let mut stream = peer.accept(&listener)?;
            let rid = start(&peer, &mut stream, None)?;
            record(&peer, &mut stream, rid, 2, b"alpha")?;
            next(&peer, &mut stream, rid)?;
            if profile == 0 {
                record(&peer, &mut stream, rid, 2, b"beyond-limit")?;
            } else if profile == 1 {
                close_identity.store(true, Ordering::SeqCst);
                while !closed_identity.load(Ordering::SeqCst) {
                    peer.guard()?;
                    thread::sleep(Duration::from_millis(1));
                }
                // The current original identity source is already lost before
                // the iterator offers END. A stale initial snapshot cannot delete.
                match peer.namestore(&mut stream, ns::Response::End { rid }) {
                    Ok(()) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::BrokenPipe
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::NotConnected
                        ) =>
                    {
                        return peer.no_replay(&listener);
                    }
                    Err(error) => return Err(error),
                }
            } else {
                drop(stream);
                return peer.no_replay(&listener);
            }
            retired_iteration(&peer, &mut stream, rid)?;
            peer.no_replay(&listener)
        });
        let mut args = fixture.args("purge-orphans");
        if profile == 0 {
            args.extend([OsString::from("--limit"), OsString::from("1")]);
        }
        let mut output = Zeroizing::new(Vec::new());
        let result = fixture.run(&args, &mut *output);
        fixture.finish()?;
        let closed = event(&output, b"namestore_management_closed")
            .next()
            .ok_or("missing refused-scan cleanup report")?;
        check(
            result.is_err()
                && !contains(&output, b"namestore_management_delete_result")
                && !contains(&output, b"namestore_management_complete")
                && contains(closed, b"\"successful_deletions\":0"),
            "incomplete scan or identity source fabricated deletion success",
        )?;
    }
    Ok(())
}

#[test]
fn second_store_refusal_or_unknown_preserves_the_actual_prefix_without_replay() -> Result {
    for reply in [Some(5013), None] {
        let mut fixture = Fixture::new()?;
        identities(&mut fixture, vec![(1, b"owned")])?;
        let listener = fixture.listener("namestore")?;
        fixture.spawn(listener, move |peer, listener| {
            let mut stream = peer.accept(&listener)?;
            let rid = start(&peer, &mut stream, None)?;
            for label in [b"alpha".as_slice(), b"beta"] {
                record(&peer, &mut stream, rid, 2, label)?;
                next(&peer, &mut stream, rid)?;
            }
            peer.namestore(&mut stream, ns::Response::End { rid })?;
            let mut writer = peer.accept(&listener)?;
            let rid = empty_store(&peer, &mut writer, 2, b"alpha")?;
            peer.namestore(&mut writer, ns::Response::Generic { rid, code: 0 })?;
            let rid = empty_store(&peer, &mut writer, 2, b"beta")?;
            if let Some(code) = reply {
                peer.namestore(&mut writer, ns::Response::Generic { rid, code })?;
                peer.eof(&mut writer)?;
            }
            drop(writer);
            peer.eof(&mut stream)?;
            peer.no_replay(&listener)
        });
        let mut output = Zeroizing::new(Vec::new());
        let result = fixture.run(&fixture.args("purge-orphans"), &mut *output);
        fixture.finish()?;
        let closed = event(&output, b"namestore_management_closed")
            .next()
            .ok_or("missing interrupted deletion cleanup report")?;
        check(
            result.is_err()
                && contains(closed, b"\"successful_deletions\":1")
                && contains(closed, b"\"ordinal\":2")
                && !contains(&output, b"namestore_management_complete"),
            "failed second STORE erased or invented the deletion prefix",
        )?;
        if reply.is_some() {
            check(
                contains(closed, b"\"code\":5013"),
                "original nonzero STORE result was lost",
            )?;
        } else {
            check(
                contains(closed, b"\"actual_service_result\":false"),
                "unknown STORE fabricated a service acknowledgement",
            )?;
        }
    }
    Ok(())
}

#[test]
fn purge_zone_scans_and_deletes_only_the_selected_current_ego() -> Result {
    let mut fixture = Fixture::new()?;
    let identity_listener = fixture.listener("identity")?;
    fixture.spawn(identity_listener, |peer, listener| {
        let mut inventory = peer.accept(&listener)?;
        identity_start(&peer, &mut inventory, &[(1, b"chosen"), (2, b"other")])?;
        let mut lookup = peer.accept(&listener)?;
        let bytes = peer.frame(&mut lookup)?;
        check(matches!(id::Request::decode(&bytes).map_err(io::Error::other)?, id::Request::Lookup { name } if name == b"chosen"), "selected ego was not resolved by its original lookup")?;
        let selected = key(1)?;
        peer.identity(&mut lookup, id::Response::Update { name: Some(b"chosen"), key: selected.view().map_err(io::Error::other)? })?;
        peer.eof(&mut lookup)?; peer.eof(&mut inventory)
    });
    let listener = fixture.listener("namestore")?;
    fixture.spawn(listener, |peer, listener| {
        let mut stream = peer.accept(&listener)?;
        let rid = start(&peer, &mut stream, Some(1))?;
        record(&peer, &mut stream, rid, 1, b"selected")?;
        next(&peer, &mut stream, rid)?;
        peer.namestore(&mut stream, ns::Response::End { rid })?;
        let mut writer = peer.accept(&listener)?;
        let rid = empty_store(&peer, &mut writer, 1, b"selected")?;
        peer.namestore(&mut writer, ns::Response::Generic { rid, code: 0 })?;
        peer.eof(&mut writer)?;
        peer.eof(&mut stream)?;
        peer.no_replay(&listener)
    });
    let mut args = fixture.args("purge-zone");
    args.extend([
        OsString::from("--ego"),
        OsString::from("chosen"),
        OsString::from("--limit"),
        OsString::from("1"),
    ]);
    let mut output = Zeroizing::new(Vec::new());
    let result = fixture.run(&args, &mut *output);
    fixture.finish()?;
    result?;
    check(
        event(&output, b"namestore_management_delete_result").count() == 1
            && contains(&output, b"\"successful_deletions\":1")
            && !contains(&output, b"\"private_key\""),
        "selected zone touched another authority or leaked its key",
    )?;
    Ok(())
}

struct ScanHook {
    output: Zeroizing<Vec<u8>>,
    line: usize,
    triggered: bool,
    request: std::sync::mpsc::SyncSender<()>,
    prefix_written: std::sync::mpsc::Receiver<()>,
}
impl Write for ScanHook {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        if self.output.last() == Some(&b'\n') {
            let selected = contains(
                &self.output[self.line..],
                b"namestore_management_scan_complete",
            );
            self.line = self.output.len();
            if selected && !self.triggered {
                self.triggered = true;
                self.request.send(()).map_err(|_| {
                    io::Error::other("partial inventory peer stopped before scan hook")
                })?;
                // Returning from the actual scan-complete output is held until
                // two original UPDATE header bytes reached the identity socket.
                self.prefix_written
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| io::Error::other("partial inventory prefix was not written"))?;
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn retained_partial_identity_update_blocks_store_until_same_key_rename_is_complete() -> Result {
    use std::sync::mpsc::sync_channel;
    let mut fixture = Fixture::new()?;
    let (request, requested) = sync_channel(1);
    let (acknowledge, prefix_written) = sync_channel(1);
    let (prefix_ready, prefix_ready_rx) = sync_channel(1);
    let (release, released) = sync_channel(1);
    let listener = fixture.listener("identity")?;
    fixture.spawn(listener, move |peer, listener| {
        let mut stream = peer.accept(&listener)?;
        identity_start(&peer, &mut stream, &[(1, b"owned")])?;
        requested
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| io::Error::other("scan did not reach the inventory handshake"))?;
        let original = key(1)?;
        let update = id::Response::Update {
            name: Some(b"owned-renamed"),
            key: original.view().map_err(io::Error::other)?,
        };
        let mut bytes = Zeroizing::new(vec![0; update.encoded_len().map_err(io::Error::other)?]);
        update.encode(&mut bytes).map_err(io::Error::other)?;
        peer.write(&mut stream, &bytes[..2])?;
        prefix_ready
            .send(())
            .map_err(|_| io::Error::other("deletion peer stopped before inventory prefix"))?;
        acknowledge
            .send(())
            .map_err(|_| io::Error::other("scan hook stopped before inventory prefix"))?;
        released
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| io::Error::other("partial inventory hold was not released"))?;
        peer.write(&mut stream, &bytes[2..])?;
        peer.eof(&mut stream)
    });
    let listener = fixture.listener("namestore")?;
    fixture.spawn(listener, move |peer, listener| {
        let mut iterator = peer.accept(&listener)?;
        let rid = start(&peer, &mut iterator, None)?;
        record(&peer, &mut iterator, rid, 2, b"orphan")?;
        next(&peer, &mut iterator, rid)?;
        peer.namestore(&mut iterator, ns::Response::End { rid })?;
        prefix_ready_rx
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| io::Error::other("original partial inventory UPDATE was not offered"))?;
        // A connection may be constructed independently, but no byte of STORE
        // may reach it while the original identity frame is still incomplete.
        let until = Instant::now() + Duration::from_millis(30);
        let mut writer: Option<UnixStream> = None;
        while Instant::now() < until {
            peer.guard()?;
            if let Some(stream) = writer.as_mut() {
                match stream.read(&mut [0]) {
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(error),
                    Ok(0) => {
                        return Err(io::Error::other(
                            "deletion source closed before legal identity rename",
                        ));
                    }
                    Ok(_) => {
                        return Err(io::Error::other(
                            "STORE advanced while identity UPDATE was incomplete",
                        ));
                    }
                }
            } else {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_millis(5)))?;
                        stream.set_write_timeout(Some(Duration::from_millis(20)))?;
                        writer = Some(stream);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        release.send(()).map_err(|_| {
            io::Error::other("identity peer stopped before completing original rename")
        })?;
        let mut writer = match writer {
            Some(stream) => stream,
            None => peer.accept(&listener)?,
        };
        let rid = empty_store(&peer, &mut writer, 2, b"orphan")?;
        peer.namestore(&mut writer, ns::Response::Generic { rid, code: 0 })?;
        peer.eof(&mut writer)?;
        peer.eof(&mut iterator)?;
        peer.no_replay(&listener)
    });
    let mut output = ScanHook {
        output: Zeroizing::new(Vec::new()),
        line: 0,
        triggered: false,
        request,
        prefix_written,
    };
    let result = fixture.run(&fixture.args("purge-orphans"), &mut output);
    fixture.finish()?;
    result?;
    let closed = event(&output.output, b"namestore_management_closed")
        .next()
        .ok_or("missing inventory-gated cleanup report")?;
    check(
        output.triggered
            && contains(closed, b"\"successful_deletions\":1")
            && contains(&output.output, b"namestore_management_complete"),
        "completed same-key rename did not release the original deletion",
    )?;
    Ok(())
}
