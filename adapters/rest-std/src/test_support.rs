//! Actual private Unix transport fixtures with source-constructed public IPC
//! replies. These are client/handler regressions, not official-service receipts.
use crate::{ConsumeProfile, Context, Error, Instances, Limits, OwnedRequest, Sources};
use gnunet_client_host::EndpointSource;
use gnunet_gnsrecord::ZoneKey;
use gnunet_reclaim::{AttributeList, PresentationList, ipc};
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use gnunet_types::Error as Fault;
use std::{
    io::{self, Read, Write},
    os::unix::{fs::DirBuilderExt, net::UnixListener},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use zeroize::Zeroizing;
pub(crate) type Failure = Box<dyn std::error::Error>;
static NEXT: AtomicUsize = AtomicUsize::new(0);
pub(crate) struct MissingIdna;
impl gnunet_dns::Idna for MissingIdna {
    fn to_ascii(&self, _: &[u8], _: &mut [u8]) -> Result<usize, Fault> {
        Err(Fault::Unavailable)
    }
    fn to_unicode_label(&self, _: &[u8], _: &mut [u8]) -> Result<usize, Fault> {
        Err(Fault::Unavailable)
    }
}
pub(crate) struct Setup {
    directory: PathBuf,
    pub clock: Arc<dyn RuntimeClock>,
    identity: gnunet_identity_client_host::Instance,
    namestore: gnunet_namestore_client_host::Instance,
    reclaim: gnunet_reclaim_client_host::Instance,
    idna: MissingIdna,
}
#[derive(Clone, Copy)]
pub(crate) enum Reply {
    Status(u32),
    LargeAttribute(u32),
    Disconnect,
    NoResponse,
}
/// Join the actual fixture owner on success, returned error and unwinding.
pub(crate) struct Peer {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<io::Result<()>>>,
}
#[derive(Debug)]
struct PeerFailure {
    original: Option<Failure>,
    peer: io::Error,
}
impl std::fmt::Display for PeerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(original) = &self.original {
            write!(f, "original handler/test failure: {original}; ")?;
        }
        write!(f, "original fixture peer failure: {}", self.peer)
    }
}
impl std::error::Error for PeerFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.original {
            Some(error) => Some(error.as_ref()),
            None => Some(&self.peer),
        }
    }
}
impl Peer {
    fn join(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| io::Error::other("fixture peer panicked"))?,
            None => Ok(()),
        }
    }
    pub fn finish(mut self, outcome: Result<(), Failure>) -> Result<(), Failure> {
        match (outcome, self.join()) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (outcome, Err(peer)) => Err(Box::new(PeerFailure {
                original: outcome.err(),
                peer,
            })),
        }
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        // During panic unwinding the original panic remains authoritative, but
        // the finite fixture thread must still be physically joined.
        let _joined = self.join();
    }
}
impl Setup {
    pub fn new() -> Result<Self, Failure> {
        let directory = std::env::temp_dir().join(format!(
            "rest-consume-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        Ok(Self {
            directory,
            clock: Arc::new(SystemClock),
            identity: Default::default(),
            namestore: Default::default(),
            reclaim: Default::default(),
            idna: MissingIdna,
        })
    }
    pub fn context(
        &self,
        profile: ConsumeProfile,
        lifetime: Duration,
    ) -> Result<Context<'_, MissingIdna>, Error> {
        let source =
            |name| EndpointSource::unix_with_clock(self.directory.join(name), self.clock.clone());
        let limits = Limits {
            lifetime,
            ..Default::default()
        };
        Ok(Context::new(
            Instances {
                identity: &self.identity,
                namestore: &self.namestore,
                reclaim: &self.reclaim,
            },
            Sources {
                identity: source("identity"),
                namestore: source("namestore"),
                reclaim: source("reclaim"),
            },
            &self.idna,
            gnunet_gnsrecord_text::Profile::LITTLE_255,
            limits,
        )?
        .with_consume_profile(profile))
    }
    pub fn peer(&self, identity: ZoneKey, replies: Vec<Reply>) -> io::Result<Peer> {
        let listener = UnixListener::bind(self.directory.join("reclaim"))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let end = std::time::Instant::now() + Duration::from_secs(5);
            for reply in replies {
                let mut stream = loop {
                    if worker_stop.load(Ordering::Acquire) {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "fixture peer stopped before its expected connection",
                        ));
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                && std::time::Instant::now() < end =>
                        {
                            thread::sleep(Duration::from_millis(1))
                        }
                        Err(error) => return Err(error),
                    }
                };
                // The listener's bounded accept loop is nonblocking; this
                // distinct worker uses bounded blocking stream IO explicitly.
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                let mut header = [0u8; 4];
                stream.read_exact(&mut header)?;
                let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
                if !(4..=65535).contains(&size) {
                    return Err(io::Error::other("invalid fixture request size"));
                }
                let mut frame = Zeroizing::new(vec![0; size]);
                frame[..4].copy_from_slice(&header);
                stream.read_exact(&mut frame[4..])?;
                let request = ipc::Request::decode(&frame).map_err(io::Error::other)?;
                let ipc::Request::ConsumeTicket { ticket, .. } = request else {
                    return Err(io::Error::other("expected actual consume request"));
                };
                if ticket.capability().map_err(io::Error::other)?.1 != identity {
                    return Err(io::Error::other("fixture consume issuer mismatch"));
                }
                let rid = request.request_id();
                match reply {
                    Reply::Disconnect => continue,
                    Reply::NoResponse => {}
                    Reply::Status(result) | Reply::LargeAttribute(result) => {
                        let mut attribute = Zeroizing::new(Vec::new());
                        if matches!(reply, Reply::LargeAttribute(_)) {
                            let mut value = [b'x'; 257];
                            value[256] = 0;
                            let item = gnunet_reclaim::Attribute::new(
                                gnunet_reclaim::Identifier::new([1; 32]),
                                gnunet_reclaim::Identifier::ZERO,
                                gnunet_reclaim::AttributeType::STRING,
                                gnunet_reclaim::Name::new(b"claim").map_err(io::Error::other)?,
                                gnunet_reclaim::Sensitive::new(&value),
                            );
                            attribute.resize(item.encoded_len().map_err(io::Error::other)?, 0);
                            item.encode(&mut attribute).map_err(io::Error::other)?;
                        }
                        let attributes =
                            AttributeList::new(&attribute, gnunet_reclaim::ListLimits::IPC)
                                .map_err(io::Error::other)?;
                        let response = ipc::Response::Consumed {
                            rid,
                            result,
                            reserved: 0,
                            identity: Some(identity),
                            attributes,
                            presentations: PresentationList::empty(),
                        };
                        let mut bytes =
                            Zeroizing::new(vec![
                                0;
                                response.encoded_len().map_err(io::Error::other)?
                            ]);
                        response.encode(&mut bytes).map_err(io::Error::other)?;
                        stream.write_all(&bytes)?;
                    }
                }
                let mut eof = [0];
                if stream.read(&mut eof)? != 0 {
                    return Err(io::Error::other("consume source replayed after its result"));
                }
            }
            Ok(())
        });
        Ok(Peer {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for Setup {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.directory);
    }
}
pub(crate) fn request(
    method: &str,
    target: &str,
    body: &[u8],
    authorization: Option<&[u8]>,
) -> Result<OwnedRequest, Failure> {
    let mut raw = Zeroizing::new(Vec::new());
    write!(
        &mut *raw,
        "{method} {target} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: {}\r\n",
        body.len(),
        if target == "/openid/token" {
            "application/x-www-form-urlencoded"
        } else {
            "application/json"
        }
    )?;
    if let Some(value) = authorization {
        raw.extend_from_slice(b"Authorization: ");
        raw.extend_from_slice(value);
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(body);
    let parsed = gnunet_rest::http::Request::parse(&raw, Default::default())?;
    let mut path = [0; 4096];
    let gnunet_rest::route::Resolution::Found(route) =
        gnunet_rest::route::resolve(&parsed, &mut path)?
    else {
        return Err("fixture route missing".into());
    };
    Ok(OwnedRequest::new(route, body, 65535)?.with_headers(&parsed, 65535)?)
}
pub(crate) fn header<'a>(response: &'a crate::Response, name: &[u8]) -> Option<&'a [u8]> {
    response
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_slice())
}
