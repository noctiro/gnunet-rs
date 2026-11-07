//! Actual native FS sockets/index worker with explicitly controlled dependencies.
//! These peers are Rust test fixtures, never unchanged-C or P2P acceptance.
#![cfg(all(unix, feature = "server"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible native service tests assert original owner retirement, actual output bytes and durable index state"
)]
use gnunet_config::Configuration;
use gnunet_fs::{content, service as pure};
use gnunet_fs_host::{
    index::{Index, Limits as IndexLimits, OnDemand},
    server::{
        Limits, NoPeers, Ports, Progress, Server, UnixAccess,
        ports::{self, Lookup, LookupProgress, NoSigner, StorePort},
    },
};
use gnunet_service_runtime::{
    Activation, BoundListeners,
    clock::SystemClock,
    framing::OwnedFrame,
    service::{Listener, ServiceOptions},
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::{Data, Response as StoreResponse},
    fs::{BlockType, Request, Response, SEARCH_LOOPBACK_ONLY, Search},
};
use std::{
    cell::RefCell,
    fs,
    future::{Future, poll_fn},
    io,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    pin::pin,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{Instant, timeout},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Native<'id, 'slots, 'seen> = Server<'id, 'slots, 'seen, ControlledStore, NoSigner, NoPeers>;
const WAIT: Duration = Duration::from_secs(3);

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-serving-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn socket(&self) -> PathBuf {
        self.0.join("fs.sock")
    }
    fn index(&self) -> PathBuf {
        self.0.join("index")
    }
    fn config(&self) -> TestResult<Configuration> {
        let mut config = Configuration::default();
        config.set_value(
            b"fs",
            b"UNIXPATH",
            Some(self.socket().as_os_str().as_bytes()),
        )?;
        config.set_number(b"fs", b"PORT", 0)?;
        Ok(config)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

#[derive(Default)]
struct StoreState {
    active: Option<Lookup>,
    starts: Vec<Lookup>,
    removing: bool,
    removes: Vec<([u8; 64], Vec<u8>)>,
    response: Option<OwnedFrame>,
    failure: Option<ports::Error>,
    waiting: Option<Waker>,
    closed: bool,
}
#[derive(Clone, Default)]
struct Control(Rc<RefCell<StoreState>>);
impl Control {
    fn starts(&self) -> Vec<Lookup> {
        self.0.borrow().starts.clone()
    }
    fn removes(&self) -> Vec<([u8; 64], Vec<u8>)> {
        self.0.borrow().removes.clone()
    }
    fn idle(&self) -> bool {
        let state = self.0.borrow();
        state.active.is_none()
            && !state.removing
            && state.response.is_none()
            && state.failure.is_none()
    }
    fn complete(&self, frame: OwnedFrame) -> TestResult {
        self.settle(Ok(frame))
    }
    fn complete_error(&self, error: ports::Error) -> TestResult {
        self.settle(Err(error))
    }
    fn settle(&self, result: Result<OwnedFrame, ports::Error>) -> TestResult {
        let waiting = {
            let mut state = self.0.borrow_mut();
            if (state.active.is_none() && !state.removing)
                || state.response.is_some()
                || state.failure.is_some()
            {
                return Err("test tried to replace an original pending operation".into());
            }
            match result {
                Ok(frame) => state.response = Some(frame),
                Err(error) => state.failure = Some(error),
            }
            state.waiting.take()
        };
        if let Some(waiting) = waiting {
            waiting.wake();
        }
        Ok(())
    }
}
struct ControlledStore(Control);
impl StorePort for ControlledStore {
    fn start(&mut self, lookup: Lookup) -> Result<(), ports::Error> {
        let mut state = self.0.0.borrow_mut();
        if state.closed || state.active.is_some() || state.removing {
            return Err(ProtocolError::Conflict.into());
        }
        state.active = Some(lookup);
        state.starts.push(lookup);
        Ok(())
    }
    fn start_remove(&mut self, key: &[u8; 64], value: &[u8]) -> Result<(), ports::Error> {
        let mut state = self.0.0.borrow_mut();
        if state.closed || state.active.is_some() || state.removing {
            return Err(ProtocolError::Conflict.into());
        }
        state.removing = true;
        state.removes.push((*key, value.to_vec()));
        Ok(())
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<LookupProgress, ports::Error>> {
        let mut state = self.0.0.borrow_mut();
        if state.active.is_none() && !state.removing {
            return Poll::Pending;
        }
        if let Some(error) = state.failure.take() {
            state.active = None;
            state.removing = false;
            return Poll::Ready(Err(error));
        }
        match state.response.take() {
            Some(frame) if state.removing => {
                state.removing = false;
                Poll::Ready(Ok(LookupProgress::Removed(
                    ports::RetainedReply::from_frame(frame),
                )))
            }
            Some(frame) => {
                state.active = None;
                // Only fixture-supplied actual DATA_END becomes None.
                let end = matches!(StoreResponse::decode(frame.bytes()), Ok(StoreResponse::End));
                Poll::Ready(Ok(LookupProgress::Complete((!end).then_some(frame))))
            }
            None => {
                state.waiting = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
    fn close(&mut self) -> Result<(), ports::Error> {
        let mut state = self.0.0.borrow_mut();
        state.closed = true;
        state.active = None;
        state.removing = false;
        state.response = None;
        state.failure = None;
        state.waiting = None;
        Ok(())
    }
}
fn make_server<'id, 'slots, 'seen>(
    protocol: pure::Service<'id, 'slots, 'seen>,
    directory: &Directory,
    control: Control,
) -> TestResult<Native<'id, 'slots, 'seen>> {
    Ok(Server::new(
        protocol,
        Ports {
            datastore: ControlledStore(control),
            signer: NoSigner,
            peers: NoPeers,
            index: Index::open(directory.index(), IndexLimits::default())?,
            clock: Arc::new(SystemClock),
        },
        Limits {
            clients: 1,
            route_slots: 1,
            index_queue: 2,
            io_slice_bytes: 3,
            rescan_interval: Duration::from_secs(3600),
        },
        ServiceOptions::default(),
        UnixAccess {
            match_uid: true,
            match_gid: false,
        },
    )?)
}
fn search(query: [u8; 64]) -> Request<'static> {
    Request::Search(Search {
        options: SEARCH_LOOPBACK_ONLY,
        block_type: BlockType::DBLOCK,
        anonymity: 0,
        target: [0; 32],
        query,
        seen: &[],
    })
}
fn frame(request: Request<'_>) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = vec![0; request.encoded_len()?];
    request.encode(&mut bytes)?;
    Ok(bytes)
}
fn stored(
    query: &[u8; 64],
    value: &[u8],
    kind: u32,
    uid: u64,
    expiration: u64,
) -> Result<OwnedFrame, ProtocolError> {
    let mut bytes = vec![0; 112 + value.len()];
    StoreResponse::Data(Data {
        reservation: 0,
        kind,
        priority: 1,
        anonymity: 0,
        replication: 1,
        uid,
        expiration: AbsoluteTime::from_micros(expiration),
        key: query,
        value,
    })
    .encode(&mut bytes)?;
    Ok(OwnedFrame::new(bytes))
}
async fn read_frame(socket: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    socket.read_exact(&mut header).await?;
    let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if n < 4 {
        return Err(io::Error::other("invalid service frame length"));
    }
    let mut frame = vec![0; n];
    frame[..4].copy_from_slice(&header);
    socket.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}
async fn step(server: &mut Native<'_, '_, '_>, listeners: &[Listener<'_>]) -> TestResult {
    match timeout(
        WAIT,
        server.drive(listeners, Some(Instant::now() + WAIT), |_| {}),
    )
    .await?
    {
        Progress::Stopped | Progress::WaitDeadline => {
            Err(io::Error::other("native service stopped or timed out before expected work").into())
        }
        _ => Ok(()),
    }
}
async fn drain_ready(server: &mut Native<'_, '_, '_>, listeners: &[Listener<'_>]) -> TestResult {
    for _ in 0..4096 {
        match timeout(WAIT, server.drive(listeners, Some(Instant::now()), |_| {})).await? {
            Progress::WaitDeadline => return Ok(()),
            Progress::Stopped => {
                return Err(io::Error::other("native service stopped during ready work").into());
            }
            _ => {}
        }
    }
    Err(io::Error::other("bounded fixture did not settle its ready work").into())
}
// Retain the original socket IO future and cancel only each observation wait.
async fn with_server<T>(
    server: &mut Native<'_, '_, '_>,
    listeners: &[Listener<'_>],
    io: impl Future<Output = io::Result<T>>,
) -> TestResult<T> {
    enum Step<T> {
        Io(Result<io::Result<T>, tokio::time::error::Elapsed>),
        Server(Progress),
    }
    let mut io = pin!(timeout(WAIT, io));
    loop {
        let mut drive = pin!(server.drive(listeners, None, |_| {}));
        match poll_fn(|cx| {
            if let Poll::Ready(value) = io.as_mut().poll(cx) {
                return Poll::Ready(Step::Io(value));
            }
            drive.as_mut().poll(cx).map(Step::Server)
        })
        .await
        {
            Step::Io(value) => return Ok(value??),
            Step::Server(Progress::Stopped | Progress::WaitDeadline) => {
                return Err(io::Error::other("service stopped during actual socket IO").into());
            }
            Step::Server(_) => {}
        }
    }
}
async fn stopped(server: &mut Native<'_, '_, '_>) -> TestResult {
    let report = timeout(WAIT, server.shutdown(|_| {})).await?;
    assert!(report.worker_quiesced);
    if let Some(error) = report.failure {
        return Err(error.into());
    }
    Ok(())
}

#[test]
fn closed_client_late_datastore_reply_cannot_authorize_replacement_and_waits_retain_output()
-> TestResult {
    let directory = Directory::new()?;
    let config = directory.config()?;
    let mut block = vec![0; content::BLOCK_BYTES + content::TAG_BYTES];
    let encoded =
        content::encode_data(b"actual content under the same requested query", &mut block)?;
    let query = encoded.key().query;
    let block = encoded.bytes().to_vec();
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&config, b"fs", Activation::default()).await?;
        let listeners = bound.listeners();
        let mut instance = pure::Instance::new();
        let mut clients = [pure::ClientSlot::default(); 1];
        let mut hashes = [[0; 64]; 4];
        let mut queries = [pure::QuerySlot::new(&mut hashes)];
        let protocol = pure::Service::new(
            &mut instance,
            &mut clients,
            &mut queries,
            pure::Limits::default(),
        )?;
        let control = Control::default();
        let mut server = make_server(protocol, &directory, control.clone())?;
        let mut old = UnixStream::connect(directory.socket()).await?;
        old.write_all(&frame(search(query))?).await?;
        while control.starts().len() != 1 {
            step(&mut server, &listeners).await?;
        }
        drain_ready(&mut server, &listeners).await?;
        {
            let mut original_wait = pin!(server.drive(&listeners, None, |_| {}));
            poll_fn(|cx| {
                assert!(original_wait.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(control.starts().len(), 1); // Dropping the pending wait did not recreate GET.
        drop(old);
        while server.report().closed != 1 {
            step(&mut server, &listeners).await?;
        }
        let mut replacement = UnixStream::connect(directory.socket()).await?;
        replacement.write_all(&frame(search(query))?).await?;
        while server.report().searches != 2 {
            step(&mut server, &listeners).await?;
        }
        assert_eq!(control.starts().len(), 1); // Original GET still owns the single port.
        control.complete(stored(&query, &block, 1, 17, 11)?)?;
        while control.starts().len() != 2 {
            step(&mut server, &listeners).await?;
        }
        drain_ready(&mut server, &listeners).await?;
        let mut one = [0];
        assert_eq!(
            replacement
                .try_read(&mut one)
                .err()
                .ok_or("late reply leaked to replacement")?
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(server.report().local_results, 0);
        control.complete(stored(&query, &block, 1, 29, 22)?)?;
        while server.report().local_results == 0 {
            step(&mut server, &listeners).await?;
        }
        assert_eq!(server.report().written_bytes, 0); // Reply is queued on its original socket.
        let answer = with_server(&mut server, &listeners, read_frame(&mut replacement)).await?;
        let Response::Put(result) = Response::decode(&answer)? else {
            return Err("fresh lookup did not produce actual FS PUT".into());
        };
        assert_eq!(result.block, block);
        assert_eq!(result.expiration, AbsoluteTime::from_micros(22));
        assert_eq!(server.report().written_bytes, answer.len() as u64);
        assert_eq!(server.report().accepted, 2);
        assert_eq!(server.report().local_results, 1);
        assert_eq!(control.starts().len(), 2);
        drop(replacement);
        stopped(&mut server).await?;
        Ok(())
    })
}

#[test]
fn actual_native_index_admin_and_type6_tail_resolve_survive_retained_worker_waits() -> TestResult {
    let directory = Directory::new()?;
    let config = directory.config()?;
    let source = directory.0.join("source.bin");
    let plaintext: Vec<_> = (0..content::BLOCK_BYTES + 21)
        .map(|i| (i * 17 + i / content::BLOCK_BYTES) as u8)
        .collect();
    fs::write(&source, &plaintext)?;
    let file_id = gnunet_crypto::hash512(&plaintext);
    let mut ciphertext = vec![0; content::BLOCK_BYTES + content::TAG_BYTES];
    let encoded = content::encode_data(&plaintext[content::BLOCK_BYTES..], &mut ciphertext)?;
    let query = encoded.key().query;
    let expected = encoded.bytes().to_vec();
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&config, b"fs", Activation::default()).await?;let listeners = bound.listeners();
        let mut instance = pure::Instance::new();let mut clients = [pure::ClientSlot::default();1];let mut hashes = [[0;64];4];let mut queries = [pure::QuerySlot::new(&mut hashes)];
        let protocol = pure::Service::new(&mut instance, &mut clients, &mut queries, pure::Limits::default())?;
        let control = Control::default();let mut server = make_server(protocol, &directory, control.clone())?;
        let mut socket = UnixStream::connect(directory.socket()).await?;
        let input = frame(Request::IndexStart { device: 0, inode: 0, file_id, filename: source.as_os_str().as_bytes() })?;
        let answer = with_server(&mut server, &listeners, async { socket.write_all(&input).await?;read_frame(&mut socket).await }).await?;
        assert!(matches!(Response::decode(&answer)?, Response::IndexStarted));
        let input = frame(Request::IndexList)?;
        let (entry, end) = with_server(&mut server, &listeners, async { socket.write_all(&input).await?;Ok((read_frame(&mut socket).await?,read_frame(&mut socket).await?)) }).await?;
        assert!(matches!(Response::decode(&entry)?, Response::IndexEntry { file_id: id, filename } if id == file_id && filename == source.as_os_str().as_bytes()));
        assert!(matches!(Response::decode(&end)?, Response::IndexEnd));
        socket.write_all(&frame(search(query))?).await?;
        while control.starts().len() != 1 { step(&mut server, &listeners).await?; }
        let record = OnDemand { file_id, offset: content::BLOCK_BYTES as u64 }.encode();
        control.complete(stored(&query, &record, 6, 31, 444)?)?;
        let answer = with_server(&mut server, &listeners, read_frame(&mut socket)).await?;
        assert!(matches!(Response::decode(&answer)?, Response::Put(value) if value.block_type == BlockType::DBLOCK && value.block == expected && value.expiration == AbsoluteTime::from_micros(444)));
        for _ in 0..2 {
            let input = frame(Request::Unindex { file_id })?;
            let answer = with_server(&mut server, &listeners, async { socket.write_all(&input).await?;read_frame(&mut socket).await }).await?;
            assert!(matches!(Response::decode(&answer)?, Response::Unindexed));
        }
        let input = frame(Request::IndexList)?;
        let answer = with_server(&mut server, &listeners, async { socket.write_all(&input).await?;read_frame(&mut socket).await }).await?;
        assert!(matches!(Response::decode(&answer)?, Response::IndexEnd));
        assert_eq!(server.report().local_results, 1);
        drop(socket);stopped(&mut server).await?;drop(server);
        assert!(Index::open(directory.index(), IndexLimits::default())?.entries()?.next().is_none());
        Ok(())
    })
}

fn store_status(code: i32, message: Option<&[u8]>) -> Result<OwnedFrame, ProtocolError> {
    let mut bytes = vec![0; 16 + message.map_or(0, <[u8]>::len)];
    StoreResponse::Status(gnunet_wire::official::datastore::Status {
        code,
        min_expiration: AbsoluteTime::from_micros(97),
        message,
    })
    .encode(&mut bytes)?;
    Ok(OwnedFrame::new(bytes))
}
fn store_end() -> Result<OwnedFrame, ProtocolError> {
    let mut bytes = vec![0; 4];
    StoreResponse::End.encode(&mut bytes)?;
    Ok(OwnedFrame::new(bytes))
}
// The dependency is explicitly held pending during this socket observation.
// Elapsed time is not interpreted as a datastore miss or FS completion.
async fn assert_pending_socket_silent(
    server: &mut Native<'_, '_, '_>,
    listeners: &[Listener<'_>],
    socket: &mut UnixStream,
) -> TestResult {
    let observation = with_server(server, listeners, async {
        Ok(timeout(Duration::from_millis(20), socket.read_u8()).await)
    })
    .await?;
    assert!(
        observation.is_err(),
        "maintenance bytes or an invented FS result reached a waiting socket"
    );
    Ok(())
}

#[test]
fn malformed_type6_cleanup_retains_exact_bytes_and_cannot_reply_to_replacement() -> TestResult {
    let directory = Directory::new()?;
    let config = directory.config()?;
    let mut ciphertext = vec![0; content::BLOCK_BYTES + content::TAG_BYTES];
    let encoded = content::encode_data(
        b"fresh result for the replacement connection",
        &mut ciphertext,
    )?;
    let query = encoded.key().query;
    let expected = encoded.bytes().to_vec();
    let malformed = b"\0malformed type6\xff";
    assert_ne!(malformed.len(), 72);
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&config, b"fs", Activation::default()).await?;
        let listeners = bound.listeners();
        let mut instance = pure::Instance::new();
        let mut clients = [pure::ClientSlot::default(); 1];
        let mut hashes = [[0; 64]; 4];
        let mut queries = [pure::QuerySlot::new(&mut hashes)];
        let protocol = pure::Service::new(
            &mut instance,
            &mut clients,
            &mut queries,
            pure::Limits::default(),
        )?;
        let control = Control::default();
        let mut server = make_server(protocol, &directory, control.clone())?;
        let mut old = UnixStream::connect(directory.socket()).await?;
        old.write_all(&frame(search(query))?).await?;
        while control.starts().len() != 1 {
            step(&mut server, &listeners).await?;
        }
        control.complete(stored(&query, malformed, 6, 17, 11)?)?;
        while control.removes().len() != 1 {
            step(&mut server, &listeners).await?;
        }
        assert_eq!(control.removes(), vec![(query, malformed.to_vec())]);
        assert_eq!(server.report().on_demand_removed, 0);
        assert_eq!(control.starts().len(), 1);
        drop(old);
        while server.report().closed != 1 {
            step(&mut server, &listeners).await?;
        }
        let mut replacement = UnixStream::connect(directory.socket()).await?;
        replacement.write_all(&frame(search(query))?).await?;
        while server.report().searches != 2 {
            step(&mut server, &listeners).await?;
        }
        assert_eq!(control.starts().len(), 1); // Original REMOVE retains the shared port.
        control.complete(store_status(1, None)?)?;
        while control.starts().len() != 2 {
            step(&mut server, &listeners).await?;
        }
        assert_eq!(server.report().on_demand_removed, 1);
        assert_eq!(server.report().on_demand_cleanup_failures, 0);
        assert_eq!(server.report().local_results, 0);
        assert_pending_socket_silent(&mut server, &listeners, &mut replacement).await?;
        control.complete(stored(&query, &expected, 1, 29, 22)?)?;
        let answer = with_server(&mut server, &listeners, read_frame(&mut replacement)).await?;
        assert!(matches!(Response::decode(&answer)?, Response::Put(value)
            if value.block == expected && value.expiration == AbsoluteTime::from_micros(22)));
        assert_eq!(server.report().local_results, 1);
        assert_eq!(control.removes(), vec![(query, malformed.to_vec())]);
        assert_eq!(control.starts().len(), 2);
        drop(replacement);
        stopped(&mut server).await?;
        Ok(())
    })
}

#[test]
fn missing_index_keeps_record_and_unavailable_source_cleanup_retains_refusal_and_unknown()
-> TestResult {
    let directory = Directory::new()?;
    let config = directory.config()?;
    let source = directory.0.join("cleanup-source.bin");
    let plaintext = b"registered source for exact type6 cleanup";
    fs::write(&source, plaintext)?;
    let file_id = gnunet_crypto::hash512(plaintext);
    let mut ciphertext = vec![0; content::BLOCK_BYTES + content::TAG_BYTES];
    let query = content::encode_data(plaintext, &mut ciphertext)?
        .key()
        .query;
    let record = OnDemand { file_id, offset: 0 }.encode();
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&config, b"fs", Activation::default()).await?;
        let listeners = bound.listeners();
        let mut instance = pure::Instance::new();
        let mut clients = [pure::ClientSlot::default(); 1];
        let mut hashes = [[0; 64]; 4];
        let mut queries = [pure::QuerySlot::new(&mut hashes)];
        let protocol = pure::Service::new(
            &mut instance,
            &mut clients,
            &mut queries,
            pure::Limits::default(),
        )?;
        let control = Control::default();
        let mut server = make_server(protocol, &directory, control.clone())?;
        let mut socket = UnixStream::connect(directory.socket()).await?;
        socket.write_all(&frame(search(query))?).await?;
        while control.starts().len() != 1 {
            step(&mut server, &listeners).await?;
        }
        // The file exists but has no local index registration: retain its record.
        control.complete(stored(&query, &record, 6, 5, 100)?)?;
        while control.starts().len() != 2 {
            step(&mut server, &listeners).await?;
        }
        assert!(control.removes().is_empty());
        assert_eq!(control.starts()[1].next_uid, 6);
        assert_pending_socket_silent(&mut server, &listeners, &mut socket).await?;
        control.complete(store_end()?)?;
        while !control.idle() {
            step(&mut server, &listeners).await?;
        }
        let input = frame(Request::IndexStart {
            device: 0,
            inode: 0,
            file_id,
            filename: source.as_os_str().as_bytes(),
        })?;
        let answer = with_server(&mut server, &listeners, async {
            socket.write_all(&input).await?;
            read_frame(&mut socket).await
        })
        .await?;
        assert!(matches!(Response::decode(&answer)?, Response::IndexStarted));
        fs::remove_file(&source)?;
        socket.write_all(&frame(search(query))?).await?;
        while control.starts().len() != 3 {
            step(&mut server, &listeners).await?;
        }
        control.complete(stored(&query, &record, 6, 21, 200)?)?;
        while control.removes().len() != 1 {
            step(&mut server, &listeners).await?;
        }
        assert_eq!(control.removes(), vec![(query, record.to_vec())]);
        let refusal = store_status(0, Some(b"actual cleanup refusal\xff\0"))?;
        let refusal_bytes = refusal.bytes().to_vec();
        control.complete(refusal)?;
        let mut actual_refusal = None;
        while control.starts().len() != 4 {
            let progress = timeout(
                WAIT,
                server.drive(&listeners, None, |event| {
                    if let gnunet_fs_host::server::Event::Fault { cause, .. } = event
                        && let gnunet_fs_host::server::Error::Port(ports::Error::RemoveRefused(
                            reply,
                        )) = cause.as_ref()
                    {
                        actual_refusal = Some(reply.bytes().to_vec());
                    }
                }),
            )
            .await?;
            assert!(!matches!(
                progress,
                Progress::Stopped | Progress::WaitDeadline
            ));
        }
        assert_eq!(actual_refusal, Some(refusal_bytes));
        assert_eq!(control.starts()[3].next_uid, 22);
        assert_eq!(server.report().on_demand_removed, 0);
        assert_eq!(server.report().on_demand_cleanup_failures, 1);
        assert_pending_socket_silent(&mut server, &listeners, &mut socket).await?;
        control.complete(store_end()?)?;
        while !control.idle() {
            step(&mut server, &listeners).await?;
        }
        socket.write_all(&frame(search(query))?).await?;
        while control.starts().len() != 5 {
            step(&mut server, &listeners).await?;
        }
        control.complete(stored(&query, &record, 6, 31, 300)?)?;
        while control.removes().len() != 2 {
            step(&mut server, &listeners).await?;
        }
        assert_eq!(control.removes(), vec![(query, record.to_vec()); 2]);
        {
            let mut original_shutdown = pin!(server.shutdown(|_| {}));
            poll_fn(|cx| {
                assert!(original_shutdown.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        // Canceling the shutdown wait must not physically retire admitted REMOVE.
        assert!(!server.report().worker_quiesced);
        assert!(control.0.borrow().removing);
        assert!(!control.0.borrow().closed);
        control.complete_error(ports::Error::DatastoreOperation {
            outcome: gnunet_datastore_host::Outcome::Unknown,
            interruption: None,
            cause: None,
            reply: None,
        })?;
        let mut unknown_observed = false;
        let report = timeout(
            WAIT,
            server.shutdown(|event| {
                if let gnunet_fs_host::server::Event::Fault { cause, .. } = event
                    && let gnunet_fs_host::server::Error::Port(error) = cause.as_ref()
                {
                    unknown_observed |=
                        error.outcome() == Some(gnunet_datastore_host::Outcome::Unknown);
                }
            }),
        )
        .await?;
        assert!(unknown_observed);
        assert!(report.worker_quiesced);
        assert!(report.failure.is_none());
        assert_eq!(report.on_demand_removed, 0);
        assert_eq!(report.on_demand_cleanup_failures, 2);
        assert_eq!(report.local_results, 0);
        assert_eq!(control.starts().len(), 5);
        assert_eq!(control.removes(), vec![(query, record.to_vec()); 2]);
        assert!(control.0.borrow().closed);
        let mut remaining = Vec::new();
        timeout(WAIT, socket.read_to_end(&mut remaining)).await??;
        assert!(
            remaining.is_empty(),
            "cleanup manufactured a client response before shutdown"
        );
        Ok(())
    })
}
