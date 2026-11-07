//! Normal CLI/task routes against real local DATASTORE peers; these are not
//! official C or P2P acceptance claims.
use super::super::{publish::settings, run};
use super::*;
use gnunet::{
    fs::{Content, Uri},
    fs_host::{durable::store, publication::Task},
    wire::datastore::{Request, Response, Status},
};
use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::DirBuilderExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
const ABSOLUTE: u64 = 9_000_000_000_123_456;
fn check(value: bool, message: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        loop {
            let path = std::env::temp_dir().join(format!(
                "fs-publish-policy-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}
struct StorePeer {
    finished: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    peer: Option<JoinHandle<io::Result<Vec<u32>>>>,
}
fn guard(until: Instant, stop: &AtomicBool) -> io::Result<()> {
    if Instant::now() >= until || stop.load(Ordering::SeqCst) {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original publication peer bound",
        ))
    } else {
        Ok(())
    }
}
fn read(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    until: Instant,
    stop: &AtomicBool,
) -> io::Result<usize> {
    loop {
        guard(until, stop)?;
        match stream.read(bytes) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            result => return result,
        }
    }
}
fn exact(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    until: Instant,
    stop: &AtomicBool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let count = read(stream, bytes, until, stop)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "partial publication frame",
            ));
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}
impl StorePeer {
    fn new(path: &Path, expected: BlockOptions) -> io::Result<Self> {
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        let finished = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let done = finished.clone();
        let stopped = stop.clone();
        let peer = thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(5);
            let mut kinds = Vec::new();
            loop {
                guard(until, &stopped)?;
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if done.load(Ordering::SeqCst) {
                            return Ok(kinds);
                        }
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                stream.set_read_timeout(Some(Duration::from_millis(20)))?;
                stream.set_write_timeout(Some(Duration::from_millis(20)))?;
                loop {
                    let mut header = [0; 4];
                    if read(&mut stream, &mut header[..1], until, &stopped)? == 0 {
                        break;
                    }
                    exact(&mut stream, &mut header[1..], until, &stopped)?;
                    let size = gnunet::wire::MessageHeader::decode(&header)
                        .map_err(io::Error::other)?
                        .size();
                    let mut bytes = Zeroizing::new(vec![0; size]);
                    bytes[..4].copy_from_slice(&header);
                    exact(&mut stream, &mut bytes[4..], until, &stopped)?;
                    let Request::Put(data) = Request::decode(&bytes).map_err(io::Error::other)?
                    else {
                        return Err(io::Error::other(
                            "normal task route issued an unexpected DATASTORE operation",
                        ));
                    };
                    check(
                        data.priority == expected.priority
                            && data.anonymity == expected.anonymity
                            && data.replication == expected.replication
                            && data.expiration == expected.expiration,
                        "actual PUT did not retain the original publication policy",
                    )?;
                    kinds.push(data.kind);
                    let mut response = [0; 16];
                    let size = Response::Status(Status {
                        code: 1,
                        min_expiration: AbsoluteTime::UNIX_EPOCH,
                        message: None,
                    })
                    .encode(&mut response)
                    .map_err(io::Error::other)?;
                    stream.write_all(&response[..size])?;
                }
            }
        });
        Ok(Self {
            finished,
            stop,
            peer: Some(peer),
        })
    }
    fn run(&self, args: &[OsString], output: &mut impl Write) -> Result {
        let result = run(args, output);
        self.finished.store(true, Ordering::SeqCst);
        result
    }
    fn finish(&mut self) -> io::Result<Vec<u32>> {
        match self
            .peer
            .take()
            .ok_or_else(|| io::Error::other("publication peer already joined"))?
            .join()
        {
            Ok(result) => result,
            Err(_) => Err(io::Error::other("publication peer panicked")),
        }
    }
}
impl Drop for StorePeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(peer) = self.peer.take() {
            let _joined = peer.join();
        }
    }
}
fn target() -> Result<OsString> {
    let uri = Uri::Content(Content {
        key: [1; 64],
        query: [2; 64],
        size: 17,
    });
    let mut bytes = vec![0; uri.encoded_len()?];
    uri.encode(&mut bytes)?;
    use std::os::unix::ffi::OsStringExt;
    Ok(OsString::from_vec(bytes))
}
fn policy(args: &mut Vec<OsString>, expiration: &str) {
    args.extend(
        [
            "-p",
            "4294967295",
            "--anonymity",
            "0",
            "-r",
            "17",
            "--expiration-us",
            expiration,
        ]
        .map(OsString::from),
    );
}
fn retained(path: &Path) -> Result<BlockOptions> {
    Ok(Task::open(path, store::Limits::default())?
        .manifest()
        .blocks)
}

#[test]
fn ordinary_file_and_its_indirect_keyword_puts_use_the_selected_policy() -> Result {
    let temporary = Temporary::new()?;
    let source = temporary.0.join("policy-keyword.txt");
    fs::write(&source, b"publication policy fixture")?;
    let socket = temporary.0.join("datastore");
    let mut peer = StorePeer::new(
        &socket,
        BlockOptions {
            priority: 17,
            anonymity: 3,
            replication: 9,
            expiration: AbsoluteTime::NEVER,
        },
    )?;
    let args = vec![
        OsString::from("publish"),
        socket.into_os_string(),
        source.into_os_string(),
        "3".into(),
        "--state".into(),
        temporary.0.join("original").into_os_string(),
        "--priority".into(),
        "17".into(),
        "-a".into(),
        "3".into(),
        "--replication".into(),
        "9".into(),
        "--expiration".into(),
        "forever".into(),
    ];
    let mut output = Zeroizing::new(Vec::new());
    let result = peer.run(&args, &mut *output);
    let kinds = peer.finish()?;
    result?;
    check(
        kinds.contains(&1) && kinds.contains(&9),
        "normal publication did not perform both content and automatic KSK PUTs",
    )?;
    Ok(())
}

#[test]
fn every_preparation_route_restores_the_same_policy_and_keeps_value_arguments_atomic() -> Result {
    let temporary = Temporary::new()?;
    let source = temporary.0.join("source");
    fs::write(&source, b"prepared file")?;
    let tree = temporary.0.join("tree");
    fs::create_dir(&tree)?;
    fs::write(tree.join("child"), b"prepared child")?;
    let key = temporary.0.join("key");
    let graph = temporary.0.join("graph");
    let mut output = Zeroizing::new(Vec::new());
    run(
        &[
            OsString::from("namespace-create"),
            key.clone().into_os_string(),
            graph.clone().into_os_string(),
        ],
        &mut *output,
    )?;
    let uri = target()?;
    let cases = [
        ("publish-task-file", vec![source.clone().into_os_string()]),
        ("publish-task-indexed", vec![source.into_os_string()]),
        ("publish-task-tree", vec![tree.clone().into_os_string()]),
        ("publish-task-tree-indexed", vec![tree.into_os_string()]),
        (
            "publish-task-keywords",
            vec!["gnunet://fs/ksk/selected".into(), uri.clone()],
        ),
        (
            "publish-task-namespace",
            vec![
                key.clone().into_os_string(),
                "identifier".into(),
                "".into(),
                uri.clone(),
            ],
        ),
        (
            "publish-task-managed-namespace",
            vec![
                key.into_os_string(),
                graph.into_os_string(),
                "identifier".into(),
                uri,
            ],
        ),
    ];
    for (index, (action, tail)) in cases.into_iter().enumerate() {
        let task = temporary.0.join(format!("task-{index}"));
        let mut args = vec![OsString::from(action), task.clone().into_os_string()];
        args.extend(tail);
        policy(&mut args, "9000000000123456");
        if action == "publish-task-managed-namespace" {
            args.extend(["--update", "--priority", "-m", "title:selected"].map(OsString::from));
        }
        run(&args, &mut *output)?;
        let original = retained(&task)?;
        check(
            original.priority == u32::MAX
                && original.anonymity == 0
                && original.replication == 17
                && original.expiration == AbsoluteTime::from_micros(ABSOLUTE),
            "prepared task did not restore its exact publication policy",
        )?;
    }
    let parsed = settings::metadata_arguments(
        &[
            "store",
            "ksk",
            "target",
            "-m",
            "--priority",
            "--timeout",
            "-r",
            "-p",
            "7",
        ],
        3,
        3,
        &[b"--timeout"],
    )?;
    check(
        parsed.manual.len() == 1
            && parsed.value(b"--timeout") == Some(OsStr::new("-r"))
            && parsed
                .publication
                .resolve(AbsoluteTime::UNIX_EPOCH)?
                .priority
                == 7,
        "metadata or named option value was rescanned as publication policy",
    )?;
    let literal = settings::content_arguments(&["--", "--priority", "--replication"])?;
    check(
        literal.positional == [OsStr::new("--priority"), OsStr::new("--replication")]
            && literal
                .publication
                .resolve(AbsoluteTime::UNIX_EPOCH)?
                .priority
                == 365,
        "literal publication paths became policy options",
    )?;
    for tail in [
        vec!["-p", "1", "--priority", "2"],
        vec!["-a", "4294967296"],
        vec!["-r", "-1"],
        vec!["--expiration-us", "18446744073709551616"],
        vec!["--expiration", "forever", "--expiration-us", "17"],
        vec!["--expiration", "-1 us"],
        vec!["--expiration", "18446744073709552 ms"],
        vec!["-p"],
    ] {
        let mut args = vec!["task", "source"];
        args.extend(tail);
        check(
            settings::content_arguments(&args).is_err(),
            "invalid publication policy was accepted",
        )?;
    }
    Ok(())
}

#[test]
fn restored_namespace_task_put_uses_its_original_policy_without_the_preparation_key() -> Result {
    let temporary = Temporary::new()?;
    let key = temporary.0.join("key");
    let graph = temporary.0.join("graph");
    let task = temporary.0.join("task");
    let mut output = Zeroizing::new(Vec::new());
    run(
        &[
            OsString::from("namespace-create"),
            key.clone().into_os_string(),
            graph.into_os_string(),
        ],
        &mut *output,
    )?;
    let mut args = vec![
        OsString::from("publish-task-namespace"),
        task.clone().into_os_string(),
        key.clone().into_os_string(),
        "original".into(),
        "".into(),
        target()?,
    ];
    policy(&mut args, "9000000000123456");
    run(&args, &mut *output)?;
    let expected = retained(&task)?;
    fs::remove_file(key)?;
    let socket = temporary.0.join("datastore");
    let mut peer = StorePeer::new(&socket, expected)?;
    let result = peer.run(
        &[
            OsString::from("publish-task-run"),
            socket.into_os_string(),
            task.into_os_string(),
            "3".into(),
        ],
        &mut *output,
    );
    let kinds = peer.finish()?;
    result?;
    check(
        kinds == [9],
        "restored namespace task did not emit exactly its original signed PUT",
    )?;
    Ok(())
}

#[test]
fn finite_publication_expirations_do_not_wrap_or_silently_become_forever() -> Result {
    struct OriginalClock(AtomicU64);
    impl RuntimeClock for OriginalClock {
        fn sample(
            &self,
        ) -> std::result::Result<gnunet_service_runtime::clock::ClockSample, gnunet_types::Error>
        {
            if self.0.fetch_add(1, Ordering::SeqCst) != 0 {
                return Err(gnunet_types::Error::Unavailable);
            }
            Ok(gnunet_service_runtime::clock::ClockSample {
                now: AbsoluteTime::from_micros(17),
                revision: 0,
            })
        }
        fn subscribe(
            &self,
        ) -> std::result::Result<
            Box<dyn gnunet_service_runtime::clock::ClockSubscription>,
            gnunet_types::Error,
        > {
            Err(gnunet_types::Error::Unsupported)
        }
    }
    let default = Selection::default();
    check(
        default
            .resolve(AbsoluteTime::from_micros(u64::MAX - DEFAULT_LIFETIME_US))
            .is_err(),
        "finite default lifetime became FOREVER",
    )?;
    let mut relative = Selection::default();
    let mut at = 0;
    check(
        relative.consume(&["--expiration", "2 days"], &mut at)?,
        "relative publication option was not consumed",
    )?;
    check(
        relative
            .resolve(AbsoluteTime::from_micros(u64::MAX - 1))
            .is_err(),
        "relative expiration wrapped absolute time",
    )?;
    let clock = OriginalClock(AtomicU64::new(0));
    let first = relative.select(&clock)?;
    check(
        first.expiration == AbsoluteTime::from_micros(172_800_000_017)
            && clock.0.load(Ordering::SeqCst) == 1,
        "relative publication expiration did not use one original sample",
    )?;
    let failure = relative
        .select(&clock)
        .err()
        .ok_or("original publication clock failure was ignored")?;
    check(
        failure.downcast_ref::<gnunet_types::Error>() == Some(&gnunet_types::Error::Unavailable),
        "original publication clock failure was replaced by expiration policy",
    )?;
    let mut forever = Selection::default();
    let mut at = 0;
    forever.consume(&["--expiration-us", "18446744073709551615"], &mut at)?;
    check(
        forever
            .resolve(AbsoluteTime::from_micros(u64::MAX - 1))?
            .expiration
            == AbsoluteTime::NEVER,
        "explicit absolute FOREVER was rejected",
    )?;
    Ok(())
}
