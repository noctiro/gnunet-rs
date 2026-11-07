//! Real signed KSK advertisements followed by native, owner-scoped range probes.
//! Local Rust service peers exercise original wire requests and encrypted blocks;
//! these fixtures are not original-C or whole-network interoperability acceptance.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Focused integration cases assert real signed advertisements, native outcomes and scoped settlement"
)]

use gnunet_fs::{
    Content, Keyword, Keywords, Uri,
    client::Instance,
    content::{BLOCK_BYTES, EncodedNode, Layout},
    ublock,
};
use gnunet_fs_host::{
    BlockSink, Buffers, Control, Insert, ipc, network,
    search::{self, ResultId, Session, Step, probe},
};
use gnunet_types::{AbsoluteTime, Duration as LogicalDuration, Error as ProtocolError};
use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Response, SEARCH_LOOPBACK_ONLY};
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Blocks = HashMap<[u8; 64], (BlockType, Vec<u8>)>;
const WAIT: Duration = Duration::from_secs(5);
const KEYWORD: &[u8] = b"availability";
const ANONYMITY: u32 = 7;

struct Socket(PathBuf);
impl Socket {
    fn bind() -> io::Result<(Self, UnixListener)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let socket = Self(std::env::temp_dir().join(format!(
            "gnunet-search-probe-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let listener = UnixListener::bind(&socket.0)?;
        Ok((socket, listener))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_file(&self.0);
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn deadline(source: &ipc::EndpointSource, micros: u64) -> Result<AbsoluteTime, ProtocolError> {
    source.clock().sample()?.now.after(LogicalDuration(micros))
}
fn session<'id>(
    identities: &'id mut [Instance],
    source: ipc::EndpointSource,
    deadline: AbsoluteTime,
) -> Result<Session<'id, impl FnMut() -> Result<ipc::EndpointSource, ipc::Error>, 4>, search::Error>
{
    let terms = [Keyword::new(KEYWORD, true)?];
    Session::new(
        Uri::Keywords(Keywords::new(&terms)?),
        identities,
        // duplicate retains the same original Arc clock for the search and
        // every detached native probe without opening another service socket.
        move || source.duplicate(),
        search::Options {
            anonymity: ANONYMITY,
            local_only: true,
            deadline,
            limits: search::Limits::default(),
            block: ublock::Limits::default(),
            protocol: ipc::ProtocolLimits::default(),
            native: ipc::Limits::default(),
        },
    )
}
async fn choose<'id, F>(session: &mut Session<'id, F, 4>) -> Result<ResultId, search::Error>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    loop {
        match session.drive(None).await? {
            Step::Result { result } | Step::Update { result } => return Ok(result),
            Step::Rejected { cause, .. } => return Err(cause),
            Step::Failed { cause, .. } => return Err(cause.into()),
            _ => {}
        }
    }
}

#[derive(Default)]
struct Store {
    blocks: Blocks,
    last_leaf: Option<[u8; 64]>,
}
impl BlockSink for Store {
    fn insert_block(&mut self, encoded: EncodedNode<'_>) -> gnunet_fs_host::Result<Insert> {
        let kind = if encoded.node().level() == 0 {
            self.last_leaf = Some(encoded.block().key().query);
            BlockType::DBLOCK
        } else {
            BlockType::IBLOCK
        };
        let _previous = self.blocks.insert(
            encoded.block().key().query,
            (kind, encoded.block().bytes().to_vec()),
        );
        Ok(Insert::Created)
    }
}
struct Tree {
    content: Content,
    blocks: Blocks,
    tail: [u8; 64],
}
fn tree(data: &[u8]) -> gnunet_fs_host::Result<Tree> {
    let mut store = Store::default();
    let published = Buffers::new().publish(
        &mut io::Cursor::new(data),
        data.len() as u64,
        &mut store,
        gnunet_fs_host::Limits::default(),
        |_| Control::Continue,
    )?;
    Ok(Tree {
        content: published.content,
        blocks: store.blocks,
        tail: store.last_leaf.ok_or(gnunet_fs_host::Error::Corrupt)?,
    })
}
fn advertisement(content: Content) -> TestResult<([u8; 64], Vec<u8>)> {
    let publisher = ublock::Publisher::keyword(KEYWORD, ublock::Limits::default())?;
    let query = *publisher.context().query();
    let mut output = vec![0; 2048];
    let block = publisher
        .seal(b"", content.uri(), None, &mut output)?
        .bytes()
        .to_vec();
    Ok((query, block))
}
async fn request(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < header.len() {
        return Err(io::Error::other("short FS frame"));
    }
    let mut frame = vec![0; length];
    frame[..4].copy_from_slice(&header);
    stream.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}
fn reply(kind: BlockType, block: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let response = Response::Put(ClientPut {
        block_type: kind,
        expiration: AbsoluteTime::NEVER,
        last_transmission: AbsoluteTime::UNIX_EPOCH,
        num_transmissions: 0,
        respect_offered: 0,
        block,
    });
    let mut frame = vec![0; response.encoded_len()?];
    response.encode(&mut frame)?;
    Ok(frame)
}
fn lookup(frame: &[u8], query: [u8; 64], kind: BlockType) -> TestResult {
    let Request::Search(search) = Request::decode(frame)? else {
        return Err("expected actual FS SEARCH".into());
    };
    assert_eq!(search.query, query);
    assert_eq!(search.block_type, kind);
    assert_eq!(search.anonymity, ANONYMITY);
    assert_eq!(search.options, SEARCH_LOOPBACK_ONLY);
    assert_eq!(search.target, [0; 32]);
    Ok(())
}
async fn advertise(stream: &mut UnixStream, query: [u8; 64], block: &[u8]) -> TestResult {
    let frame = request(stream).await?;
    lookup(&frame, query, BlockType::UBLOCK)?;
    stream.write_all(&reply(BlockType::UBLOCK, block)?).await?;
    Ok(())
}
async fn closed(stream: &mut UnixStream) -> io::Result<()> {
    let mut extra = [0];
    assert_eq!(stream.read(&mut extra).await?, 0);
    Ok(())
}

#[test]
fn signed_result_tail_probe_retains_native_proof_and_rejects_foreign_sessions() -> TestResult {
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        let tree = tree(&vec![19; 3 * BLOCK_BYTES + 19])?;
        let (query, signed) = advertisement(tree.content)?;
        let source = ipc::EndpointSource::unix(socket.0.clone());
        let session_deadline = deadline(&source, 4_000_000)?;
        let layout = Layout::new(tree.content.size);
        assert_eq!(layout.levels(), 2);
        let leaf = layout.leaf_count() - 1;
        let range = layout.leaf(leaf)?.range();
        let peer = async {
            let (mut a, _) = listener.accept().await?;
            advertise(&mut a, query, &signed).await?;
            let (mut b, _) = listener.accept().await?;
            advertise(&mut b, query, &signed).await?;
            let (mut native, _) = listener.accept().await?;
            let mut last = Vec::new();
            // This exact fixture has one index root and one short tail leaf.
            // Requests for any of the three full leaves fail the assertion.
            for wanted in [tree.content.query, tree.tail] {
                let frame = request(&mut native).await?;
                let (kind, block) = tree.blocks.get(&wanted).ok_or("missing path block")?;
                lookup(&frame, wanted, *kind)?;
                last = reply(*kind, block)?;
                native.write_all(&last).await?;
            }
            closed(&mut native).await?;
            closed(&mut a).await?;
            closed(&mut b).await?;
            Ok::<_, Box<dyn std::error::Error>>(last)
        };
        let client = async {
            let mut a_ids = [Instance::new()];
            let mut b_ids = [Instance::new()];
            let mut a = session(&mut a_ids, source.duplicate()?, session_deadline)?;
            let mut b = session(&mut b_ids, source.duplicate()?, session_deadline)?;
            let a_result = choose(&mut a).await?;
            let b_result = choose(&mut b).await?;
            assert_eq!(a_result.index(), b_result.index());
            assert_ne!(a_result, b_result);
            assert!(b.result(a_result).is_none());
            assert!(matches!(
                b.begin_probe(
                    a_result,
                    leaf,
                    probe::Options::new(deadline(&source, 2_000_000)?)
                ),
                Err(search::Error::Protocol(ProtocolError::Stale))
            ));
            assert!(b.availability_summary(b_result).is_none());
            let ticket = a.begin_probe(
                a_result,
                leaf,
                probe::Options::new(deadline(&source, 2_000_000)?),
            )?;
            assert_eq!(ticket.result(), a_result);
            let completed = ticket.run(&mut Buffers::new(), |_| Control::Continue).await;
            {
                let observed = completed
                    .observation()
                    .as_ref()
                    .map_err(|failure| io::Error::other(failure.to_string()))?;
                assert_eq!(observed.verified().content(), tree.content);
                assert_eq!(observed.range(), range);
                assert_eq!(observed.progress().blocks, 2);
                assert_eq!(observed.progress().plaintext_bytes, 19);
                assert_eq!(observed.queries_written(), 2);
                assert_eq!(observed.policy().anonymity, ANONYMITY);
                assert!(observed.policy().local_only);
                assert_eq!(observed.policy().target, [0; 32]);
                assert!(observed.retired());
            }
            let refused = b
                .finish_probe(completed)
                .err()
                .ok_or("foreign completion accepted")?;
            assert_eq!(refused.cause, ProtocolError::Stale);
            assert!(b.availability_summary(b_result).is_none());
            assert!(
                a.availability_summary(a_result)
                    .ok_or("missing active book")?
                    .active()
            );
            let report = a
                .finish_probe(*refused.original)
                .map_err(|refused| refused.cause)?;
            assert_eq!(report.result, a_result);
            assert_eq!((report.summary.rank(), report.summary.certainty()), (1, 1));
            assert_eq!(report.summary.successes(), 1);
            assert!(!report.summary.active());
            assert_eq!(a.availability_summary(a_result), Some(report.summary));
            let observed = report
                .observation
                .map_err(|failure| io::Error::other(failure.to_string()))?;
            a.cancel()?;
            b.cancel()?;
            Ok::<_, Box<dyn std::error::Error>>(observed)
        };
        let (observed, last) = timeout(WAIT, async { tokio::try_join!(client, peer) }).await??;
        assert_eq!(observed.last_response(), last);
        Ok(())
    })
}

#[test]
fn cancel_deadline_and_forgotten_completion_remain_distinct_observations() -> TestResult {
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        let tree = tree(&[23])?;
        let (query, signed) = advertisement(tree.content)?;
        let source = ipc::EndpointSource::unix(socket.0.clone());
        let session_deadline = deadline(&source, 4_000_000)?;
        let peer = async {
            let (mut search, _) = listener.accept().await?;
            advertise(&mut search, query, &signed).await?;
            // The unrun cancelled ticket creates no connection. Both actual
            // native runs write one SEARCH, receive no response, then retire.
            for _ in 0..2 {
                let (mut native, _) = listener.accept().await?;
                let frame = request(&mut native).await?;
                lookup(&frame, tree.content.query, BlockType::DBLOCK)?;
                closed(&mut native).await?;
            }
            closed(&mut search).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let client = async {
            let mut identities = [Instance::new()];
            let mut session = session(&mut identities, source.duplicate()?, session_deadline)?;
            let result = choose(&mut session).await?;
            let ticket = session.begin_probe(
                result,
                0,
                probe::Options::new(deadline(&source, 2_000_000)?),
            )?;
            let summary = session
                .cancel_probe(ticket)
                .map_err(|refused| refused.cause)?;
            assert_eq!(
                (summary.cancelled(), summary.certainty(), summary.rank()),
                (1, 0, 0)
            );
            assert_eq!(summary.queries_written(), 0);
            assert!(!summary.active());

            let completed = session
                .begin_probe(result, 0, probe::Options::new(deadline(&source, 200_000)?))?
                .run(&mut Buffers::new(), |_| Control::Continue)
                .await;
            {
                let failure = completed
                    .observation()
                    .as_ref()
                    .err()
                    .ok_or("expected quiet deadline")?;
                assert!(matches!(failure.cause(), network::Error::Deadline { .. }));
                assert_eq!(failure.queries_written(), 1);
                assert!(failure.retired());
            }
            let report = session
                .finish_probe(completed)
                .map_err(|refused| refused.cause)?;
            assert_eq!((report.summary.rank(), report.summary.certainty()), (-1, 1));
            assert_eq!(report.summary.successes(), 0);
            assert_eq!(report.summary.setup_deadlines(), 0);
            assert_eq!(report.summary.cancelled(), 1);
            assert!(report.observation.is_err());

            let completed = session
                .begin_probe(result, 0, probe::Options::new(deadline(&source, 200_000)?))?
                .run(&mut Buffers::new(), |_| Control::Continue)
                .await;
            let forgotten = session.forget_probe(result)?;
            assert_eq!(
                (
                    forgotten.cancelled(),
                    forgotten.certainty(),
                    forgotten.rank()
                ),
                (2, 1, -1)
            );
            let refused = session
                .finish_probe(completed)
                .err()
                .ok_or("forgotten completion accepted")?;
            assert_eq!(refused.cause, ProtocolError::StaleGeneration);
            let original = *refused.original;
            let failure = original
                .observation()
                .as_ref()
                .err()
                .ok_or("original outcome lost")?;
            assert!(matches!(failure.cause(), network::Error::Deadline { .. }));
            assert_eq!(failure.queries_written(), 1);
            assert!(failure.retired());
            assert_eq!(session.availability_summary(result), Some(forgotten));
            session.cancel()?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        timeout(WAIT, async { tokio::try_join!(client, peer) }).await??;
        Ok(())
    })
}
