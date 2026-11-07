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
    content::{BLOCK_BYTES, EncodedNode},
    ublock,
};
use gnunet_fs_host::{
    BlockSink, Buffers, Control, Insert, ipc, network,
    search::{
        self, Session, Step,
        automatic::{Automatic, Event, Policy},
    },
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
const WAIT: Duration = Duration::from_secs(7);
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

struct TailEntropy;
impl gnunet_crypto::Entropy for TailEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), ProtocolError> {
        let bytes = 3u64.to_be_bytes();
        if output.len() != bytes.len() {
            return Err(ProtocolError::Entropy);
        }
        output.copy_from_slice(&bytes);
        Ok(())
    }
}

#[test]
fn automatic_driver_interleaves_real_hits_and_drains_a_quiet_partial_native_probe() -> TestResult {
    runtime()?.block_on(async {
        let (socket, listener)=Socket::bind()?;
        let a=tree(&vec![19;3*BLOCK_BYTES+19])?;
        let b=tree(&vec![23;3*BLOCK_BYTES+23])?;
        let (query,signed_a)=advertisement(a.content)?;
        let (_,signed_b)=advertisement(b.content)?;
        let source=ipc::EndpointSource::unix(socket.0.clone());
        let end=deadline(&source,5_000_000)?;
        let peer=async {
            let (mut search,_)=listener.accept().await?;
            advertise(&mut search,query,&signed_a).await?;
            search.write_all(&reply(BlockType::UBLOCK,&signed_b)?).await?;
            let (mut first,_)=listener.accept().await?;
            let frame=request(&mut first).await?;
            lookup(&frame,a.content.query,BlockType::IBLOCK)?;
            let (_,root)=a.blocks.get(&a.content.query).ok_or("missing first root")?;
            first.write_all(&reply(BlockType::IBLOCK,root)?).await?;
            let frame=request(&mut first).await?;lookup(&frame,a.tail,BlockType::DBLOCK)?;
            let (mut second,_)=listener.accept().await?;
            let frame=request(&mut second).await?;
            lookup(&frame,b.content.query,BlockType::IBLOCK)?;
            let (_,root)=b.blocks.get(&b.content.query).ok_or("missing second root")?;
            second.write_all(&reply(BlockType::IBLOCK,root)?).await?;
            let frame=request(&mut second).await?;lookup(&frame,b.tail,BlockType::DBLOCK)?;
            let (_,tail)=b.blocks.get(&b.tail).ok_or("missing second leaf")?;
            let frame=reply(BlockType::DBLOCK,tail)?;
            second.write_all(&frame[..5]).await?;
            let (_,tail)=a.blocks.get(&a.tail).ok_or("missing first leaf")?;
            let frame=reply(BlockType::DBLOCK,tail)?;
            first.write_all(&frame).await?;
            closed(&mut first).await?;closed(&mut second).await?;closed(&mut search).await?;
            Ok::<_,Box<dyn std::error::Error>>(())
        };
        let client=async {
            let mut ids=[Instance::new()];
            let original=session(&mut ids,source,end)?;
            let mut auto=Automatic::new(original,Policy{max_running:2,..Policy::default()})?;
            let stop=auto.stop_handle();
            let mut entropy=TailEntropy;
            let mut visible=0;let mut successes=0;let mut cancellations=0;
            while let Some(event)=auto.next(&mut entropy).await? {
                match event {
                    Event::Search(step)=>match *step {
                        Step::Result{..}=>visible+=1,
                        Step::Failed{cause,..}=>return Err(Box::new(cause) as Box<dyn std::error::Error>),
                        Step::Rejected{cause,..}=>return Err(Box::new(cause) as Box<dyn std::error::Error>),
                        _=>{},
                    },
                    Event::Probe(report)=>{
                        assert!(report.persistence.is_none());
                        let report=report.native;
                        let record=auto.session().result(report.result).ok_or("original result missing")?;
                        assert!(record.visible());
                        match report.observation {
                            Ok(observed)=>{
                                assert_eq!(observed.verified().content(),a.content);
                                assert_eq!(observed.range(),3*BLOCK_BYTES as u64..a.content.size);
                                assert_eq!(observed.progress().plaintext_bytes,19);
                                assert_eq!(observed.progress().blocks,2);
                                assert_eq!(observed.queries_written(),2);
                                assert_eq!((report.summary.successes(),report.summary.trials()),(1,1));
                                successes+=1;stop.request();
                            },
                            Err(failure)=>{
                                assert!(matches!(failure.cause(),network::Error::Cancelled(_)));
                                assert_eq!(failure.content(),b.content);
                                assert_eq!(failure.progress().blocks,1);
                                assert_eq!(failure.progress().plaintext_bytes,0);
                                assert_eq!(failure.queries_written(),2);
                                assert_eq!((report.summary.trials(),report.summary.cancelled()),(0,1));
                                assert!(failure.retired());cancellations+=1;
                            },
                        }
                        assert!(!report.summary.active());
                    },
                    Event::AdmissionFailed{cause,..}=>return Err(Box::new(cause) as Box<dyn std::error::Error>),
                    Event::AccountingRefused{native,..}=>return Err(Box::new(native.cause) as Box<dyn std::error::Error>),
                    Event::PersistenceFailed{..}=>return Err("unexpected persistent path in ordinary automatic driver".into()),
                }
            }
            assert_eq!((visible,successes,cancellations),(2,1,1));
            let progress=auto.progress();assert_eq!((progress.admitted,progress.settled,progress.max_active),(2,2,2));
            assert_eq!(progress.admission_failures,0);
            let original=auto.into_session().map_err(|_|"active owner remained after drain")?;
            assert_eq!(original.results().len(),2);
            Ok::<_,Box<dyn std::error::Error>>(())
        };
        timeout(WAIT,async {tokio::try_join!(peer,client)}).await??;
        Ok(())
    })
}
