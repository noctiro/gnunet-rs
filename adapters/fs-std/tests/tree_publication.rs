//! Native socket fixtures; these do not claim original-C acceptance.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible fixtures assert actual acknowledgements, source-change receipt and exact raw metadata"
)]
use gnunet_client_host::EndpointSource;
use gnunet_fs::{Content, Uri, content::NodeRef, directory as dir, metadata as md};
use gnunet_fs_host::input_tree::{InputDir, SourceError};
use gnunet_fs_host::{
    BlockSource, Buffers, Control, Limits,
    network::{
        BlockOptions, PublishOptions,
        tree_publish::{TreePublishCause, TreePublishOptions, TreeStage},
    },
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::datastore::{Request, Response, Status};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs, io,
    os::unix::ffi::OsStrExt,
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
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-tree-publish-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn options(source: &EndpointSource) -> Result<TreePublishOptions, ProtocolError> {
    let mut publish = PublishOptions::new(
        AbsoluteTime::from_micros(
            source
                .clock()
                .sample()?
                .now
                .as_micros()
                .checked_add(5_000_000)
                .ok_or(ProtocolError::Overflow)?,
        ),
        BlockOptions {
            expiration: AbsoluteTime::from_micros(999_999),
            priority: 365,
            anonymity: 1,
            replication: 1,
        },
    );
    publish.reserve_space = false;
    Ok(TreePublishOptions::new(publish))
}
async fn frame(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0; 4];
    if stream.read(&mut head[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut head[1..]).await?;
    let size = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if size < 4 {
        return Err(io::Error::other("short frame"));
    }
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&head);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(Some(bytes))
}
#[derive(Default)]
struct Captured(HashMap<[u8; 64], Vec<u8>>);
impl BlockSource for Captured {
    fn read_block(&mut self, request: NodeRef, output: &mut [u8]) -> gnunet_fs_host::Result<usize> {
        let bytes = self
            .0
            .get(&request.key().query)
            .ok_or(ProtocolError::NotFound)?;
        if output.len() < bytes.len() {
            return Err(ProtocolError::Capacity.into());
        }
        output[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }
}
async fn peer(listener: UnixListener, objects: usize) -> TestResult<Captured> {
    let mut captured = Captured::default();
    for _ in 0..objects {
        let (mut stream, _) = listener.accept().await?;
        // Every fixture object fits in one full-insertion data block.
        let bytes = frame(&mut stream).await?.ok_or(ProtocolError::Truncated)?;
        let Request::Put(value) = Request::decode(&bytes)? else {
            return Err(ProtocolError::Malformed.into());
        };
        assert_eq!(
            (
                value.kind,
                value.reservation,
                value.priority,
                value.anonymity,
                value.replication
            ),
            (1, 0, 365, 1, 1)
        );
        captured.0.insert(*value.key, value.value.to_vec());
        let status = Response::Status(Status {
            code: 1,
            min_expiration: AbsoluteTime::UNIX_EPOCH,
            message: None,
        });
        let mut reply = [0; 16];
        let length = status.encode(&mut reply)?;
        stream.write_all(&reply[..length]).await?;
        assert!(frame(&mut stream).await?.is_none());
    }
    Ok(captured)
}
fn root_mime(content: Content, blocks: &mut Captured) -> TestResult {
    let mut wire = Vec::new();
    Buffers::new().copy_to(blocks, content, &mut wire, Limits::default(), |_| {
        Control::Continue
    })?;
    assert_eq!(&wire[..8], dir::MAGIC);
    let length = u32::from_be_bytes(wire[8..12].try_into()?) as usize;
    let metadata = md::decode_uncompressed(
        &wire[12..12 + length],
        md::Limits::default(),
        md::Mode::Strict,
    )?;
    let md::Decoded::Present(metadata) = metadata else {
        return Err(ProtocolError::Malformed.into());
    };
    assert_eq!(dir::claims_directory(metadata.items()), Some(true));
    Ok(())
}

#[test]
fn nested_tree_publishes_real_postorder_chks_and_raw_filename_metadata() -> TestResult {
    runtime()?.block_on(async {
        timeout(Duration::from_secs(8), async {
            let temporary = Temporary::new()?;
            let input = temporary.0.join("input");
            fs::create_dir(&input)?;
            fs::create_dir(input.join("nested"))?;
            let mut raw_name = b"opaque\xff".as_slice();
            match fs::write(input.join(OsStr::from_bytes(raw_name)), b"payload") {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(nix::libc::EILSEQ) => {
                    // APFS refuses non-UTF-8 names. Still verify unchanged byte
                    // metadata using a non-ASCII name on this filesystem.
                    raw_name = "opaque中".as_bytes();
                    fs::write(input.join(OsStr::from_bytes(raw_name)), b"payload")?;
                }
                Err(error) => return Err(error.into()),
            }
            fs::write(input.join("nested/empty"), b"")?;
            let socket = temporary.0.join("store.sock");
            let listener = UnixListener::bind(&socket)?;
            let source = EndpointSource::unix(socket);
            let policy = options(&source)?;
            let input = InputDir::open(input)?;
            let mut order = Vec::new();
            let publish = async {
                Buffers::new()
                    .store_tree(&input, source, policy, |event| {
                        if event.completed.is_some() {
                            order.push(event.path.to_path_buf());
                        }
                        Control::Continue
                    })
                    .await
                    .map_err(Box::<dyn std::error::Error>::from)
            };
            let (done, blocks) = tokio::join!(publish, peer(listener, 4));
            let done = done?;
            let mut blocks = blocks?;
            assert_eq!(
                (
                    done.progress.files,
                    done.progress.directories,
                    done.progress.entries
                ),
                (2, 2, 3)
            );
            assert_eq!(order.last(), Some(&PathBuf::new()));
            assert!(
                order
                    .iter()
                    .position(|p| p == &PathBuf::from("nested/empty"))
                    < order.iter().position(|p| p == &PathBuf::from("nested"))
            );
            root_mime(done.root.content, &mut blocks)?;
            let mut nested = None;
            let mut names = Vec::new();
            Buffers::new().visit_directory(
                &mut blocks,
                done.root.content,
                Limits::default(),
                dir::Limits::default(),
                |verified| {
                    let entry = verified.entry();
                    let filename =
                        dir::filename(entry.metadata.items()).ok_or(ProtocolError::NotFound)?;
                    names.push(filename.to_vec());
                    if filename == b"nested" {
                        assert_eq!(dir::claims_directory(entry.metadata.items()), Some(true));
                        let Uri::Content(content) = entry.uri()? else {
                            return Err(ProtocolError::Malformed.into());
                        };
                        nested = Some(content);
                    }
                    Ok(())
                },
            )?;
            assert!(names.contains(&raw_name.to_vec()));
            root_mime(nested.ok_or(ProtocolError::NotFound)?, &mut blocks)?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await
    })??;
    Ok(())
}

#[test]
fn final_source_change_preserves_already_acknowledged_root_without_success_receipt() -> TestResult {
    runtime()?.block_on(async {
        timeout(Duration::from_secs(8), async {
            let temporary = Temporary::new()?;
            let path = temporary.0.join("input");
            fs::create_dir(&path)?;
            let file = path.join("source");
            fs::write(&file, b"old")?;
            let socket = temporary.0.join("store.sock");
            let listener = UnixListener::bind(&socket)?;
            let source = EndpointSource::unix(socket);
            let policy = options(&source)?;
            let input = InputDir::open(&path)?;
            let mut changed = false;
            let mut write_error = None;
            let publish = async {
                Buffers::new()
                    .store_tree(&input, source, policy, |event| {
                        if event.stage == TreeStage::Directory
                            && event.path.as_os_str().is_empty()
                            && event.completed.is_some()
                        {
                            changed = true;
                            write_error =
                                fs::write(&file, b"changed after root acknowledgement").err();
                        }
                        Control::Continue
                    })
                    .await
            };
            let (result, served) = tokio::join!(publish, peer(listener, 2));
            served?;
            if let Some(error) = write_error {
                return Err::<_, Box<dyn std::error::Error>>(error.into());
            }
            let error = match result {
                Err(error) => error,
                Ok(_) => return Err(ProtocolError::Malformed.into()),
            };
            assert!(changed);
            assert!(matches!(
                error.cause,
                TreePublishCause::Source(SourceError::Changed)
            ));
            assert_eq!(
                (
                    error.progress.files,
                    error.progress.directories,
                    error.progress.acknowledged.blocks
                ),
                (1, 1, 2)
            );
            assert!(error.acknowledged_content.is_some());
            assert_eq!(error.current.blocks, 0);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await
    })??;
    Ok(())
}
