//! Actual Rust socket fixtures for indexed trees; not original-C acceptance.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible fixtures assert original index certainty, actual wire payload and ACK preservation"
)]
use gnunet_client_host::EndpointSource;
use gnunet_crypto::hash512;
use gnunet_fs::client::Event as IndexEvent;
use gnunet_fs_host::input_tree::InputDir;
use gnunet_fs_host::{
    Buffers, Control,
    network::{
        BlockOptions, IndexPublishCause, IndexRegistration, PublishOptions,
        tree_publish::{TreePublishCause, TreePublishOptions},
    },
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::{
    datastore::{Request, Response, Status},
    fs::{Request as FsRequest, Response as FsResponse},
};
use std::{
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

#[test]
fn indexed_growth_cannot_exceed_the_admitted_tree_budget_before_registration() -> TestResult {
    runtime()?.block_on(async {
        let temporary = Temporary::new()?;
        let root = temporary.0.join("input");
        fs::create_dir(&root)?;
        fs::write(root.join("file"), b"x")?;
        let input = InputDir::open(&root)?;
        let (fs_path, fs_listener) = temporary.socket("fs.sock")?;
        let (ds_path, ds_listener) = temporary.socket("store.sock")?;
        let source = EndpointSource::unix(ds_path);
        let mut policy = options(&source)?;
        policy.limits.max_file_bytes = 1;
        let mut changed = false;
        let mut mutation_error = None;
        let result = Buffers::new()
            .store_indexed_tree(
                &input,
                &root,
                EndpointSource::unix(fs_path),
                source,
                policy,
                |event| {
                    if !changed
                        && event.stage == gnunet_fs_host::network::tree_publish::TreeStage::File
                    {
                        changed = true;
                        if let Err(error) = fs::write(root.join("file"), b"xx") {
                            mutation_error = Some(error);
                            return Control::Cancel;
                        }
                    }
                    Control::Continue
                },
            )
            .await;
        if let Some(error) = mutation_error {
            return Err(error.into());
        }
        assert!(changed);
        let failure = result.err().ok_or("grown source was published")?;
        assert_eq!(failure.progress.stored_bytes, 0);
        assert_eq!(failure.current_stored_bytes, 0);
        let TreePublishCause::Indexed(indexed) = failure.cause else {
            return Err("growth did not reach the indexed pre-registration resource check".into());
        };
        assert_eq!(indexed.registration, IndexRegistration::NotSubmitted);
        assert!(indexed.file_id.is_none());
        assert!(
            timeout(Duration::from_millis(20), fs_listener.accept())
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(20), ds_listener.accept())
                .await
                .is_err()
        );
        Ok(())
    })
}
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-indexed-tree-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn socket(&self, name: &str) -> io::Result<(PathBuf, UnixListener)> {
        let path = self.0.join(name);
        let listener = UnixListener::bind(&path)?;
        Ok((path, listener))
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
    let publish = PublishOptions::new(
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
    Ok(TreePublishOptions::new(publish))
}
async fn frame(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0; 4];
    if stream.read(&mut head[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut head[1..]).await?;
    let length = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if length < 4 {
        return Err(io::Error::other("short frame"));
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&head);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(Some(bytes))
}
struct Registration {
    path: PathBuf,
    id: [u8; 64],
    refused: bool,
}
async fn fs_peer(listener: UnixListener, registrations: Vec<Registration>) -> TestResult {
    for registration in registrations {
        let (mut stream, _) = listener.accept().await?;
        let bytes = frame(&mut stream).await?.ok_or(ProtocolError::Truncated)?;
        assert!(
            matches!(FsRequest::decode(&bytes)?,FsRequest::IndexStart{device:0,inode:0,file_id,filename} if file_id==registration.id && filename==registration.path.as_os_str().as_bytes())
        );
        let response = if registration.refused {
            FsResponse::IndexFailed {
                message: b"\xffdenied",
            }
        } else {
            FsResponse::IndexStarted
        };
        let mut bytes = vec![0; response.encoded_len()?];
        response.encode(&mut bytes)?;
        stream.write_all(&bytes).await?;
        assert!(frame(&mut stream).await?.is_none());
    }
    Ok(())
}
#[derive(Default)]
struct Stored {
    bytes: u128,
    blocks: u64,
    queries: Vec<Vec<[u8; 64]>>,
}
struct Object {
    id: Option<[u8; 64]>,
    leaves: usize,
    nodes: usize,
}
async fn ds_peer(listener: UnixListener, objects: Vec<Object>) -> TestResult<Stored> {
    let mut stored = Stored::default();
    for object in objects {
        let (mut stream, _) = listener.accept().await?;
        let mut nodes = 0;
        let mut leaves = 0;
        let mut queries = Vec::new();
        while let Some(bytes) = frame(&mut stream).await? {
            let Request::Put(value) = Request::decode(&bytes)? else {
                return Err(ProtocolError::Malformed.into());
            };
            assert_eq!(
                (
                    value.reservation,
                    value.priority,
                    value.anonymity,
                    value.replication
                ),
                (0, 365, 1, 1)
            );
            if let Some(id) = object.id {
                match value.kind {
                    6 => {
                        assert_eq!(value.value.len(), 72);
                        assert_eq!(&value.value[..64], &id);
                        assert_eq!(&value.value[64..], &((leaves as u64) * 32768).to_be_bytes());
                        leaves += 1;
                    }
                    2 => assert!(object.nodes > 1),
                    _ => return Err(ProtocolError::Malformed.into()),
                }
            } else {
                assert!(matches!(value.kind, 1 | 2));
            }
            queries.push(*value.key);
            nodes += 1;
            stored.blocks += 1;
            stored.bytes += value.value.len() as u128;
            let response = Response::Status(Status {
                code: 1,
                min_expiration: AbsoluteTime::UNIX_EPOCH,
                message: None,
            });
            let mut bytes = [0; 16];
            let length = response.encode(&mut bytes)?;
            stream.write_all(&bytes[..length]).await?;
        }
        assert_eq!(nodes, object.nodes);
        assert_eq!(leaves, object.leaves);
        stored.queries.push(queries);
    }
    Ok(stored)
}

#[test]
fn indexed_tree_preserves_duplicate_paths_empty_file_and_actual_payload_counts() -> TestResult {
    runtime()?.block_on(async {
        timeout(Duration::from_secs(8), async {
            let temporary = Temporary::new()?;
            let path = temporary.0.join("input");
            fs::create_dir(&path)?;
            fs::create_dir(path.join("nested"))?;
            let data: Vec<u8> = (0..70_000)
                .map(|i| ((i * 17 + i / 32768) % 256) as u8)
                .collect();
            fs::write(path.join("a"), &data)?;
            fs::write(path.join("b"), &data)?;
            fs::write(path.join("nested/empty"), b"")?;
            let canonical = fs::canonicalize(&path)?;
            let id = hash512(&data);
            let empty = hash512(b"");
            let (fs_path, fs_listener) = temporary.socket("fs.sock")?;
            let (ds_path, ds_listener) = temporary.socket("ds.sock")?;
            let registrations = vec![
                Registration {
                    path: canonical.join("a"),
                    id,
                    refused: false,
                },
                Registration {
                    path: canonical.join("b"),
                    id,
                    refused: false,
                },
                Registration {
                    path: canonical.join("nested/empty"),
                    id: empty,
                    refused: false,
                },
            ];
            let objects = vec![
                Object {
                    id: Some(id),
                    leaves: 3,
                    nodes: 4,
                },
                Object {
                    id: Some(id),
                    leaves: 3,
                    nodes: 4,
                },
                Object {
                    id: Some(empty),
                    leaves: 1,
                    nodes: 1,
                },
                Object {
                    id: None,
                    leaves: 0,
                    nodes: 1,
                },
                Object {
                    id: None,
                    leaves: 0,
                    nodes: 1,
                },
            ];
            let source = EndpointSource::unix(ds_path);
            let policy = options(&source)?;
            let input = InputDir::open(&path)?;
            let mut completed_ids = Vec::new();
            let publish = async {
                Buffers::new()
                    .store_indexed_tree(
                        &input,
                        &path,
                        EndpointSource::unix(fs_path),
                        source,
                        policy,
                        |event| {
                            if let Some(file_id) = event.file_id {
                                assert!(event.completed.is_some());
                                completed_ids.push(file_id);
                            }
                            Control::Continue
                        },
                    )
                    .await
            };
            let (result, fs_result, ds_result) = tokio::join!(
                publish,
                fs_peer(fs_listener, registrations),
                ds_peer(ds_listener, objects)
            );
            fs_result?;
            let stored = ds_result?;
            let done = result?;
            assert_eq!(
                (
                    done.progress.files,
                    done.progress.indexed_files,
                    done.progress.directories
                ),
                (3, 3, 2)
            );
            assert_eq!(completed_ids, vec![id, id, empty]);
            assert_eq!(stored.queries[0], stored.queries[1]);
            assert_eq!(
                (
                    done.progress.acknowledged.blocks,
                    done.progress.stored_bytes
                ),
                (11, stored.bytes)
            );
            assert_eq!(stored.blocks, 11);
            assert!(done.progress.stored_bytes < done.progress.acknowledged.encoded_bytes);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await
    })??;
    Ok(())
}

#[test]
fn indexed_tree_keeps_accepted_prefix_and_original_second_index_refusal() -> TestResult {
    runtime()?.block_on(async {
        timeout(Duration::from_secs(8), async {
            let temporary = Temporary::new()?;
            let path = temporary.0.join("input");
            fs::create_dir(&path)?;
            fs::write(path.join("a"), b"x")?;
            fs::write(path.join("b"), b"y")?;
            let canonical = fs::canonicalize(&path)?;
            let first = hash512(b"x");
            let second = hash512(b"y");
            let (fs_path, fs_listener) = temporary.socket("fs.sock")?;
            let (ds_path, ds_listener) = temporary.socket("ds.sock")?;
            let registrations = vec![
                Registration {
                    path: canonical.join("a"),
                    id: first,
                    refused: false,
                },
                Registration {
                    path: canonical.join("b"),
                    id: second,
                    refused: true,
                },
            ];
            let objects = vec![Object {
                id: Some(first),
                leaves: 1,
                nodes: 1,
            }];
            let source = EndpointSource::unix(ds_path);
            let policy = options(&source)?;
            let input = InputDir::open(&path)?;
            let publish = async {
                Buffers::new()
                    .store_indexed_tree(
                        &input,
                        &path,
                        EndpointSource::unix(fs_path),
                        source,
                        policy,
                        |_| Control::Continue,
                    )
                    .await
            };
            let (result, fs_result, ds_result) = tokio::join!(
                publish,
                fs_peer(fs_listener, registrations),
                ds_peer(ds_listener, objects)
            );
            fs_result?;
            let stored = ds_result?;
            let error = match result {
                Err(error) => error,
                Ok(_) => return Err(ProtocolError::Malformed.into()),
            };
            assert_eq!(error.path, PathBuf::from("b"));
            assert_eq!(
                (
                    error.progress.files,
                    error.progress.indexed_files,
                    error.progress.directories,
                    error.progress.stored_bytes
                ),
                (1, 1, 0, 72)
            );
            assert_eq!(stored.bytes, 72);
            assert_eq!(error.current.blocks, 0);
            assert_eq!(error.current_stored_bytes, 0);
            assert_eq!(error.indexed_file_id, Some(second));
            let TreePublishCause::Indexed(indexed) = &error.cause else {
                return Err(ProtocolError::Malformed.into());
            };
            assert_eq!(indexed.registration, IndexRegistration::Refused);
            let IndexPublishCause::Registration(failure) = &indexed.cause else {
                return Err(ProtocolError::Malformed.into());
            };
            assert!(matches!(
                failure.response.as_ref().map(|response| response.event()),
                Some(IndexEvent::IndexFailed(b"\xffdenied"))
            ));
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await
    })??;
    Ok(())
}
