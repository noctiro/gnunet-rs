//! Selected extraction must finish before deletion; durable recovery reuses
//! the actual first selection. These local wire peers are not C/P2P acceptance.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "These fallible regressions assert actual selection, native requests and persisted receipts"
)]
use gnunet_datastore_host::{
    Client, Instance, Limits as NativeLimits, ProtocolClient, ProtocolLimits, ReservationSlot, Slot,
};
use gnunet_fs::{content, ublock};
use gnunet_fs_host::{
    Buffers, Control,
    extraction::{self, MetadataSettings},
    ipc::EndpointSource,
    network::unindex,
    unindex_task::{self, Task},
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::{datastore, fs as wire_fs};
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{Instant, timeout},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        loop {
            let path = std::env::temp_dir().join(format!(
                "fs-unindex-meta-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn native<'a, 's, 'b>(
    instance: &'a mut Instance,
    slots: &'s mut [Slot<'b>],
    reservations: &'s mut [ReservationSlot],
    source: EndpointSource,
) -> std::result::Result<Client<'a, 's, 'b>, gnunet_datastore_host::Error> {
    Client::new(
        ProtocolClient::new(
            instance,
            slots,
            reservations,
            ProtocolLimits {
                max_pending: 1,
                ..ProtocolLimits::default()
            },
        )?,
        source,
        NativeLimits {
            reply_frames: 1,
            reply_bytes: 65535,
            ..NativeLimits::default()
        },
    )
}
fn deadline(source: &EndpointSource) -> std::result::Result<AbsoluteTime, gnunet_types::Error> {
    source
        .clock()
        .sample()?
        .now
        .after(gnunet_types::Duration(5_000_000))
}
async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if n < 4 {
        return Err(io::Error::other("short unindex fixture frame"));
    }
    let mut bytes = vec![0; n];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn store_reply(stream: &mut UnixStream, response: datastore::Response<'_>) -> Result {
    let mut bytes = [0; 16];
    let n = response.encode(&mut bytes)?;
    stream.write_all(&bytes[..n]).await?;
    Ok(())
}

#[test]
fn selected_provider_failure_preserves_its_cause_before_any_native_mutation() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temp = Temporary::new()?;
            let filename = temp.0.join("report.txt");
            let data = b"original indexed file";
            fs::write(&filename, data)?;
            let mut input = fs::File::open(&filename)?;
            let fs_path = temp.0.join("fs.sock");
            let store_path = temp.0.join("store.sock");
            let fs_listener = UnixListener::bind(&fs_path)?;
            let store_listener = UnixListener::bind(&store_path)?;
            let fs_source = EndpointSource::unix(fs_path);
            let store_source = EndpointSource::unix_with_clock(store_path, fs_source.clock());
            let mut instance = Instance::new();
            let mut bytes = vec![0; 65535];
            let mut slots = [Slot::new(&mut bytes)];
            let mut reservations = [];
            let client = native(&mut instance, &mut slots, &mut reservations, store_source)?;
            let mut options = unindex::Options::new(
                deadline(&fs_source)?,
                Instant::now() + Duration::from_secs(5),
            );
            options.extra_keywords = &[b"known-explicit"];
            options.metadata = MetadataSettings::new(
                false,
                Some(b"pdf:exact-options"),
                Some(temp.0.join("missing-provider.dylib")),
            )?;
            let failure = timeout(
                Duration::from_secs(2),
                Buffers::new().unindex_file(
                    &mut input,
                    &filename,
                    fs_source,
                    client,
                    options,
                    |_| Control::Continue,
                ),
            )
            .await?
            .err()
            .ok_or("missing real provider refusal")?;
            assert!(failure.operation.is_none());
            assert!(failure.store_cleanup.is_none());
            assert_eq!(failure.report.file_id, Some(gnunet_crypto::hash512(data)));
            assert_eq!(failure.report.observation.hashed_bytes, data.len() as u64);
            assert_eq!(failure.report.selected_keywords, 0);
            assert_eq!(failure.report.observation.encoded.blocks, 0);
            assert_eq!(failure.report.observation.content_positive, 0);
            assert!(!failure.report.fs_admitted);
            let Some(extraction::Error::Extractor(original)) = failure.keywords.as_ref() else {
                return Err("original provider failure was replaced".into());
            };
            assert!(matches!(
                &original.cause,
                gnunet_extractor_host::Cause::Native(
                    gnunet_extractor_host::NativeError::Loader { .. }
                        | gnunet_extractor_host::NativeError::Io { .. }
                )
            ));
            assert!(
                timeout(Duration::from_millis(10), store_listener.accept())
                    .await
                    .is_err()
            );
            assert!(
                timeout(Duration::from_millis(10), fs_listener.accept())
                    .await
                    .is_err()
            );
            assert_eq!(fs::read(filename)?, data);
            Ok(())
        })
}

#[test]
fn durable_resume_keeps_selected_settings_and_reuses_the_first_keyword_set() -> Result {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let temp = Temporary::new()?;
        let filename = temp.0.join("report.txt");
        let data = b"original indexed payload";
        fs::write(&filename, data)?;
        let metadata = MetadataSettings::new(false, Some(b"-"), None)?;
        let original_settings = metadata.snapshot()?;
        let mut expected = extraction::file_keywords_with_metadata(&fs::File::open(&filename)?,
            &filename, Default::default(), metadata.clone(), |_| Control::Continue)?;
        let extras = vec![b"known-explicit".to_vec()];
        if !expected.contains(&extras[0]) { expected.push(extras[0].clone()); }
        let queries = expected.iter().map(|word| ublock::Context::keyword(word, Default::default())
            .map(|context| *context.query())).collect::<std::result::Result<Vec<_>, _>>()?;
        assert!(!queries.is_empty());
        let file_id = gnunet_crypto::hash512(data);
        let mut encoded = vec![0; content::BLOCK_BYTES + content::TAG_BYTES];
        let query = content::encode_data(data, &mut encoded)?.key().query;
        let mut descriptor = [0; 72];
        descriptor[..64].copy_from_slice(&file_id);
        let task_path = temp.0.join("task");
        let limits = unindex_task::Limits::default();
        let mut task = Task::create(&task_path, &filename, &extras, metadata, limits)?;
        let original_task = *task.task_id();
        let fs_path = temp.0.join("fs.sock");
        let store_path = temp.0.join("store.sock");
        let fs_listener = UnixListener::bind(&fs_path)?;
        let store_listener = UnixListener::bind(&store_path)?;
        let fs_source = EndpointSource::unix(fs_path.clone());
        let clock = fs_source.clock();
        let mut instance = Instance::new();
        let mut bytes = vec![0; 65535];
        let mut slots = [Slot::new(&mut bytes)];
        let mut reservations = [];
        let client = native(&mut instance, &mut slots, &mut reservations,
            EndpointSource::unix_with_clock(store_path.clone(), clock.clone()))?;
        let peer = async {
            let (mut stream, _) = store_listener.accept().await?;
            assert!(matches!(datastore::Request::decode(&frame(&mut stream).await?)?,
                datastore::Request::Remove { key, value } if *key == query && value == descriptor));
            store_reply(&mut stream, datastore::Response::Status(datastore::Status {
                code: 1, min_expiration: AbsoluteTime::UNIX_EPOCH, message: None,
            })).await?;
            assert_eq!(stream.read(&mut [0]).await?, 0);
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let mut buffers = Buffers::new();
        let run = task.run(&mut buffers, fs_source, client, clock.sample()?.now.after(gnunet_types::Duration(5_000_000))?,
            Instant::now() + Duration::from_secs(5), |observation| {
                if observation.content_positive == 1 { unindex_task::Control::Pause }
                else { unindex_task::Control::Continue }
            });
        let (run, ()) = timeout(Duration::from_secs(3), async { tokio::try_join!(async { Ok::<_, Box<dyn std::error::Error>>(run.await) }, peer) }).await??;
        let paused = run.err().ok_or("expected caller pause after actual REMOVE receipt")?;
        assert!(paused.resumable());
        assert!(paused.status.keywords_bound);
        assert_eq!(paused.status.accepted, 1);
        assert_eq!(paused.status.pending, None);
        drop(task);
        let mut task = Task::open(&task_path, limits)?;
        assert_eq!(*task.task_id(), original_task);
        assert_eq!(task.manifest().metadata.snapshot()?, original_settings);
        assert!(!task.manifest().metadata.format_extraction_enabled());
        let mut instance = Instance::new();
        let mut bytes = vec![0; 65535];
        let mut slots = [Slot::new(&mut bytes)];
        let mut reservations = [];
        let client = native(&mut instance, &mut slots, &mut reservations,
            EndpointSource::unix_with_clock(store_path, clock.clone()))?;
        let peer = async {
            let (mut stream, _) = store_listener.accept().await?;
            for query in &queries {
                assert!(matches!(datastore::Request::decode(&frame(&mut stream).await?)?,
                    datastore::Request::Get { key: Some(key), kind: 9, next_uid: 0, random: false } if key == query));
                store_reply(&mut stream, datastore::Response::End).await?;
            }
            assert_eq!(stream.read(&mut [0]).await?, 0);
            let (mut stream, _) = fs_listener.accept().await?;
            assert_eq!(wire_fs::Request::decode(&frame(&mut stream).await?)?, wire_fs::Request::Unindex { file_id });
            let mut answer = [0; 4];
            wire_fs::Response::Unindexed.encode(&mut answer)?;
            stream.write_all(&answer).await?;
            assert_eq!(stream.read(&mut [0]).await?, 0);
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let mut buffers = Buffers::new();
        let run = task.run(&mut buffers, EndpointSource::unix_with_clock(fs_path, clock.clone()), client,
            clock.sample()?.now.after(gnunet_types::Duration(5_000_000))?, Instant::now() + Duration::from_secs(5),
            |_| unindex_task::Control::Continue);
        let (run, ()) = timeout(Duration::from_secs(3), async { tokio::try_join!(async { Ok::<_, Box<dyn std::error::Error>>(run.await) }, peer) }).await??;
        let done = run?;
        assert_eq!(done.status.phase, unindex_task::Phase::Complete);
        assert_eq!(done.native.reconstructed_keywords, 0);
        assert_eq!(done.native.selected_keywords, expected.len());
        assert_eq!(done.native.observation.retained_removals, 1);
        assert_eq!(done.native.observation.keyword_queries, queries.len() as u64);
        assert!(done.native.unindexed);
        Ok(())
    })
}
