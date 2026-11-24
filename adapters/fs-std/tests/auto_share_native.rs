//! Original indexed tree preparation, private snapshot recovery and local wire receipts.
#![cfg(all(any(unix, windows), feature = "auto-share"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The private native scenario asserts actual preparations, exact source hashes, original replies and absence of replay"
)]
#[path = "support/local_peer.rs"]
mod local_peer;
use gnunet_client_host::EndpointSource;
use gnunet_fs_host::auto_share::{Event, Limits, Options, Owner, Stop};
use gnunet_native::filesystem::Directory;
use gnunet_service_runtime::{clock::SystemClock, local::Stream};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::{datastore, fs as wire};
use local_peer::{Listener, Temporary};
use std::io::Write;
use std::{collections::HashSet, fs, io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(12);

fn limits() -> Limits {
    Limits {
        stability: Duration::from_millis(1),
        minimum_scan: Duration::from_millis(2),
        maximum_scan: Duration::from_millis(4),
        operation: Duration::from_secs(8),
        lifetime: Duration::from_secs(10),
        ..Limits::default()
    }
}
fn options() -> Options {
    Options {
        disable_extractor: true,
        disable_creation_time: true,
        content_lifetime: Some(Duration::from_secs(3600)),
        ..Options::default()
    }
}
async fn frame(stream: &mut Stream) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0; 4];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err(io::Error::other("short original frame"));
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(Some(bytes))
}
async fn indexes(listener: &Listener, expected: &HashSet<[u8; 64]>) -> Result {
    let mut seen = HashSet::new();
    for _ in expected {
        let (mut stream, _) = listener.accept().await?;
        let bytes = frame(&mut stream)
            .await?
            .ok_or("missing original index request")?;
        let wire::Request::IndexStart {
            device,
            inode,
            file_id,
            filename,
        } = wire::Request::decode(&bytes)?
        else {
            return Err("expected original INDEX_START".into());
        };
        assert_eq!((device, inode), (0, 0));
        assert!(expected.contains(&file_id));
        assert!(seen.insert(file_id));
        assert!(!filename.is_empty());
        let mut response = [0; 4];
        let used = wire::Response::IndexStarted.encode(&mut response)?;
        stream.write_all(&response[..used]).await?;
        assert!(frame(&mut stream).await?.is_none());
    }
    assert_eq!(&seen, expected);
    Ok(())
}
async fn puts(listener: &Listener, expected: &HashSet<[u8; 64]>) -> Result<usize> {
    let (mut stream, _) = listener.accept().await?;
    let mut indexed = HashSet::new();
    let mut count = 0;
    while let Some(bytes) = frame(&mut stream).await? {
        let datastore::Request::Put(data) = datastore::Request::decode(&bytes)? else {
            return Err("expected actual PUT".into());
        };
        if data.kind == 6 {
            assert_eq!(data.value.len(), 72);
            let id: [u8; 64] = data.value[..64].try_into()?;
            assert!(expected.contains(&id));
            assert_eq!(&data.value[64..], &[0; 8]);
            assert!(indexed.insert(id));
        } else {
            assert!(matches!(data.kind, 1 | 2));
            assert!(!data.value.is_empty());
        }
        let mut response = [0; 32];
        let used = datastore::Response::Status(datastore::Status {
            code: 1,
            min_expiration: AbsoluteTime::NEVER,
            message: None,
        })
        .encode(&mut response)?;
        stream.write_all(&response[..used]).await?;
        count += 1;
    }
    assert_eq!(&indexed, expected);
    Ok(count)
}
async fn quiet(listener: &Listener) -> Result {
    assert!(
        timeout(Duration::from_millis(40), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn replaced_live_catalog_refuses_new_intent_without_overwriting_the_foreign_image() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temporary = Temporary::new()?;
            let parent = Directory::open(&temporary.0)?;
            drop(parent.create_private_directory("source".as_ref())?);
            let source = temporary.0.join("source");
            fs::write(source.join("one.txt"), b"original indexed source")?;
            let fs_path = temporary.0.join("fs.sock");
            let ds_path = temporary.0.join("ds.sock");
            let fs_listener = Listener::bind(&fs_path).await?;
            let ds_listener = Listener::bind(&ds_path).await?;
            let clock = Arc::new(SystemClock);
            let fs = EndpointSource::unix_with_clock(fs_path, clock.clone());
            let ds = EndpointSource::unix_with_clock(ds_path, clock);
            let mut owner = Owner::open(&source, fs, ds, options(), limits(), Stop::default())?;
            let state = source.join(".auto-share-rust");
            let image = state.join("catalog.image");
            let bytes = fs::read(&image)?;
            fs::rename(&image, state.join("held-image"))?;
            let mut foreign =
                Directory::open(&state)?.create_private_file("catalog.image".as_ref())?;
            foreign.write_all(&bytes)?;
            foreign.sync_all()?;
            let failed = timeout(WAIT, owner.run(|_| {}))
                .await?
                .err()
                .ok_or("replaced catalog admitted new intent")?;
            assert!(failed.cause.is_some());
            assert_eq!(owner.catalog_directory_sync(), None);
            assert_eq!((failed.report.prepared, failed.report.published), (0, 0));
            assert_eq!(fs::read(&image)?, bytes);
            assert_eq!(fs::read(state.join("held-image"))?, bytes);
            assert!(!state.join("catalog.next").exists());
            quiet(&fs_listener).await?;
            quiet(&ds_listener).await?;
            Ok(())
        })
}

#[test]
fn changed_catalog_after_preparation_refuses_original_task_admission() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temporary = Temporary::new()?;
            let parent = Directory::open(&temporary.0)?;
            drop(parent.create_private_directory("source".as_ref())?);
            let source = temporary.0.join("source");
            fs::write(source.join("one.txt"), b"original indexed source")?;
            let fs_path = temporary.0.join("fs.sock");
            let ds_path = temporary.0.join("ds.sock");
            let fs_listener = Listener::bind(&fs_path).await?;
            let ds_listener = Listener::bind(&ds_path).await?;
            let clock = Arc::new(SystemClock);
            let fs = EndpointSource::unix_with_clock(fs_path, clock.clone());
            let ds = EndpointSource::unix_with_clock(ds_path, clock);
            let mut owner = Owner::open(&source, fs, ds, options(), limits(), Stop::default())?;
            let state = source.join(".auto-share-rust");
            let replacement = b"independent change";
            let mut mutation = None;
            let failed = timeout(
                WAIT,
                owner.run(|event| {
                    if mutation.is_none() && matches!(event, Event::Prepared { .. }) {
                        mutation = Some((|| -> io::Result<()> {
                            let mut file = Directory::open(&state)?
                                .open_file_for_update("catalog.image".as_ref())?;
                            file.set_len(0)?;
                            file.write_all(replacement)?;
                            file.sync_all()
                        })());
                    }
                }),
            )
            .await?
            .err()
            .ok_or("changed catalog admitted a prepared publication")?;
            mutation.ok_or("prepared catalog was not exercised")??;
            assert!(failed.cause.is_some());
            assert_eq!((failed.report.prepared, failed.report.published), (1, 0));
            assert_eq!(owner.catalog_directory_sync(), None);
            assert_eq!(fs::read(state.join("catalog.image"))?, replacement);
            assert!(!state.join("catalog.next").exists());
            quiet(&fs_listener).await?;
            quiet(&ds_listener).await
        })
}

#[test]
fn prepared_nested_tree_reopens_publishes_original_objects_and_never_replays_complete_work()
-> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temporary = Temporary::new()?;
            let parent = Directory::open(&temporary.0)?;
            drop(parent.create_private_directory("source".as_ref())?);
            let source = temporary.0.join("source");
            #[cfg(windows)]
            fs::write(
                source.join(".AUTO-SHARE"),
                b"private native state must not be published",
            )?;
            fs::create_dir_all(source.join("album/deeper"))?;
            let first = b"first actual original indexed file";
            let second = b"second actual original indexed file";
            fs::write(source.join("album/one.txt"), first)?;
            fs::write(source.join("album/deeper/snow-雪.bin"), second)?;
            let expected = HashSet::from([
                gnunet_crypto::hash512(first),
                gnunet_crypto::hash512(second),
            ]);
            let fs_path = temporary.0.join("fs.sock");
            let ds_path = temporary.0.join("ds.sock");
            let fs_listener = Listener::bind(&fs_path).await?;
            let ds_listener = Listener::bind(&ds_path).await?;
            let clock = Arc::new(SystemClock);
            let fs = EndpointSource::unix_with_clock(fs_path, clock.clone());
            let ds = EndpointSource::unix_with_clock(ds_path, clock);
            let stop = Stop::default();
            let mut owner = Owner::open(
                &source,
                fs.duplicate()?,
                ds.duplicate()?,
                options(),
                limits(),
                stop.clone(),
            )?;
            let prepared = timeout(
                WAIT,
                owner.run(|event| match event {
                    Event::Prepared { .. } | Event::Failed { .. } | Event::Blocked { .. } => {
                        stop.request()
                    }
                    _ => {}
                }),
            )
            .await
            .map_err(|error| format!("initial tree preparation: {error}"))??;
            assert_eq!(
                (
                    prepared.prepared,
                    prepared.published,
                    prepared.failures,
                    prepared.blocked
                ),
                (1, 0, 0, 0)
            );
            let source_barrier = Directory::open_source(&source)?.sync()?;
            let state_barrier = Directory::open(&source.join(".auto-share-rust"))?.sync()?;
            assert_eq!(
                owner.catalog_directory_sync(),
                Some(source_barrier.combine(state_barrier))
            );
            quiet(&fs_listener).await?;
            quiet(&ds_listener).await?;
            drop(owner);

            let stop = Stop::default();
            let mut owner = Owner::open(
                &source,
                fs.duplicate()?,
                ds.duplicate()?,
                options(),
                limits(),
                stop.clone(),
            )?;
            assert_eq!(owner.catalog_directory_sync(), None);
            let work = owner.run(|event| match event {
                Event::Published { .. } | Event::Failed { .. } | Event::Blocked { .. } => {
                    stop.request()
                }
                _ => {}
            });
            let peers = async {
                tokio::try_join!(
                    indexes(&fs_listener, &expected),
                    puts(&ds_listener, &expected)
                )
            };
            let (published, (_, count)) = timeout(WAIT, async {
                tokio::try_join!(
                    async {
                        let report = work.await?;
                        if report.failures != 0 || report.blocked != 0 {
                            return Err(
                                format!("reopened tree failed to publish: {report:?}").into()
                            );
                        }
                        Ok::<_, Box<dyn std::error::Error>>(report)
                    },
                    peers
                )
            })
            .await
            .map_err(|error| format!("reopened tree publication: {error}"))??;
            assert_eq!(
                (
                    published.prepared,
                    published.published,
                    published.failures,
                    published.blocked
                ),
                (0, 1, 0, 0)
            );
            assert!(count > expected.len());
            drop(owner);

            let stop = Stop::default();
            let mut owner = Owner::open(
                &source,
                fs.duplicate()?,
                ds.duplicate()?,
                options(),
                limits(),
                stop.clone(),
            )?;
            let restored = timeout(
                WAIT,
                owner.run(|event| match event {
                    Event::Scanned { .. } | Event::Failed { .. } | Event::Blocked { .. } => {
                        stop.request()
                    }
                    _ => {}
                }),
            )
            .await??;
            assert_eq!(
                (
                    restored.prepared,
                    restored.published,
                    restored.failures,
                    restored.blocked
                ),
                (0, 0, 0, 0)
            );
            assert!(restored.scans > 0);
            quiet(&fs_listener).await?;
            quiet(&ds_listener).await?;
            Ok(())
        })
}
