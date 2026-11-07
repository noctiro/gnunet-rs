//! Long-lived official client ownership over actual Unix sockets.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible integration tests assert actual socket traffic, callback ownership and deadlines"
)]
use gnunet_client::{
    statistics::Selector,
    statistics_handle::{DestroyOutcome, GetFlow, SetterAdmission},
};
use gnunet_ipc_unix::{
    handle::{Event, Limits, Progress, StatisticsHandle},
    server,
};
use gnunet_statistics::Statistics;
use std::{
    error::Error,
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
type Handle<'owner> = StatisticsHandle<'owner, 24, 128, 8, 32, 16>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "gnunet-handle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn path(&self) -> PathBuf {
        self.0.join("s.sock")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn handle<'owner>(
    instance: &'owner mut gnunet_client::statistics_handle::Instance,
    path: &Path,
    chunk: usize,
) -> Result<Handle<'owner>> {
    Ok(Handle::new(
        instance,
        path,
        b"s",
        true,
        Limits {
            max_frame_bytes: 256,
            write_chunk_bytes: chunk,
        },
    )?
    .ok_or("enabled owner missing")?)
}
async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if !(4..=65535).contains(&size) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn progressed(progress: Progress) -> Result<()> {
    if matches!(
        progress,
        Progress::WaitDeadline | Progress::Idle | Progress::Closed
    ) {
        return Err(format!("unexpected driver outcome {progress:?}").into());
    }
    Ok(())
}

#[test]
fn lazy_noop_and_coalescing_across_get_match_independent_wire_order() -> Result<()> {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let listener = UnixListener::bind(dir.path())?;
        let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
        let mut client = handle(&mut statistics_instance_1, &dir.path(), 3)?;
        assert_eq!(client.update(b"n", 0, true)?, SetterAdmission::Noop);
        assert!(client.connection_epoch().is_none());
        assert_eq!(
            client
                .drive(Some(Instant::now() + Duration::from_millis(20)), |_, _| {
                    GetFlow::Continue
                })
                .await?,
            Progress::Idle
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(
                frame(&mut stream).await?,
                b"\0\x19\0\xa8\0\0\0\0\0\0\0\0\0\0\0\0s\0anchor\0"
            );
            assert_eq!(
                frame(&mut stream).await?,
                b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x02s\0n\0"
            );
            assert_eq!(frame(&mut stream).await?, b"\0\x08\0\xa9s\0n\0");
            let reply = b"\0\x14\0\xaa\x80\0\0\x01\0\0\0\0\0\0\0\x02s\0n\0\0\x04\0\xab";
            for byte in reply {
                stream.write_all(&[*byte]).await?;
            }
            assert_eq!(stream.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        client.set(b"anchor", 0, false)?;
        client.set(b"n", 1, false)?;
        let get = client.get(Selector {
            subsystem: b"s",
            name: b"n",
        })?;
        assert_eq!(client.set(b"n", 2, true)?, SetterAdmission::Coalesced);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut done = false;
        let mut rows = Vec::new();
        while !done {
            progressed(
                client
                    .drive(Some(deadline), |event, _| {
                        match event {
                            Event::GetValue { get: id, statistic } => {
                                assert_eq!(id, get);
                                rows.push((statistic.value, statistic.persistent()));
                            }
                            Event::GetComplete(completion) => {
                                assert_eq!(completion.get, get);
                                assert!(completion.result.is_ok());
                                done = true;
                            }
                            _ => {}
                        }
                        GetFlow::Continue
                    })
                    .await?,
            )?;
        }
        assert_eq!(rows, [(2, true)]);
        client.destroy(true)?;
        let mut report = None;
        assert_eq!(
            client
                .drive(Some(deadline), |event, _| {
                    if let Event::Destroyed(value) = event {
                        report = Some(value);
                    }
                    GetFlow::Continue
                })
                .await?,
            Progress::Closed
        );
        let report = report.ok_or("missing destruction report")?;
        assert_eq!(report.outcome, DestroyOutcome::Discarded);
        assert_eq!(report.unconfirmed_mutations, 2);
        peer.await??;
        Ok(())
    })
}

#[test]
fn cancellation_inside_callback_drains_old_end_before_next_query() -> Result<()> {
    runtime()?.block_on(async{
    let dir=Directory::new()?;let listener=UnixListener::bind(dir.path())?;
    let peer=tokio::spawn(async move{
        let(mut stream,_)=listener.accept().await?;
        assert_eq!(frame(&mut stream).await?,b"\0\x08\0\xa9s\0a\0");
        stream.write_all(b"\0\x14\0\xaa\0\0\0\0\0\0\0\0\0\0\0\x01s\0a\0\0\x14\0\xaa\0\0\0\0\0\0\0\0\0\0\0\x02s\0a\0\0\x04\0\xab").await?;
        assert_eq!(frame(&mut stream).await?,b"\0\x08\0\xa9s\0b\0");
        stream.write_all(b"\0\x14\0\xaa\0\0\0\x01\0\0\0\0\0\0\0\x09s\0b\0\0\x04\0\xab").await?;
        assert_eq!(stream.read(&mut[0]).await?,0);Ok::<_,io::Error>(())
    });
    let mut statistics_instance_2=gnunet_client::statistics_handle::Instance::new();
    let mut client=handle(&mut statistics_instance_2, &dir.path(),65535)?;
    let first=client.get(Selector{subsystem:b"s",name:b"a"})?;
    let cancelled=client.get(Selector{subsystem:b"s",name:b"c"})?;client.get_cancel(cancelled)?;
    let(mut second,mut done,mut failure)=(None,false,None);let mut rows=Vec::new();let deadline=Instant::now()+Duration::from_secs(2);
    while !done{
        progressed(client.drive(Some(deadline),|event,context|{
            match event{
                Event::GetValue{get,statistic}=>{
                    rows.push((get,statistic.value));
                    if get==first{
                        assert!(context.owns_get(first)); assert!(context.get_callbacks_enabled(first));
                        if let Err(error)=context.get_cancel(first){failure=Some(error);}
                        assert!(context.owns_get(first)); assert!(!context.get_callbacks_enabled(first));
                        match context.get(Selector{subsystem:b"s",name:b"b"}){Ok(id)=>second=Some(id),Err(error)=>failure=Some(error)}
                    }
                },
                Event::GetComplete(completion)=>{assert_eq!(Some(completion.get),second);assert!(completion.result.is_ok());done=true;},
                _=>{}
            }GetFlow::Continue
        }).await?)?;
        if let Some(error)=failure.take(){return Err(error.into());}
    }
    assert_eq!(rows,[(first,1),(second.ok_or("missing second request")?,9)]);
    client.destroy(false)?;peer.await??;Ok(())
})
}

#[test]
fn initial_socket_retry_retains_virtual_mq_and_immutable_first_setter() -> Result<()> {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut statistics_instance_3 = gnunet_client::statistics_handle::Instance::new();
        let mut client = handle(&mut statistics_instance_3, &dir.path(), 4)?;
        client.set(b"n", 1, false)?;
        let epoch = client.connection_epoch().ok_or("virtual MQ missing")?;
        let mut retry = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        while !retry {
            progressed(
                client
                    .drive(Some(deadline), |event, _| {
                        if let Event::ConnectRetry { epoch: id, .. } = event {
                            assert_eq!(id, epoch);
                            retry = true;
                        }
                        GetFlow::Continue
                    })
                    .await?,
            )?;
        }
        assert!(client.take_io_error().is_some());
        client.set(b"n", 2, false)?;
        assert_eq!(client.set(b"n", 3, false)?, SetterAdmission::Coalesced);
        let get = client.get(Selector {
            subsystem: b"s",
            name: b"n",
        })?;
        let listener = UnixListener::bind(dir.path())?;
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            for value in [1u64, 3] {
                let bytes = frame(&mut stream).await?;
                assert_eq!(&bytes[..8], b"\0\x14\0\xa8\0\0\0\0");
                assert_eq!(
                    u64::from_be_bytes(
                        bytes[8..16]
                            .try_into()
                            .map_err(|_| io::ErrorKind::InvalidData)?
                    ),
                    value
                );
                assert_eq!(&bytes[16..], b"s\0n\0");
            }
            assert_eq!(frame(&mut stream).await?, b"\0\x08\0\xa9s\0n\0");
            stream
                .write_all(b"\0\x14\0\xaa\0\0\0\0\0\0\0\0\0\0\0\x03s\0n\0\0\x04\0\xab")
                .await?;
            assert_eq!(stream.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let mut done = false;
        let mut values = Vec::new();
        while !done {
            progressed(
                client
                    .drive(Some(deadline), |event, _| {
                        match event {
                            Event::GetValue { statistic, .. } => values.push(statistic.value),
                            Event::GetComplete(completion) => {
                                assert_eq!(completion.get, get);
                                assert!(completion.result.is_ok());
                                done = true;
                            }
                            Event::ConnectionLost { .. } => assert!(
                                !matches!(event, Event::ConnectionLost { .. }),
                                "initial refusal must not retire MQ"
                            ),
                            _ => {}
                        }
                        GetFlow::Continue
                    })
                    .await?,
            )?;
            assert_eq!(client.connection_epoch(), Some(epoch));
        }
        assert_eq!(values, [3]);
        client.destroy(false)?;
        peer.await??;
        Ok(())
    })
}

#[test]
fn cancelling_a_drive_future_preserves_partial_header_and_original_get() -> Result<()> {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let listener = UnixListener::bind(dir.path())?;
        let (mut release, mut wait) = UnixStream::pair()?;
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(frame(&mut stream).await?, b"\0\x08\0\xa9s\0n\0");
            stream.write_all(b"\0\x14").await?;
            wait.read_exact(&mut [0]).await?;
            stream
                .write_all(b"\0\xaa\0\0\0\0\0\0\0\0\0\0\0\x07s\0n\0\0\x04\0\xab")
                .await?;
            assert_eq!(stream.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let mut statistics_instance_4 = gnunet_client::statistics_handle::Instance::new();
        let mut client = handle(&mut statistics_instance_4, &dir.path(), 2)?;
        let get = client.get(Selector {
            subsystem: b"s",
            name: b"n",
        })?;
        let epoch = client.connection_epoch();
        let mut cancelled_wait = false;
        for _ in 0..24 {
            match tokio::time::timeout(
                Duration::from_millis(20),
                client.drive(None, |event, _| {
                    assert!(!matches!(
                        event,
                        Event::GetValue { .. } | Event::GetComplete(_)
                    ));
                    GetFlow::Continue
                }),
            )
            .await
            {
                Err(_) => {
                    cancelled_wait = true;
                    break;
                }
                Ok(result) => progressed(result?)?,
            }
        }
        assert!(cancelled_wait);
        assert_eq!(client.connection_epoch(), epoch);
        release.write_all(&[1]).await?;
        let mut done = false;
        let mut values = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !done {
            progressed(
                client
                    .drive(Some(deadline), |event, _| {
                        match event {
                            Event::GetValue { get: id, statistic } => {
                                assert_eq!(id, get);
                                values.push(statistic.value);
                            }
                            Event::GetComplete(completion) => {
                                assert_eq!(completion.get, get);
                                assert!(completion.result.is_ok());
                                done = true;
                            }
                            Event::ConnectionLost { .. } => assert!(
                                !matches!(event, Event::ConnectionLost { .. }),
                                "cancelled drive lost original operation"
                            ),
                            _ => {}
                        }
                        GetFlow::Continue
                    })
                    .await?,
            )?;
        }
        assert_eq!(values, [7]);
        client.destroy(false)?;
        peer.await??;
        Ok(())
    })
}

type ServiceCore = Statistics<8, 128, 8, 16, 32>;
fn start_service(
    path: &Path,
    mut core: ServiceCore,
) -> io::Result<(
    UnixStream,
    tokio::task::JoinHandle<std::result::Result<ServiceCore, gnunet_ipc_unix::IpcError>>,
)> {
    let listener = UnixListener::bind(path)?;
    let (mut wait, release) = UnixStream::pair()?;
    let task = tokio::spawn(async move {
        server::serve_statistics(
            &listener,
            &mut core,
            server::Limits {
                max_connections: 8,
                max_frame_bytes: 256,
                max_pending_bytes: 4096,
                idle_timeout: Duration::MAX,
            },
            async {
                match wait.read(&mut [0]).await {
                    Ok(_) | Err(_) => {}
                }
            },
            |_| {},
        )
        .await?;
        Ok(core)
    });
    Ok((release, task))
}

#[test]
fn restart_remaps_cancelled_watch_holes_to_stable_logical_owners() -> Result<()> {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let mut core = ServiceCore::new();
        let seed = core.connect()?;
        for (name, value) in [(b"a" as &[u8], 10), (b"b", 20), (b"c", 30)] {
            core.set(
                seed,
                gnunet_statistics::Set {
                    selector: Selector {
                        subsystem: b"s",
                        name,
                    },
                    flags: 2,
                    value,
                },
            )?;
        }
        core.disconnect(seed)?;
        let (stop, server) = start_service(&dir.path(), core)?;
        let mut statistics_instance_5 = gnunet_client::statistics_handle::Instance::new();
        let mut client = handle(&mut statistics_instance_5, &dir.path(), 65535)?;
        let first = client.watch(Selector {
            subsystem: b"s",
            name: b"a",
        })?;
        let survivor = client.watch(Selector {
            subsystem: b"s",
            name: b"b",
        })?;
        let mut initial = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while initial.len() < 2 {
            progressed(
                client
                    .drive(Some(deadline), |event, _| {
                        if let Event::WatchValue {
                            watch,
                            notification,
                            ..
                        } = event
                        {
                            initial.push((watch, notification.value));
                        }
                        GetFlow::Continue
                    })
                    .await?,
            )?;
        }
        assert_eq!(initial, [(first, 10), (survivor, 20)]);
        client.watch_cancel(first)?;
        let replacement = client.watch(Selector {
            subsystem: b"s",
            name: b"c",
        })?;
        let mut saw_replacement = false;
        while !saw_replacement {
            progressed(
                client
                    .drive(Some(deadline), |event, _| {
                        if let Event::WatchValue {
                            watch,
                            notification,
                            ..
                        } = event
                        {
                            assert_eq!(watch, replacement);
                            assert_eq!(notification.value, 30);
                            saw_replacement = true;
                        }
                        GetFlow::Continue
                    })
                    .await?,
            )?;
        }
        let old_epoch = client.connection_epoch();
        drop(stop);
        let core = server.await??;
        std::fs::remove_file(dir.path())?;
        let mut lost = false;
        while !lost {
            progressed(
                client
                    .drive(Some(deadline), |event, _| {
                        if let Event::ConnectionLost { .. } = event {
                            lost = true;
                        }
                        GetFlow::Continue
                    })
                    .await?,
            )?;
        }
        let (stop, restarted) = start_service(&dir.path(), core)?;
        let mut again = Vec::new();
        while again.len() < 2 {
            progressed(
                client
                    .drive(Some(deadline), |event, _| {
                        if let Event::WatchValue {
                            watch,
                            selector,
                            notification,
                        } = event
                        {
                            again.push((
                                watch,
                                selector.name.to_vec(),
                                notification.wid,
                                notification.value,
                            ));
                        }
                        GetFlow::Continue
                    })
                    .await?,
            )?;
        }
        assert_ne!(client.connection_epoch(), old_epoch);
        assert_eq!(
            again,
            [
                (survivor, b"b".to_vec(), 0, 20),
                (replacement, b"c".to_vec(), 1, 30)
            ]
        );
        client.destroy(false)?;
        drop(stop);
        restarted.await??;
        Ok(())
    })
}

#[test]
fn expired_destroy_never_submits_a_late_connect_and_delivers_failure_report() -> Result<()> {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let listener = UnixListener::bind(dir.path())?;
        let mut statistics_instance_6 = gnunet_client::statistics_handle::Instance::new();
        let mut client = handle(&mut statistics_instance_6, &dir.path(), 1)?;
        client.set(b"n", 1, true)?;
        client.destroy(true)?;
        tokio::time::sleep(Duration::from_millis(15)).await;
        let mut report = None;
        let result = client
            .drive(None, |event, _| {
                if let Event::Destroyed(value) = event {
                    report = Some(value);
                }
                GetFlow::Continue
            })
            .await?;
        assert_eq!(result, Progress::Closed);
        assert!(client.is_closed());
        assert_eq!(
            report.ok_or("missing deadline report")?.outcome,
            DestroyOutcome::Deadline
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    })
}

#[test]
fn iterator_abort_completes_on_end_but_suppresses_disconnect_continuation() -> Result<()> {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let listener = UnixListener::bind(dir.path())?;
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(frame(&mut stream).await?, b"\0\x08\0\xa9s\0a\0");
            stream.write_all(b"\0\x14\0\xaa\0\0\0\0\0\0\0\0\0\0\0\x01s\0a\0\0\x14\0\xaa\0\0\0\0\0\0\0\0\0\0\0\x02s\0a\0\0\x04\0\xab").await?;
            assert_eq!(frame(&mut stream).await?, b"\0\x08\0\xa9s\0b\0");
            stream.write_all(b"\0\x14\0\xaa\0\0\0\x01\0\0\0\0\0\0\0\x09s\0b\0\0\x14\0\xaa\0\0\0\x01\0\0\0\0\0\0\0\x0as\0b\0").await?;
            Ok::<_, io::Error>(())
        });
        let mut statistics_instance_7=gnunet_client::statistics_handle::Instance::new();
        let mut client = handle(&mut statistics_instance_7, &dir.path(), 2)?;
        let first = client.get(Selector { subsystem: b"s", name: b"a" })?;
        let second = client.get(Selector { subsystem: b"s", name: b"b" })?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let (mut lost, mut completions) = (false, Vec::new());
        let mut rows = Vec::new();
        while !lost {
            progressed(client.drive(Some(deadline), |event, _| {
                match event {
                    Event::GetValue { get, statistic } => { rows.push((get, statistic.value)); return GetFlow::AbortIteration; }
                    Event::GetComplete(completion) => completions.push(completion),
                    Event::ConnectionLost { .. } => lost = true,
                    _ => {}
                }
                GetFlow::Continue
            }).await?)?;
        }
        assert_eq!(rows, [(first, 1), (second, 9)]);
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].get, first);
        assert!(completions[0].result.is_ok());
        assert!(!client.owns_get(first)); assert!(!client.get_callbacks_enabled(first));
        assert!(!client.owns_get(second)); assert!(!client.get_callbacks_enabled(second));
        client.destroy(false)?;
        assert_eq!(client.drive(Some(deadline), |event, _| {
            assert!(!matches!(event, Event::GetValue { .. } | Event::GetComplete(_)));
            GetFlow::Continue
        }).await?, Progress::Closed);
        peer.await??;
        Ok(())
    })
}

#[test]
fn processing_confirmation_retires_socket_and_callback_admission() -> Result<()> {
    runtime()?.block_on(async {
        let dir = Directory::new()?;
        let listener = UnixListener::bind(dir.path())?;
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert_eq!(frame(&mut stream).await?, b"\0\x0b\0\xa9s\0warm\0");
            stream.write_all(b"\0\x04\0\xab").await?;
            assert_eq!(
                frame(&mut stream).await?,
                b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x07s\0n\0"
            );
            assert_eq!(frame(&mut stream).await?, b"\0\x04\0\xae");
            stream.write_all(b"\0\x04\0\xaf").await?;
            assert_eq!(stream.read(&mut [0]).await?, 0);
            Ok::<_, io::Error>(())
        });
        let mut statistics_instance_8 = gnunet_client::statistics_handle::Instance::new();
        let mut client = handle(&mut statistics_instance_8, &dir.path(), 65535)?;
        let get = client.get(Selector {
            subsystem: b"s",
            name: b"warm",
        })?;
        let (mut completed, mut report) = (false, None);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !completed {
            progressed(
                client
                    .drive(Some(deadline), |event, _| {
                        if let Event::GetComplete(completion) = event {
                            assert_eq!(completion.get, get);
                            assert!(completion.result.is_ok());
                            completed = true;
                        }
                        GetFlow::Continue
                    })
                    .await?,
            )?;
        }
        client.set(b"n", 7, true)?;
        client.destroy(true)?;
        while report.is_none() {
            let progress = client
                .drive(Some(deadline), |event, context| {
                    if let Event::Destroyed(value) = event {
                        report = Some(value);
                        assert!(matches!(
                            context.set(b"late", 1, false),
                            Err(gnunet_ipc_unix::IpcError::Protocol(
                                gnunet_types::Error::Closed
                            ))
                        ));
                    }
                    GetFlow::Continue
                })
                .await?;
            assert!(!matches!(progress, Progress::WaitDeadline | Progress::Idle));
        }
        let report = report.ok_or("missing confirmation report")?;
        assert_eq!(report.outcome, DestroyOutcome::ProcessingConfirmed);
        assert_eq!(report.unconfirmed_mutations, 0);
        assert!(client.is_closed());
        let mut callback_after = false;
        assert_eq!(
            client
                .drive(None, |_, _| {
                    callback_after = true;
                    GetFlow::Continue
                })
                .await?,
            Progress::Closed
        );
        assert!(!callback_after);
        peer.await??;
        Ok(())
    })
}
