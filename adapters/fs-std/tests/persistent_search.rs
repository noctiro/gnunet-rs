//! Real native advertisements, persistent mandatory matches and source reauthentication.
//! Local Rust peers; this is not original-C or P2P acceptance.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible task tests assert genuine advertisements, history and refusal boundaries"
)]
use gnunet_crypto::{EddsaPublicKey, gns::EdkeySecret};
use gnunet_fs::{Content, Keyword, Keywords, Namespace, Uri, metadata as md, ublock};
use gnunet_fs_host::{
    durable::store::{self, Store},
    ipc,
    search::{
        self, Options, Step,
        task::{Cause, Control, Event, Limits, Phase, StopReason, Task},
    },
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Response};
use std::{
    fs, io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{sleep, timeout},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(5);
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gnunet-persistent-search-{}-{stamp}-{}",
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
fn options(source: &ipc::EndpointSource) -> Result<Options, ProtocolError> {
    Ok(Options {
        anonymity: 1,
        local_only: true,
        deadline: deadline(source)?,
        limits: Default::default(),
        block: Default::default(),
        protocol: Default::default(),
        native: Default::default(),
    })
}
fn deadline(source: &ipc::EndpointSource) -> Result<AbsoluteTime, ProtocolError> {
    Ok(AbsoluteTime::from_micros(
        source.clock().sample()?.now.as_micros() + 4_000_000,
    ))
}
async fn search_query(stream: &mut UnixStream) -> TestResult<[u8; 64]> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 112 {
        return Err("short native search".into());
    }
    let mut frame = vec![0; length];
    frame[..4].copy_from_slice(&header);
    stream.read_exact(&mut frame[4..]).await?;
    let Request::Search(search) = Request::decode(&frame)? else {
        return Err("expected actual SEARCH".into());
    };
    assert_eq!(search.block_type, BlockType::UBLOCK);
    assert_eq!(search.options, 1);
    Ok(search.query)
}
async fn reply(stream: &mut UnixStream, wire: &[u8], expiration: AbsoluteTime) -> TestResult {
    let response = Response::Put(ClientPut {
        block_type: BlockType::UBLOCK,
        expiration,
        last_transmission: AbsoluteTime::UNIX_EPOCH,
        num_transmissions: 0,
        respect_offered: 0,
        block: wire,
    });
    let mut frame = vec![0; response.encoded_len()?];
    response.encode(&mut frame)?;
    stream.write_all(&frame).await?;
    Ok(())
}
async fn closed(stream: &mut UnixStream) -> TestResult {
    let mut end = [0];
    assert_eq!(stream.read(&mut end).await?, 0);
    Ok(())
}
async fn pair(
    listener: &UnixListener,
    a: [u8; 64],
    b: [u8; 64],
) -> TestResult<(UnixStream, UnixStream)> {
    let (mut first, _) = listener.accept().await?;
    let first_query = search_query(&mut first).await?;
    let (mut second, _) = listener.accept().await?;
    let second_query = search_query(&mut second).await?;
    if first_query == a && second_query == b {
        Ok((first, second))
    } else if first_query == b && second_query == a {
        Ok((second, first))
    } else {
        Err("unexpected original query pair".into())
    }
}
fn keyword(label: &[u8], content: Content) -> TestResult<([u8; 64], Vec<u8>)> {
    let publisher = ublock::Publisher::keyword(label, ublock::Limits::default())?;
    let mut output = vec![0; 4096];
    let query = *publisher.context().query();
    Ok((
        query,
        publisher
            .seal(b"", content.uri(), None, &mut output)?
            .bytes()
            .to_vec(),
    ))
}
fn namespace(
    secret: &EdkeySecret,
    label: &[u8],
    update: &[u8],
    content: Content,
    title: &[u8],
) -> TestResult<([u8; 64], Vec<u8>)> {
    let publisher = ublock::Publisher::namespace(secret, label, ublock::Limits::default())?;
    let items = [md::Item {
        kind: 4,
        format: md::Format::CString,
        data: title,
        plugin: None,
        mime: None,
    }];
    let mut order = [0];
    let mut scratch = vec![0; 4096];
    let metadata = md::plan_uncompressed(
        &items,
        &mut order,
        &mut scratch,
        md::Limits::default(),
        md::Options::default(),
    )?;
    let mut output = vec![0; 4096];
    let query = *publisher.context().query();
    Ok((
        query,
        publisher
            .seal(update, content.uri(), Some(&metadata), &mut output)?
            .bytes()
            .to_vec(),
    ))
}

#[test]
fn required_keyword_pending_match_survives_reopen_and_duplicate_hit_adds_no_raw_record()
-> TestResult {
    runtime()?.block_on(async {
        let temporary=Temporary::new()?;let socket=temporary.0.join("fs.sock");let listener=UnixListener::bind(&socket)?;
        let source=ipc::EndpointSource::unix(socket.clone());let policy=options(&source)?;
        let terms=[Keyword::new(b"required-a",true)?,Keyword::new(b"required-b",true)?];
        let query=Uri::Keywords(Keywords::new(&terms)?);
        let content=Content{key:[31;64],query:[32;64],size:45};
        let a=keyword(b"required-a",content)?;let b=keyword(b"required-b",content)?;
        let path=temporary.0.join("task");let mut task=Task::create(&path,query,policy,Limits::default())?;
        let first_peer=async {
            let (mut left,mut right)=pair(&listener,a.0,b.0).await?;
            reply(&mut left,&a.1,AbsoluteTime::NEVER).await?;closed(&mut left).await?;closed(&mut right).await?;
            Ok::<_,Box<dyn std::error::Error>>(())
        };
        let mut pending_seen=false;
        let first_run=task.run(source.duplicate()?,deadline(&source)?,|progress,event|{
            if let Event::Live{step:Step::Pending{..},record:Some(record),..}=event {
                assert_eq!(progress.recorded_observations,1);assert_eq!(progress.results,1);assert_eq!(progress.visible_results,0);
                assert!(!record.visible());assert_eq!(record.mandatory_missing(),1);pending_seen=true;Control::Pause
            }else{Control::Continue}
        });
        let (paused,())=timeout(WAIT,async {tokio::try_join!(async {first_run.await.map_err(|error|error as Box<dyn std::error::Error>)},first_peer)}).await??;
        assert!(pending_seen);assert_eq!(paused.reason,StopReason::CallerPause);assert_eq!(paused.progress.new_observations,1);
        assert!(paused.query_failures.is_empty());assert_eq!(task.status().phase,Phase::Paused);
        assert_eq!(task.status().historical.results,1);assert_eq!(task.status().historical.visible,0);
        drop(task);
        let mut task=Task::open(&path,store::Limits::default())?;
        assert_eq!(task.status().recorded_observations,1);assert_eq!(task.status().historical.visible,0);
        let ignored=Arc::new(AtomicBool::new(false));let peer_ignored=ignored.clone();
        let second_peer=async {
            let (mut left,mut right)=pair(&listener,a.0,b.0).await?;
            reply(&mut left,&a.1,AbsoluteTime::NEVER).await?;
            while !peer_ignored.load(Ordering::SeqCst){sleep(Duration::from_millis(5)).await;}
            reply(&mut right,&b.1,AbsoluteTime::NEVER).await?;
            closed(&mut left).await?;closed(&mut right).await?;
            assert!(timeout(Duration::from_millis(50),listener.accept()).await.is_err());
            Ok::<_,Box<dyn std::error::Error>>(())
        };
        let mut historical_pending=false;let mut new_visible=false;
        let second_run=task.run(source.duplicate()?,deadline(&source)?,|progress,event|{
            if progress.replayed_observations==1&&progress.results==1&&progress.visible_results==0 {historical_pending=true;}
            match event {
                Event::Live{step:Step::Ignored,..}=>{ignored.store(true,Ordering::SeqCst);Control::Continue}
                Event::Live{step:Step::Result{..},record:Some(record),..}=>{
                    assert!(historical_pending);assert!(ignored.load(Ordering::SeqCst));assert_eq!(progress.recorded_observations,2);
                    assert_eq!(progress.new_observations,1);assert_eq!(progress.new_visible_results,1);assert_eq!(record.mandatory_missing(),0);
                    assert_eq!(record.matched_queries().len(),2);assert!(matches!(record.uri(policy.block.uri),Ok(Uri::Content(actual)) if actual==content));
                    new_visible=true;Control::Pause
                }
                _=>Control::Continue,
            }
        });
        let (resumed,())=timeout(WAIT,async {tokio::try_join!(async {second_run.await.map_err(|error|error as Box<dyn std::error::Error>)},second_peer)}).await??;
        assert!(historical_pending&&new_visible);assert_eq!(resumed.reason,StopReason::CallerPause);
        assert_eq!(resumed.progress.replayed_observations,1);assert_eq!(resumed.progress.new_observations,1);
        assert_eq!(resumed.progress.visible_results,1);assert_eq!(task.status().recorded_observations,2);
        drop(task);let reopened=Task::open(&path,store::Limits::default())?;
        assert_eq!(reopened.status().historical.visible,1);assert_eq!(reopened.status().historical.results,1);
        Ok(())
    })
}

#[test]
fn expired_sks_history_replays_without_endpoint_and_fresh_crc_cannot_forge_ciphertext() -> TestResult
{
    runtime()?.block_on(async {
        let temporary=Temporary::new()?;let socket=temporary.0.join("fs.sock");let listener=UnixListener::bind(&socket)?;
        let source=ipc::EndpointSource::unix(socket.clone());let policy=options(&source)?;
        let secret=EdkeySecret::from_seed([0x58;32]);let namespace_key=secret.public_key();
        let query=Uri::Namespace(Namespace::new(EddsaPublicKey::from_bytes(namespace_key),b"root")?);
        let first=Content{key:[41;64],query:[42;64],size:23};let second=Content{key:[43;64],query:[44;64],size:27};
        let a=namespace(&secret,b"root",b"child",first,b"root title\0")?;
        let b=namespace(&secret,b"child",b"",second,b"child title\0")?;
        let expiry=AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros()+900_000);
        let path=temporary.0.join("task");let mut task=Task::create(&path,query,policy,Limits::default())?;
        let peer=async {
            let (mut left,_)=listener.accept().await?;assert_eq!(search_query(&mut left).await?,a.0);reply(&mut left,&a.1,expiry).await?;
            let (mut right,_)=listener.accept().await?;assert_eq!(search_query(&mut right).await?,b.0);reply(&mut right,&b.1,expiry).await?;
            closed(&mut left).await?;closed(&mut right).await?;
            assert!(timeout(Duration::from_millis(50),listener.accept()).await.is_err());
            Ok::<_,Box<dyn std::error::Error>>(())
        };
        let run=task.run(source.duplicate()?,deadline(&source)?,|progress,event|{
            if matches!(event,Event::Live{step:Step::Result{..},..})&&progress.visible_results==2 {Control::Pause}else{Control::Continue}
        });
        let (paused,())=timeout(WAIT,async {tokio::try_join!(async {run.await.map_err(|error|error as Box<dyn std::error::Error>)},peer)}).await??;
        assert_eq!(paused.reason,StopReason::CallerPause);assert_eq!(paused.progress.recorded_observations,2);
        assert_eq!(task.status().historical.queries,2);drop(task);drop(listener);
        sleep(Duration::from_millis(950)).await;
        let absent=ipc::EndpointSource::unix(temporary.0.join("absent.sock"));
        assert!(absent.clock().sample()?.now.as_micros()>expiry.as_micros());
        let mut task=Task::open(&path,store::Limits::default())?;let mut restored=0usize;
        let replay=task.run(absent.duplicate()?,deadline(&absent)?,|progress,event|{
            if let Event::Restored{result,record,query,continuation}=event {
                assert_eq!(progress.replayed_observations,2);assert_eq!(progress.new_observations,0);
                assert_eq!(progress.visible_results,2);assert_eq!(progress.queries,2);
                assert!(query.is_some());let Some(query)=query else {return Control::Cancel;};
                assert_eq!(*query.namespace,namespace_key);
                if result.index()==0 {
                    assert_eq!(query.label,b"root");assert!(query.parents.is_empty());
                    assert!(continuation.is_some());let Some(child)=continuation else {return Control::Cancel;};assert_eq!(child.label,b"child");
                    assert!(matches!(record.uri(policy.block.uri),Ok(Uri::Content(actual)) if actual==first));
                    assert!(record.metadata().iter().any(|item|item.item().data==b"root title\0"));
                }else {
                    assert_eq!(query.label,b"child");assert_eq!(query.parents.len(),1);assert_eq!(query.parents[0].index(),0);assert!(continuation.is_none());
                    assert!(matches!(record.uri(policy.block.uri),Ok(Uri::Content(actual)) if actual==second));
                    assert!(record.metadata().iter().any(|item|item.item().data==b"child title\0"));
                }
                restored+=1;if restored==2 {Control::Pause}else{Control::Continue}
            }else {Control::Continue}
        });
        let replay=timeout(WAIT,replay).await??;assert_eq!(restored,2);assert_eq!(replay.reason,StopReason::CallerPause);
        assert!(replay.query_failures.is_empty());assert_eq!(task.status().recorded_observations,2);drop(task);
        // Recompute valid private Store framing around a changed original UBLOCK.
        // Structural open is allowed; current result authentication must refuse.
        let mut store=Store::open(&path,store::Limits::default())?;
        let corrupt_path=temporary.0.join("tampered");let mut corrupt=Store::create(&corrupt_path,store::Limits::default())?;let mut changed=false;
        for index in 0..store.record_count() {
            let record=store.read_record(index)?.ok_or("original search record missing")?;
            let kind=record.kind;
            let mut body=record.bytes.to_vec();
            if !changed&&let Some(offset)=body.windows(a.1.len()).position(|candidate|candidate==a.1.as_slice()) {
                body[offset+a.1.len()-1]^=1;changed=true;
            }
            corrupt.append(kind,&body)?;
        }
        assert!(changed);drop(corrupt);drop(store);
        let mut corrupt=Task::open(&corrupt_path,store::Limits::default())?;assert_eq!(corrupt.status().recorded_observations,2);
        let mut current_result=false;
        let failure=timeout(WAIT,corrupt.run(absent.duplicate()?,deadline(&absent)?,|_,event|{
            if matches!(event,Event::Restored{..}|Event::Live{record:Some(_),..}) {current_result=true;}
            Control::Continue
        })).await?.err().ok_or("fresh CRC was incorrectly treated as source authentication")?;
        assert!(!current_result);assert!(matches!(failure.cause,Some(Cause::Search(search::Error::Block(_)))));
        assert!(failure.query_failures.is_empty());assert_eq!(failure.progress.replayed_observations,0);
        assert_eq!(failure.progress.recorded_observations,2);assert_eq!(corrupt.status().phase,Phase::Failed);
        Ok(())
    })
}

#[test]
fn dropping_a_live_task_closes_its_original_mq_without_recording_a_settled_pause() -> TestResult {
    runtime()?.block_on(async {
        let temporary=Temporary::new()?;
        let socket=temporary.0.join("quiet.sock");let listener=UnixListener::bind(&socket)?;
        let source=ipc::EndpointSource::unix(socket);
        let terms=[Keyword::new(b"drop-original",true)?];
        let query=Uri::Keywords(Keywords::new(&terms)?);
        let expected=*ublock::Context::keyword(b"drop-original",ublock::Limits::default())?.query();
        let path=temporary.0.join("task");let mut task=Task::create(&path,query,options(&source)?,Limits::default())?;
        let received=Arc::new(tokio::sync::Notify::new());let observed=received.clone();
        let peer=async {
            let (mut stream,_)=listener.accept().await?;
            assert_eq!(search_query(&mut stream).await?,expected);
            observed.notify_one();closed(&mut stream).await
        };
        let host=async {
            let mut running=Box::pin(task.run(source.duplicate()?,deadline(&source)?,|_,_|Control::Continue));
            tokio::select! {
                ()=received.notified()=>{},
                result=&mut running=>return Err(format!("quiet search stopped before drop: {result:?}").into()),
            }
            drop(running);
            assert!(!task.status().active);assert!(task.status().interrupted);
            assert_eq!(task.status().phase,Phase::Running);
            assert_eq!(task.status().recorded_observations,0);
            drop(task);
            let mut reopened=Task::open(&path,store::Limits::default())?;
            assert!(reopened.status().interrupted);assert_eq!(reopened.status().phase,Phase::Running);
            reopened.request_cancel()?;let cancelled=reopened.settle_cancel()?;
            assert_eq!(cancelled.reason,StopReason::Cancelled);
            assert_eq!(reopened.status().phase,Phase::Cancelled);
            assert!(reopened.run(source.duplicate()?,deadline(&source)?,|_,_|Control::Continue).await.is_err());
            Ok::<_,Box<dyn std::error::Error>>(())
        };
        timeout(WAIT,async {tokio::try_join!(host,peer)}).await??;
        assert!(timeout(Duration::from_millis(80),listener.accept()).await.is_err());
        Ok(())
    })
}
