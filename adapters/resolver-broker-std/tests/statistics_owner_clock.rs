//! Source clock owner deadlines, separate from native CLIENT socket retry.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite owned Unix fixtures assert exact original GET and source task ordering"
)]
#[path = "../../ipc-unix/tests/support/clock_source.rs"]
pub mod clock_source;
use gnunet_client::{
    statistics::Selector,
    statistics_handle::{DestroyOutcome, GetFlow},
};
use gnunet_config::Configuration;
use gnunet_ipc_unix::handle::{Event, Progress, StatisticsHandle};
use gnunet_resolver_broker::{FamilyProfile, Limits, LiveConfiguration, broker};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::{MessageHeader, message_type};
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
    time::{Instant, timeout},
};
type Test = Result<(), Box<dyn StdError>>;
type Stats<'owner> = StatisticsHandle<'owner, 8, 64, 4, 64, 16>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Dir(PathBuf);
impl Dir {
    fn new() -> io::Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "gnunet-statistics-owner-clock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
fn profile() -> Result<FamilyProfile, Box<dyn StdError>> {
    let p = gnunet_resolver_broker::native_profile()?;
    Ok(FamilyProfile::new(
        p.encode(gnunet_resolver_broker::Family::V4),
        p.encode(gnunet_resolver_broker::Family::V6),
    )?)
}
fn cfg(section: &[u8], path: &std::path::Path) -> Result<Configuration, Box<dyn StdError>> {
    let mut c = Configuration::default();
    c.set_value(
        section,
        b"UNIXPATH",
        Some(path.as_os_str().as_encoded_bytes()),
    )?;
    Ok(c)
}
async fn alongside<'owner, F: Future>(
    host: &mut Stats<'owner>,
    future: F,
) -> Result<F::Output, Box<dyn StdError>> {
    let mut future = std::pin::pin!(future);
    Ok(timeout(
        Duration::from_secs(3),
        poll_fn(|cx| {
            if let Poll::Ready(result) = future.as_mut().poll(cx) {
                return Poll::Ready(Ok(result));
            }
            let mut drive = std::pin::pin!(host.drive(None, |_, _| GetFlow::Continue));
            match drive.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(Progress::Activity)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(_)) => Poll::Ready(Err(gnunet_ipc_unix::IpcError::Closed)),
            }
        }),
    )
    .await??)
}
async fn frame(socket: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    socket.read_exact(&mut header).await?;
    let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if len < 4 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; len];
    bytes[..4].copy_from_slice(&header);
    socket.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
#[test]
fn configuration_refusal_owner_retry_obeys_shared_forward_revision_and_keeps_queued_get() -> Test {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
  let dir=Dir::new()?;let path=dir.0.join("statistics");let clock=Arc::new(clock_source::Adjustable::advancing(1_000_000,8)?);
  let(context,_driver)=broker::<4,64>(LiveConfiguration::new(cfg(b"resolver",&dir.0.join("unused"))?),Limits::default(),profile()?,clock.clone())?;
  let mut statistics_instance_1=gnunet_client::statistics_handle::Instance::new();
  let live=LiveConfiguration::new(Configuration::default());let mut host=Stats::from_live_config(&mut statistics_instance_1, live.clone(),context.resolution_context(),b"owner",Default::default())?.ok_or("disabled")?;
  let selector=Selector{subsystem:b"owner",name:b"value"};let get=host.get(selector)?;let mut failures=0;let until=Instant::now()+Duration::from_secs(4);
  while failures<10{host.drive(Some(until),|event,_|{if matches!(event,Event::ConnectionUnavailable{..}){failures+=1;}GetFlow::Continue}).await?;assert!(Instant::now()<until);}
  assert_eq!(host.connection_epoch(),None);assert!(host.owns_get(get));
  let listener=UnixListener::bind(&path)?;live.replace(cfg(b"statistics",&path)?)?;clock.set_offset(2_000_000)?;
  let accepted=alongside(&mut host,timeout(Duration::from_millis(100),listener.accept())).await?;
  assert!(accepted.is_ok(),"source forward revision must wake original STATISTICS-owner retry, not only native CLIENT retry");
  let(mut socket,_)=accepted??;let actual=alongside(&mut host,frame(&mut socket)).await??;let mut expected=[0;128];let len=selector.encode_get(&mut expected)?;assert_eq!(actual,&expected[..len]);assert!(host.owns_get(get));host.destroy(false)?;drop(host);assert_eq!(socket.read(&mut[0]).await?,0);Ok(())
 })
}
#[test]
fn deferred_destruction_uses_original_shared_absolute_deadline_not_native_elapsed_time() -> Test {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
  let dir=Dir::new()?;let path=dir.0.join("statistics");let listener=UnixListener::bind(&path)?;let clock=Arc::new(clock_source::Adjustable::frozen(1_000_000,8)?);
  let(context,_driver)=broker::<4,64>(LiveConfiguration::new(cfg(b"resolver",&dir.0.join("unused"))?),Limits::default(),profile()?,clock.clone())?;
  let mut statistics_instance_2=gnunet_client::statistics_handle::Instance::new();
  let mut host=Stats::from_config(&mut statistics_instance_2, &cfg(b"statistics",&path)?,context.resolution_context(),b"owner",Default::default())?.ok_or("disabled")?;
  host.set(b"value",7,false)?;host.destroy(true)?;assert!(!host.is_closed());
  let(mut socket,_)=alongside(&mut host,listener.accept()).await??;let first=alongside(&mut host,frame(&mut socket)).await??;assert_eq!(MessageHeader::decode(&first)?.message_type(),message_type::STATISTICS_SET);
  let barrier=alongside(&mut host,frame(&mut socket)).await??;assert_eq!(MessageHeader::decode(&barrier)?.message_type(),message_type::STATISTICS_DISCONNECT);
  let mut terminal=None;let until=Instant::now()+Duration::from_millis(20);
  while Instant::now()<until&&!host.is_closed(){host.drive(Some(until),|event,_|{if let Event::Destroyed(report)=event{terminal=Some(report.outcome);}GetFlow::Continue}).await?;}
  assert!(!host.is_closed()&&terminal.is_none(),"native elapsed20ms cannot expire a5ms logical deadline while shared source remains frozen");
  clock.set(1_005_000)?;let until=Instant::now()+Duration::from_secs(1);
  while terminal.is_none(){host.drive(Some(until),|event,_|{if let Event::Destroyed(report)=event{terminal=Some(report.outcome);}GetFlow::Continue}).await?;assert!(Instant::now()<until);}
  assert_eq!(terminal,Some(DestroyOutcome::Deadline));assert_eq!(socket.read(&mut[0]).await?,0);Ok(())
 })
}
#[test]
fn get_failure_continuation_changes_source_before_original_reconnect_registration() -> Test {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
  let dir=Dir::new()?;let path=dir.0.join("statistics");let listener=UnixListener::bind(&path)?;let clock=Arc::new(clock_source::Adjustable::frozen(1_000_000,8)?);
  let(context,_driver)=broker::<4,64>(LiveConfiguration::new(cfg(b"resolver",&dir.0.join("unused"))?),Limits::default(),profile()?,clock.clone())?;
  let mut statistics_instance_3=gnunet_client::statistics_handle::Instance::new();
  let mut host=Stats::from_config(&mut statistics_instance_3, &cfg(b"statistics",&path)?,context.resolution_context(),b"owner",Default::default())?.ok_or("disabled")?;
  let first=host.get(Selector{subsystem:b"owner",name:b"first"})?;let(mut socket,_)=alongside(&mut host,listener.accept()).await??;alongside(&mut host,frame(&mut socket)).await??;drop(socket);
  let mut completed=0;let mut replacement=None;let mut callback_error=None;let until=Instant::now()+Duration::from_secs(1);
  while completed==0{host.drive(Some(until),|event,callback|{if let Event::GetComplete(report)=event{assert_eq!(report.get,first);assert!(report.result.is_err());completed+=1;if let Err(e)=clock.set(5_000_000){callback_error=Some(e.to_string());}match callback.get(Selector{subsystem:b"owner",name:b"second"}){Ok(id)=>replacement=Some(id),Err(e)=>callback_error=Some(e.to_string())}}GetFlow::Continue}).await?;assert!(Instant::now()<until);}
  if let Some(error)=callback_error{return Err(error.into());}let second=replacement.ok_or("missing second GET")?;assert!(host.owns_get(second));
  assert!(alongside(&mut host,timeout(Duration::from_millis(20),listener.accept())).await?.is_err(),"reconnect is registered after original continuation returns at5M; its1ms cannot already be due at frozen5M");
  clock.set(5_001_000)?;let(mut next,_)=alongside(&mut host,listener.accept()).await??;let actual=alongside(&mut host,frame(&mut next)).await??;let mut expected=[0;128];let len=Selector{subsystem:b"owner",name:b"second"}.encode_get(&mut expected)?;assert_eq!(actual,&expected[..len]);assert_eq!(completed,1);host.destroy(false)?;drop(host);Ok(())
 })
}
#[test]
fn confirmation_finalization_is_sticky_ready_after_callback_instead_of_inline_destruction() -> Test
{
    type Core<'owner> = gnunet_client::statistics_handle::StatisticsHandle<'owner, 4, 64, 2, 64, 8>;
    let mut statistics_instance_4 = gnunet_client::statistics_handle::Instance::new();
    let mut core = Core::new(&mut statistics_instance_4, b"owner", true)?.ok_or("disabled")?;
    core.set(b"value", 7, false)?;
    let epoch = core.begin_connection(AbsoluteTime::from_micros(1_000))?;
    let mut bytes = [0; 128];
    let set = core.next_request(epoch, &mut bytes)?.ok_or("missing set")?;
    core.begin_destroy(true, AbsoluteTime::from_micros(1_000))?;
    core.on_frame_written(epoch, set.transmit)?;
    let barrier = core
        .next_request(epoch, &mut bytes)?
        .ok_or("missing barrier")?;
    core.on_frame_written(epoch, barrier.transmit)?;
    let mut confirm = [0; 4];
    MessageHeader::new(message_type::STATISTICS_DISCONNECT_CONFIRM, 0)?.encode(&mut confirm)?;
    core.receive(epoch, &confirm, AbsoluteTime::from_micros(1_001))?;
    assert!(
        !core.is_closed(),
        "C handle_disconnect_confirm cancels delay and enqueues add_now; it does not run do_destroy inline"
    );
    assert_eq!(core.next_wakeup(), Some(AbsoluteTime::from_micros(0)));
    core.tick(AbsoluteTime::from_micros(0))?;
    assert!(core.is_closed());
    assert_eq!(
        core.take_destroy_report()
            .ok_or("missing original report")?
            .outcome,
        DestroyOutcome::ProcessingConfirmed
    );
    Ok(())
}

struct FaultSource {
    clock: clock_source::Adjustable,
    failed: std::sync::atomic::AtomicBool,
    samples: AtomicU64,
    fail_at: AtomicU64,
    replace_after_read: AtomicU64,
}
impl gnunet_service_runtime::clock::RuntimeClock for FaultSource {
    fn sample(&self) -> Result<gnunet_service_runtime::clock::ClockSample, gnunet_types::Error> {
        let count = self.samples.fetch_add(1, Ordering::SeqCst) + 1;
        if count == self.fail_at.load(Ordering::SeqCst) || self.failed.load(Ordering::SeqCst) {
            Err(gnunet_types::Error::Io)
        } else {
            let sample = gnunet_service_runtime::clock::RuntimeClock::sample(&self.clock)?;
            let replacement = self.replace_after_read.swap(u64::MAX, Ordering::SeqCst);
            if replacement != u64::MAX {
                self.clock.set(replacement)?;
            }
            Ok(sample)
        }
    }
    fn subscribe(
        &self,
    ) -> Result<Box<dyn gnunet_service_runtime::clock::ClockSubscription>, gnunet_types::Error>
    {
        gnunet_service_runtime::clock::RuntimeClock::subscribe(&self.clock)
    }
}
fn fault_source(capacity: usize) -> Result<Arc<FaultSource>, Box<dyn StdError>> {
    Ok(Arc::new(FaultSource {
        clock: clock_source::Adjustable::frozen(1_000_000, capacity)?,
        failed: std::sync::atomic::AtomicBool::new(false),
        samples: AtomicU64::new(0),
        fail_at: AtomicU64::new(u64::MAX),
        replace_after_read: AtomicU64::new(u64::MAX),
    }))
}
#[test]
fn constructor_reserves_distinct_clock_before_host_publication_and_disabled_owner_reserves_nothing()
-> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dir = Dir::new()?;
            let source = fault_source(1)?;
            let (context, _driver) = broker::<4, 64>(
                LiveConfiguration::new(cfg(b"resolver", &dir.0.join("unused"))?),
                Limits::default(),
                profile()?,
                source.clone(),
            )?;
            let erased: Arc<dyn gnunet_service_runtime::clock::RuntimeClock> = source.clone();
            assert!(Arc::ptr_eq(&erased, &context.resolution_context().clock()));
            let configuration = cfg(b"statistics", &dir.0.join("never-created"))?;
            let mut statistics_instance_5 = gnunet_client::statistics_handle::Instance::new();
            let error = match Stats::from_config(
                &mut statistics_instance_5,
                &configuration,
                context.resolution_context(),
                b"owner",
                Default::default(),
            ) {
                Err(e) => e,
                Ok(_) => return Err("exhausted waiter returned a host".into()),
            };
            match error {
                gnunet_ipc_unix::IpcError::Io(error) => {
                    let marker = gnunet_client_host::resolution::PortError::from_io(&error)
                        .ok_or("missing source boundary")?;
                    assert_eq!(
                        marker
                            .cause()
                            .get_ref()
                            .and_then(|e| e.downcast_ref::<gnunet_types::Error>()),
                        Some(&gnunet_types::Error::Capacity)
                    );
                }
                other => return Err(format!("wrong constructor error {other}").into()),
            }
            assert_eq!(source.clock.listeners()?, 1);
            assert_eq!(context.pending_requests()?, 0);
            assert!(!dir.0.join("never-created").exists());
            let mut disabled = configuration.duplicate()?;
            disabled.set_value(b"statistics", b"DISABLE", Some(b"YES"))?;
            let mut statistics_instance_6 = gnunet_client::statistics_handle::Instance::new();
            assert!(
                Stats::from_config(
                    &mut statistics_instance_6,
                    &disabled,
                    context.resolution_context(),
                    b"owner",
                    Default::default()
                )?
                .is_none()
            );
            assert_eq!(source.clock.listeners()?, 1);
            Ok(())
        })
}
#[test]
fn failed_source_cannot_block_cancel_immediate_destroy_or_closed_owner_credit_reuse() -> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dir = Dir::new()?;
            let source = fault_source(4)?;
            let (context, _driver) = broker::<4, 64>(
                LiveConfiguration::new(cfg(b"resolver", &dir.0.join("unused"))?),
                Limits::default(),
                profile()?,
                source.clone(),
            )?;
            let mut statistics_instance_7 = gnunet_client::statistics_handle::Instance::new();
            let mut host = Stats::from_config(
                &mut statistics_instance_7,
                &cfg(b"statistics", &dir.0.join("never-connected"))?,
                context.resolution_context(),
                b"owner",
                Default::default(),
            )?
            .ok_or("disabled")?;
            let get = host.get(Selector {
                subsystem: b"owner",
                name: b"value",
            })?;
            let watch = host.watch(Selector {
                subsystem: b"owner",
                name: b"watch",
            })?;
            source.failed.store(true, Ordering::SeqCst);
            let count = source.samples.load(Ordering::SeqCst);
            host.get_cancel(get)?;
            host.watch_cancel(watch)?;
            host.destroy(false)?;
            assert!(host.is_closed());
            assert_eq!(source.samples.load(Ordering::SeqCst), count);
            assert_eq!(source.clock.listeners()?, 1);
            let mut destroyed = 0;
            assert_eq!(
                host.drive(None, |event, _| {
                    if let Event::Destroyed(report) = event {
                        assert_eq!(report.outcome, DestroyOutcome::Discarded);
                        destroyed += 1;
                    }
                    GetFlow::Continue
                })
                .await?,
                Progress::Closed
            );
            assert_eq!(destroyed, 1);
            assert_eq!(source.samples.load(Ordering::SeqCst), count);
            source.failed.store(false, Ordering::SeqCst);
            let replacement = context.resolution_context().timer(Duration::MAX)?;
            assert_eq!(source.clock.listeners()?, 2);
            drop(host);
            assert_eq!(source.clock.listeners()?, 2);
            drop(replacement);
            assert_eq!(source.clock.listeners()?, 1);
            Ok(())
        })
}
#[test]
fn actual_confirmation_ready_cleanup_does_not_resample_failed_source_or_release_another_waiter()
-> Test {
    use tokio::io::AsyncWriteExt;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dir = Dir::new()?;
            let path = dir.0.join("confirm");
            let listener = UnixListener::bind(&path)?;
            let source = fault_source(4)?;
            let (context, _driver) = broker::<4, 64>(
                LiveConfiguration::new(cfg(b"resolver", &dir.0.join("unused"))?),
                Limits::default(),
                profile()?,
                source.clone(),
            )?;
            let mut statistics_instance_8 = gnunet_client::statistics_handle::Instance::new();
            let mut host = Stats::from_config(
                &mut statistics_instance_8,
                &cfg(b"statistics", &path)?,
                context.resolution_context(),
                b"owner",
                Default::default(),
            )?
            .ok_or("disabled")?;
            host.set(b"value", 1, true)?;
            host.destroy(true)?;
            let (mut socket, _) = alongside(&mut host, listener.accept()).await??;
            alongside(&mut host, frame(&mut socket)).await??;
            let barrier = alongside(&mut host, frame(&mut socket)).await??;
            assert_eq!(
                MessageHeader::decode(&barrier)?.message_type(),
                message_type::STATISTICS_DISCONNECT
            );
            let mut confirm = [0; 4];
            MessageHeader::new(message_type::STATISTICS_DISCONNECT_CONFIRM, 0)?
                .encode(&mut confirm)?;
            socket.write_all(&confirm).await?;
            assert_eq!(
                host.drive(None, |_, _| GetFlow::Continue).await?,
                Progress::Activity
            );
            assert!(!host.is_closed());
            source.failed.store(true, Ordering::SeqCst);
            let count = source.samples.load(Ordering::SeqCst);
            let mut report = None;
            assert_eq!(
                host.drive(None, |event, _| {
                    if let Event::Destroyed(value) = event {
                        report = Some(value);
                    }
                    GetFlow::Continue
                })
                .await?,
                Progress::Closed
            );
            assert_eq!(
                report.ok_or("missing final report")?.outcome,
                DestroyOutcome::ProcessingConfirmed
            );
            assert_eq!(source.samples.load(Ordering::SeqCst), count);
            assert_eq!(source.clock.listeners()?, 1);
            assert_eq!(socket.read(&mut [0]).await?, 0);
            Ok(())
        })
}
#[test]
fn confirmation_and_destroy_preserve_never_deadline_but_add_now_cleanup_remains_ready_at_max()
-> Test {
    type Core<'owner> = gnunet_client::statistics_handle::StatisticsHandle<'owner, 4, 64, 2, 64, 8>;
    let mut statistics_instance_9 = gnunet_client::statistics_handle::Instance::new();
    let mut core = Core::new(&mut statistics_instance_9, b"owner", true)?.ok_or("disabled")?;
    core.set(b"value", 7, false)?;
    let epoch = core.begin_connection(AbsoluteTime::from_micros(u64::MAX))?;
    let mut bytes = [0; 128];
    let set = core.next_request(epoch, &mut bytes)?.ok_or("set")?;
    core.begin_destroy(true, AbsoluteTime::from_micros(u64::MAX))?;
    assert_eq!(
        core.destruction_deadline(),
        Some(AbsoluteTime::from_micros(u64::MAX))
    );
    core.tick(AbsoluteTime::from_micros(u64::MAX))?;
    assert!(!core.is_closed());
    core.on_frame_written(epoch, set.transmit)?;
    let barrier = core.next_request(epoch, &mut bytes)?.ok_or("barrier")?;
    core.on_frame_written(epoch, barrier.transmit)?;
    let mut confirm = [0; 4];
    MessageHeader::new(message_type::STATISTICS_DISCONNECT_CONFIRM, 0)?.encode(&mut confirm)?;
    core.receive(epoch, &confirm, AbsoluteTime::from_micros(u64::MAX))?;
    assert!(core.ready_destroy_pending());
    assert_eq!(
        core.destruction_deadline(),
        Some(AbsoluteTime::from_micros(u64::MAX))
    );
    core.tick(AbsoluteTime::from_micros(u64::MAX))?;
    assert!(core.is_closed());
    let mut statistics_instance_10 = gnunet_client::statistics_handle::Instance::new();
    let mut retry = Core::new(&mut statistics_instance_10, b"owner", true)?.ok_or("disabled")?;
    let get = retry.get(Selector {
        subsystem: b"owner",
        name: b"queued",
    })?;
    assert!(
        retry.connection_needed(AbsoluteTime::from_micros(u64::MAX)),
        "initial work is ready at MAX"
    );
    retry.connection_unavailable(AbsoluteTime::from_micros(u64::MAX))?;
    assert_eq!(
        retry.next_wakeup(),
        Some(AbsoluteTime::from_micros(u64::MAX))
    );
    assert!(
        !retry.connection_needed(AbsoluteTime::from_micros(u64::MAX)),
        "delayed saturated retry is FOREVER, unlike initial add_now work"
    );
    assert!(retry.owns_get(get));
    Ok(())
}

#[test]
fn failed_sample_after_get_failure_callback_preserves_original_admission_until_retry_registration()
-> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dir = Dir::new()?;
            let path = dir.0.join("callback-error");
            let listener = UnixListener::bind(&path)?;
            let source = fault_source(4)?;
            let (context, _driver) = broker::<4, 64>(
                LiveConfiguration::new(cfg(b"resolver", &dir.0.join("unused"))?),
                Limits::default(),
                profile()?,
                source.clone(),
            )?;
            let mut statistics_instance_11 = gnunet_client::statistics_handle::Instance::new();
            let mut host = Stats::from_config(
                &mut statistics_instance_11,
                &cfg(b"statistics", &path)?,
                context.resolution_context(),
                b"owner",
                Default::default(),
            )?
            .ok_or("disabled")?;
            let original = host.get(Selector {
                subsystem: b"owner",
                name: b"original",
            })?;
            let (mut socket, _) = alongside(&mut host, listener.accept()).await??;
            alongside(&mut host, frame(&mut socket)).await??;
            drop(socket);
            let mut replacement = None;
            let mut completions = 0;
            let mut callback_error = None;
            let until = Instant::now() + Duration::from_secs(1);
            loop {
                let result = host
                    .drive(Some(until), |event, callback| {
                        if let Event::GetComplete(report) = event {
                            assert_eq!(report.get, original);
                            assert!(report.result.is_err());
                            completions += 1;
                            source.failed.store(true, Ordering::SeqCst);
                            match callback.get(Selector {
                                subsystem: b"owner",
                                name: b"replacement",
                            }) {
                                Ok(id) => replacement = Some(id),
                                Err(e) => callback_error = Some(e.to_string()),
                            }
                        }
                        GetFlow::Continue
                    })
                    .await;
                match result {
                    Err(gnunet_ipc_unix::IpcError::Io(e)) => {
                        let marker = gnunet_client_host::resolution::PortError::from_io(&e)
                            .ok_or("time source became native IO failure")?;
                        assert_eq!(
                            marker
                                .cause()
                                .get_ref()
                                .and_then(|e| e.downcast_ref::<gnunet_types::Error>()),
                            Some(&gnunet_types::Error::Io)
                        );
                        break;
                    }
                    Err(e) => return Err(e.into()),
                    Ok(_) => assert!(Instant::now() < until),
                }
            }
            if let Some(error) = callback_error {
                return Err(error.into());
            }
            let replacement = replacement.ok_or("callback lost admitted replacement ID")?;
            assert_eq!(completions, 1);
            assert!(!host.owns_get(original));
            assert!(host.owns_get(replacement));
            assert_eq!(host.connection_epoch(), None);
            assert_eq!(source.clock.listeners()?, 2);
            assert!(
                host.take_io_error().is_none(),
                "orderly peer EOF supplies no fabricated native errno"
            );
            source.clock.set(5_000_000)?;
            source.failed.store(false, Ordering::SeqCst);
            assert!(
                alongside(
                    &mut host,
                    timeout(Duration::from_millis(20), listener.accept())
                )
                .await?
                .is_err(),
                "post-callback registration must wait original1ms from recovered5M"
            );
            source.clock.set(5_001_000)?;
            let (mut socket, _) = alongside(&mut host, listener.accept()).await??;
            let actual = alongside(&mut host, frame(&mut socket)).await??;
            let mut expected = [0; 128];
            let n = Selector {
                subsystem: b"owner",
                name: b"replacement",
            }
            .encode_get(&mut expected)?;
            assert_eq!(actual, &expected[..n]);
            assert!(
                alongside(
                    &mut host,
                    timeout(Duration::from_millis(20), socket.read(&mut [0]))
                )
                .await?
                .is_err(),
                "one post-callback registration must send one original GET"
            );
            host.destroy(false)?;
            drop(host);
            assert_eq!(socket.read(&mut [0]).await?, 0);
            Ok(())
        })
}

#[test]
fn post_read_source_failure_retains_exact_complete_end_until_same_epoch_dispatch_can_resume() -> Test
{
    use tokio::io::AsyncWriteExt;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dir = Dir::new()?;
            let path = dir.0.join("frame-error");
            let listener = UnixListener::bind(&path)?;
            let source = fault_source(4)?;
            let (context, _driver) = broker::<4, 64>(
                LiveConfiguration::new(cfg(b"resolver", &dir.0.join("unused"))?),
                Limits::default(),
                profile()?,
                source.clone(),
            )?;
            let mut statistics_instance_12 = gnunet_client::statistics_handle::Instance::new();
            let mut host = Stats::from_config(
                &mut statistics_instance_12,
                &cfg(b"statistics", &path)?,
                context.resolution_context(),
                b"owner",
                Default::default(),
            )?
            .ok_or("disabled")?;
            let first = host.get(Selector {
                subsystem: b"owner",
                name: b"first",
            })?;
            let second = host.get(Selector {
                subsystem: b"owner",
                name: b"second",
            })?;
            let epoch = host.connection_epoch();
            let (mut socket, _) = alongside(&mut host, listener.accept()).await??;
            alongside(&mut host, frame(&mut socket)).await??;
            let mut end = [0; 4];
            MessageHeader::new(message_type::STATISTICS_END, 0)?.encode(&mut end)?;
            socket.write_all(&end).await?;
            // Selected native read step: owner pump, subscription/sample handshake,
            // IO pump and pre-read tick succeed; the post-read dispatch sample fails.
            // This is a deterministic caller time-port fault, not an OS clock edit.
            let fail_at = source.samples.load(Ordering::SeqCst) + 5;
            source.fail_at.store(fail_at, Ordering::SeqCst);
            let mut completions = Vec::new();
            let mut other_callbacks = 0;
            let result = host
                .drive(None, |event, _| {
                    if let Event::GetComplete(report) = event {
                        completions.push(report);
                    } else {
                        other_callbacks += 1;
                    }
                    GetFlow::Continue
                })
                .await;
            let error = match result {
                Err(gnunet_ipc_unix::IpcError::Io(e)) => e,
                other => return Err(format!("post-read clock boundary missing: {other:?}").into()),
            };
            assert!(gnunet_client_host::resolution::PortError::from_io(&error).is_some());
            assert_eq!(source.samples.load(Ordering::SeqCst), fail_at);
            assert!(completions.is_empty());
            assert_eq!(other_callbacks, 0);
            assert_eq!(host.connection_epoch(), epoch);
            assert!(host.owns_get(first));
            assert!(host.owns_get(second));
            assert!(host.take_io_error().is_none());
            let until = Instant::now() + Duration::from_secs(1);
            while completions.is_empty() {
                host.drive(Some(until), |event, _| {
                    if let Event::GetComplete(report) = event {
                        completions.push(report);
                    }
                    GetFlow::Continue
                })
                .await?;
                assert!(Instant::now() < until);
            }
            assert_eq!(completions.len(), 1);
            assert_eq!(completions[0].get, first);
            assert_eq!(completions[0].result, Ok(()));
            let actual = alongside(&mut host, frame(&mut socket)).await??;
            let mut expected = [0; 128];
            let n = Selector {
                subsystem: b"owner",
                name: b"second",
            }
            .encode_get(&mut expected)?;
            assert_eq!(actual, &expected[..n]);
            assert_eq!(host.connection_epoch(), epoch);
            assert!(
                alongside(
                    &mut host,
                    timeout(Duration::from_millis(20), socket.read(&mut [0]))
                )
                .await?
                .is_err(),
                "retained END must neither replay a GET nor finish the second query"
            );
            assert!(host.get_callbacks_enabled(second));
            host.get_cancel(second)?;
            host.destroy(false)?;
            drop(host);
            assert_eq!(socket.read(&mut [0]).await?, 0);
            Ok(())
        })
}

#[test]
fn retry_registration_samples_once_after_continuation_and_retains_target_across_between_read_rollback()
-> Test {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let dir=Dir::new()?;let path=dir.0.join("r");let listener=UnixListener::bind(&path)?;
        let source=fault_source(4)?;
        let(context,_driver)=broker::<4,64>(LiveConfiguration::new(cfg(b"resolver",&dir.0.join("unused"))?),Limits::default(),profile()?,source.clone())?;
        let mut statistics_instance_13=gnunet_client::statistics_handle::Instance::new();
        let mut host=Stats::from_config(&mut statistics_instance_13, &cfg(b"statistics",&path)?,context.resolution_context(),b"owner",Default::default())?.ok_or("disabled")?;
        let original=host.get(Selector{subsystem:b"owner",name:b"original"})?;
        let(mut socket,_)=alongside(&mut host,listener.accept()).await??;alongside(&mut host,frame(&mut socket)).await??;drop(socket);
        let mut replacement=None;let mut done=false;let mut callback_error=None;let mut sample_at_return=0;
        let until=Instant::now()+Duration::from_secs(1);
        while !done {
            host.drive(Some(until),|event,callback|{
                if let Event::GetComplete(report)=event {
                    assert_eq!(report.get,original);assert!(report.result.is_err());done=true;
                    if let Err(e)=source.clock.set(10_000_000){callback_error=Some(e.to_string());}
                    source.replace_after_read.store(5_000_000,Ordering::SeqCst);
                    match callback.get(Selector{subsystem:b"owner",name:b"replacement"}){Ok(id)=>replacement=Some(id),Err(e)=>callback_error=Some(e.to_string())}
                    sample_at_return=source.samples.load(Ordering::SeqCst);
                }
                GetFlow::Continue
            }).await?;assert!(Instant::now()<until);
        }
        if let Some(error)=callback_error{return Err(error.into());}
        let replacement=replacement.ok_or("missing replacement")?;
        assert_eq!(host.connection_epoch(),None,"fresh delayed retry cannot reuse a pre-registration high clock to create MQ after rollback");
        assert_eq!(source.samples.load(Ordering::SeqCst),sample_at_return+1,"only source add_delayed reads time after synchronous error continuation");
        assert!(host.owns_get(replacement));
        source.clock.set(10_000_000)?;
        assert!(alongside(&mut host,timeout(Duration::from_millis(20),listener.accept())).await?.is_err(),"original10M+1ms deadline must survive rollback; neither5M+1ms nor10M is due");
        source.clock.set(10_001_000)?;
        let(mut socket,_)=alongside(&mut host,listener.accept()).await??;
        let actual=alongside(&mut host,frame(&mut socket)).await??;let mut expected=[0;128];let n=Selector{subsystem:b"owner",name:b"replacement"}.encode_get(&mut expected)?;assert_eq!(actual,&expected[..n]);
        host.destroy(false)?;drop(host);assert_eq!(socket.read(&mut[0]).await?,0);Ok(())
    })
}
