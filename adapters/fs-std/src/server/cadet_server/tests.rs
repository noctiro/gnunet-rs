//! Actual Unix MQ cursors/timers/EOF with an explicit terminal-controlled source
//! model. These checks do not claim official C or real DATASTORE interoperability.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native lifecycle regressions assert original frame exposure, EOF and source query ownership"
)]
use super::*;
use gnunet_cadet_host::{ChannelSlot, EndpointSource, Instance, Limits as NativeLimits, PortSlot};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription};
use gnunet_wire::official::{
    AbsoluteTime,
    cadet::{Request, Response},
    datastore::{DATA_LEN, Data, Response as StoreResponse},
    fs::BlockType,
    fs_cadet::QUERY_BYTES,
};
use std::{
    cell::Cell,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    task::Waker,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

type Failure = Box<dyn std::error::Error + Send + Sync>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct FrozenClock;
impl RuntimeClock for FrozenClock {
    fn sample(&self) -> Result<ClockSample, ProtocolError> {
        Ok(ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(1_000_000),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, ProtocolError> {
        Ok(Box::new(FrozenSubscription))
    }
}
struct FrozenSubscription;
impl ClockSubscription for FrozenSubscription {
    fn poll_changed(
        &mut self,
        _cx: &mut Context<'_>,
        _revision: u64,
    ) -> Poll<Result<ClockSample, ProtocolError>> {
        Poll::Pending
    }
}
struct Socket(PathBuf);
impl Socket {
    fn new() -> Result<(Self, UnixListener), Failure> {
        let path = std::env::temp_dir().join(format!(
            "gnrs-fs-serve-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
    fn endpoint(&self) -> EndpointSource {
        EndpointSource::unix(self.0.clone())
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}
struct Source {
    ready: Rc<Cell<bool>>,
    reads: Rc<Cell<usize>>,
    selection: Option<Selection>,
    retiring: bool,
    record: Option<OwnedFrame>,
}
impl BlockSource for Source {
    fn request_retire(&mut self) {
        self.retiring = true;
    }
    fn start(&mut self, selection: Selection) -> Result<(), source::Failure> {
        if self.selection.is_some() {
            return Err(source::Failure::operation(ProtocolError::Conflict));
        }
        self.selection = Some(selection);
        self.retiring = false;
        self.reads.set(self.reads.get() + 1);
        Ok(())
    }
    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<Result<source::Progress, source::Failure>> {
        if !self.ready.get() {
            return Poll::Pending;
        }
        let Some(selection) = self.selection.take() else {
            return Poll::Pending;
        };
        if self.retiring {
            Poll::Ready(Ok(source::Progress::Retired(source::Retired {
                selection,
                observation: self
                    .record
                    .take()
                    .map_or(source::Retirement::StorageEnd, source::Retirement::Data),
            })))
        } else if let Some(record) = self.record.take() {
            Poll::Ready(
                source::Block::from_record(record)
                    .map(source::Progress::Found)
                    .map_err(source::Failure::operation),
            )
        } else {
            Poll::Ready(Ok(source::Progress::NotFound))
        }
    }
    fn close(&mut self) -> Result<(), source::Failure> {
        self.selection = None;
        Ok(())
    }
}
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
async fn next<'id>(server: &mut Server<'id, '_, Source>) -> Result<Step<'id>, Failure> {
    match server
        .drive(Some(Instant::now() + Duration::from_secs(3)))
        .await?
    {
        Step::WaitDeadline => Err("native serving observation timed out".into()),
        step => Ok(step),
    }
}
async fn connect<'id>(server: &mut Server<'id, '_, Source>) -> Result<(), Failure> {
    while server.client.epoch().is_none() {
        match next(server).await? {
            Step::Activity | Step::ConnectRetry { .. } => {}
            _ => return Err("unexpected event before actual attachment".into()),
        }
    }
    Ok(())
}
async fn listening<'id>(server: &mut Server<'id, '_, Source>) -> Result<Epoch<'id>, Failure> {
    loop {
        match next(server).await? {
            Step::Listening { source, .. } => return Ok(source),
            Step::Activity => {}
            _ => return Err("event before original port announcement completed".into()),
        }
    }
}
async fn partial<'id>(
    server: &mut Server<'id, '_, Source>,
    kind: TransmitKind,
) -> Result<(), Failure> {
    loop {
        if server
            .client
            .pending_transmit()
            .is_some_and(|tx| tx.kind() == kind)
        {
            return Ok(());
        }
        if !matches!(next(server).await?, Step::Activity) {
            return Err("unexpected event before original partial frame".into());
        }
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err("short native frame".into());
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn response(stream: &mut UnixStream, response: Response<'_>) -> Result<(), Failure> {
    let mut bytes = [0; 256];
    let length = response.encode(&mut bytes)?;
    stream.write_all(&bytes[..length]).await?;
    Ok(())
}
async fn query(stream: &mut UnixStream, selection: Selection, credit: bool) -> Result<(), Failure> {
    response(
        stream,
        Response::ChannelCreate {
            channel: 0,
            peer: [0x77; 32],
            port: hash512(PORT_LABEL),
            options: 0,
        },
    )
    .await?;
    if credit {
        response(stream, Response::Ack { channel: 0 }).await?;
    }
    let mut bytes = [0; QUERY_BYTES];
    Query {
        block_type: selection.block_type,
        query: &selection.query,
    }
    .encode(&mut bytes)?;
    response(
        stream,
        Response::Data {
            channel: 0,
            priority: 0,
            messages: &bytes,
        },
    )
    .await
}

#[test]
fn original_partial_reply_survives_cancel_then_retires_and_reannounces() -> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, listener) = Socket::new()?;
        let value = [0x49; 512];
        let selection = Selection {
            block_type: BlockType::DBLOCK,
            query: hash512(&value),
        };
        let record = StoreResponse::Data(Data {
            reservation: 0,
            kind: 1,
            priority: 0,
            anonymity: 0,
            replication: 0,
            uid: 1,
            expiration: AbsoluteTime::NEVER,
            key: &selection.query,
            value: &value,
        });
        let mut bytes = vec![0; DATA_LEN + value.len()];
        record.encode(&mut bytes)?;
        let reads = Rc::new(Cell::new(0));
        let source = Source {
            ready: Rc::new(Cell::new(true)),
            reads: reads.clone(),
            selection: None,
            retiring: false,
            record: Some(OwnedFrame::new(bytes)),
        };
        let mut identity = Instance::new();
        let mut ports = [PortSlot::new(); 1];
        let mut channels = [ChannelSlot::new(); 2];
        let client = Client::new(
            &mut identity,
            socket.endpoint(),
            &mut ports,
            &mut channels,
            NativeLimits {
                io_slice_bytes: 1,
                ..NativeLimits::default()
            },
        )?;
        let mut server = Server::new(
            client,
            source,
            Limits {
                write_timeout: Duration::from_millis(250),
                ..Limits::default()
            },
        )?;
        let (connected, accepted) = tokio::join!(connect(&mut server), listener.accept());
        connected?;
        let (mut remote, _) = accepted?;
        let old_epoch = listening(&mut server).await?;
        assert!(matches!(
            Request::decode(&frame(&mut remote).await?)?,
            Request::PortOpen { .. }
        ));
        query(&mut remote, selection, true).await?;
        partial(&mut server, TransmitKind::Data).await?;
        let channel = server.entries[0].channel;
        let original = server
            .write_bound
            .as_ref()
            .ok_or("missing actual write bound")?;
        let (transmit, hard) = (original.transmit, original.hard);
        // One byte actually crossed the MQ. Canceling and further one-byte
        // writes must preserve this exact frame's original native target.
        remote.read_exact(&mut [0; 1]).await?;
        server.cancel(channel)?;
        for _ in 0..2 {
            assert!(matches!(next(&mut server).await?, Step::Activity));
            let bound = server.write_bound.as_ref().ok_or("lost admitted frame")?;
            assert_eq!((bound.transmit, bound.hard), (transmit, hard));
        }
        tokio::time::sleep_until(hard).await;
        let Step::Lost {
            report,
            cause: LossCause::Requested,
        } = next(&mut server).await?
        else {
            return Err("expired original reply did not physically retire".into());
        };
        assert_eq!(report.epoch, old_epoch);
        let pending = report.pending.ok_or("lost actual partial reply exposure")?;
        assert_eq!(pending.transmit, transmit);
        assert!(pending.exposed);
        assert_eq!(server.report().write_timeouts, 1);
        assert_eq!(server.report().replies_written, 0);
        assert_eq!(server.report().receipts_written, 0);
        let mut rest = Vec::new();
        remote.read_to_end(&mut rest).await?;
        assert_eq!(rest.len(), 2, "no Destroy may splice an unfinished reply");

        let (connected, accepted) = tokio::join!(connect(&mut server), listener.accept());
        connected?;
        let (mut replacement, _) = accepted?;
        assert_ne!(server.client.epoch(), Some(old_epoch));
        partial(&mut server, TransmitKind::PortOpen).await?;
        let automatic = server
            .write_bound
            .as_ref()
            .ok_or("automatic PortOpen lacks bound")?;
        let (transmit, hard) = (automatic.transmit, automatic.hard);
        for _ in 0..2 {
            assert!(matches!(next(&mut server).await?, Step::Activity));
            let bound = server
                .write_bound
                .as_ref()
                .ok_or("automatic frame lost original bound")?;
            assert_eq!((bound.transmit, bound.hard), (transmit, hard));
        }
        listening(&mut server).await?;
        assert_eq!(
            Request::decode(&frame(&mut replacement).await?)?,
            Request::PortOpen {
                port: hash512(PORT_LABEL)
            }
        );
        assert_eq!(
            reads.get(),
            1,
            "loss cannot replay a settled source selection"
        );
        let closed = server.close();
        closed.native?;
        closed.source?;
        assert!(closed.pending_query.is_none());
        assert_eq!(replacement.read(&mut [0; 1]).await?, 0);
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

#[test]
fn shutdown_has_one_cleanup_bound_and_retains_actual_source_debt() -> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(5), async {
        for observe_terminal in [true, false] {
            let (socket, listener) = Socket::new()?;
            let ready = Rc::new(Cell::new(false));
            let reads = Rc::new(Cell::new(0));
            let source = Source {
                ready: ready.clone(),
                reads: reads.clone(),
                selection: None,
                retiring: false,
                record: None,
            };
            let mut identity = Instance::new();
            let mut ports = [PortSlot::new(); 1];
            let mut channels = [ChannelSlot::new(); 2];
            let client = Client::new(
                &mut identity,
                socket.endpoint(),
                &mut ports,
                &mut channels,
                NativeLimits {
                    io_slice_bytes: 1,
                    ..NativeLimits::default()
                },
            )?;
            let mut server = Server::new(
                client,
                source,
                Limits {
                    write_timeout: Duration::from_secs(2),
                    drain_timeout: Duration::from_millis(200),
                    ..Limits::default()
                },
            )?;
            let (connected, accepted) = tokio::join!(connect(&mut server), listener.accept());
            connected?;
            let (mut remote, _) = accepted?;
            listening(&mut server).await?;
            frame(&mut remote).await?;
            let selection = Selection {
                block_type: BlockType::DBLOCK,
                query: [0x23; 64],
            };
            query(&mut remote, selection, false).await?;
            while server.job.is_none() {
                assert!(matches!(next(&mut server).await?, Step::Activity));
            }
            let job = server
                .job
                .as_ref()
                .ok_or("original source admission missing")?;
            let (serial, channel) = (job.serial, job.channel);
            server.request_shutdown();
            let cleanup = server.cleanup.ok_or("missing original cleanup target")?;
            partial(&mut server, TransmitKind::PortClose).await?;
            while server.withdrawal.is_some() {
                assert!(matches!(next(&mut server).await?, Step::Activity));
                assert_eq!(server.cleanup, Some(cleanup));
            }
            assert!(matches!(
                Request::decode(&frame(&mut remote).await?)?,
                Request::PortClose { .. }
            ));
            partial(&mut server, TransmitKind::ChannelDestroy).await?;
            remote.read_exact(&mut [0; 1]).await?;
            server.request_shutdown();
            assert_eq!(
                server.cleanup,
                Some(cleanup),
                "repeat shutdown cannot renew cleanup"
            );
            tokio::time::sleep_until(cleanup).await;
            let Step::Lost {
                report,
                cause: LossCause::Requested,
            } = next(&mut server).await?
            else {
                return Err("cleanup hard limit did not physically close original MQ".into());
            };
            let pending = report
                .pending
                .ok_or("partial Destroy exposure was discarded")?;
            assert_eq!(pending.transmit.kind(), TransmitKind::ChannelDestroy);
            assert!(pending.exposed);
            assert!(server.native_stopped);
            assert!(!server.quiesced(), "source has no actual terminal yet");
            assert_eq!(server.report().drain_timeouts, 1);
            assert_eq!(server.report().write_timeouts, 0);
            assert_eq!(server.report().not_found, 0);
            assert_eq!(server.report().receipts_written, 0);
            assert_eq!(
                server
                    .job
                    .as_ref()
                    .map(|job| (job.serial, job.channel, job.selection)),
                Some((serial, channel, selection))
            );
            let mut cx = Context::from_waker(Waker::noop());
            assert!(server.poll(&mut cx, None).is_pending());
            let mut rest = Vec::new();
            remote.read_to_end(&mut rest).await?;
            assert!(
                rest.is_empty(),
                "the timed-out Destroy must not finish after hard close"
            );
            if observe_terminal {
                ready.set(true);
                let Step::SourceRetired {
                    query,
                    channel: actual,
                    retired,
                } = next(&mut server).await?
                else {
                    return Err(
                        "original source terminal was not retained after native close".into(),
                    );
                };
                assert_eq!(
                    (query, actual, retired.selection),
                    (serial, channel, selection)
                );
                assert!(matches!(
                    retired.observation,
                    source::Retirement::StorageEnd
                ));
                assert!(matches!(next(&mut server).await?, Step::Quiesced));
            }
            let closed = server.close();
            assert!(closed.native?.is_none());
            closed.source?;
            assert_eq!(
                closed
                    .pending_query
                    .map(|job| (job.query, job.channel, job.selection)),
                (!observe_terminal).then_some((serial, channel, selection))
            );
            assert_eq!(reads.get(), 1);
        }
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

#[test]
fn reconnected_wire_channel_cannot_receive_the_original_source_result() -> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, listener) = Socket::new()?;
        let value = [0x57; 16];
        let selection = Selection {
            block_type: BlockType::DBLOCK,
            query: hash512(&value),
        };
        let record = StoreResponse::Data(Data {
            reservation: 0,
            kind: 1,
            priority: 0,
            anonymity: 0,
            replication: 0,
            uid: 1,
            expiration: AbsoluteTime::NEVER,
            key: &selection.query,
            value: &value,
        });
        let mut bytes = vec![0; DATA_LEN + value.len()];
        record.encode(&mut bytes)?;
        let ready = Rc::new(Cell::new(false));
        let reads = Rc::new(Cell::new(0));
        let source = Source {
            ready: ready.clone(),
            reads: reads.clone(),
            selection: None,
            retiring: false,
            record: Some(OwnedFrame::new(bytes)),
        };
        let mut identity = Instance::new();
        let mut ports = [PortSlot::new(); 1];
        let mut channels = [ChannelSlot::new(); 2];
        let client = Client::new(
            &mut identity,
            socket.endpoint(),
            &mut ports,
            &mut channels,
            NativeLimits {
                io_slice_bytes: 1,
                ..NativeLimits::default()
            },
        )?;
        let mut server = Server::new(
            client,
            source,
            Limits {
                write_timeout: Duration::from_millis(250),
                ..Limits::default()
            },
        )?;
        let (connected, accepted) = tokio::join!(connect(&mut server), listener.accept());
        connected?;
        let (mut original, _) = accepted?;
        listening(&mut server).await?;
        frame(&mut original).await?;
        query(&mut original, selection, false).await?;
        while server.job.is_none() {
            assert!(matches!(next(&mut server).await?, Step::Activity));
        }
        let old = server.job.as_ref().ok_or("missing original query")?;
        let (serial, channel) = (old.serial, old.channel);
        server.cancel(channel)?;
        partial(&mut server, TransmitKind::ChannelDestroy).await?;
        original.read_exact(&mut [0; 1]).await?;
        let hard = server
            .write_bound
            .as_ref()
            .ok_or("missing Destroy bound")?
            .hard;
        tokio::time::sleep_until(hard).await;
        let Step::Lost { report, .. } = next(&mut server).await? else {
            return Err("original pending Destroy did not retire".into());
        };
        assert_eq!(report.epoch, channel.epoch());
        assert!(server.job.is_some());
        assert!(!server.stopping);
        let mut tail = Vec::new();
        original.read_to_end(&mut tail).await?;
        assert!(tail.is_empty());

        let (connected, accepted) = tokio::join!(connect(&mut server), listener.accept());
        connected?;
        let (mut replacement, _) = accepted?;
        listening(&mut server).await?;
        frame(&mut replacement).await?;
        let new_selection = Selection {
            query: [0x92; 64],
            ..selection
        };
        query(&mut replacement, new_selection, false).await?;
        while !server.entries.iter().any(|entry| entry.packet.is_some()) {
            assert!(matches!(next(&mut server).await?, Step::Activity));
        }
        let new_channel = server.entries[0].channel;
        assert_eq!(channel.wire_id(), new_channel.wire_id());
        assert_ne!(channel, new_channel);
        assert_eq!(reads.get(), 1, "the original source owner is still busy");
        ready.set(true);
        let Step::SourceRetired {
            query,
            channel: actual,
            retired,
        } = next(&mut server).await?
        else {
            return Err("original DATA lost its original query ownership".into());
        };
        assert_eq!(
            (query, actual, retired.selection),
            (serial, channel, selection)
        );
        let source::Retirement::Data(record) = retired.observation else {
            return Err("original terminal DATA was replaced by an invented negative".into());
        };
        let StoreResponse::Data(data) = StoreResponse::decode(record.bytes())? else {
            return Err("original source DATA frame was lost".into());
        };
        assert_eq!((*data.key, data.value), (selection.query, value.as_slice()));
        assert_eq!(server.report().retired_completions, 1);
        assert_eq!(server.report().replies_written, 0);
        assert_eq!(server.entries[0].channel, new_channel);
        assert!(server.entries[0].reply.is_none());
        assert!(!server.entries[0].working);
        assert!(server.entries[0].packet.is_some());
        assert_eq!(
            reads.get(),
            1,
            "retirement must not admit the new query early"
        );
        let closed = server.close();
        closed.native?;
        closed.source?;
        assert!(closed.pending_query.is_none());
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

#[test]
fn frozen_logical_clock_cannot_retain_a_reply_without_send_credit() -> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, listener) = Socket::new()?;
        let clock: Arc<dyn RuntimeClock> = Arc::new(FrozenClock);
        let value = [0x63; 16];
        let selection = Selection {
            block_type: BlockType::DBLOCK,
            query: hash512(&value),
        };
        let record = StoreResponse::Data(Data {
            reservation: 0,
            kind: 1,
            priority: 0,
            anonymity: 0,
            replication: 0,
            uid: 1,
            expiration: AbsoluteTime::NEVER,
            key: &selection.query,
            value: &value,
        });
        let mut bytes = vec![0; DATA_LEN + value.len()];
        record.encode(&mut bytes)?;
        let reads = Rc::new(Cell::new(0));
        let source = Source {
            ready: Rc::new(Cell::new(true)),
            reads: reads.clone(),
            selection: None,
            retiring: false,
            record: Some(OwnedFrame::new(bytes)),
        };
        let mut identity = Instance::new();
        let mut ports = [PortSlot::new(); 1];
        let mut channels = [ChannelSlot::new(); 2];
        let client = Client::new(
            &mut identity,
            EndpointSource::unix_with_clock(socket.0.clone(), clock.clone()),
            &mut ports,
            &mut channels,
            NativeLimits {
                io_slice_bytes: 1,
                ..NativeLimits::default()
            },
        )?;
        let mut server = Server::new(
            client,
            source,
            Limits {
                idle_timeout: Duration::from_millis(200),
                write_timeout: Duration::from_secs(2),
                drain_timeout: Duration::from_millis(200),
                ..Limits::default()
            },
        )?;
        let (connected, accepted) = tokio::join!(connect(&mut server), listener.accept());
        connected?;
        let (mut remote, _) = accepted?;
        listening(&mut server).await?;
        frame(&mut remote).await?;
        query(&mut remote, selection, false).await?;
        while !server.entries.iter().any(|entry| entry.reply.is_some()) {
            assert!(matches!(next(&mut server).await?, Step::Activity));
        }
        let channel = server.entries[0].channel;
        let idle_hard = server.entries[0].hard;
        assert_eq!(server.client.channel_info(channel)?.send_credit, 0);
        assert!(server.client.pending_transmit().is_none());
        assert!(server.write_bound.is_none());
        assert!(matches!(next(&mut server).await?, Step::Activity));
        assert!(server.entries[0].closing);
        let cleanup = server.entries[0].hard;
        assert_eq!(cleanup, idle_hard + server.limits.drain_timeout);
        partial(&mut server, TransmitKind::ChannelDestroy).await?;
        remote.read_exact(&mut [0; 1]).await?;
        server.cancel(channel)?;
        assert_eq!(
            server.entries[0].hard, cleanup,
            "cancel must not renew channel drain"
        );
        tokio::time::sleep_until(cleanup).await;
        let Step::Lost {
            report,
            cause: LossCause::Requested,
        } = next(&mut server).await?
        else {
            return Err("credit-starved reply did not reach actual bounded MQ retirement".into());
        };
        let pending = report
            .pending
            .ok_or("actual partial Destroy lost its exposure")?;
        assert_eq!(pending.transmit.kind(), TransmitKind::ChannelDestroy);
        assert!(pending.exposed);
        assert_eq!(clock.sample()?.now, AbsoluteTime::from_micros(1_000_000));
        assert_eq!(server.report().idle_expirations, 1);
        assert_eq!(server.report().drain_timeouts, 1);
        assert_eq!(server.report().replies_written, 0);
        assert_eq!(server.report().receipts_written, 0);
        assert!(
            !server.stopping,
            "a local channel timeout must permit service recovery"
        );
        let mut tail = Vec::new();
        remote.read_to_end(&mut tail).await?;
        assert!(tail.is_empty());
        assert_eq!(reads.get(), 1);
        let closed = server.close();
        closed.native?;
        closed.source?;
        assert!(closed.pending_query.is_none());
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

#[test]
fn constructor_rejects_idle_forever_overflow_and_submicrosecond_cycles() -> Result<(), Failure> {
    for timeout in [
        Duration::MAX,
        Duration::from_micros(u64::MAX),
        Duration::from_micros(u64::MAX - 1),
        Duration::from_nanos(999),
        Duration::ZERO,
    ] {
        let mut identity = Instance::new();
        let mut ports = [PortSlot::new(); 1];
        let mut channels = [ChannelSlot::new(); 2];
        let client = Client::new(
            &mut identity,
            EndpointSource::unix_with_clock(
                std::env::temp_dir().join("gnrs-unused-fs-idle.sock"),
                Arc::new(FrozenClock),
            ),
            &mut ports,
            &mut channels,
            NativeLimits::default(),
        )?;
        let source = Source {
            ready: Rc::new(Cell::new(false)),
            reads: Rc::new(Cell::new(0)),
            selection: None,
            retiring: false,
            record: None,
        };
        assert!(
            Server::new(
                client,
                source,
                Limits {
                    idle_timeout: timeout,
                    ..Limits::default()
                }
            )
            .is_err(),
            "invalid idle cycle {timeout:?} was admitted"
        );
    }
    Ok(())
}
