//! Behavioral regressions over the actual service owner, without C credit.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Protocol assertions identify ownership and wire failures"
)]
#[path = "more_tests.rs"]
mod more_tests;
#[path = "review_generation_credit.rs"]
mod review_generation_credit;
#[path = "review_late_credit.rs"]
mod review_late_credit;
use super::*;
use gnunet_wire::official::core::{
    Direction, FULL_OUTBOUND, HEADER_INBOUND, HEADER_OUTBOUND, MessageTypes, Request, Response,
    Traffic,
};
const LOCAL: PeerId = PeerId([17; 32]);
const REMOTE: PeerId = PeerId([34; 32]);
const OTHER: PeerId = PeerId([51; 32]);
const MESSAGE: [u8; 8] = [0, 8, 0, 0, 1, 2, 3, 4];
fn apps() -> Applications {
    Applications::new(
        LOCAL,
        PeerClass::SERVER,
        ClassOrder::Little,
        Limits::default(),
    )
}
fn command(a: &mut Applications, id: u64, r: Request<'_>) -> Result<(), Error> {
    let mut b = vec![0; 65535];
    let n = r.encode(&mut b)?;
    a.request(id, &b[..n])
}
fn init(a: &mut Applications, id: u64, options: u32, types: &[u16]) -> Result<(), Error> {
    a.attach(id)?;
    command(
        a,
        id,
        Request::Init {
            options,
            types: MessageTypes::new(types),
        },
    )?;
    drop(a.take_output(id));
    Ok(())
}
fn connected(a: &mut Applications, id: PeerId) {
    a.set_peer(
        id,
        PeerState {
            class: PeerClass::MOBILE,
            state: 7,
            timeout: 123456,
            established: true,
        },
    );
}
fn request(
    a: &mut Applications,
    id: u64,
    peer: PeerId,
    size: u16,
    request_id: u16,
) -> Result<(), Error> {
    command(
        a,
        id,
        Request::SendRequest {
            peer,
            size,
            request_id,
            priority: 0,
            deadline: 0,
        },
    )
}
fn send(a: &mut Applications, id: u64, peer: PeerId, messages: &[u8]) -> Result<(), Error> {
    command(
        a,
        id,
        Request::Send {
            peer,
            messages,
            priority: 1,
            deadline: 0,
        },
    )
}
fn outputs(a: &mut Applications, id: u64) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    while let Some(frame) = a.take_output(id) {
        all.push(frame);
    }
    all
}

#[test]
fn legal_disconnect_barrier_and_old_partial_send_do_not_authorize_new_request() -> Result<(), Error>
{
    let mut a = apps();
    init(&mut a, 1, 0, &[0])?;
    connected(&mut a, REMOTE);
    drop(outputs(&mut a, 1));
    request(&mut a, 1, REMOTE, 8, 9)?;
    a.remove_peer(REMOTE);
    connected(&mut a, REMOTE);
    send(&mut a, 1, REMOTE, &MESSAGE)?; // old tail is discarded before new request arrives
    assert!(a.find_submission(|_| true).is_none());
    request(&mut a, 1, REMOTE, 8, 1)?;
    let all = outputs(&mut a, 1);
    assert_eq!(all.len(), 4);
    assert!(matches!(
        Response::decode(&all[0], ClassOrder::Little)?,
        Response::SendReady { request_id: 9, .. }
    ));
    assert_eq!(
        Response::decode(&all[1], ClassOrder::Little)?,
        Response::Disconnected(REMOTE)
    );
    assert!(matches!(
        Response::decode(&all[2], ClassOrder::Little)?,
        Response::Connected { peer: REMOTE, .. }
    ));
    assert!(matches!(
        Response::decode(&all[3], ClassOrder::Little)?,
        Response::SendReady { request_id: 1, .. }
    ));
    send(&mut a, 1, REMOTE, &MESSAGE)?;
    let i = a.find_submission(|_| true).ok_or(Error::NotReady)?;
    assert_eq!(
        a.submission(i).ok_or(Error::NotReady)?.messages.as_slice(),
        MESSAGE
    );
    Ok(())
}
#[test]
fn self_loopback_preserves_per_message_direction_order_and_real_header_profiles()
-> Result<(), Error> {
    for (types, headers) in [(&[1][..], true), (&[][..], false)] {
        let mut a = apps();
        init(&mut a, 1, HEADER_INBOUND | HEADER_OUTBOUND, types)?;
        request(&mut a, 1, LOCAL, 16, 1)?;
        drop(outputs(&mut a, 1));
        let both = [MESSAGE.as_slice(), MESSAGE.as_slice()].concat();
        send(&mut a, 1, LOCAL, &both)?;
        let out = outputs(&mut a, 1);
        assert_eq!(out.len(), 4);
        for (i, frame) in out.iter().enumerate() {
            let Response::Traffic {
                direction,
                peer,
                traffic,
            } = Response::decode(frame, ClassOrder::Little)?
            else {
                return Err(Error::Malformed);
            };
            assert_eq!(peer, LOCAL);
            assert_eq!(
                direction,
                if i % 2 == 0 {
                    Direction::Outbound
                } else {
                    Direction::Inbound
                }
            );
            assert!(match traffic {
                Traffic::Header(h) => h.size() == 8,
                Traffic::Full(v) => !headers && i % 2 == 1 && v == MESSAGE,
            });
        }
    }
    let mut a = apps();
    init(&mut a, 1, FULL_OUTBOUND, &[0])?;
    request(&mut a, 1, LOCAL, 8, 1)?;
    drop(outputs(&mut a, 1));
    send(&mut a, 1, LOCAL, &MESSAGE)?;
    let all = outputs(&mut a, 1);
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|v| v.len() == 44));
    Ok(())
}
#[test]
fn canceled_replaced_request_releases_real_reservation_and_original_reply_ids() -> Result<(), Error>
{
    let mut a = Applications::new(
        LOCAL,
        PeerClass::UNKNOWN,
        ClassOrder::Little,
        Limits {
            max_reserved_bytes: 65535,
            ..Default::default()
        },
    );
    init(&mut a, 1, 0, &[0])?;
    init(&mut a, 2, 0, &[0])?;
    request(&mut a, 1, LOCAL, 40000, 8)?;
    request(&mut a, 2, LOCAL, 40000, 9)?;
    assert!(a.output(2).is_none());
    request(&mut a, 1, LOCAL, 4, 10)?;
    let own = outputs(&mut a, 1);
    assert_eq!(own.len(), 2);
    assert!(matches!(
        Response::decode(&own[0], ClassOrder::Little)?,
        Response::SendReady { request_id: 8, .. }
    ));
    assert!(matches!(
        Response::decode(&own[1], ClassOrder::Little)?,
        Response::SendReady { request_id: 10, .. }
    ));
    let peer = outputs(&mut a, 2);
    assert!(matches!(
        Response::decode(&peer[0], ClassOrder::Little)?,
        Response::SendReady { request_id: 9, .. }
    ));
    a.remove(1);
    a.remove(2);
    Ok(())
}
#[test]
fn bounded_notifications_retain_their_real_size_and_slow_clients_retire() -> Result<(), Error> {
    let mut a = Applications::new(
        LOCAL,
        PeerClass::UNKNOWN,
        ClassOrder::Little,
        Limits {
            max_pending_frames: 1,
            ..Default::default()
        },
    );
    init(&mut a, 1, 0, &[0])?;
    connected(&mut a, REMOTE);
    let frame = a.take_output(1).ok_or(Error::NotReady)?;
    assert_eq!(frame.len(), 44);
    assert_eq!(frame.capacity(), 44);
    connected(&mut a, OTHER);
    a.remove_peer(OTHER);
    assert!(!a.alive(1));
    Ok(())
}
#[test]
fn backpressured_peer_does_not_block_other_peer_or_reorder_its_own_messages() -> Result<(), Error> {
    let mut a = apps();
    init(&mut a, 1, 0, &[0])?;
    connected(&mut a, REMOTE);
    connected(&mut a, OTHER);
    drop(outputs(&mut a, 1));
    for (peer, n) in [(REMOTE, 1), (REMOTE, 2), (OTHER, 3)] {
        request(&mut a, 1, peer, 8, n)?;
        send(&mut a, 1, peer, &MESSAGE)?;
    }
    let index = a
        .find_submission(|s| s.peer == OTHER)
        .ok_or(Error::NotReady)?;
    assert_eq!(index, 2);
    let ready = a.take_submission(index).ok_or(Error::NotReady)?;
    assert_eq!(ready.peer, OTHER);
    assert!(
        a.find_submission(|s| s.peer == REMOTE && s.priority != 1)
            .is_none()
    );
    let first = a.take_submission(0).ok_or(Error::NotReady)?;
    assert_eq!(first.peer, REMOTE);
    assert_eq!(a.submission(0).ok_or(Error::NotReady)?.peer, REMOTE);
    Ok(())
}
#[test]
fn monitor_covers_unconfirmed_snapshot_and_continues_after_finished_marker() -> Result<(), Error> {
    let mut a = apps();
    a.set_peer(
        REMOTE,
        PeerState {
            class: PeerClass::UNKNOWN,
            state: 2,
            timeout: u64::MAX,
            established: false,
        },
    );
    a.attach(1)?;
    command(&mut a, 1, Request::Monitor)?;
    let initial = outputs(&mut a, 1);
    assert_eq!(initial.len(), 2);
    assert!(matches!(
        Response::decode(&initial[0], ClassOrder::Little)?,
        Response::Monitor {
            state: gnunet_wire::official::core::KxState(2),
            peer: REMOTE,
            ..
        }
    ));
    assert!(
        matches!(Response::decode(&initial[1],ClassOrder::Little)?,Response::Monitor {state:gnunet_wire::official::core::KxState(11),peer,timeout:u64::MAX} if peer==PeerId([0;32]))
    );
    connected(&mut a, REMOTE);
    a.remove_peer(REMOTE);
    let updates = outputs(&mut a, 1);
    assert_eq!(updates.len(), 2);
    assert!(matches!(
        Response::decode(&updates[1], ClassOrder::Little)?,
        Response::Monitor {
            state: gnunet_wire::official::core::KxState(10),
            ..
        }
    ));
    Ok(())
}
#[test]
fn admitted_request_size_cannot_be_bypassed_and_known_invalid_init_is_not_unknown()
-> Result<(), Error> {
    let mut a = apps();
    init(&mut a, 1, 0, &[0])?;
    request(&mut a, 1, LOCAL, 4, 1)?;
    assert_eq!(send(&mut a, 1, LOCAL, &MESSAGE), Err(Error::Malformed));
    send(&mut a, 1, LOCAL, &[0, 4, 0, 0])?;
    assert!(!unknown_request(&[0, 8, 0, 64, 0x80, 0, 0, 0]));
    assert!(unknown_request(&[0, 4, 0x7f, 0xff]));
    Ok(())
}

use gnunet_service_runtime::clock::ClockSample;
use std::sync::Mutex;
use std::task::Waker;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
struct ClockState {
    now: u64,
    revision: u64,
    fail: bool,
    subscribed: bool,
    waker: Option<Waker>,
}
#[derive(Clone)]
struct ManualClock(Arc<Mutex<ClockState>>);
impl ManualClock {
    fn new(now: u64) -> Self {
        Self(Arc::new(Mutex::new(ClockState {
            now,
            revision: 0,
            fail: false,
            subscribed: false,
            waker: None,
        })))
    }
    fn change(&self, now: u64, fail: bool) -> Result<(), Error> {
        let wake = {
            let mut s = self.0.lock().map_err(|_| Error::Io)?;
            s.now = now;
            s.fail = fail;
            s.revision += 1;
            s.waker.take()
        };
        if let Some(w) = wake {
            w.wake();
        }
        Ok(())
    }
    fn subscribed(&self) -> Result<bool, Error> {
        Ok(self.0.lock().map_err(|_| Error::Io)?.subscribed)
    }
}
impl RuntimeClock for ManualClock {
    fn sample(&self) -> Result<ClockSample, Error> {
        let s = self.0.lock().map_err(|_| Error::Io)?;
        if s.fail {
            return Err(Error::TimeUncertain);
        }
        Ok(ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(s.now),
            revision: s.revision,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        let mut s = self.0.lock().map_err(|_| Error::Io)?;
        if s.subscribed {
            return Err(Error::Capacity);
        }
        s.subscribed = true;
        Ok(Box::new(ManualSubscription(self.clone())))
    }
}
struct ManualSubscription(ManualClock);
impl ClockSubscription for ManualSubscription {
    fn poll_changed(
        &mut self,
        cx: &mut Context<'_>,
        seen: u64,
    ) -> Poll<Result<ClockSample, Error>> {
        let mut s = match self.0.0.lock() {
            Ok(s) => s,
            Err(_) => return Poll::Ready(Err(Error::Io)),
        };
        if s.fail {
            return Poll::Ready(Err(Error::TimeUncertain));
        }
        if s.revision != seen {
            return Poll::Ready(Ok(ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(s.now),
                revision: s.revision,
            }));
        }
        s.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
impl Drop for ManualSubscription {
    fn drop(&mut self) {
        if let Ok(mut s) = self.0.0.lock() {
            s.subscribed = false;
            s.waker = None;
        }
    }
}
fn endpoint() -> Result<Endpoint, Box<dyn std::error::Error>> {
    Ok(Endpoint::unix("/not-a-live-core-host-test-service".into())?)
}
fn pair() -> std::io::Result<(Connection, tokio::net::UnixStream)> {
    let (a, b) = std::os::unix::net::UnixStream::pair()?;
    a.set_nonblocking(true)?;
    b.set_nonblocking(true)?;
    Ok((
        Connection::from_unix(tokio::net::UnixStream::from_std(a)?),
        tokio::net::UnixStream::from_std(b)?,
    ))
}
async fn frame(stream: &mut tokio::net::UnixStream) -> std::io::Result<Vec<u8>> {
    let mut h = [0; 4];
    stream.read_exact(&mut h).await?;
    let size = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if size < 4 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&h);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn alongside<T>(
    host: &mut Host<'_>,
    operation: impl Future<Output = Result<T, Box<dyn std::error::Error>>>,
) -> Result<T, Box<dyn std::error::Error>> {
    let mut operation = std::pin::pin!(operation);
    let mut drive = std::pin::pin!(host.drive(&[], |_| {}));
    tokio::time::timeout(
        Duration::from_secs(3),
        poll_fn(|cx| {
            if let Poll::Ready(v) = operation.as_mut().poll(cx) {
                return Poll::Ready(v);
            }
            match drive.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(())) => Poll::Ready(Err("unexpected stopped host".into())),
                Poll::Pending => Poll::Pending,
            }
        }),
    )
    .await?
}
#[tokio::test(flavor = "current_thread")]
async fn actual_partial_app_frame_survives_canceled_drive_and_typed_loopback()
-> Result<(), Box<dyn std::error::Error>> {
    use gnunet_client::core::{CoreClient, Event, Instance, SendOutcome};
    let identity = Identity::from_seed([92; 32]);
    let mut host = Host::new(
        &identity,
        b"",
        PeerClass::SERVER,
        endpoint()?,
        Limits {
            io_slice_bytes: 1,
            ..Default::default()
        },
        ServiceOptions::default(),
    )?;
    let (connection, mut stream) = pair()?;
    host.attach_client(connection)?;
    let mut instance = Instance::new();
    let mut client = CoreClient::<4, 4>::new(&mut instance, ClassOrder::Little, 0, &[0])?;
    let mut bytes = vec![0; 65535];
    let (epoch, n) = client.begin(&mut bytes)?;
    stream.write_all(&bytes[..2]).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(5), host.drive(&[], |_| {}))
            .await
            .is_err()
    );
    let expected = host.identity();
    alongside(&mut host,async {
        stream.write_all(&bytes[2..n]).await?;
        let first=frame(&mut stream).await?;let Event::Ready {local,..}=client.receive(epoch,&first)? else {return Err("expected actual init reply".into());};assert_eq!(local.identity(),expected);
        let (original,n)=client.request_send(local,1,0,MESSAGE.to_vec(),&mut bytes).map_err(|r|r.reason)?;
        for chunk in bytes[..n].chunks(2){stream.write_all(chunk).await?;}
        let ready=frame(&mut stream).await?;assert!(matches!(client.receive(epoch,&ready)?,Event::SendReady {..}));
        let prepared=client.prepare_payload(&original,&mut bytes)?;
        for chunk in prepared.bytes().chunks(3){stream.write_all(chunk).await?;client.payload_bytes_written(prepared.send(),chunk.len())?;}
        assert_eq!(client.finish(original).map_err(|r|r.reason)?.outcome,SendOutcome::Written);
        let received=frame(&mut stream).await?;
        assert!(matches!(client.receive(epoch,&received)?,Event::Traffic {traffic:Traffic::Full(v),..} if v==MESSAGE));Ok(())
    }).await?;
    assert_eq!(host.report().requests, 3);
    host.shutdown();
    assert_eq!(host.report().closed, 1);
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn canonical_clock_rollback_preserves_monitor_target_and_errors_are_not_forever()
-> Result<(), Box<dyn std::error::Error>> {
    let a = Identity::from_seed([53; 32]);
    let b = Identity::from_seed([54; 32]);
    let (identity, remote) = if gnunet_core::wire::is_initiator(
        a.public_key().as_bytes(),
        b.public_key().as_bytes(),
        WordOrder::Little,
    ) {
        (&a, &b)
    } else {
        (&b, &a)
    };
    let clock = Arc::new(ManualClock::new(10_000_000));
    let mut host = Host::with_clock(
        identity,
        b"",
        PeerClass::UNKNOWN,
        endpoint()?,
        Limits::default(),
        ServiceOptions::default(),
        clock.clone(),
    )?;
    host.connect_now = false;
    host.retry_at = u64::MAX;
    let peer = PeerId(*remote.public_key().as_bytes());
    let mut bytes = [0; 40];
    tr::Response::Connected(tr::PeerId(peer.0)).encode(&mut bytes)?;
    host.transport_frame(&bytes, 10_000_000)?;
    host.maintenance(10_000_000)?;
    assert_eq!(host.peers[&peer].session.next_deadline(), 11_000_000);
    host.applications.attach(1)?;
    command(&mut host.applications, 1, Request::Monitor)?;
    let snapshot = outputs(&mut host.applications, 1);
    assert!(matches!(
        Response::decode(&snapshot[0], ClassOrder::Little)?,
        Response::Monitor {
            timeout: 11_000_000,
            ..
        }
    ));
    clock.change(9_000_000, false)?;
    let mut cx = Context::from_waker(Waker::noop());
    assert!(host.poll(&mut cx, &[], &mut |_| {}).is_pending());
    assert_eq!(host.peers[&peer].session.next_deadline(), 11_000_000);
    assert!(host.applications.output(1).is_none());
    clock.change(11_000_000, false)?;
    assert!(host.poll(&mut cx, &[], &mut |_| {}).is_pending());
    assert_eq!(host.peers[&peer].session.next_deadline(), 13_000_000);
    let update = host.applications.take_output(1).ok_or(Error::NotReady)?;
    assert!(matches!(
        Response::decode(&update, ClassOrder::Little)?,
        Response::Monitor {
            timeout: 13_000_000,
            ..
        }
    ));
    clock.change(11_000_000, true)?;
    assert!(matches!(
        host.poll(&mut cx, &[], &mut |_| {}),
        Poll::Ready(Err(HostError::Clock(Error::TimeUncertain)))
    ));
    assert!(host.applications.output(1).is_none());
    assert!(clock.subscribed()?);
    host.shutdown();
    assert!(!clock.subscribed()?);
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn real_transport_fifo_reserves_receive_credit_when_data_capacity_is_full()
-> Result<(), Box<dyn std::error::Error>> {
    let (connection, mut stream) = pair()?;
    let mut link = Link::new(connection, 65535, 1, 1)?;
    link.control_reserve(4)?;
    let mut data = vec![0; 65535];
    let n = tr::Request::Start(tr::Start::new(None, true)).encode(&mut data)?;
    data.truncate(n);
    link.enqueue(data)?;
    assert!(!link.capacity(40));
    assert!(link.control_capacity(40));
    let mut ack = vec![0; 40];
    tr::Request::ReceiveContinue {
        peer: tr::PeerId(REMOTE.0),
        increase: 1,
    }
    .encode(&mut ack)?;
    link.enqueue_control(ack)?;
    let read = async {
        let first = frame(&mut stream).await?;
        let second = frame(&mut stream).await?;
        Ok::<_, std::io::Error>((first, second))
    };
    let mut read = std::pin::pin!(read);
    let actual = tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| {
            if let Poll::Ready(v) = read.as_mut().poll(cx) {
                return Poll::Ready(v);
            }
            match link.poll_tx(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
            Poll::Pending
        }),
    )
    .await??;
    assert!(matches!(
        tr::Request::decode(&actual.0)?,
        tr::Request::Start(_)
    ));
    assert!(matches!(
        tr::Request::decode(&actual.1)?,
        tr::Request::ReceiveContinue { increase: 1, .. }
    ));
    Ok(())
}

#[path = "framing_regression.rs"]
mod framing_regression;
