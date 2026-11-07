//! Real local DATASTORE frames, caller control and one original mutation owner.
//! The socket peers are focused Rust fixtures, not original-C or FS artifact acceptance.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible native tests assert actual mutation certainty and original reply bytes"
)]
use super::{Submission, execute_controlled};
use crate::network::{Error, TimeLimit};
use gnunet_datastore_host::{
    Client, Instance, Interruption, Limits, Outcome, ProtocolClient, ProtocolLimits,
    ReservationSlot, Slot,
};
use gnunet_types::{AbsoluteTime, Duration as LogicalDuration, Error as ProtocolError};
use gnunet_wire::official::datastore::{Data, Request, Response, Status};
use std::{
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{sleep, timeout},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(3);
const KEY: [u8; 64] = [0x37; 64];
const VALUE: &[u8] = b"opaque datastore payload";
struct Socket(PathBuf);
impl Socket {
    fn bind() -> io::Result<(Self, UnixListener)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-put-control-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
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
fn client<'id, 's, 'b>(
    id: &'id mut Instance,
    slots: &'s mut [Slot<'b>],
    reservations: &'s mut [ReservationSlot],
    socket: &Socket,
) -> Result<Client<'id, 's, 'b>, gnunet_client_host::ConnectError> {
    let pure = ProtocolClient::new(
        id,
        slots,
        reservations,
        ProtocolLimits {
            max_pending: 1,
            drain_timeout: LogicalDuration(75_000),
            ..Default::default()
        },
    )?;
    Client::new(
        pure,
        gnunet_client_host::EndpointSource::unix(socket.0.clone()),
        Limits {
            reply_frames: 1,
            reply_bytes: 65535,
            io_slice_bytes: 13,
            ..Default::default()
        },
    )
}
fn request() -> Request<'static> {
    Request::Put(Data {
        reservation: 0,
        kind: 1,
        priority: 7,
        anonymity: 2,
        replication: 3,
        uid: 0,
        expiration: AbsoluteTime::NEVER,
        key: &KEY,
        value: VALUE,
    })
}
fn time(client: &Client<'_, '_, '_>) -> Result<TimeLimit, Error> {
    let clock = client.clock();
    let target = AbsoluteTime::from_micros(clock.sample()?.now.as_micros() + 300_000_000);
    TimeLimit::new(clock, target)
}
async fn received(stream: &mut UnixStream) -> TestResult {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err("short native frame".into());
    }
    let mut frame = vec![0; length];
    frame[..4].copy_from_slice(&header);
    stream.read_exact(&mut frame[4..]).await?;
    let Request::Put(data) = Request::decode(&frame)? else {
        return Err("expected one original PUT".into());
    };
    assert_eq!(
        (
            data.reservation,
            data.kind,
            data.priority,
            data.anonymity,
            data.replication,
            data.uid
        ),
        (0, 1, 7, 2, 3, 0)
    );
    assert_eq!(data.key, &KEY);
    assert_eq!(data.value, VALUE);
    Ok(())
}
async fn closed(stream: &mut UnixStream) -> TestResult {
    let mut extra = [0];
    assert_eq!(stream.read(&mut extra).await?, 0);
    Ok(())
}
#[test]
fn cancel_before_submit_is_known_unsent_and_quiet_written_cancel_is_unknown_without_replay()
-> TestResult {
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        {
            let mut id = Instance::new();
            let mut wire = vec![0; 65535];
            let mut slots = [Slot::new(&mut wire)];
            let mut reservations = [];
            let mut native = client(&mut id, &mut slots, &mut reservations, &socket)?;
            let mut time = time(&native)?;
            let refusal =
                execute_controlled(&mut native, &mut time, request(), None, Some(KEY), || false)
                    .await
                    .err()
                    .ok_or("pre-submit cancellation became completion")?;
            assert_eq!(refusal.submission, Submission::NotSubmitted);
            assert!(refusal.requested_cancel);
            assert!(refusal.settlement_error.is_none());
            assert!(matches!(
                refusal.cause,
                Error::Protocol(ProtocolError::Cancelled)
            ));
            assert_eq!(native.pending(), 0);
            native.close()?;
            assert!(
                timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err()
            );
        }
        let seen = Arc::new(AtomicBool::new(false));
        let replied = seen.clone();
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            received(&mut stream).await?;
            replied.store(true, Ordering::SeqCst);
            // No response is sent. Native cancellation must close this same MQ
            // after its bounded drain, rather than waiting five minutes.
            closed(&mut stream).await
        };
        let host = async {
            let mut id = Instance::new();
            let mut wire = vec![0; 65535];
            let mut slots = [Slot::new(&mut wire)];
            let mut reservations = [];
            let mut native = client(&mut id, &mut slots, &mut reservations, &socket)?;
            let mut time = time(&native)?;
            let mut observations = 0usize;
            let answer =
                execute_controlled(&mut native, &mut time, request(), None, Some(KEY), || {
                    observations += 1;
                    observations < 4 || !seen.load(Ordering::SeqCst)
                })
                .await
                .map_err(|error| error.cause)?;
            assert!(observations >= 4);
            assert!(answer.requested_cancel);
            assert_eq!(answer.taken.completion.outcome, Outcome::Unknown);
            assert_eq!(
                answer.taken.completion.interruption,
                Some(Interruption::Cancelled)
            );
            assert!(answer.taken.bytes().is_none());
            native.close()?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        timeout(WAIT, async { tokio::try_join!(peer, host) }).await??;
        assert!(
            timeout(Duration::from_millis(40), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    })
}
#[test]
fn a_real_status_after_cancellation_retains_acceptance_and_original_interruption() -> TestResult {
    runtime()?.block_on(async {
        let (socket,listener)=Socket::bind()?;
        let seen=Arc::new(AtomicBool::new(false));let first=seen.clone();
        let cancelled=Arc::new(AtomicBool::new(false));let wanted=cancelled.clone();
        let response=Response::Status(Status {code:1,min_expiration:AbsoluteTime::from_micros(99),message:Some(b"accepted after interruption\0".as_slice())});
        let mut expected=vec![0;65535];let used=response.encode(&mut expected)?;expected.truncate(used);
        let peer=async {
            let (mut stream,_)=listener.accept().await?;received(&mut stream).await?;first.store(true,Ordering::SeqCst);
            while !wanted.load(Ordering::SeqCst) {sleep(Duration::from_millis(5)).await;}
            stream.write_all(&expected).await?;closed(&mut stream).await
        };
        let host=async {
            let mut id=Instance::new();let mut wire=vec![0;65535];let mut slots=[Slot::new(&mut wire)];let mut reservations=[];
            let mut native=client(&mut id,&mut slots,&mut reservations,&socket)?;let mut time=time(&native)?;
            let answer=execute_controlled(&mut native,&mut time,request(),None,Some(KEY),||{
                if seen.load(Ordering::SeqCst) {cancelled.store(true,Ordering::SeqCst);false}else{true}
            }).await.map_err(|error|error.cause)?;
            assert!(answer.requested_cancel);
            assert!(matches!(answer.taken.completion.outcome,Outcome::Status {code:1,..}));
            assert_eq!(answer.taken.completion.interruption,Some(Interruption::Cancelled));
            assert_eq!(answer.taken.bytes(),Some(expected.as_slice()));
            assert!(matches!(answer.taken.response()?,Some(Response::Status(value)) if value.message==Some(b"accepted after interruption\0".as_slice())));
            native.close()?;Ok::<_,Box<dyn std::error::Error>>(())
        };
        timeout(WAIT,async {tokio::try_join!(peer,host)}).await??;
        assert!(timeout(Duration::from_millis(40),listener.accept()).await.is_err());
        Ok(())
    })
}
