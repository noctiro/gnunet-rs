//! Controlled real Unix IPC model, not an official VPN service or TUN profile.
//! The actor returns only allocation failure; no successful lease is fabricated.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Exact original native bytes, epochs, cancellation and no-replay outcomes are asserted"
)]
use gnunet_vpn_client_host::{
    Address, AfProfile, Cancel, Client, EndpointSource, Family, Instance, Limits, Outcome,
    Progress, Protocol, Reason, Service, Submission,
    clock::{RuntimeClock, SystemClock},
    ipc::{Request, Response},
};
use gnunet_wire::official::MessageHeader;
use std::{error::Error, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
type Failure = Box<dyn Error + Send + Sync>;
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Failure> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gvpc-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let mut bytes = vec![0; MessageHeader::decode(&header)?.size()];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn rid(request: Request) -> [u8; 8] {
    match request {
        Request::Internet { request_id, .. } | Request::Service { request_id, .. } => request_id,
    }
}
async fn unavailable(stream: &mut UnixStream, request_id: [u8; 8]) -> Result<(), Failure> {
    let result = Response {
        request_id,
        address: None,
    };
    let mut bytes = vec![0; result.encoded_len()?];
    result.encode_with_profile(&mut bytes, AfProfile::DARWIN)?;
    for part in bytes.chunks(3) {
        stream.write_all(part).await?;
    }
    Ok(())
}
async fn actor(listener: UnixListener, lease: u64) -> Result<(), Failure> {
    let (mut first, _) = listener.accept().await?;
    let a = Request::decode_with_profile(&frame(&mut first).await?, AfProfile::DARWIN)?;
    assert!(matches!(a, Request::Internet {
        reserved: 0, expires, result_af: 30,
        destination: Address::V4([192, 0, 2, 1]), ..
    } if expires == lease));
    unavailable(&mut first, rid(a)).await?;
    let b = Request::decode_with_profile(&frame(&mut first).await?, AfProfile::DARWIN)?;
    assert!(matches!(
        b,
        Request::Internet {
            destination: Address::V6(_),
            ..
        }
    ));
    assert_ne!(rid(a), rid(b));
    unavailable(&mut first, rid(b)).await?; // Deliberately late after local cancellation.
    let c = Request::decode_with_profile(&frame(&mut first).await?, AfProfile::DARWIN)?;
    assert!(matches!(
        c,
        Request::Service {
            protocol: 17,
            peer,
            service,
            ..
        } if peer == [7; 32] && service == [8; 64]
    ));
    assert_ne!(rid(b), rid(c));
    drop(first); // Complete request without a response: unknown allocation, no replay.
    let (mut second, _) = listener.accept().await?;
    let d = Request::decode_with_profile(&frame(&mut second).await?, AfProfile::DARWIN)?;
    assert!(matches!(
        d,
        Request::Internet {
            destination: Address::V4([192, 0, 2, 99]),
            result_af: 0,
            ..
        }
    ));
    assert_ne!(rid(c), rid(d));
    unavailable(&mut second, rid(d)).await?;
    let mut byte = [0; 1];
    assert_eq!(second.read(&mut byte).await?, 0);
    Ok(())
}
#[test]
fn original_allocation_cancel_partial_drain_loss_and_no_replay() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("v");
        let listener = UnixListener::bind(&path)?;
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        let expires = clock.sample()?.now.as_micros().checked_add(15_000_000).ok_or("deadline overflow")?;
        let lease = u64::MAX;
        let actor = tokio::spawn(actor(listener, lease));
        let mut instance = Instance::new();
        let mut client = Client::new(&mut instance, EndpointSource::unix_with_clock(path, clock),
            AfProfile::DARWIN, Limits { operations: 4, io_slice_bytes: 3, ..Limits::default() })?;
        let wait = Some(Instant::now() + Duration::from_secs(6));
        let unsent = client.internet(Address::V4([192, 0, 2, 55]), None, lease, expires)?;
        assert_eq!(client.cancel(unsent)?, Cancel::Unsent);
        assert!(matches!(client.next_event(), Some(Progress::Completed {
            epoch: None, operation, outcome: Outcome::Local { reason: Reason::Cancelled, submission: Submission::Unsent }
        }) if operation == unsent));
        let first = client.internet(Address::V4([192, 0, 2, 1]), Some(Family::V6), lease, expires)?;
        loop {
            match client.drive(wait).await? {
                Progress::Completed { operation, outcome: Outcome::Allocation(None), .. } if operation == first => break,
                Progress::WaitDeadline => return Err("original USE_IP failure timed out".into()),
                _ => {}
            }
        }
        let partial = client.internet(Address::V6([3; 16]), None, lease, expires)?;
        loop {
            match client.drive(wait).await? {
                Progress::Activity { written_bytes: 3, .. } => break,
                Progress::WaitDeadline => return Err("partial original request timed out".into()),
                _ => {}
            }
        }
        assert_eq!(client.cancel(partial)?, Cancel::Draining);
        loop {
            match client.drive(wait).await? {
                Progress::Completed { operation, outcome: Outcome::Local {
                    reason: Reason::Cancelled, submission: Submission::Unknown }, .. } if operation == partial => break,
                Progress::Completed { operation, outcome: Outcome::Allocation(_), .. } if operation == partial => {
                    return Err("canceled callback was delivered".into());
                }
                Progress::WaitDeadline => return Err("original partial drain timed out".into()),
                _ => {}
            }
        }
        let lost = client.service(Service { peer: [7; 32], descriptor: [8; 64], protocol: Protocol::Udp },
            None, lease, expires)?;
        let mut fenced = false;
        let mut late_ignored = false;
        loop {
            match client.drive(wait).await? {
                Progress::Ignored(_) => late_ignored = true,
                Progress::Lost { epoch: Some(_), .. } => fenced = true,
                Progress::Completed { operation, outcome: Outcome::Local {
                    reason: Reason::Lost, submission: Submission::Unknown }, .. } if operation == lost => {
                    assert!(fenced && late_ignored);
                    break;
                }
                Progress::WaitDeadline => return Err("original loss timed out".into()),
                _ => {}
            }
        }
        let fresh = client.internet(Address::V4([192, 0, 2, 99]), None, lease, expires)?;
        loop {
            match client.drive(wait).await? {
                Progress::Completed { operation, outcome: Outcome::Allocation(None), .. } if operation == fresh => break,
                Progress::WaitDeadline => return Err("explicit new request timed out".into()),
                _ => {}
            }
        }
        assert_eq!(client.pending(), 0);
        assert!(matches!(client.close()?, Some(Progress::Lost { .. })));
        actor.await??;
        Ok(())
    })
}
