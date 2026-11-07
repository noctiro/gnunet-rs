//! Actual numeric-loopback TCP plus separate owned local IPC fixture streams.
//! These fixtures execute no C daemon and are not counted as normal-peer proof.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual socket tests assert protocol and callback results"
)]
#[expect(
    dead_code,
    reason = "Shared controlled component adapter has separate Driver and Communicator facades; each existing fixture uses one"
)]
#[path = "support/history.rs"]
mod history;
use core::{
    cell::{Cell, RefCell},
    num::NonZeroUsize,
};
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_tcp_communicator_core::{
    session::{
        Buffers, CIPHERTEXT_CAPACITY, CompletionSlot, Identity, Phase, Policy, Scope, Session, Time,
    },
    wire,
};
use gnunet_tcp_communicator_host::{Capacity, HostError};
use gnunet_types::Error;
use history::Driver;
use std::{
    io,
    rc::Rc,
    task::{Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
};
struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        for x in b {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *x = self.0 as u8;
        }
        Ok(())
    }
}
fn clock() -> Result<Time, Error> {
    let t = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::TimeUncertain)?
            .as_micros(),
    )
    .map_err(|_| Error::Overflow)?;
    Ok(Time { now: t, signed: t })
}
async fn frame(s: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut h = [0; 4];
    s.read_exact(&mut h).await?;
    let n = u16::from_be_bytes([h[0], h[1]]) as usize;
    if n < 4 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&h);
    s.read_exact(&mut b[4..]).await?;
    Ok(b)
}
async fn next_frame(s: &mut UnixStream, done: &Cell<bool>) -> io::Result<Option<Vec<u8>>> {
    // Keep one read future across timer observations so a fragmented header
    // cannot lose its consumed prefix when the peer has not finished yet.
    let reading = frame(s);
    tokio::pin!(reading);
    loop {
        tokio::select! {
            result = &mut reading => return result.map(Some),
            () = tokio::time::sleep(Duration::from_millis(1)) => {
                if done.get() { return Ok(None); }
            }
        }
    }
}
async fn ps(mut s: UnixStream, done: Rc<Cell<bool>>) -> io::Result<UnixStream> {
    while let Some(b) = next_frame(&mut s, &done).await? {
        let kind = u16::from_be_bytes([b[2], b[3]]);
        if kind == 821 || kind == 820 {
            let at = if kind == 821 { 36 } else { 44 };
            let mut end = [0; 12];
            end[..2].copy_from_slice(&12u16.to_be_bytes());
            end[2..4].copy_from_slice(&(if kind == 821 { 823u16 } else { 827u16 }).to_be_bytes());
            end[4..8].copy_from_slice(&b[at..at + 4]);
            end[8..].copy_from_slice(&1i32.to_be_bytes());
            for fragment in end.chunks(3) {
                s.write_all(fragment).await?;
                tokio::task::yield_now().await;
            }
        }
    }
    Ok(s)
}
async fn tr(
    mut s: UnixStream,
    send: bool,
    done: Rc<Cell<bool>>,
) -> io::Result<(Vec<u8>, UnixStream)> {
    let mut result = Vec::new();
    while let Some(b) = next_frame(&mut s, &done).await? {
        let kind = u16::from_be_bytes([b[2], b[3]]);
        if kind == 1204 {
            assert_eq!(&b[64..], b"tcp-127.0.0.1:1234\0");
            assert_eq!(
                u32::from_be_bytes(
                    b[44..48]
                        .try_into()
                        .map_err(|_| io::ErrorKind::InvalidData)?
                ),
                65535
            );
            if send {
                let mut message = vec![0; 56];
                message[..2].copy_from_slice(&56u16.to_be_bytes());
                message[2..4].copy_from_slice(&1209u16.to_be_bytes());
                message[4..8].copy_from_slice(&b[4..8]);
                message[8..16].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
                message[16..48].copy_from_slice(&b[8..40]);
                message[48..].copy_from_slice(&[0, 8, 0, 17, 1, 2, 3, 4]);
                s.write_all(&message).await?;
            }
        } else if kind == 1202 {
            assert!(!send);
            assert_eq!(b.len(), 96);
            result = b[88..].to_vec();
            let mut ack = [0; 48];
            ack[..2].copy_from_slice(&48u16.to_be_bytes());
            ack[2..4].copy_from_slice(&1203u16.to_be_bytes());
            ack[8..16].copy_from_slice(&b[8..16]);
            ack[16..].copy_from_slice(&b[24..56]);
            s.write_all(&ack).await?;
            done.set(true);
        } else if kind == 1210 {
            assert!(send);
            assert_eq!(&b[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(&b[4..8], &1i32.to_be_bytes());
        }
    }
    Ok((result, s))
}
async fn drive(d: &mut Driver<'_>, r: &mut Random, done: Rc<Cell<bool>>) -> Result<(), HostError> {
    loop {
        if done.get() && d.core().backpressure() == 0 {
            return Ok(());
        }
        tokio::select! {a=d.step(clock()?,r)=>{let _activity=a?;},()=tokio::time::sleep(Duration::from_millis(1))=>{}}
    }
}
#[tokio::test(flavor = "current_thread")]
async fn actual_tcp_fragmented_service_replies_box_and_original_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (connect, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    let a_stream = connect?;
    let (b_stream, _) = accepted?;
    a_stream.set_nodelay(true)?;
    b_stream.set_nodelay(true)?;
    let (pa, pas) = UnixStream::pair()?;
    let (ta, tas) = UnixStream::pair()?;
    let (pb, pbs) = UnixStream::pair()?;
    let (tb, tbs) = UnixStream::pair()?;
    let ak = EddsaPrivateKey::from_seed([1; 32]);
    let bk = EddsaPrivateKey::from_seed([2; 32]);
    let ae = gnunet_session_crypto::exchange::EcdheSecret::from_eddsa_seed([1; 32]);
    let be = gnunet_session_crypto::exchange::EcdheSecret::from_eddsa_seed([2; 32]);
    let (mut ascope, mut bscope) = (Scope::new(), Scope::new());
    let (mut arx, mut atx, mut apl) = (
        vec![0; wire::MAX_RECORD],
        vec![0; CIPHERTEXT_CAPACITY],
        vec![0; wire::MAX_RECORD],
    );
    let (mut brx, mut btx, mut bpl) = (
        vec![0; wire::MAX_RECORD],
        vec![0; CIPHERTEXT_CAPACITY],
        vec![0; wire::MAX_RECORD],
    );
    let (mut ac, mut bc) = ([CompletionSlot::default()], [CompletionSlot::default()]);
    let mut p = Policy::reference(NonZeroUsize::new(128).ok_or(Error::InvalidInput)?);
    p.max_backpressure = 1;
    let (mut ra, mut rb) = (Random(1987), Random(2977));
    let a = Session::new(
        &mut ascope,
        Identity::new(&ak, &ae)?,
        Some(bk.public_key()),
        Buffers {
            receive: &mut arx,
            transmit: &mut atx,
            plaintext: &mut apl,
            completions: &mut ac,
        },
        p,
        clock()?,
        &mut ra,
    )?;
    let b = Session::new(
        &mut bscope,
        Identity::new(&bk, &be)?,
        None,
        Buffers {
            receive: &mut brx,
            transmit: &mut btx,
            plaintext: &mut bpl,
            completions: &mut bc,
        },
        p,
        clock()?,
        &mut rb,
    )?;
    let cap = Capacity {
        ipc_bytes: 131070,
        ipc_frames: 16,
        callbacks: 1,
    };
    let mut a = Driver::new(
        a,
        Connection::from_tcp(a_stream),
        [Connection::from_unix(pa), Connection::from_unix(ta)],
        cap,
        b"tcp-127.0.0.1:1234",
        1,
    )?;
    let mut b = Driver::new(
        b,
        Connection::from_tcp(b_stream),
        [Connection::from_unix(pb), Connection::from_unix(tb)],
        cap,
        b"tcp-127.0.0.1:1234",
        1,
    )?;
    let done = Rc::new(Cell::new(false));
    let results = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            drive(&mut a, &mut ra, done.clone()),
            drive(&mut b, &mut rb, done.clone()),
            ps(pas, done.clone()),
            ps(pbs, done.clone()),
            tr(tas, true, done.clone()),
            tr(tbs, false, done.clone())
        )
    })
    .await?;
    results.0?;
    results.1?;
    let _a_peerstore = results.2?;
    let _b_peerstore = results.3?;
    let (_sent, _a_transport) = results.4?;
    let (received, _b_transport) = results.5?;
    assert_eq!(received, [0, 8, 0, 17, 1, 2, 3, 4]);
    assert_eq!(a.core().phase(), Phase::Established);
    assert_eq!(b.core().phase(), Phase::Established);
    assert_eq!(b.core().backpressure(), 0);
    // Replace the actual inbound TRANSPORT MQ. The original qid, peer, role and
    // address must survive; the signed TCP session itself remains the same owner.
    b.transport_lost(clock()?)?;
    let (replacement, mut replacement_server) = UnixStream::pair()?;
    b.attach_transport(Connection::from_unix(replacement))
        .map_err(|r| r.reason)?;
    let restored = Rc::new(Cell::new(false));
    let restored_waker = Rc::new(RefCell::new(None::<Waker>));
    let results = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(
            async {
                while !restored.get() {
                    tokio::select! {
                        result=b.step(clock()?,&mut rb)=>match result{
                            Ok(_)=>{},
                            Err(HostError::Peerstore(error)) if error.io_retired()=>{},
                            Err(e)=>return Err(e),
                        },
                        ()=std::future::poll_fn(|cx|{
                            if restored.get(){Poll::Ready(())}else{
                                *restored_waker.borrow_mut()=Some(cx.waker().clone());
                                Poll::Pending
                            }
                        })=>{},
                    }
                }
                Ok::<_, HostError>(())
            },
            async {
                let announcement = frame(&mut replacement_server).await?;
                assert_eq!(u16::from_be_bytes([announcement[2], announcement[3]]), 1211);
                let setup = frame(&mut replacement_server).await?;
                assert_eq!(u16::from_be_bytes([setup[2], setup[3]]), 1204);
                assert_eq!(&setup[4..8], &0u32.to_be_bytes());
                assert_eq!(&setup[8..40], ak.public_key().as_bytes());
                assert_eq!(&setup[60..64], &1u32.to_be_bytes());
                assert_eq!(&setup[64..], b"tcp-127.0.0.1:1234\0");
                restored.set(true);
                if let Some(waker) = restored_waker.borrow_mut().take() {
                    waker.wake();
                }
                Ok::<_, io::Error>(replacement_server)
            }
        )
    })
    .await?;
    results.0?;
    let _replacement_server = results.1?;
    assert_eq!(b.core().phase(), Phase::Established);
    Ok(())
}
