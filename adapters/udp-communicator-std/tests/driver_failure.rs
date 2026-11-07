//! Actual fixed-session MQ rejection and terminal draining; no C interop claim.
#![cfg(feature = "transport")]
use gnunet_crypto::Entropy;
use gnunet_service_runtime::connection::Connection;
use gnunet_types::Error;
use gnunet_udp_communicator_core::Identity;
use gnunet_udp_communicator_host::{
    driver::{Activity, Capacity, Configuration, Driver},
    replay::Journal,
    socket::DatagramSocket,
};
use gnunet_wire::official::Frame;
use std::{
    future::poll_fn,
    io::{Read, Write},
    net::UdpSocket,
    os::unix::net::UnixStream as NativeStream,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::net::UnixStream;

type Failure = Box<dyn std::error::Error>;
type Test = Result<(), Failure>;
static NEXT: AtomicU64 = AtomicU64::new(0);
fn require(value: bool, message: &'static str) -> Test {
    if value { Ok(()) } else { Err(message.into()) }
}
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
struct Random {
    fail: bool,
    calls: usize,
}
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.calls = self.calls.checked_add(1).ok_or(Error::Overflow)?;
        if self.fail {
            bytes.fill(0);
            return Err(Error::Entropy);
        }
        getrandom::fill(bytes).map_err(|_| Error::Entropy)
    }
}
struct Harness {
    driver: Driver,
    local: Identity,
    peer: [u8; 32],
    journal: Journal,
    service: NativeStream,
    remote: UdpSocket,
    random: Random,
    wire: Vec<u8>,
    eof: bool,
    native_sends: usize,
    now: u64,
    late_on_command: Option<u64>,
    _scratch: Scratch,
}
impl Harness {
    fn new(fail_entropy: bool) -> Result<Self, Failure> {
        let scratch = Scratch(std::env::temp_dir().join(format!(
            "udp-driver-failure-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        std::fs::create_dir(&scratch.0)?;
        let local = Identity::from_seed([3; 32]);
        let peer = Identity::from_seed([5; 32]).peer();
        let remote = UdpSocket::bind("127.0.0.1:0")?;
        remote.set_nonblocking(true)?;
        let socket = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
        let (service, communicator) = UnixStream::pair()?;
        let configuration = Configuration {
            local: local.peer(),
            peer,
            target: remote.local_addr()?,
            network: 1,
            capacity: Capacity {
                frames: 4,
                bytes: 65535,
                io_slice: 1,
            },
            transmit: socket.profile().sender_policy(),
        };
        let driver = Driver::new(
            Connection::from_unix(communicator),
            socket,
            configuration,
            100,
        )?;
        let journal = Journal::open(&scratch.0, local.peer(), 2)?;
        Ok(Self {
            driver,
            local,
            peer,
            journal,
            service: service.into_std()?,
            remote,
            random: Random {
                fail: fail_entropy,
                calls: 0,
            },
            wire: Vec::new(),
            eof: false,
            native_sends: 0,
            now: 100,
            late_on_command: fail_entropy.then_some(
                100u64
                    .checked_add(configuration.transmit.acknowledgement_timeout_us)
                    .ok_or(Error::Overflow)?,
            ),
            _scratch: scratch,
        })
    }
    fn send(&mut self, qid: u32, peer: [u8; 32], mid: [u8; 8]) -> Test {
        let mut frame = [0; 56];
        frame[..2].copy_from_slice(&56u16.to_be_bytes());
        frame[2..4].copy_from_slice(&1209u16.to_be_bytes());
        frame[4..8].copy_from_slice(&qid.to_be_bytes());
        frame[8..16].copy_from_slice(&mid);
        frame[16..48].copy_from_slice(&peer);
        frame[48..].copy_from_slice(&[0, 8, 0, 0, 1, 2, 3, 4]);
        self.service.write_all(&frame)?;
        Ok(())
    }
    fn read(&mut self) -> Result<bool, Failure> {
        let mut progress = false;
        if self.eof {
            return Ok(false);
        }
        loop {
            let mut block = [0; 512];
            match self.service.read(&mut block) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(true);
                }
                Ok(n) => {
                    if self.wire.len().checked_add(n).is_none_or(|n| n > 8192) {
                        return Err(Error::Capacity.into());
                    }
                    self.wire.extend_from_slice(&block[..n]);
                    progress = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(progress);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    fn frames(&self) -> Result<Vec<&[u8]>, Error> {
        let mut frames = Vec::new();
        let mut at = 0;
        while let Some(header) = self.wire.get(at..at + 4) {
            let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
            if size < 4 {
                return Err(Error::Malformed);
            }
            let Some(frame) = self.wire.get(at..at + size) else {
                break;
            };
            Frame::decode(frame)?;
            frames.push(frame);
            at += size;
        }
        Ok(frames)
    }
    fn callbacks(&self) -> Result<usize, Error> {
        Ok(self
            .frames()?
            .iter()
            .filter(|frame| frame[2..4] == 1210u16.to_be_bytes())
            .count())
    }
    async fn until(&mut self, ready: impl Fn(&Self) -> Result<bool, Error>) -> Test {
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                let mut progress = false;
                for _ in 0..16 {
                    if !self.driver.is_quiescent() {
                        match self.driver.poll_step(
                            cx,
                            &self.local,
                            &mut self.journal,
                            self.now,
                            &mut self.random,
                        ) {
                            Poll::Ready(Ok(activity)) => {
                                if matches!(activity, Activity::NativeSent { .. }) {
                                    self.native_sends += 1;
                                }
                                if activity == Activity::Command
                                    && let Some(now) = self.late_on_command.take()
                                {
                                    self.now = now;
                                }
                                progress = true;
                            }
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                            Poll::Pending => {}
                        }
                    }
                    progress |= self.read()?;
                    if ready(self)? {
                        return Poll::Ready(Ok::<(), Failure>(()));
                    }
                    if !progress {
                        break;
                    }
                }
                if progress {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }),
        )
        .await??;
        Ok(())
    }
    fn no_datagram(&self) -> Test {
        match self.remote.recv_from(&mut [0; 2048]) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            _ => Err("unexpected native datagram".into()),
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn known_send_entropy_refusal_drains_original_failure_and_down_even_past_ack_target() -> Test
{
    let mut h = Harness::new(true)?;
    let mid = [0x41; 8];
    h.send(1, h.peer, mid)?;
    h.until(|h| Ok(h.driver.is_quiescent() && h.eof)).await?;
    require(h.native_sends == 0, "rejected packet reached native send")?;
    require(h.random.calls == 1, "failed entropy was retried")?;
    require(h.journal.commits() == 1, "original monotime was replayed")?;
    h.no_datagram()?;
    let frames = h.frames()?;
    let mut callbacks = 0;
    let mut downs = 0;
    for frame in frames {
        match u16::from_be_bytes([frame[2], frame[3]]) {
            1210 => {
                require(
                    downs == 0 && frame.len() == 52,
                    "failure did not precede teardown",
                )?;
                require(
                    frame[4..8] == (-1i32).to_be_bytes(),
                    "refusal became success",
                )?;
                require(
                    frame[8..16] == mid
                        && frame[16..20] == 1u32.to_be_bytes()
                        && frame[20..] == h.peer,
                    "failure owner changed",
                )?;
                callbacks += 1;
            }
            1205 => {
                require(
                    frame.len() == 40 && frame[4..8] == 1u32.to_be_bytes() && frame[8..] == h.peer,
                    "teardown owner changed",
                )?;
                downs += 1;
            }
            1211 | 1204 => {}
            _ => return Err("unexpected effect after original refusal".into()),
        }
    }
    require(
        callbacks == 1 && downs == 1,
        "original failure or teardown duplicated/omitted",
    )?;
    require(
        h.driver.next_wakeup().is_none(),
        "retired session retained an ACK timer",
    )
}

#[tokio::test(flavor = "current_thread")]
async fn foreign_send_ids_fail_without_retiring_the_actual_fixed_session() -> Test {
    let mut h = Harness::new(false)?;
    let foreign_mid = [0x51; 8];
    let foreign_peer_mid = [0x52; 8];
    let live_mid = [0x53; 8];
    h.send(99, h.peer, foreign_mid)?;
    h.send(1, [0x81; 32], foreign_peer_mid)?;
    h.send(1, h.peer, live_mid)?;
    h.until(|h| Ok(h.native_sends == 1 && h.callbacks()? == 3))
        .await?;
    require(
        !h.driver.is_quiescent(),
        "foreign send retired the valid session",
    )?;
    require(
        h.journal.commits() == 1,
        "foreign send spent an original monotime",
    )?;
    let mut datagram = [0; 2048];
    let (size, _) = h.remote.recv_from(&mut datagram)?;
    require(size > 8, "original valid datagram missing")?;
    h.no_datagram()?;
    let mut received = Vec::new();
    for frame in h.frames()? {
        if frame[2..4] == 1210u16.to_be_bytes() {
            let mid: [u8; 8] = frame[8..16].try_into().map_err(|_| Error::Truncated)?;
            let status = i32::from_be_bytes(frame[4..8].try_into().map_err(|_| Error::Truncated)?);
            received.push((mid, status));
        }
        require(
            frame[2..4] != 1205u16.to_be_bytes(),
            "valid session was withdrawn",
        )?;
    }
    require(
        received == [(foreign_mid, -1), (foreign_peer_mid, -1), (live_mid, 1)],
        "original callback outcomes or order changed",
    )?;
    h.driver.finish()?;
    h.until(|h| Ok(h.driver.is_quiescent() && h.eof)).await?;
    require(
        h.callbacks()? == 3,
        "shutdown replayed an old SEND callback",
    )
}
