//! One retained result, backpressured before taking another native delivery.
use crate::Cause;
use gnunet_dht_client_host::{
    MonitorKind,
    ipc::{self, ResultMessage},
};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    future::Future,
    io::{self, Stdout, Write},
    os::fd::AsFd,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub(super) struct Output {
    stdout: Stdout,
    bytes: Vec<u8>,
    offset: usize,
    alarm: Pin<Box<Sleep>>,
}
impl Output {
    pub fn new(stdout: Stdout) -> Self {
        Self {
            stdout,
            bytes: Vec::new(),
            offset: 0,
            alarm: Box::pin(tokio::time::sleep(Duration::ZERO)),
        }
    }
    pub fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
    fn begin(&mut self, needed: usize) -> Result<(), Cause> {
        if !self.finished() {
            return Err("previous DHT output remains retained".into());
        }
        if needed > 128 * 1024 {
            return Err(gnunet_types::Error::TooLarge.into());
        }
        self.bytes.clear();
        self.offset = 0;
        // Grow only for the current observation. Small replies and HELLO
        // absence do not allocate the full worst-case output budget.
        self.bytes.try_reserve_exact(needed)?;
        self.alarm.as_mut().reset(Instant::now());
        Ok(())
    }
    pub fn hello(&mut self, url: Option<&[u8]>) -> Result<(), Cause> {
        self.begin(url.map_or(0, |url| url.len().saturating_add(1)))?;
        if let Some(url) = url {
            self.bytes.extend_from_slice(url);
            self.bytes.push(b'\n');
        }
        Ok(())
    }
    pub fn monitor(&mut self, kind: MonitorKind, frame: &[u8], count: u64) -> Result<(), Cause> {
        let (label, block_type, key, payload, expiration) = match kind {
            MonitorKind::Get => {
                let m = ipc::MonitorGet::decode(frame)?;
                ("GET", m.block_type, m.key, &[][..], None)
            }
            MonitorKind::Result => {
                let m = ipc::MonitorResult::decode(frame)?;
                (
                    "RESPONSE",
                    m.block_type,
                    m.key,
                    m.payload,
                    Some(m.expiration),
                )
            }
            MonitorKind::Put => {
                let m = ipc::MonitorPut::decode(frame)?;
                ("PUT", m.block_type, m.key, m.payload, Some(m.expiration))
            }
        };
        let data_bytes = if block_type == 8 { payload.len() } else { 0 };
        self.begin(256usize.saturating_add(data_bytes))?;
        let mut encoded = [0; 103];
        let n = gnunet_gnsrecord::encode_base32(key, &mut encoded)?;
        write!(self.bytes, "{label} #{count}: type {block_type}, key `")?;
        self.bytes.extend_from_slice(&encoded[..n]);
        self.bytes.push(b'\'');
        if let Some(expiration) = expiration {
            write!(self.bytes, ", expires-us {}", expiration.as_micros())?;
        }
        if kind != MonitorKind::Get && block_type == 8 {
            self.bytes.extend_from_slice(b", data `");
            let n = payload
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(payload.len());
            self.bytes.extend_from_slice(&payload[..n]);
            self.bytes.push(b'\'');
        }
        self.bytes.push(b'\n');
        Ok(())
    }
    pub fn result(
        &mut self,
        result: ResultMessage<'_>,
        count: u64,
        paths: bool,
    ) -> Result<(), Cause> {
        let data_bytes = if result.block_type == 8 {
            result.payload.len()
        } else {
            0
        };
        let path_bytes = if paths {
            result
                .get_path
                .len()
                .saturating_add(result.put_path.len())
                .saturating_mul(53)
        } else {
            0
        };
        // 256 covers headers, separators and the optional truncation marker;
        // each displayed path entry needs at most52 digits plus one separator.
        self.begin(
            256usize
                .saturating_add(data_bytes)
                .saturating_add(path_bytes),
        )?;
        writeln!(self.bytes, "Result {count}, type {}:", result.block_type)?;
        if result.block_type == 8 {
            let n = result
                .payload
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(result.payload.len());
            self.bytes.extend_from_slice(&result.payload[..n]);
            self.bytes.push(b'\n');
        }
        if paths {
            for (label, path) in [
                (b"  GET path: ".as_slice(), result.get_path),
                (b"  PUT path: ".as_slice(), result.put_path),
            ] {
                self.bytes.extend_from_slice(label);
                for (i, e) in path.elements().enumerate() {
                    if i != 0 {
                        self.bytes.push(b'-');
                    }
                    let mut encoded = [0; 52];
                    let n = gnunet_gnsrecord::encode_base32(e.predecessor(), &mut encoded)?;
                    self.bytes.extend_from_slice(&encoded[..n]);
                }
                self.bytes.push(b'\n');
            }
            if let Some(peer) = result.truncated_peer {
                self.bytes.extend_from_slice(b"  Truncated at: ");
                let mut encoded = [0; 52];
                let n = gnunet_gnsrecord::encode_base32(peer, &mut encoded)?;
                self.bytes.extend_from_slice(&encoded[..n]);
                self.bytes.push(b'\n');
            }
        }
        self.alarm.as_mut().reset(Instant::now());
        Ok(())
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.finished() {
            return Poll::Pending;
        }
        if self.alarm.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.alarm
            .as_mut()
            .reset(Instant::now() + Duration::from_millis(25));
        let mut fds = [PollFd::new(self.stdout.as_fd(), PollFlags::POLLOUT)];
        match poll(&mut fds, PollTimeout::ZERO) {
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Poll::Ready(Err(error.into())),
            Ok(_) => {
                let flags = fds[0].revents().unwrap_or(PollFlags::empty());
                if flags.intersects(PollFlags::POLLNVAL | PollFlags::POLLHUP | PollFlags::POLLERR) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "DHT stdout readiness failed",
                    )));
                }
                if flags.contains(PollFlags::POLLOUT) {
                    let end = self.bytes.len().min(self.offset + 512);
                    match nix::unistd::write(self.stdout.as_fd(), &self.bytes[self.offset..end]) {
                        Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => {}
                        Err(error) => return Poll::Ready(Err(error.into())),
                        Ok(0) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "DHT stdout zero write",
                            )));
                        }
                        Ok(n) => {
                            self.offset += n;
                            self.alarm.as_mut().reset(Instant::now());
                            return Poll::Ready(Ok(n));
                        }
                    }
                }
            }
        }
        let _registered = self.alarm.as_mut().poll(cx);
        Poll::Pending
    }
}
