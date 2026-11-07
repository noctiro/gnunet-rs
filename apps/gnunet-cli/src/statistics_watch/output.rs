//! One bounded immutable JSON line and real borrowed-stdout cursor.
use super::{Failure, driver::Names};
use gnunet_client::statistics::{Statistic, WatchValue};
use nix::{
    poll::{PollFd, PollFlags, PollTimeout},
    sys::stat::{self, SFlag},
};
use std::{
    io::{self, Write},
    os::fd::AsFd,
};
const CAPACITY: usize = 8192;
pub(super) struct Output {
    bytes: Vec<u8>,
    used: usize,
    capacity: usize,
    stdout: io::Stdout,
    regular: bool,
}
struct Limited<'a>(&'a mut Vec<u8>, usize);
impl Write for Limited<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(data.len())
            .is_none_or(|n| n > self.1)
        {
            return Err(io::Error::other(
                "STATISTICS row exceeds original fixed output bound",
            ));
        }
        let needed = self
            .0
            .len()
            .checked_add(data.len())
            .ok_or_else(|| io::Error::other("STATISTICS output length overflow"))?;
        if needed > self.0.capacity() {
            let target = self.0.capacity().saturating_mul(2).max(needed).min(self.1);
            self.0
                .try_reserve_exact(target - self.0.len())
                .map_err(io::Error::other)?;
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Output {
    pub fn new() -> Result<Self, Failure> {
        Self::with_capacity(CAPACITY)
    }
    pub fn with_capacity(capacity: usize) -> Result<Self, Failure> {
        let bytes = Vec::new();
        let stdout = io::stdout();
        let metadata = stat::fstat(stdout.as_fd())?;
        let kind = SFlag::from_bits_truncate(metadata.st_mode);
        Ok(Self {
            bytes,
            used: 0,
            capacity,
            stdout,
            regular: (kind & SFlag::S_IFMT) == SFlag::S_IFREG,
        })
    }
    pub fn stage(
        &mut self,
        names: &Names,
        epoch: u64,
        index: u32,
        generation: u32,
        value: WatchValue,
    ) -> Result<(), Failure> {
        if !self.bytes.is_empty() {
            return Err("previous actual WATCH row still owns stdout".into());
        }
        self.used = 0;
        let mut out = Limited(&mut self.bytes, self.capacity);
        write!(
            out,
            "{{\"event\":\"statistics_watch_value\",\"epoch\":{epoch},\"logical_index\":{index},\"logical_generation\":{generation},\"wid\":{},\"flags\":{},\"reserved\":{},\"value\":{},\"persistent\":{},\"subsystem\":",
            value.wid,
            value.flags,
            value.reserved,
            value.value,
            value.persistent()
        )?;
        serde_json::to_writer(&mut out, &String::from_utf8_lossy(&names.subsystem))?;
        out.write_all(b",\"name\":")?;
        serde_json::to_writer(&mut out, &String::from_utf8_lossy(&names.name))?;
        out.write_all(b",\"subsystem_bytes\":")?;
        serde_json::to_writer(&mut out, &names.subsystem)?;
        out.write_all(b",\"name_bytes\":")?;
        serde_json::to_writer(&mut out, &names.name)?;
        out.write_all(b"}\n")?;
        Ok(())
    }
    pub fn stage_get(&mut self, value: Statistic<'_>) -> Result<(), Failure> {
        if !self.bytes.is_empty() {
            return Err("previous STATISTICS row still owns stdout".into());
        }
        self.used = 0;
        let mut out = Limited(&mut self.bytes, self.capacity);
        write!(
            out,
            "{{\"event\":\"statistics_value\",\"uid\":{},\"persistent\":{},\"value\":{},\"subsystem\":",
            value.uid(),
            value.persistent(),
            value.value
        )?;
        serde_json::to_writer(&mut out, &String::from_utf8_lossy(value.selector.subsystem))?;
        out.write_all(b",\"name\":")?;
        serde_json::to_writer(&mut out, &String::from_utf8_lossy(value.selector.name))?;
        out.write_all(b",\"subsystem_bytes\":")?;
        serde_json::to_writer(&mut out, &value.selector.subsystem)?;
        out.write_all(b",\"name_bytes\":")?;
        serde_json::to_writer(&mut out, &value.selector.name)?;
        out.write_all(b"}\n")?;
        Ok(())
    }
    pub fn stage_terminal(&mut self, count: Option<u64>, noop: bool) -> Result<(), Failure> {
        if !self.bytes.is_empty() {
            return Err("previous STATISTICS row still owns stdout".into());
        }
        self.used = 0;
        let mut out = Limited(&mut self.bytes, self.capacity);
        if let Some(count) = count {
            writeln!(out, "{{\"event\":\"statistics_end\",\"count\":{count}}}")?;
        } else if noop {
            out.write_all(b"{\"event\":\"statistics_set_noop\"}\n")?;
        } else {
            out.write_all(b"{\"event\":\"statistics_set_confirmed\"}\n")?;
        }
        Ok(())
    }
    /// None means no positive byte progress; caller owns real timer/readiness wait.
    pub fn step(&mut self) -> io::Result<Option<bool>> {
        if self.bytes.is_empty() {
            return Ok(Some(true));
        }
        if !self.regular {
            let mut descriptors = [PollFd::new(self.stdout.as_fd(), PollFlags::POLLOUT)];
            match nix::poll::poll(&mut descriptors, PollTimeout::ZERO) {
                Ok(_) => {
                    let event = descriptors[0]
                        .revents()
                        .ok_or_else(|| io::Error::other("unknown stdout poll bits"))?;
                    if event.contains(PollFlags::POLLNVAL) {
                        return Err(io::Error::from_raw_os_error(nix::libc::EBADF));
                    }
                    if !event
                        .intersects(PollFlags::POLLOUT | PollFlags::POLLERR | PollFlags::POLLHUP)
                    {
                        return Ok(None);
                    }
                }
                Err(nix::errno::Errno::EINTR) => return Ok(None),
                Err(e) => return Err(io::Error::from(e)),
            }
        }
        let end = if self.regular {
            self.bytes.len()
        } else {
            self.used.saturating_add(512).min(self.bytes.len())
        };
        match nix::unistd::write(self.stdout.as_fd(), &self.bytes[self.used..end]) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "zero original WATCH stdout write",
            )),
            Ok(n) => {
                self.used += n;
                Ok(Some(self.used == self.bytes.len()))
            }
            Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => Ok(None),
            Err(e) => Err(io::Error::from(e)),
        }
    }
    pub fn pending(&self) -> (usize, usize) {
        (self.used, self.bytes.len())
    }
    pub fn release(&mut self) {
        self.bytes.clear();
        self.used = 0;
    }
    pub fn flush(&mut self) -> io::Result<()> {
        self.stdout.flush()
    }
}
