//! Bounded record projection and one real stdout partial-write cursor.
use crate::{Cause, options::Settings};
use gnunet_gns_client_host::{Answer, RecordFlags};
use gnunet_gnsrecord_text::{Codec, Limits, Profile, Workspace, type_name};
use gnunet_program_host::reporting::Reporter;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    future::Future,
    io::{self, Stdout},
    os::fd::AsFd,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;

#[derive(Default, Debug)]
pub(super) struct Projection {
    pub records: usize,
    pub formatted: usize,
    pub malformed: usize,
}
pub(super) struct Output {
    stdout: Stdout,
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
    limit: usize,
    alarm: Pin<Box<Sleep>>,
}
impl Output {
    pub(super) fn new(stdout: Stdout, limit: usize) -> Self {
        Self {
            stdout,
            bytes: Zeroizing::new(Vec::new()),
            offset: 0,
            limit,
            alarm: Box::pin(tokio::time::sleep(Duration::ZERO)),
        }
    }
    pub(super) fn extent(&self) -> (usize, usize) {
        (self.bytes.len(), self.offset)
    }
    pub(super) fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), Cause> {
        let len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or("GNS output length overflow")?;
        if len > self.limit {
            return Err("bounded GNS output capacity exceeded".into());
        }
        self.bytes.try_reserve_exact(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub(super) fn looking(&mut self, settings: &Settings) -> Result<(), Cause> {
        if !settings.raw {
            self.append(b">>> Looking for `")?;
            self.append(&settings.type_name)?;
            self.append(b"' records under `")?;
            self.append(&settings.name)?;
            self.append(b"'\n")?;
        }
        Ok(())
    }
    pub(super) fn answer(
        &mut self,
        answer: &Answer<'_>,
        raw: bool,
        reporter: &Reporter,
        observed: &mut Projection,
        elapsed: Duration,
        native_deadline: Option<Instant>,
    ) -> Result<(), Cause> {
        let records = answer.result()?.records();
        observed.records = records.len();
        if !raw {
            self.append(format!("<<< {} record(s) found:\n\n", records.len()).as_bytes())?;
        }
        if records.is_empty() {
            if !raw {
                self.append(
                    format!(
                        "\nResolution finished after {} microseconds\n",
                        elapsed.as_micros()
                    )
                    .as_bytes(),
                )?;
            }
            return Ok(());
        }
        let mut stage = filled(262140)?;
        let mut names = [0u8; 510];
        let mut work = [0u8; 1024];
        let mut formatted = Zeroizing::new(filled(262140)?);
        let mut idna_scratch = gnunet_idna::Workspace::new();
        let idna = gnunet_idna::Backend::new(
            &mut idna_scratch,
            gnunet_idna::Limits::GNUNET,
            gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
        );
        let mut codec = Codec::new(
            &idna,
            Workspace::new(&mut stage, &mut names, &mut work),
            Profile::NATIVE_255,
            Limits::default(),
        )?;
        for (index, record) in records.iter().enumerate() {
            if native_deadline.is_some_and(|hard| Instant::now() >= hard) {
                return Err(gnunet_types::Error::Deadline.into());
            }
            let record = record?;
            let n = match codec.value_to_string(record.record_type, record.data, &mut formatted) {
                Ok(n) => n,
                Err(error) => {
                    observed.malformed += 1;
                    reporter.warning(
                        "gns.record.malformed",
                        format_args!(
                            "Record {index} of type {} cannot be formatted ({error}); skipping",
                            record.record_type.value()
                        ),
                    );
                    if reporter.failed() {
                        return Err("selected Logger failed while projecting GNS records".into());
                    }
                    continue;
                }
            };
            if raw {
                self.append(&formatted[..n])?;
                self.append(b"\n")?;
            } else {
                let kind = type_name(record.record_type).unwrap_or("UNKNOWN");
                self.append(kind.as_bytes())?;
                self.append(b": `")?;
                self.append(&formatted[..n])?;
                self.append(if record.flags.contains(RecordFlags::SUPPLEMENTAL) {
                    b"' (supplemental)\n"
                } else {
                    b"' \n"
                })?;
            }
            observed.formatted += 1;
            if reporter.failed() {
                return Err("selected Logger failed while projecting GNS records".into());
            }
        }
        if !raw {
            self.append(
                format!(
                    "\nResolution finished after {} microseconds\n",
                    elapsed.as_micros()
                )
                .as_bytes(),
            )?;
        }
        Ok(())
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
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
                        "stdout readiness failed",
                    )));
                }
                if flags.contains(PollFlags::POLLOUT) {
                    let end = self.bytes.len().min(self.offset + 512);
                    // This sole stdout owner never alters the shared OFD flags.
                    // A synchronous OS write cannot be forcibly interrupted by
                    // the async deadline, even after readiness was reported.
                    match nix::unistd::write(self.stdout.as_fd(), &self.bytes[self.offset..end]) {
                        Err(nix::errno::Errno::EINTR | nix::errno::Errno::EAGAIN) => {}
                        Err(error) => return Poll::Ready(Err(error.into())),
                        Ok(0) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "stdout wrote zero bytes",
                            )));
                        }
                        Ok(count) => {
                            self.offset += count;
                            self.alarm.as_mut().reset(Instant::now());
                            return Poll::Ready(Ok(count));
                        }
                    }
                }
            }
        }
        let _registered = self.alarm.as_mut().poll(cx);
        Poll::Pending
    }
}

fn filled(size: usize) -> Result<Vec<u8>, Cause> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size)?;
    bytes.resize(size, 0);
    Ok(bytes)
}
