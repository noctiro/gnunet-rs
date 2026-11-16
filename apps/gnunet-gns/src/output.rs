//! Bounded record projection and caller-owned native output retirement.
mod retirement;
use crate::{Cause, options::Settings};
use gnunet_gns_client_host::{Answer, RecordFlags};
use gnunet_gnsrecord_text::{Codec, Limits, Profile, Workspace, type_name};
use gnunet_program_host::{binary_io, reporting::Reporter};
pub(super) use retirement::{Close, Retained, retained, settle};
use std::{
    future::Future,
    io,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
use zeroize::Zeroizing;
const CHUNK: usize = 16 * 1024;
#[derive(Default, Debug)]
pub(super) struct Projection {
    pub records: usize,
    pub formatted: usize,
    pub malformed: usize,
}
pub(super) struct Output {
    native: Option<binary_io::Output>,
    retired: Retained,
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
    limit: usize,
    pending: bool,
    fenced: bool,
}
impl Output {
    pub(super) fn new(retired: Retained, limit: usize) -> Result<Self, Cause> {
        let native = binary_io::Output::stdout_text(CHUNK)?;
        Ok(Self {
            native: Some(native),
            retired,
            bytes: Zeroizing::new(Vec::new()),
            offset: 0,
            limit,
            pending: false,
            fenced: false,
        })
    }
    pub(super) fn extent(&self) -> (usize, usize) {
        (self.bytes.len(), self.offset)
    }
    pub(super) fn finished(&self) -> bool {
        self.offset == self.bytes.len() && !self.pending
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
        if len > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(len)
                .min(self.limit);
            // Wipe the previous allocation instead of reallocating plaintext.
            let mut grown = Zeroizing::new(Vec::new());
            grown.try_reserve_exact(capacity)?;
            grown.extend_from_slice(&self.bytes);
            self.bytes = grown;
        }
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
        if self.finished() || self.fenced {
            return Poll::Pending;
        }
        let Some(native) = &mut self.native else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        if !self.pending {
            let maximum = self.bytes.len().min(self.offset + CHUNK);
            let mut end = maximum;
            // End valid UTF-8 chunks at a scalar boundary. A partial file/pipe
            // write may leave a leading suffix byte; redirected output remains raw.
            while end < self.bytes.len() && end > self.offset && self.bytes[end] & 0xc0 == 0x80 {
                end -= 1;
            }
            if end == self.offset {
                end = maximum;
            }
            if let Err(error) = native.begin(&self.bytes[self.offset..end]) {
                self.fenced = true;
                return Poll::Ready(Err(error));
            }
            self.pending = true;
        }
        let result = {
            let mut complete = std::pin::pin!(native.complete());
            complete.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = false;
                match result {
                    Ok(0) => {
                        self.fenced = true;
                        Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
                    }
                    Ok(count) => {
                        self.offset += count;
                        Poll::Ready(Ok(count))
                    }
                    Err(error) => {
                        self.fenced = true;
                        Poll::Ready(Err(error))
                    }
                }
            }
        }
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            *self.retired.borrow_mut() = Some(Close::new(native.retire()));
        }
    }
}

fn filled(size: usize) -> Result<Vec<u8>, Cause> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size)?;
    bytes.resize(size, 0);
    Ok(bytes)
}
