//! Only qualified Loaded/Job/Committed receipts affect durable metadata state.
use crate::{Core, Error, Fault, Learned, Uri, http::validate_uri};
use gnunet_snapshot_host::{
    backend::{Loaded, Namespace, Store},
    worker::{Job, Stopped, Worker},
};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"GNHLURL1";
const FIXED: usize = 2 + 8 + 4 + 8 + 8 + 4;
/// Actual persistence observations; no URL, authentication, or body is printed.
#[derive(Debug)]
pub enum DurableEvent {
    /// Actual qualified store load; no previous live source/provider is restored.
    Loaded {
        /// Original actual created-directory bit.
        created_directory: bool,
        /// Actual original Loaded generation, before any fresh initialization.
        generation: u64,
        /// Actual same-lease initial commit, absent for an existing canonical image.
        initialized_generation: Option<u64>,
        /// Safely cleaned owned temporary count.
        recovered_temporaries: usize,
    },
    /// Actual worker queue admission, not committed metadata.
    Queued {
        /// Private original worker job.
        job: Job,
        /// Snapshot business revision frozen at actual admission.
        revision: u64,
    },
    /// Actual original file+directory commit/readback receipt.
    Committed {
        /// Original job, never matched by bare generation.
        job: Job,
        /// Actual durable generation.
        generation: u64,
        /// Original submitted metadata revision.
        revision: u64,
    },
    /// Actual first persistence failure with known/unknown exposure and cleanup.
    Failed(Arc<gnunet_snapshot_host::backend::Failure>),
    /// Real owned worker joined; no socket deadline is called filesystem cancel.
    Joined(Stopped),
}
struct Pending {
    job: Job,
    revision: u64,
    expected: u64,
}
/// Exactly one explicit shared snapshot worker and one original pending job.
pub struct Durable {
    worker: Worker,
    generation: u64,
    loaded_generation: u64,
    initialized_generation: Option<u64>,
    saved: u64,
    pending: Option<Pending>,
    blocked: bool,
    created: bool,
    recovered: usize,
    load_reported: bool,
    body_bytes: usize,
    entries: usize,
}
fn read<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
    if input.len() < n {
        return Err(Fault::Truncated.into());
    }
    let (value, rest) = input.split_at(n);
    *input = rest;
    Ok(value)
}
fn u16be(input: &mut &[u8]) -> Result<u16, Error> {
    let b = read(input, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
fn u32be(input: &mut &[u8]) -> Result<u32, Error> {
    let b = read(input, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64be(input: &mut &[u8]) -> Result<u64, Error> {
    let b = read(input, 8)?;
    let mut raw = [0; 8];
    raw.copy_from_slice(b);
    Ok(u64::from_be_bytes(raw))
}
impl Durable {
    /// Consume the actual original Store/Loaded pair before starting its worker.
    /// Fresh initialization commits under that same writer lease without an await;
    /// existing missing history is refused. No C file or key is imported.
    pub fn recover(
        mut store: Store,
        loaded: Loaded,
        core: &mut Core,
        body_bytes: usize,
        entries: usize,
    ) -> Result<Self, Error> {
        if store.namespace() != Namespace::Hostlist
            || loaded.namespace() != Namespace::Hostlist
            || store.generation() != loaded.generation()
            || body_bytes == 0
            || entries == 0
        {
            return Err(Fault::Authentication.into());
        }
        let loaded_generation = loaded.generation();
        let mut generation = loaded_generation;
        let created = loaded.created_directory();
        let recovered = loaded.recovered_temporaries();
        let body = loaded.into_body();
        if generation == 0 && !created {
            return Err(Fault::OutcomeUnknown.into());
        }
        if (generation == 0) != body.is_empty() {
            return Err(Fault::Malformed.into());
        }
        if body.len() > body_bytes {
            return Err(Fault::Capacity.into());
        }
        if !body.is_empty() {
            let mut input = body.as_slice();
            if read(&mut input, 8)? != MAGIC {
                return Err(Fault::Malformed.into());
            }
            let count = usize::try_from(u32be(&mut input)?).map_err(|_| Fault::Overflow)?;
            let delay = u64be(&mut input)?;
            if count > entries {
                return Err(Fault::Capacity.into());
            }
            core.restore_retry_delay(delay)?;
            for _ in 0..count {
                let length = usize::from(u16be(&mut input)?);
                let quality = u64be(&mut input)?;
                let times_used = u32be(&mut input)?;
                let created = u64be(&mut input)?;
                let last_used = u64be(&mut input)?;
                let hello_count = u32be(&mut input)?;
                let bytes = read(&mut input, length)?;
                let parsed = validate_uri(bytes)?;
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    return Err(Fault::Authentication.into());
                }
                let uri = Uri::copy_from(bytes)?;
                core.restore(Learned {
                    uri,
                    quality,
                    times_used,
                    created,
                    last_used,
                    hello_count,
                })?;
            }
            if !input.is_empty() {
                return Err(Fault::Malformed.into());
            }
        } else if generation != 0 {
            return Err(Fault::Malformed.into());
        }
        drop(body);
        let initialized_generation = if generation == 0 {
            // Prepare the actual legal business snapshot before a worker exists.
            // No await/cancellation split can orphan a normal first-open stop.
            let body = Self::encode_core(core, body_bytes, entries)?;
            let committed = store.commit(0, body).map_err(Error::Store)?;
            if committed.namespace() != Namespace::Hostlist
                || committed.generation() != 1
                || store.generation() != 1
            {
                return Err(Fault::OutcomeUnknown.into());
            }
            generation = committed.generation();
            Some(generation)
        } else {
            None
        };
        let worker = Worker::start(store)?;
        Ok(Self {
            worker,
            generation,
            loaded_generation,
            initialized_generation,
            saved: core.learned_revision(),
            pending: None,
            blocked: false,
            created,
            recovered,
            load_reported: false,
            body_bytes,
            entries,
        })
    }
    /// Emit actual recovery metadata once, after the real qualified open.
    pub fn report_load(&mut self, observe: &mut impl FnMut(DurableEvent)) {
        if !self.load_reported {
            self.load_reported = true;
            observe(DurableEvent::Loaded {
                created_directory: self.created,
                generation: self.loaded_generation,
                initialized_generation: self.initialized_generation,
                recovered_temporaries: self.recovered,
            })
        }
    }
    fn encode_core(
        core: &Core,
        body_bytes: usize,
        entries: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut length = 20usize;
        let mut count = 0usize;
        for row in core.learned() {
            let parsed = validate_uri(row.uri.bytes())?;
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(Fault::Authentication.into());
            }
            count += 1;
            if count > entries {
                return Err(Fault::Capacity.into());
            }
            length = length
                .checked_add(FIXED)
                .and_then(|n| n.checked_add(row.uri.bytes().len()))
                .ok_or(Fault::Overflow)?;
        }
        if length > body_bytes {
            return Err(Fault::Capacity.into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Fault::Capacity)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(
            &u32::try_from(count)
                .map_err(|_| Fault::Overflow)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&core.retry_delay().to_be_bytes());
        for row in core.learned() {
            bytes.extend_from_slice(
                &u16::try_from(row.uri.bytes().len())
                    .map_err(|_| Fault::Capacity)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&row.quality.to_be_bytes());
            bytes.extend_from_slice(&row.times_used.to_be_bytes());
            bytes.extend_from_slice(&row.created.to_be_bytes());
            bytes.extend_from_slice(&row.last_used.to_be_bytes());
            bytes.extend_from_slice(&row.hello_count.to_be_bytes());
            bytes.extend_from_slice(row.uri.bytes());
        }
        Ok(bytes)
    }
    /// Actual admitted original job only. Temporary capacity refusal leaves the
    /// current metadata dirty; it does not mint a durable receipt or drop a job.
    pub fn save(
        &mut self,
        core: &Core,
        force: bool,
        observe: &mut impl FnMut(DurableEvent),
    ) -> Result<bool, Error> {
        if self.blocked || self.pending.is_some() || !self.worker.available() {
            return Ok(false);
        }
        if !force && self.saved == core.learned_revision() && self.generation != 0 {
            return Ok(false);
        }
        let body = Self::encode_core(core, self.body_bytes, self.entries)?;
        let expected = self.generation;
        let revision = core.learned_revision();
        let job = match self.worker.submit(expected, body) {
            Ok(job) => job,
            Err((Fault::WouldBlock, _body)) => return Ok(false),
            Err((error, _body)) => return Err(error.into()),
        };
        if job.namespace() != Namespace::Hostlist {
            self.worker.request_stop();
            self.blocked = true;
            return Err(Fault::Authentication.into());
        }
        self.pending = Some(Pending {
            job: job.clone(),
            revision,
            expected,
        });
        observe(DurableEvent::Queued { job, revision });
        Ok(true)
    }
    /// Consume only the original private worker completion.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(DurableEvent),
    ) -> Poll<Result<bool, Error>> {
        let completion = match self.worker.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.blocked = true;
                return Poll::Ready(Err(error.into()));
            }
            Poll::Ready(Ok(None)) => return Poll::Ready(Ok(false)),
            Poll::Ready(Ok(Some(completion))) => completion,
        };
        let Some(pending) = self.pending.take() else {
            return Poll::Ready(Err(Fault::Stale.into()));
        };
        let (job, result) = completion.into_parts();
        if job != pending.job || job.namespace() != Namespace::Hostlist {
            self.blocked = true;
            self.worker.request_stop();
            return Poll::Ready(Err(Fault::Stale.into()));
        }
        match result {
            Ok(committed) => {
                if committed.namespace() != Namespace::Hostlist
                    || committed.generation()
                        != pending.expected.checked_add(1).ok_or(Fault::Overflow)?
                {
                    self.blocked = true;
                    self.worker.request_stop();
                    return Poll::Ready(Err(Fault::Stale.into()));
                }
                self.generation = committed.generation();
                self.saved = pending.revision;
                observe(DurableEvent::Committed {
                    job,
                    generation: self.generation,
                    revision: pending.revision,
                });
                Poll::Ready(Ok(true))
            }
            Err(failure) => {
                self.blocked = true;
                self.worker.request_stop();
                observe(DurableEvent::Failed(failure.clone()));
                Poll::Ready(Err(Error::Store(failure)))
            }
        }
    }
    /// Stop admission only; it never claims cancellation of an admitted fsync.
    pub fn request_stop(&mut self) {
        self.worker.request_stop()
    }
    /// Finish original pending IO, optionally persist the final current metadata,
    /// then join the one actual worker. Network owners must already be stopped.
    pub async fn shutdown(
        &mut self,
        core: &Core,
        mut observe: impl FnMut(DurableEvent),
    ) -> Result<(), Error> {
        let mut first = None;
        if self.pending.is_some()
            && let Err(error) = std::future::poll_fn(|cx| self.poll(cx, &mut observe)).await
        {
            first = Some(error)
        }
        if !self.blocked {
            match self.save(core, true, &mut observe) {
                Ok(true) => {
                    if let Err(error) = std::future::poll_fn(|cx| self.poll(cx, &mut observe)).await
                        && first.is_none()
                    {
                        first = Some(error)
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    if first.is_none() {
                        first = Some(error)
                    }
                }
            }
        }
        let mut unmatched = false;
        let stopped = self.worker.shutdown(|_completion| unmatched = true).await;
        if unmatched && first.is_none() {
            first = Some(Fault::Stale.into())
        }
        match stopped {
            Ok(stopped) => {
                if stopped.namespace != Namespace::Hostlist && first.is_none() {
                    first = Some(Fault::Authentication.into())
                }
                if let Some(failure) = &stopped.failure
                    && first.is_none()
                {
                    first = Some(Error::Store(failure.clone()))
                }
                observe(DurableEvent::Joined(stopped));
            }
            Err(error) => {
                if first.is_none() {
                    first = Some(error.into())
                }
            }
        }
        first.map_or(Ok(()), Err)
    }
}
