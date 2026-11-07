//! Active CONFIG GET/POST over shared Configuration and one explicit file worker.
//! Admission, publication/sync receipt and visible configuration are distinct.
use crate::{
    Error, Response,
    output::{Json, decoded, parse},
};
use gnunet_client_host::LiveConfiguration;
use gnunet_config::Configuration;
use gnunet_types::Error as Fault;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    time::Instant,
};
use zeroize::Zeroizing;
pub mod worker;
use worker::{Committed, Exposure, Job, Worker};
/// Finite CONFIG representation/persistence resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum serialized complete INI output; existing cfg can impose less.
    pub image_bytes: usize,
    /// Maximum POST JSON body and parser quotas.
    pub json: gnunet_json::Limits,
    /// Maximum JSON GET result.
    pub output_bytes: usize,
    /// Maximum section/key pairs changed by one request.
    pub values: usize,
    /// Maximum concurrent admitted/waiting CONFIG request futures.
    pub requests: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            image_bytes: 4 * 1024 * 1024,
            json: Default::default(),
            output_bytes: 4 * 1024 * 1024,
            values: 4096,
            requests: 16,
        }
    }
}
struct State {
    clock: Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    live: LiveConfiguration,
    generation: AtomicU64,
    blocked: AtomicBool,
    closed: AtomicBool,
    admissions: Arc<Semaphore>,
    gate: Arc<Semaphore>,
    limits: Limits,
}
/// Original actual successful CONFIG commit. Its private worker receipt cannot
/// be constructed from a local enqueue, HTTP write or arbitrary generation.
pub struct Receipt {
    committed: Committed,
}
impl Receipt {
    /// Actual original native file job.
    pub fn job(&self) -> &Job {
        self.committed.job()
    }
    /// Actual generation after file+directory sync.
    pub const fn generation(&self) -> u64 {
        self.committed.generation()
    }
}
impl std::fmt::Debug for Receipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receipt")
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}
struct Admission {
    expected: u64,
    configuration: Option<Configuration>,
    image: Zeroizing<Vec<u8>>,
    reply: oneshot::Sender<Result<Receipt, Error>>,
    gate: OwnedSemaphorePermit,
    _request: OwnedSemaphorePermit,
    until: u64,
    hard: Instant,
}
struct Pending {
    job: Job,
    admission: Admission,
}
/// Cloneable explicit local request port. It creates no thread or file itself.
#[derive(Clone)]
pub struct Port {
    state: Arc<State>,
    sender: mpsc::Sender<Admission>,
}
impl Port {
    /// Exact original runtime clock selected for this explicit file worker.
    pub fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.state.clock.clone()
    }

    /// Actual currently visible shared configuration. This is a coherent snapshot,
    /// not a claim that pending writes committed or that file state is permanent.
    pub fn snapshot(&self) -> Result<Configuration, Error> {
        if self.state.blocked.load(Ordering::Acquire) {
            return Err(Error::ConfigurationUnknown);
        }
        if self.state.closed.load(Ordering::Acquire) {
            return Err(Fault::Closed.into());
        }
        Ok(self.state.live.snapshot()?)
    }
    /// Actual official GET shape: nested sections for /config, flat section object
    /// for `/config/<section>`, preserving shared configuration iteration semantics.
    pub fn get(&self, section: &[u8]) -> Result<Response, Error> {
        let configuration = self.snapshot()?;
        let mut json = Json::new(self.state.limits.output_bytes)?;
        json.raw(b"{")?;
        if section.is_empty() {
            let mut count = 0;
            for section in configuration.sections() {
                let mut values = section
                    .entries()
                    .iter()
                    .filter_map(|entry| entry.value().map(|value| (entry.key(), value)))
                    .peekable();
                if values.peek().is_none() {
                    continue;
                }
                if count != 0 {
                    json.raw(b",")?
                }
                json.string(section.name())?;
                json.raw(b":{")?;
                for (n, (key, value)) in values.enumerate() {
                    if n != 0 {
                        json.raw(b",")?
                    }
                    json.string(key)?;
                    json.raw(b":")?;
                    json.string(value)?;
                }
                json.raw(b"}")?;
                count += 1;
            }
        } else {
            for (n, (_, key, value)) in configuration.section_values(section).enumerate() {
                if n != 0 {
                    json.raw(b",")?
                }
                json.string(key)?;
                json.raw(b":")?;
                json.string(value)?;
            }
        }
        json.raw(b"}")?;
        Ok(Response::json(json.bytes))
    }
    /// Prepare a complete new configuration and actually admit one immutable file
    /// job. The original until/hard remain attached; phases never renew them.
    /// Dropping before channel admission writes nothing. Dropping after admission
    /// only suppresses this HTTP callback: Driver still consumes the original
    /// receipt, installs actual committed state or latches uncertainty, and releases
    /// the exact serialization permit. No write is replayed into another worker.
    pub async fn post(
        &self,
        section: &[u8],
        body: &[u8],
        until: u64,
        hard: Instant,
    ) -> Result<Receipt, Error> {
        if self.state.closed.load(Ordering::Acquire) {
            return Err(Fault::Closed.into());
        }
        let request = self
            .state
            .admissions
            .clone()
            .try_acquire_owned()
            .map_err(|_| Fault::Capacity)?;
        let gate = self
            .state
            .gate
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Fault::Closed)?;
        if self.state.blocked.load(Ordering::Acquire) {
            return Err(Error::ConfigurationUnknown);
        }
        if Instant::now() >= hard
            || self
                .state
                .clock
                .sample()
                .map_err(Error::Clock)?
                .now
                .as_micros()
                >= until
        {
            return Err(Error::Deadline);
        }
        let mut configuration = self.state.live.snapshot()?;
        let limits = self.state.limits;
        parse(body, limits.json, |root| {
            let mut count = 0usize;
            if section.is_empty() {
                for section in root.members()? {
                    let section_name = decoded(section.name)?;
                    for member in section.value.members()? {
                        apply(
                            &mut configuration,
                            &section_name,
                            member,
                            &mut count,
                            limits.values,
                        )?;
                    }
                }
            } else {
                for member in root.members()? {
                    apply(
                        &mut configuration,
                        section,
                        member,
                        &mut count,
                        limits.values,
                    )?;
                }
            }
            Ok(())
        })?;
        let image = Zeroizing::new(configuration.serialize().map_err(Error::Configuration)?);
        if image.len() > limits.image_bytes {
            return Err(Fault::Capacity.into());
        }
        let expected = self.state.generation.load(Ordering::Acquire);
        let (reply, receiver) = oneshot::channel();
        let admission = Admission {
            expected,
            configuration: Some(configuration),
            image,
            reply,
            gate,
            _request: request,
            until,
            hard,
        };
        self.sender
            .send(admission)
            .await
            .map_err(|_| Fault::Closed)?;
        receiver.await.map_err(|_| Error::ConfigurationUnknown)?
    }
}
fn apply(
    configuration: &mut Configuration,
    section: &[u8],
    member: gnunet_json::Member<'_>,
    count: &mut usize,
    maximum: usize,
) -> Result<(), Error> {
    *count = count.checked_add(1).ok_or(Fault::Overflow)?;
    if *count > maximum {
        return Err(Fault::Capacity.into());
    }
    let key = decoded(member.name)?;
    if section.is_empty()
        || section
            .iter()
            .any(|b| matches!(b, 0..=31 | 127 | b'[' | b']'))
        || key.is_empty()
        || key
            .iter()
            .any(|b| matches!(b, 0..=31 | 127 | b'=' | b'[' | b']'))
        || section.first().is_some_and(u8::is_ascii_whitespace)
        || section.last().is_some_and(u8::is_ascii_whitespace)
        || key.first().is_some_and(u8::is_ascii_whitespace)
        || key.last().is_some_and(u8::is_ascii_whitespace)
    {
        return Err(Fault::InvalidInput.into());
    }
    use gnunet_json::ValueKind;
    let value = match member.value.kind() {
        ValueKind::String => Some(decoded(member.value.string()?)?),
        ValueKind::Null => None,
        ValueKind::True => Some(crate::output::copy(b"yes")?),
        ValueKind::False => Some(crate::output::copy(b"no")?),
        ValueKind::Number => {
            let value = u64::try_from(member.value.integer()?).map_err(|_| Fault::InvalidInput)?;
            configuration
                .set_number(section, &key, value)
                .map_err(Error::Configuration)?;
            return Ok(());
        }
        _ => return Err(Fault::Malformed.into()),
    };
    configuration
        .set_value(section, &key, value.as_deref().map(Vec::as_slice))
        .map_err(Error::Configuration)?;
    Ok(())
}
/// Explicit worker owner. The foreground must poll this next to HTTP/Resolver,
/// and drain/join it during shutdown. It never stores an HTTP connection/future.
pub struct Driver {
    state: Arc<State>,
    receiver: mpsc::Receiver<Admission>,
    worker: Worker,
    pending: Option<Pending>,
    stopping: bool,
}
impl Driver {
    /// Explicit native target claim and sole thread creation. The provided live cfg
    /// is the caller's actual prepared configuration, not loaded from any key file.
    /// The path is an authorized user configuration output; no key/store discovery
    /// or old identity directory adoption occurs.
    pub fn start(
        live: LiveConfiguration,
        path: PathBuf,
        clock: Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
        limits: Limits,
    ) -> Result<(Port, Self), Error> {
        if limits.image_bytes == 0
            || limits.output_bytes == 0
            || limits.values == 0
            || limits.requests == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        let worker = Worker::start(path, limits.image_bytes, clock.clone())?;
        let state = Arc::new(State {
            clock,
            live,
            generation: AtomicU64::new(0),
            blocked: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            admissions: Arc::new(Semaphore::new(limits.requests)),
            gate: Arc::new(Semaphore::new(1)),
            limits,
        });
        let (sender, receiver) = mpsc::channel(1);
        Ok((
            Port {
                state: state.clone(),
                sender,
            },
            Self {
                state,
                receiver,
                worker,
                pending: None,
                stopping: false,
            },
        ))
    }
    /// Poll real admission/completion. Busy requests wait on the original actual
    /// semaphore and completion receiver; there is no permanent WouldBlock poll.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.pending.is_none() && !self.stopping {
            match self.receiver.poll_recv(cx) {
                Poll::Ready(Some(mut admission)) => {
                    if Instant::now() >= admission.hard {
                        let _delivery = admission.reply.send(Err(Error::Deadline));
                        return Poll::Ready(Ok(()));
                    }
                    if self.state.blocked.load(Ordering::Acquire) {
                        let _delivery = admission.reply.send(Err(Error::ConfigurationUnknown));
                        return Poll::Ready(Ok(()));
                    }
                    let image = std::mem::take(&mut admission.image);
                    let Some(configuration) = admission.configuration.take() else {
                        return Poll::Ready(Err(Fault::Conflict.into()));
                    };
                    match self.worker.submit(
                        admission.expected,
                        image,
                        configuration,
                        admission.until,
                        admission.hard,
                    ) {
                        Ok(job) => self.pending = Some(Pending { job, admission }),
                        Err(rejected) => {
                            let _delivery = admission.reply.send(Err(rejected.reason.into()));
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
                Poll::Ready(None) => self.stopping = true,
                Poll::Pending => {}
            }
        }
        match self.worker.poll(cx) {
            Poll::Ready(Some(completion)) => {
                let Some(pending) = self.pending.take() else {
                    self.state.blocked.store(true, Ordering::Release);
                    return Poll::Ready(Err(Error::ConfigurationUnknown));
                };
                if completion.job != pending.job {
                    self.state.blocked.store(true, Ordering::Release);
                    let _delivery = pending
                        .admission
                        .reply
                        .send(Err(Error::ConfigurationUnknown));
                    return Poll::Ready(Err(Error::ConfigurationUnknown));
                }
                let result = match completion.result {
                    Ok((committed, configuration)) => {
                        if committed.job() != &pending.job
                            || committed.generation()
                                != pending.admission.expected.saturating_add(1)
                        {
                            self.state.blocked.store(true, Ordering::Release);
                            Err(Error::ConfigurationUnknown)
                        } else {
                            match self.state.live.replace(configuration) {
                                Ok(()) => {
                                    self.state
                                        .generation
                                        .store(committed.generation(), Ordering::Release);
                                    Ok(Receipt { committed })
                                }
                                Err(error) => {
                                    self.state.blocked.store(true, Ordering::Release);
                                    Err(Error::Native(error))
                                }
                            }
                        }
                    }
                    Err(failure) => {
                        if failure.exposure == Exposure::Unknown {
                            self.state.blocked.store(true, Ordering::Release)
                        }
                        Err(Error::ConfigurationWrite(failure))
                    }
                };
                let uncertain = self.state.blocked.load(Ordering::Acquire);
                let (result, original) = match result {
                    Err(error) if uncertain => {
                        let error = Arc::new(error);
                        (Err(Error::ConfigurationFailure(error.clone())), Some(error))
                    }
                    other => (other, None),
                };
                let _delivery = pending.admission.reply.send(result);
                drop(pending.admission.gate);
                if uncertain {
                    self.request_stop();
                    return Poll::Ready(Err(original
                        .map(Error::ConfigurationFailure)
                        .unwrap_or(Error::ConfigurationUnknown)));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                if let Some(pending) = self.pending.take() {
                    self.state.blocked.store(true, Ordering::Release);
                    let _delivery = pending
                        .admission
                        .reply
                        .send(Err(Error::ConfigurationUnknown));
                    return Poll::Ready(Err(Error::ConfigurationUnknown));
                }
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    }
    /// Stop new file admissions; retained original jobs remain drainable. HTTP
    /// cancellation alone does not call this and cannot silently roll back a write.
    pub fn request_stop(&mut self) {
        self.stopping = true;
        self.state.closed.store(true, Ordering::Release);
        self.state.admissions.close();
        self.state.gate.close();
        self.receiver.close();
        while let Ok(admission) = self.receiver.try_recv() {
            let _delivery = admission.reply.send(Err(Fault::Closed.into()));
        }
        self.worker.request_stop();
    }
    /// Consume actual original completions until native thread/result termination,
    /// then physically join that same owner. OS filesystem progress is required;
    /// no synthetic timeout/cancel result proves an admitted rename did not happen.
    pub async fn shutdown(&mut self) -> Result<worker::Stopped, Error> {
        self.request_stop();
        let mut first = None;
        while self.pending.is_some() {
            if let Err(error) = std::future::poll_fn(|cx| self.poll(cx)).await
                && first.is_none()
            {
                first = Some(error)
            }
        }
        let stopped = std::future::poll_fn(|cx| self.worker.poll_join(cx)).await?;
        match first {
            Some(error) => Err(error),
            None => Ok(stopped),
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.state.closed.store(true, Ordering::Release);
        if self.pending.is_some() {
            self.state.blocked.store(true, Ordering::Release);
        }
        self.request_stop();
    }
}
