//! Caller-owned actual GNUnet DID operations over original IDENTITY, NAMESTORE
//! and the existing GNS native query client. No resolver/service/task is created.
#![forbid(unsafe_code)]
#![cfg(unix)]
pub use gnunet_client_host::EndpointSource;
use gnunet_crypto::Entropy;
pub use gnunet_did as did;
pub use gnunet_gns_client_host as gns;
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType, ZoneKey};
pub use gnunet_identity_client_host as identity;
pub use gnunet_namestore_client_host as ns;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use gnunet_wire::official::namestore as wire;
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
use zeroize::Zeroizing;
mod identity_io;
mod records_io;
mod types;
pub use types::*;
type Result<T> = std::result::Result<T, Error>;
impl Sources {
    fn frozen(&self) -> Result<Self> {
        let first = self
            .identity
            .as_ref()
            .or(self.namestore.as_ref())
            .or(self.gns.as_ref())
            .ok_or(Fault::Unavailable)?;
        let [identity, namestore, gns] = EndpointSource::snapshot_all([
            self.identity.as_ref().unwrap_or(first),
            self.namestore.as_ref().unwrap_or(first),
            self.gns.as_ref().unwrap_or(first),
        ])?;
        Ok(Self {
            clock: self.clock.clone(),
            identity: self.identity.as_ref().map(|_| identity),
            namestore: self.namestore.as_ref().map(|_| namestore),
            gns: self.gns.as_ref().map(|_| gns),
        })
    }
}
/// One bounded high-level caller owner. Actual SDK owners exist only during the
/// original async operation and physically close on every return/future Drop.
/// Stable caller allocation domains prevent old tokens being rebound on reuse.
pub struct Client<'i, 'n, 'g> {
    instances: Instances<'i, 'n, 'g>,
    sources: Sources,
    limits: Limits,
    clock: Arc<dyn RuntimeClock>,
}
impl<'i, 'n, 'g> Client<'i, 'n, 'g> {
    /// Bind explicit dependencies and exact shared clock; opens no socket/key.
    pub fn new(instances: Instances<'i, 'n, 'g>, sources: Sources, limits: Limits) -> Result<Self> {
        let clock = sources.clock.clone();
        if [&sources.identity, &sources.namestore, &sources.gns]
            .into_iter()
            .flatten()
            .any(|source| !Arc::ptr_eq(&clock, &source.clock()))
        {
            return Err(Fault::Conflict.into());
        }
        if limits.document_bytes == 0
            || limits.document_bytes > 48 * 1024
            || limits.records == 0
            || limits.records > 4096
            || limits.egos == 0
            || limits.egos > 4096
            || limits.json.bytes < limits.document_bytes
            || limits.json.bytes > 65535
            || limits.json.nodes == 0
            || limits.json.nodes > 16384
            || limits.json.depth == 0
            || limits.json.depth > 64
            || limits.json.work == 0
            || limits.json.work > 64_000_000
            || limits.io_slice_bytes == 0
            || limits.io_slice_bytes > 65535
            || limits.retirement_grace.is_zero()
            || Instant::now()
                .checked_add(limits.retirement_grace)
                .is_none()
        {
            return Err(Fault::InvalidInput.into());
        }
        Ok(Self {
            instances,
            sources,
            limits,
            clock,
        })
    }
    /// The exact original source clock, without a listener/Resolver side effect.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Construct one fixed finite budget spanning all phases of an operation.
    pub fn deadline(&self, lifetime: Duration) -> Result<Deadline> {
        let micros = u64::try_from(lifetime.as_micros()).map_err(|_| Fault::Overflow)?;
        let now = self.clock.sample()?.now.as_micros();
        if micros == 0 || lifetime.is_zero() {
            return Err(Fault::Deadline.into());
        }
        let until = now
            .checked_add(micros)
            .filter(|v| *v != u64::MAX)
            .ok_or(Fault::Overflow)?;
        let hard = Instant::now()
            .checked_add(lifetime)
            .ok_or(Fault::Overflow)?;
        hard.checked_add(self.limits.retirement_grace)
            .ok_or(Fault::Overflow)?;
        Ok(Deadline {
            clock: self.clock.clone(),
            until,
            hard,
            observed: std::cell::Cell::new(now),
        })
    }
    fn check(&self, deadline: &Deadline) -> Result<()> {
        if !Arc::ptr_eq(&self.clock, &deadline.clock) {
            return Err(Fault::Conflict.into());
        }
        check_deadline(deadline)
    }
    fn snapshot_operation(&mut self) -> Result<Client<'_, '_, '_>> {
        let sources = self.sources.frozen()?;
        let limits = self.limits;
        Client::new(
            Instances {
                identity: self.instances.identity,
                namestore: self.instances.namestore,
                gns: &mut *self.instances.gns,
            },
            sources,
            limits,
        )
    }
    /// Show the exact public DID for one real original ego; no synthetic key.
    pub async fn show(
        &mut self,
        name: &[u8],
        deadline: &Deadline,
        mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
        mut observe: impl FnMut(Event),
    ) -> Result<did::Did> {
        self.check(deadline)?;
        let mut operation = self.snapshot_operation()?;
        operation.check(deadline)?;
        let key = operation
            .key(name, deadline, cancel.as_mut(), &mut observe)
            .await?
            .ok_or(Fault::NotFound)?;
        public(&key)
    }
    /// Read the real bounded initial IDENTITY snapshot through its actual END.
    /// It does not claim that every ego already has a published DID document.
    pub async fn show_all(
        &mut self,
        deadline: &Deadline,
        cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
        mut observe: impl FnMut(Event),
    ) -> Result<Vec<NamedDid>> {
        self.check(deadline)?;
        let mut operation = self.snapshot_operation()?;
        operation.check(deadline)?;
        operation.directory(deadline, cancel, &mut observe).await
    }
    /// Create/replace the canonical-label official record. Missing ego creation
    /// uses the explicit entropy provider, and waits for the original real
    /// IDENTITY result. No OS RNG/key file is selected by this library.
    pub async fn publish(
        &mut self,
        request: Publish<'_>,
        entropy: &mut impl Entropy,
        deadline: &Deadline,
        mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
        mut observe: impl FnMut(Event),
    ) -> Result<did::Did> {
        self.check(deadline)?;
        let mut operation = self.snapshot_operation()?;
        operation.check(deadline)?;
        operation
            .sources
            .namestore
            .as_ref()
            .ok_or(Fault::Unavailable)?;
        if request
            .document
            .is_some_and(|d| d.len() > operation.limits.document_bytes)
            || request.mode == PublishMode::Replace && request.create_ego
        {
            return Err(Fault::InvalidInput.into());
        }
        let key = match operation
            .key(request.ego, deadline, cancel.as_mut(), &mut observe)
            .await?
        {
            Some(key) => key,
            None if request.mode == PublishMode::Create
                && request.create_ego
                && request.document.is_none() =>
            {
                operation
                    .create_key(
                        request.ego,
                        entropy,
                        deadline,
                        cancel.as_mut(),
                        &mut observe,
                    )
                    .await?
            }
            None => return Err(Fault::NotFound.into()),
        };
        if key.key_type() != identity::KeyType::Eddsa {
            return Err(Fault::Unsupported.into());
        }
        let did = public(&key)?;
        let mut body = Zeroizing::new(Vec::new());
        if let Some(raw) = request.document {
            body.try_reserve_exact(raw.len())
                .map_err(|_| Fault::Capacity)?;
            body.extend_from_slice(raw);
        } else {
            body.try_reserve_exact(did::TEMPLATE_BYTES)
                .map_err(|_| Fault::Capacity)?;
            body.resize(did::TEMPLATE_BYTES, 0);
            did::template(did, &mut body)?;
        }
        let mut scratch = Scratch::new(operation.limits)?;
        did::check_document(did, &body, &mut scratch.workspace(), operation.limits.json)?;
        operation
            .mutate(
                &key,
                Mutation {
                    did,
                    body: Some(&body),
                    expiration: request.expiration_micros,
                    mode: if request.mode == PublishMode::Create {
                        Mode::Create
                    } else {
                        Mode::Replace
                    },
                },
                deadline,
                cancel.as_mut(),
                &mut observe,
            )
            .await?;
        Ok(did)
    }
    /// Remove only bound DID records at `didd`, retaining unrelated records and
    /// the IDENTITY ego. It never clears `@` or claims GNS caches were flushed.
    pub async fn remove(
        &mut self,
        name: &[u8],
        deadline: &Deadline,
        mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
        mut observe: impl FnMut(Event),
    ) -> Result<did::Did> {
        self.check(deadline)?;
        let mut operation = self.snapshot_operation()?;
        operation.check(deadline)?;
        operation
            .sources
            .namestore
            .as_ref()
            .ok_or(Fault::Unavailable)?;
        let key = operation
            .key(name, deadline, cancel.as_mut(), &mut observe)
            .await?
            .ok_or(Fault::NotFound)?;
        let did = public(&key)?;
        operation
            .mutate(
                &key,
                Mutation {
                    did,
                    body: None,
                    expiration: 0,
                    mode: Mode::Remove,
                },
                deadline,
                cancel.as_mut(),
                &mut observe,
            )
            .await?;
        Ok(did)
    }
    /// One real original ANY lookup at canonical `didd`, selecting authoritative
    /// DID_DOCUMENT first and only a matching validated current-C TXT fallback.
    /// The selected GNS service supplies authentication; this is no resolver.
    pub async fn resolve(
        &mut self,
        did: did::Did,
        deadline: &Deadline,
        cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
        mut observe: impl FnMut(Event),
    ) -> Result<Resolved> {
        self.check(deadline)?;
        let mut operation = self.snapshot_operation()?;
        operation.check(deadline)?;
        operation.query(did, deadline, cancel, &mut observe).await
    }
}
fn public(key: &identity::SecretKey) -> Result<did::Did> {
    Ok(did::Did::from_public(ZoneKey::from_wire(
        &key.public_key()?,
    )?))
}
struct Scratch {
    payload: Zeroizing<Vec<u8>>,
    tokens: Zeroizing<Vec<gnunet_json::Token>>,
    stack: Zeroizing<Vec<gnunet_json::Nest>>,
}
impl Scratch {
    fn new(limits: Limits) -> Result<Self> {
        let mut payload = Zeroizing::new(Vec::new());
        payload
            .try_reserve_exact(limits.json.bytes)
            .map_err(|_| Fault::Capacity)?;
        payload.resize(limits.json.bytes, 0);
        let mut tokens = Zeroizing::new(Vec::new());
        tokens
            .try_reserve_exact(limits.json.nodes)
            .map_err(|_| Fault::Capacity)?;
        tokens.resize(limits.json.nodes, gnunet_json::Token::EMPTY);
        let mut stack = Zeroizing::new(Vec::new());
        stack
            .try_reserve_exact(limits.json.depth)
            .map_err(|_| Fault::Capacity)?;
        stack.resize(limits.json.depth, gnunet_json::Nest::EMPTY);
        Ok(Self {
            payload,
            tokens,
            stack,
        })
    }
    fn workspace(&mut self) -> gnunet_json::Workspace<'_> {
        gnunet_json::Workspace::new(&mut self.payload, &mut self.tokens, &mut self.stack)
    }
}
async fn step<T>(
    future: impl Future<Output = std::result::Result<T, gnunet_client_host::ConnectError>>,
    deadline: &Deadline,
    mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> Result<T> {
    check_deadline(deadline)?;
    let mut future = std::pin::pin!(future);
    let mut hard = std::pin::pin!(tokio::time::sleep_until(deadline.hard));
    poll_fn(|cx| {
        // Register and enforce the original native target before a dependency
        // can remain Pending on canonical-clock stabilization. Recreating this
        // wait for another observation never grants a later target.
        if hard.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        if let Err(error) = check_deadline(deadline) {
            return Poll::Ready(Err(error));
        }
        if let Poll::Ready(signal) = cancel.as_mut().poll(cx) {
            return Poll::Ready(match signal {
                Ok(()) => Err(Fault::Cancelled.into()),
                Err(e) => Err(Error::Signal(e)),
            });
        }
        future.as_mut().poll(cx).map(|r| r.map_err(Error::from))
    })
    .await
}
// Cleanup has a separate original native grace target. It must remain able to
// finish while the shared canonical clock or Resolver refuses to stabilize.
async fn native_step<T>(future: impl Future<Output = T>, until: Instant) -> Option<T> {
    let mut future = std::pin::pin!(future);
    let mut hard = std::pin::pin!(tokio::time::sleep_until(until));
    poll_fn(|cx| {
        if hard.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        future.as_mut().poll(cx).map(Some)
    })
    .await
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Create,
    Replace,
    Remove,
}
struct Mutation<'a> {
    did: did::Did,
    body: Option<&'a [u8]>,
    expiration: u64,
    mode: Mode,
}

async fn checkpoint(
    deadline: &Deadline,
    mut cancel: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> Result<()> {
    check_deadline(deadline)?;
    poll_fn(|cx| {
        Poll::Ready(match cancel.as_mut().poll(cx) {
            Poll::Pending => Ok(()),
            Poll::Ready(Ok(())) => Err(Fault::Cancelled.into()),
            Poll::Ready(Err(e)) => Err(Error::Signal(e)),
        })
    })
    .await
}

fn check_deadline(deadline: &Deadline) -> Result<()> {
    let now = deadline.clock.sample()?.now.as_micros();
    if now < deadline.observed.get() {
        return Err(Fault::TimeUncertain.into());
    }
    deadline.observed.set(now);
    if Instant::now() >= deadline.hard || now >= deadline.until {
        return Err(Fault::Deadline.into());
    }
    Ok(())
}
