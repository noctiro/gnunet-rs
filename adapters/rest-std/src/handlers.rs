use crate::{
    Error,
    output::{bytes, copy},
};
use gnunet_rest::route::{Endpoint, Route};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
use zeroize::Zeroizing;
const COPYING:&[u8]=b"GNU Affero General Public License version 3 or later. See also: <http://www.gnu.org/licenses/>";
/// All caller-owned stable native token domains. No hidden global domain exists.
#[derive(Clone, Copy)]
pub struct Instances<'a> {
    /// IDENTITY original allocations.
    pub identity: &'a gnunet_identity_client_host::Instance,
    /// NAMESTORE original allocations.
    pub namestore: &'a gnunet_namestore_client_host::Instance,
    /// RECLAIM original allocations.
    pub reclaim: &'a gnunet_reclaim_client_host::Instance,
}
/// Explicit endpoint sources. Duplicating selection authority does not replay a job.
pub struct Sources {
    /// IDENTITY source used for each actual directory initialization.
    pub identity: gnunet_client_host::EndpointSource,
    /// NAMESTORE operation/iterator source.
    pub namestore: gnunet_client_host::EndpointSource,
    /// RECLAIM operation/iterator source.
    pub reclaim: gnunet_client_host::EndpointSource,
}
/// Finite per-request retained storage and original wait lifetime.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original total handler lifetime; no phase resets this deadline.
    pub lifetime: Duration,
    /// Maximum body/JSON value/native frame storage.
    pub bytes: usize,
    /// Maximum complete output body.
    pub output_bytes: usize,
    /// Maximum complete record text result/scratch, independent of native frame.
    pub text_bytes: usize,
    /// Maximum returned list items or input records.
    pub items: usize,
    /// Complete JSON parser budgets.
    pub json: gnunet_json::Limits,
    /// Actual native IDENTITY resource limits.
    pub identity: gnunet_identity_client_host::Limits,
    /// Actual native NAMESTORE resource limits.
    pub namestore: gnunet_namestore_client_host::Limits,
    /// Actual native RECLAIM resource limits.
    pub reclaim: gnunet_reclaim_client_host::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            lifetime: Duration::from_secs(30),
            bytes: 65535,
            output_bytes: 262144,
            text_bytes: 262140,
            items: 1024,
            json: gnunet_json::Limits::default(),
            identity: Default::default(),
            namestore: Default::default(),
            reclaim: Default::default(),
        }
    }
}
/// Bounded owned original request. Debug does not expose names/query/capabilities.
pub struct OwnedRequest {
    pub(crate) endpoint: Endpoint,
    pub(crate) suffix: Zeroizing<Vec<u8>>,
    pub(crate) query: Zeroizing<Vec<u8>>,
    pub(crate) body: Zeroizing<Vec<u8>>,
    pub(crate) content_type: Option<Zeroizing<Vec<u8>>>,
    pub(crate) authorization: Option<Zeroizing<Vec<u8>>>,
    pub(crate) cookie: Option<Zeroizing<Vec<u8>>>,
}
impl OwnedRequest {
    /// Copy a complete original route and decoded HTTP body once. This performs no
    /// client admission, key generation, resolution or native I/O.
    pub fn new(route: Route<'_>, body: &[u8], limit: usize) -> Result<Self, Error> {
        let total = route
            .suffix()
            .len()
            .checked_add(route.query().expose_raw().len())
            .and_then(|n| n.checked_add(body.len()))
            .ok_or(Fault::Overflow)?;
        if total > limit {
            return Err(Fault::TooLarge.into());
        }
        Ok(Self {
            endpoint: route.endpoint(),
            suffix: copy(route.suffix())?,
            query: copy(route.query().expose_raw())?,
            body: copy(body)?,
            content_type: None,
            authorization: None,
            cookie: None,
        })
    }
    /// Preserve only the selected original HTTP fields required by actual form,
    /// OAuth and cookie contracts. Duplicates are rejected before native admission.
    pub fn with_headers(
        mut self,
        request: &gnunet_rest::http::Request<'_>,
        limit: usize,
    ) -> Result<Self, Error> {
        let mut used = self
            .suffix
            .len()
            .checked_add(self.query.len())
            .and_then(|n| n.checked_add(self.body.len()))
            .ok_or(Fault::Overflow)?;
        for h in request.headers() {
            let h = h?;
            let target = if h.name.eq_ignore_ascii_case(b"content-type") {
                &mut self.content_type
            } else if h.name.eq_ignore_ascii_case(b"authorization") {
                &mut self.authorization
            } else if h.name.eq_ignore_ascii_case(b"cookie") {
                &mut self.cookie
            } else {
                continue;
            };
            if target.is_some() {
                return Err(Fault::Conflict.into());
            }
            used = used.checked_add(h.value.len()).ok_or(Fault::Overflow)?;
            if used > limit {
                return Err(Fault::Capacity.into());
            }
            *target = Some(copy(h.value)?);
        }
        Ok(self)
    }
    #[cfg(feature = "oidc")]
    pub(crate) fn parameter(
        &self,
        key: &[u8],
        cap: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let query = self.query(key, cap)?;
        if self.body.is_empty() {
            return Ok(query);
        }
        let Some(kind) = &self.content_type else {
            return Err(Fault::Malformed.into());
        };
        let form = gnunet_rest::form::Form::new(
            kind,
            &self.body,
            gnunet_rest::form::Limits {
                bytes: cap,
                value_bytes: cap,
                ..Default::default()
            },
        )?;
        let mut name = bytes(cap)?;
        let mut output = bytes(cap)?;
        let body = form.get(key, &mut name, &mut output)?;
        if body.is_some() && query.is_some() {
            return Err(Fault::Conflict.into());
        }
        Ok(match body {
            Some(n) => {
                output.truncate(n);
                Some(output)
            }
            None => query,
        })
    }
    /// Actual recognized endpoint, without secret contents.
    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }
    pub(crate) fn query_bytes(
        &self,
        key: &[u8],
        cap: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let mut name = bytes(cap)?;
        let mut value = bytes(cap)?;
        let found =
            gnunet_rest::route::Query::new(&self.query).get_bytes(key, &mut name, &mut value)?;
        Ok(found.map(|n| {
            value.truncate(n);
            value
        }))
    }
    pub(crate) fn query(
        &self,
        key: &[u8],
        cap: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let mut name = bytes(cap)?;
        let mut value = bytes(cap)?;
        let found = gnunet_rest::route::Query::new(&self.query).get(key, &mut name, &mut value)?;
        Ok(found.map(|n| {
            value.truncate(n);
            value
        }))
    }
}
impl std::fmt::Debug for OwnedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedRequest")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}
/// Actual handler result. Private JSON is erased on Drop; HTTP writing remains
/// a separate physical operation and cannot turn local admission into success.
pub struct Response {
    /// Actual official HTTP status selected from service result or static content.
    pub status: u16,
    /// Complete bounded response body, explicitly exposed to the HTTP writer.
    pub body: Zeroizing<Vec<u8>>,
    /// Actual representation MIME type.
    pub content_type: &'static [u8],
    /// Bounded original response fields (cookie/location/cache directives).
    pub headers: Vec<ResponseHeader>,
    /// Actual raw RECLAIM status when supplied; never silently byte-normalized.
    pub service_status: Option<i64>,
}
/// Owned private field value; Debug never exposes cookie/capability contents.
pub struct ResponseHeader {
    pub(crate) name: &'static [u8],
    pub(crate) value: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for ResponseHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseHeader")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}
impl Response {
    pub(crate) fn header(mut self, name: &'static [u8], value: &[u8]) -> Result<Self, Error> {
        if self.headers.len() >= 8
            || value.len() > 65535
            || value.iter().any(|b| matches!(b, 0..=31 | 127))
        {
            return Err(Fault::InvalidInput.into());
        }
        self.headers
            .try_reserve_exact(1)
            .map_err(|_| Fault::Capacity)?;
        self.headers.push(ResponseHeader {
            name,
            value: copy(value)?,
        });
        Ok(self)
    }
    pub(crate) fn empty(status: u16) -> Self {
        Self {
            status,
            body: Zeroizing::new(Vec::new()),
            content_type: b"application/json",
            service_status: None,
            headers: Vec::new(),
        }
    }
    pub(crate) fn json(body: Zeroizing<Vec<u8>>) -> Self {
        Self {
            status: 200,
            body,
            content_type: b"application/json",
            service_status: None,
            headers: Vec::new(),
        }
    }
}
impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}
/// Shared explicit authority. Each consuming execute future owns all of its MQs;
/// cancel/drop closes those originals, including during partial frame writes.
pub struct Context<'a, I: gnunet_dns::Idna> {
    #[cfg(feature = "oidc")]
    pub(crate) oidc_port: Option<&'a crate::oidc::Provider>,
    pub(crate) configuration: Option<&'a crate::config::Port>,
    pub(crate) gns_port: Option<&'a crate::gns::Gns>,
    pub(crate) instances: Instances<'a>,
    pub(crate) sources: Sources,
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) idna: &'a I,
    pub(crate) profile: gnunet_gnsrecord_text::Profile,
    pub(crate) consume_profile: crate::ConsumeProfile,
    pub(crate) limits: Limits,
}
impl<'a, I: gnunet_dns::Idna> Context<'a, I> {
    /// Bind existing caller sources and IDNA backend. All sources must use exactly
    /// the same actual clock Arc. No socket, resolver, task or key is created.
    pub fn new(
        instances: Instances<'a>,
        sources: Sources,
        idna: &'a I,
        profile: gnunet_gnsrecord_text::Profile,
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.lifetime.is_zero()
            || limits.bytes == 0
            || limits.output_bytes == 0
            || limits.items == 0
            || limits.text_bytes == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        profile.validate()?;
        let clock = sources.identity.clock();
        if !Arc::ptr_eq(&clock, &sources.namestore.clock())
            || !Arc::ptr_eq(&clock, &sources.reclaim.clock())
        {
            return Err(Fault::Conflict.into());
        }
        Ok(Self {
            #[cfg(feature = "oidc")]
            oidc_port: None,
            configuration: None,
            gns_port: None,
            instances,
            sources,
            clock,
            idna,
            profile,
            consume_profile: crate::ConsumeProfile::Canonical,
            limits,
        })
    }
    /// Select the actual RECLAIM backend's result-word producer once for both
    /// ordinary REST consumption and OpenID UserInfo. No word is auto-detected.
    pub fn with_consume_profile(mut self, profile: crate::ConsumeProfile) -> Self {
        self.consume_profile = profile;
        self
    }
    /// Attach a real explicit owned OIDC signer/cache provider. No fallback or
    /// implicit key import/generation is performed by Context.
    #[cfg(feature = "oidc")]
    pub fn with_oidc(mut self, provider: &'a crate::oidc::Provider) -> Result<Self, Error> {
        if !Arc::ptr_eq(&self.clock, &provider.clock()) {
            return Err(Fault::Conflict.into());
        }
        self.oidc_port = Some(provider);
        Ok(self)
    }
    /// Attach the explicit CONFIG worker port, whose Driver the caller must poll.
    pub fn with_configuration(mut self, port: &'a crate::config::Port) -> Result<Self, Error> {
        if !Arc::ptr_eq(&self.clock, &port.clock()) {
            return Err(Fault::Conflict.into());
        }
        self.configuration = Some(port);
        Ok(self)
    }
    /// Attach an existing query client endpoint, never a resolver/service backend.
    pub fn with_gns(mut self, port: &'a crate::gns::Gns) -> Result<Self, Error> {
        if !Arc::ptr_eq(&self.clock, &port.clock()) {
            return Err(Fault::Conflict.into());
        }
        self.gns_port = Some(port);
        Ok(self)
    }
    /// Shared original source clock; this conveys no provider/service readiness.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Execute one original bounded request. Its canonical AND native hard limits
    /// are fixed before any backend construction. Native expiry is polled before
    /// the canonical subscription, so repeated revision races cannot extend it.
    /// Cancellation drops the inner future and every actual original MQ it owns.
    pub async fn execute(&self, request: OwnedRequest) -> Result<Response, Error> {
        let hard = Instant::now()
            .checked_add(self.limits.lifetime)
            .ok_or(Fault::Overflow)?;
        let sample = self.clock.sample().map_err(Error::Clock)?;
        let micros =
            u64::try_from(self.limits.lifetime.as_micros()).map_err(|_| Fault::Overflow)?;
        let until = sample
            .now
            .as_micros()
            .checked_add(micros)
            .ok_or(Fault::Overflow)?;
        let mut native = Box::pin(tokio::time::sleep_until(hard));
        let mut logical = Box::pin(
            Deadline::at(
                self.clock.clone(),
                gnunet_types::AbsoluteTime::from_micros(until),
            )
            .map_err(Error::Clock)?,
        );
        let mut work = Box::pin(self.process(request, until, hard));
        let result = poll_fn(|cx| {
            if native.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(Error::Deadline));
            }
            match logical.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => return Poll::Ready(Err(Error::Deadline)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
                Poll::Pending => {}
            }
            work.as_mut().poll(cx)
        })
        .await;
        // Close every original inner MQ before exposing its terminal result.
        drop(work);
        result
    }
    /// The actual header-only OPTIONS result. Reuse this decision before a
    /// waiting100 client sends a body; no source snapshot or native IO occurs.
    pub(crate) fn options(&self, family: gnunet_rest::route::Family) -> Result<Response, Error> {
        if family == gnunet_rest::route::Family::Openid {
            #[cfg(feature = "oidc")]
            if self.oidc_port.is_some() {
                return Ok(Response::empty(200));
            }
            return Err(Error::Capability);
        }
        Ok(Response::empty(200))
    }
    pub(crate) async fn process(
        &self,
        request: OwnedRequest,
        until: u64,
        hard: Instant,
    ) -> Result<Response, Error> {
        if matches!(
            request.endpoint,
            Endpoint::Copying
                | Endpoint::ConfigGet
                | Endpoint::ConfigPost
                | Endpoint::Options(_)
                | Endpoint::Discovery
                | Endpoint::Jwks
        ) {
            return self.dispatch(request, until, hard, None).await;
        }
        let (sources, frozen_gns) = match self.gns_port {
            Some(port) => {
                let (sources, gns) = port.freeze_with(&self.sources)?;
                (sources, Some(gns))
            }
            None => (self.sources.snapshot()?, None),
        };
        let scoped = Self {
            #[cfg(feature = "oidc")]
            oidc_port: self.oidc_port,
            instances: self.instances,
            sources,
            clock: self.clock.clone(),
            idna: self.idna,
            profile: self.profile,
            consume_profile: self.consume_profile,
            limits: self.limits,
            configuration: self.configuration,
            gns_port: self.gns_port,
        };
        scoped
            .dispatch(request, until, hard, frozen_gns.as_ref())
            .await
    }
    async fn dispatch(
        &self,
        request: OwnedRequest,
        until: u64,
        hard: Instant,
        frozen_gns: Option<&crate::gns::Frozen>,
    ) -> Result<Response, Error> {
        use Endpoint::*;
        match request.endpoint {
            Copying => Ok(Response {
                status: 200,
                body: copy(COPYING)?,
                content_type: b"text/plain",
                service_status: None,
                headers: Vec::new(),
            }),
            Options(family) => self.options(family),
            ConfigGet => self
                .configuration
                .ok_or(Error::Capability)?
                .get(&request.suffix),
            ConfigPost => {
                self.configuration
                    .ok_or(Error::Capability)?
                    .post(&request.suffix, &request.body, until, hard)
                    .await?;
                Ok(Response::empty(200))
            }
            GnsGet => {
                self.gns(request, frozen_gns.ok_or(Error::Capability)?, until, hard)
                    .await
            }
            Authorize | Login | Token | Userinfo | Discovery | Jwks => {
                #[cfg(feature = "oidc")]
                {
                    self.openid(
                        request,
                        self.oidc_port.ok_or(Error::Capability)?,
                        frozen_gns,
                        until,
                        hard,
                    )
                    .await
                }
                #[cfg(not(feature = "oidc"))]
                {
                    Err(Error::Capability)
                }
            }
            Identities | IdentityName | IdentityPublic | IdentityCreate | IdentityRenameName
            | IdentityRenamePublic | IdentityDeleteName | IdentityDeletePublic | IdentitySign => {
                self.identity(request, until, hard).await
            }
            Names | NameAppend | NameReplace | NameDelete | NameImport => {
                self.namestore(request, until, hard).await
            }
            Attributes | AttributeStore | AttributeDelete | Credentials | CredentialStore
            | CredentialDelete | Tickets | Revoke | Consume => {
                self.reclaim(request, until, hard).await
            }
        }
    }

    pub(crate) async fn directory(
        &self,
        hard: Instant,
    ) -> Result<gnunet_identity_client_host::Client<'a>, Error> {
        use gnunet_identity_client_host::Progress;
        let mut client = gnunet_identity_client_host::Client::monitor(
            self.instances.identity,
            self.sources.identity.duplicate()?,
            self.limits.identity,
        )?;
        loop {
            match poll_fn(|cx| client.poll(cx, Some(hard))).await? {
                Progress::Initialized(_) => return Ok(client),
                Progress::Lost { cause, .. } => return Err(Error::IdentitySource(cause)),
                Progress::Unavailable(error) => return Err(Error::Native(error)),
                Progress::ConnectRetry { error, .. } => return Err(Error::Io(error)),
                Progress::Closed => return Err(Error::SourceLost),
                Progress::WaitDeadline => return Err(Error::Deadline),
                _ => {}
            }
        }
    }
}
// The future owns each native client rather than lending it into a detached task.
// Native Client/Channel Drop closes its exact socket; no close syscall ACK exists.

impl Sources {
    fn snapshot(&self) -> Result<Self, Error> {
        let [identity, namestore, reclaim] = gnunet_client_host::EndpointSource::snapshot_all([
            &self.identity,
            &self.namestore,
            &self.reclaim,
        ])?;
        Ok(Self {
            identity,
            namestore,
            reclaim,
        })
    }
}
