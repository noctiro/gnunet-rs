//! Explicit conditional OpenID owner. Each handler still owns its actual MQs.
//! Session/grant/access caches are finite, erased, and never persisted implicitly.
use crate::{
    Context, Error, OwnedRequest, Response,
    output::{Json, bytes, copy, decoded, parse},
};
use gnunet_gnsrecord::ZoneKey;
use gnunet_reclaim::{AttributeList, ListLimits, PresentationList, Uri};
use gnunet_reclaim_client_host::{Client, Iterator, Outcome, Progress, ipc};
use gnunet_rest::{
    oidc::{self, base64},
    route::Endpoint,
};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{cell::RefCell, future::poll_fn, rc::Rc, sync::Arc, time::Duration};
use tokio::time::Instant;
use zeroize::Zeroizing;
mod claims;
/// Explicit owned signer/issued-state storage and actual durable commit driver.
pub mod persistence;
/// The algorithm is selected by explicit caller authority, never a JWT header.
pub enum Signer {
    /// Actual mature non-FIPS AWS-LC native/asm RS256 backend.
    Rs256(gnunet_oidc_crypto_host::Rsa),
    /// Explicit HS512 provider; never an RSA failure fallback.
    Hs512(gnunet_oidc_crypto_host::Hs512),
}
impl Signer {
    fn algorithm(&self) -> &'static [u8] {
        match self {
            Self::Rs256(_) => b"RS256",
            Self::Hs512(_) => b"HS512",
        }
    }
    fn sign(&self, payload: &[u8], out: &mut [u8]) -> Result<usize, Fault> {
        match self {
            Self::Rs256(key) => key.sign_jwt(payload, out),
            Self::Hs512(key) => key.sign_jwt(payload, out),
        }
    }
}
impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OidcSigner([REDACTED])")
    }
}
/// Finite server-owned OAuth state. No cache is an IDENTITY or native MQ epoch.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneously retained three-second login sessions.
    pub sessions: usize,
    /// Maximum reserved/issued original authorization codes.
    pub grants: usize,
    /// Maximum originally issued access capabilities.
    pub accesses: usize,
    /// Aggregate retained code/client/redirect/access byte ceiling.
    pub bytes: usize,
    /// Original authorization-code and token lifetime, independently native bounded.
    pub ttl: Duration,
    /// Original authorization artifact and list quotas.
    pub code: oidc::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            sessions: 64,
            grants: 16,
            accesses: 32,
            bytes: 1_048_576,
            ttl: Duration::from_secs(300),
            code: Default::default(),
        }
    }
}
#[derive(Clone, Copy)]
struct Bound {
    until: u64,
    hard: Instant,
    wall_until: u64,
}
impl Bound {
    fn live(&self, now: u64) -> bool {
        now < self.until && Instant::now() < self.hard
    }
}
struct Session {
    subject: ZoneKey,
    bound: Bound,
}
struct Grant {
    serial: u64,
    bound: Bound,
    state: GrantState,
}
enum GrantState {
    Reserved,
    Issued {
        code: Zeroizing<Vec<u8>>,
        client: Zeroizing<Vec<u8>>,
        redirect: Zeroizing<Vec<u8>>,
        subject: ZoneKey,
    },
}
struct Access {
    bound: Bound,
    token: Zeroizing<Vec<u8>>,
    subject: ZoneKey,
}
struct State {
    sessions: Vec<Option<Session>>,
    grants: Vec<Option<Grant>>,
    accesses: Vec<Option<Access>>,
    next: u64,
}
/// Actual reusable OIDC provider. Constructor receives explicit owned signing key;
/// it does not read old C/Rust key files, create a key, spawn or access a network.
pub struct Provider {
    clock: Arc<dyn RuntimeClock>,
    signer: Signer,
    origin: Zeroizing<Vec<u8>>,
    login_ui: Zeroizing<Vec<u8>>,
    client_secret: Option<Zeroizing<Vec<u8>>>,
    limits: Limits,
    state: Rc<RefCell<State>>,
    persistent: Option<persistence::Port>,
}
fn slots<T>(n: usize) -> Result<Vec<Option<T>>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    out.resize_with(n, || None);
    Ok(out)
}
impl Provider {
    /// Explicit origin/login URI and optional confidential-client secret. Secrets
    /// remain owned/zeroizing; absence enables only public clients with PKCE.
    pub fn new(
        clock: Arc<dyn RuntimeClock>,
        signer: Signer,
        origin: &[u8],
        login_ui: &[u8],
        client_secret: Option<&[u8]>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.sessions == 0
            || limits.grants == 0
            || limits.accesses == 0
            || limits.bytes == 0
            || limits.ttl.is_zero()
            || limits.ttl.as_micros() > u128::from(u64::MAX)
        {
            return Err(Fault::InvalidInput.into());
        }
        for uri in [origin, login_ui] {
            if uri.is_empty()
                || uri.len() > 4096
                || !(uri.starts_with(b"http://") || uri.starts_with(b"https://"))
                || uri.iter().any(|b| matches!(b, 0..=32 | 127 | b'#'))
            {
                return Err(Fault::InvalidInput.into());
            }
        }
        if origin.ends_with(b"/") || origin.contains(&b'?') {
            return Err(Fault::InvalidInput.into());
        }
        if client_secret.is_some_and(|s| s.is_empty() || s.len() > 4096) {
            return Err(Fault::InvalidInput.into());
        }
        let state = State {
            sessions: slots(limits.sessions)?,
            grants: slots(limits.grants)?,
            accesses: slots(limits.accesses)?,
            next: 1,
        };
        Ok(Self {
            clock,
            signer,
            origin: copy(origin)?,
            login_ui: copy(login_ui)?,
            client_secret: client_secret.map(copy).transpose()?,
            limits,
            state: Rc::new(RefCell::new(state)),
            persistent: None,
        })
    }
    /// Original shared clock domain; this does not confer service readiness.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    fn now(&self) -> Result<u64, Error> {
        let now = match self.clock.sample() {
            Ok(now) => now.now.as_micros(),
            Err(error) => {
                if let Some(port) = &self.persistent {
                    port.clock_failed(error);
                }
                return Err(Error::Clock(error));
            }
        };
        let mut state = self.state.borrow_mut();
        for row in &mut state.sessions {
            if row.as_ref().is_some_and(|r| !r.bound.live(now)) {
                *row = None
            }
        }
        for row in &mut state.grants {
            if row.as_ref().is_some_and(|r| !r.bound.live(now)) {
                *row = None
            }
        }
        for row in &mut state.accesses {
            if row.as_ref().is_some_and(|r| !r.bound.live(now)) {
                *row = None
            }
        }
        Ok(now)
    }
    fn bound(&self, now: u64, duration: Duration) -> Result<Bound, Error> {
        let wall = persistence::wall_now()?;
        let hard = Instant::now()
            .checked_add(duration)
            .ok_or(Fault::Overflow)?;
        let micros = u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow)?;
        Ok(Bound {
            until: now.checked_add(micros).ok_or(Fault::Overflow)?,
            hard,
            wall_until: wall.checked_add(micros).ok_or(Fault::Overflow)?,
        })
    }
    fn reserve(&self) -> Result<Reservation<'_>, Error> {
        if let Some(p) = &self.persistent {
            p.available()?;
        }
        let now = self.now()?;
        let mut state = self.state.borrow_mut();
        let row = state
            .grants
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let serial = state.next;
        state.next = serial.checked_add(1).ok_or(Fault::Overflow)?;
        state.grants[row] = Some(Grant {
            serial,
            bound: self.bound(now, self.limits.ttl)?,
            state: GrantState::Reserved,
        });
        Ok(Reservation {
            provider: self,
            row,
            serial,
        })
    }
    fn retained(&self) -> usize {
        let state = self.state.borrow();
        let grants = state
            .grants
            .iter()
            .flatten()
            .map(|r| match &r.state {
                GrantState::Reserved => 0,
                GrantState::Issued {
                    code,
                    client,
                    redirect,
                    ..
                } => code
                    .len()
                    .saturating_add(client.len())
                    .saturating_add(redirect.len()),
            })
            .fold(0usize, usize::saturating_add);
        let access = state
            .accesses
            .iter()
            .flatten()
            .map(|r| r.token.len())
            .fold(0usize, usize::saturating_add);
        grants.saturating_add(access)
    }
    fn discovery(&self, cap: usize) -> Result<Response, Error> {
        let mut json = Json::new(cap)?;
        json.raw(b"{\"issuer\":")?;
        json.string(&self.origin)?;
        for (field, path) in [
            (
                b"authorization_endpoint".as_slice(),
                b"/openid/authorize".as_slice(),
            ),
            (b"token_endpoint", b"/openid/token"),
            (b"userinfo_endpoint", b"/openid/userinfo"),
            (b"jwks_uri", b"/jwks.json"),
        ] {
            json.raw(b",")?;
            json.string(field)?;
            json.raw(b":")?;
            let mut uri = copy(&self.origin)?;
            uri.try_reserve_exact(path.len())
                .map_err(|_| Fault::Capacity)?;
            uri.extend_from_slice(path);
            json.string(&uri)?
        }
        json.raw(b",\"response_types_supported\":[\"code\"],\"grant_types_supported\":[\"authorization_code\"],\"subject_types_supported\":[\"public\"],\"claim_types_supported\":[\"normal\",\"aggregated\"],\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"address\",\"phone\"],\"code_challenge_methods_supported\":[\"S256\"],\"id_token_signing_alg_values_supported\":[")?;
        json.string(self.signer.algorithm())?;
        json.raw(b"],\"token_endpoint_auth_methods_supported\":[\"none\"")?;
        if self.client_secret.is_some() {
            json.raw(b",\"client_secret_basic\",\"client_secret_post\"")?
        }
        json.raw(b"]}")?;
        Ok(Response::json(json.bytes))
    }
    fn jwks(&self, cap: usize) -> Result<Response, Error> {
        let mut json = Json::new(cap)?;
        json.raw(b"{\"keys\":[")?;
        if let Signer::Rs256(key) = &self.signer {
            let mut out = bytes(cap)?;
            let n = key.public().write_jwk(&mut out)?;
            json.raw(&out[..n])?
        }
        json.raw(b"]}")?;
        Ok(Response::json(json.bytes))
    }
}
impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcProvider")
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}
struct Reservation<'a> {
    provider: &'a Provider,
    row: usize,
    serial: u64,
}
impl Reservation<'_> {
    async fn publish(
        &self,
        code: Zeroizing<Vec<u8>>,
        client: Zeroizing<Vec<u8>>,
        redirect: Zeroizing<Vec<u8>>,
        subject: ZoneKey,
        until: u64,
        hard: Instant,
    ) -> Result<(), Error> {
        let now = self.provider.now()?;
        if self
            .provider
            .retained()
            .checked_add(code.len())
            .and_then(|n| n.checked_add(client.len()))
            .and_then(|n| n.checked_add(redirect.len()))
            .is_none_or(|n| n > self.provider.limits.bytes)
        {
            return Err(Fault::Capacity.into());
        }
        if let Some(port) = &self.provider.persistent {
            let bound = {
                let state = self.provider.state.borrow();
                state.grants[self.row]
                    .as_ref()
                    .filter(|g| {
                        g.serial == self.serial
                            && g.bound.live(now)
                            && matches!(g.state, GrantState::Reserved)
                    })
                    .ok_or(Fault::Stale)?
                    .bound
            };
            let grant = Grant {
                serial: self.serial,
                bound,
                state: GrantState::Issued {
                    code,
                    client,
                    redirect,
                    subject,
                },
            };
            port.submit(
                self.provider,
                persistence::Change::Issue {
                    row: self.row,
                    serial: self.serial,
                    grant,
                },
                until,
                hard,
            )
            .await?;
            let now = self.provider.now()?;
            if now >= until || Instant::now() >= hard {
                return Err(Error::Deadline);
            }
            if !self.provider.state.borrow().grants[self.row]
                .as_ref()
                .is_some_and(|g| {
                    g.serial == self.serial
                        && g.bound.live(now)
                        && matches!(g.state, GrantState::Issued { .. })
                })
            {
                return Err(Error::Deadline);
            }
            return Ok(());
        }
        let mut state = self.provider.state.borrow_mut();
        let row = state.grants[self.row]
            .as_mut()
            .filter(|r| {
                r.serial == self.serial
                    && r.bound.live(now)
                    && matches!(r.state, GrantState::Reserved)
            })
            .ok_or(Fault::Stale)?;
        row.state = GrantState::Issued {
            code,
            client,
            redirect,
            subject,
        };
        Ok(())
    }
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        let mut state = self.provider.state.borrow_mut();
        if self
            .provider
            .persistent
            .as_ref()
            .is_some_and(|p| p.retains(self.row, self.serial))
        {
            return;
        }
        if state.grants[self.row]
            .as_ref()
            .is_some_and(|r| r.serial == self.serial && matches!(r.state, GrantState::Reserved))
        {
            state.grants[self.row] = None
        }
    }
}
fn equal(a: &[u8], b: &[u8]) -> bool {
    let mut d = a.len() ^ b.len();
    for (i, c) in a.iter().enumerate() {
        d |= usize::from(*c ^ b.get(i).copied().unwrap_or(0))
    }
    d == 0
}
fn oauth(status: u16, error: &'static str, description: &'static str) -> Error {
    Error::OAuth {
        status,
        error,
        description,
        challenge: None,
        service_status: None,
    }
}
// RFC6749 section5.2: authentication failure belongs to this token flow, not
// to global HTTP Basic or another endpoint that happens to return401.
fn client_authentication(description: &'static str) -> Error {
    Error::OAuth {
        status: 401,
        error: "invalid_client",
        description,
        challenge: Some(crate::OAuthChallenge::ClientBasic),
        service_status: None,
    }
}
// RFC6750 sections3/3.1: actual invalid credentials at the protected resource.
// Provider/source failures must never be converted through this constructor.
fn bearer_authentication(description: &'static str, raw: Option<u32>) -> Error {
    Error::OAuth {
        status: 401,
        error: "invalid_token",
        description,
        challenge: Some(crate::OAuthChallenge::ResourceBearer),
        service_status: raw.map(i64::from),
    }
}
fn required(request: &OwnedRequest, key: &[u8], cap: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    request
        .parameter(key, cap)?
        .ok_or_else(|| oauth(400, "invalid_request", "A required parameter is missing"))
}
fn public(text: &[u8]) -> Result<ZoneKey, Error> {
    let mut key = [0u8; 36];
    gnunet_rest::text::decode(text, &mut key)?;
    Ok(ZoneKey::from_wire(&key)?)
}
fn public_text(key: ZoneKey) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut text = bytes(58)?;
    let n = gnunet_rest::text::encode(&key.to_wire(), &mut text)?;
    text.truncate(n);
    Ok(text)
}
fn percent(value: &[u8], out: &mut Json) -> Result<(), Error> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in value {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.raw(&[*b])?
        } else {
            out.raw(&[b'%', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]])?
        }
    }
    Ok(())
}
fn location(
    base: &[u8],
    pairs: &[(&[u8], &[u8])],
    cap: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if base.iter().any(|b| matches!(b, 0..=32 | 127 | b'#')) {
        return Err(Fault::InvalidInput.into());
    }
    let mut out = Json::new(cap)?;
    out.raw(base)?;
    for (n, (key, value)) in pairs.iter().enumerate() {
        out.raw(if n == 0 && !base.contains(&b'?') {
            b"?"
        } else {
            b"&"
        })?;
        out.raw(key)?;
        out.raw(b"=")?;
        percent(value, &mut out)?
    }
    Ok(out.bytes)
}
fn redirect(uri: &[u8]) -> Result<Response, Error> {
    Response::empty(302).header(b"Location", uri)
}
// Only call after the actual client zone registered this exact redirect URI.
// OAuth request errors return to that original callback; independent provider,
// clock, native and resource causes remain their original typed failures.
fn trusted_authorization_error(
    cause: Error,
    uri: &[u8],
    state: &[u8],
    cap: usize,
) -> Result<Response, Error> {
    match cause {
        Error::OAuth {
            error, description, ..
        } => redirect(&location(
            uri,
            &[
                (b"error", error.as_bytes()),
                (b"error_description", description.as_bytes()),
                (b"state", state),
            ],
            cap,
        )?),
        cause => Err(cause),
    }
}
impl<I: gnunet_dns::Idna> Context<'_, I> {
    pub(crate) async fn openid(
        &self,
        request: OwnedRequest,
        provider: &Provider,
        gns: Option<&crate::gns::Frozen>,
        until: u64,
        hard: Instant,
    ) -> Result<Response, Error> {
        match request.endpoint {
            Endpoint::Discovery => provider.discovery(self.limits.output_bytes),
            Endpoint::Jwks => provider.jwks(self.limits.output_bytes),
            Endpoint::Login => self.oidc_login(request, provider, hard).await,
            Endpoint::Authorize => {
                self.oidc_authorize(
                    request,
                    provider,
                    gns.ok_or(Error::Capability)?,
                    until,
                    hard,
                )
                .await
            }
            Endpoint::Token => self.oidc_token(request, provider, until, hard).await,
            Endpoint::Userinfo => self.oidc_userinfo(request, provider, until, hard).await,
            _ => Err(Fault::InvalidInput.into()),
        }
    }
    async fn oidc_login(
        &self,
        request: OwnedRequest,
        provider: &Provider,
        hard: Instant,
    ) -> Result<Response, Error> {
        let identity = parse(&request.body, self.limits.json, |root| {
            decoded(root.get(b"identity").ok_or(Fault::Malformed)?.string()?)
        })?;
        if identity.as_slice() != b"Denied" {
            let zone = public(&identity)?;
            let directory = self.directory(hard).await?;
            if !directory
                .egos()
                .any(|ego| ego.public_key().is_ok_and(|p| p == zone.to_wire()))
            {
                return Err(oauth(
                    400,
                    "invalid_request",
                    "Identity is not present on the actual service",
                ));
            }
            let now = provider.now()?;
            let mut state = provider.state.borrow_mut();
            let row = state
                .sessions
                .iter()
                .position(|s| s.as_ref().is_some_and(|s| s.subject == zone))
                .or_else(|| state.sessions.iter().position(Option::is_none))
                .ok_or(Fault::Capacity)?;
            state.sessions[row] = Some(Session {
                subject: zone,
                bound: provider.bound(now, Duration::from_secs(3))?,
            });
        }
        let mut cookie = Json::new(128)?;
        cookie.raw(b"Identity=")?;
        cookie.raw(&identity)?;
        cookie.raw(b";Max-Age=3;Path=/openid;HttpOnly;SameSite=Lax")?;
        if provider.origin.starts_with(b"https://") {
            cookie.raw(b";Secure")?;
        }
        Response::empty(200)
            .header(b"Set-Cookie", &cookie.bytes)?
            .header(b"Access-Control-Allow-Methods", b"POST")
    }
    async fn oidc_authorize(
        &self,
        request: OwnedRequest,
        provider: &Provider,
        gns: &crate::gns::Frozen,
        until: u64,
        hard: Instant,
    ) -> Result<Response, Error> {
        let client = required(&request, b"client_id", self.limits.bytes)?;
        let rp = public(&client)?;
        let uri = required(&request, b"redirect_uri", self.limits.bytes)?;
        Uri::new(&uri)?;
        if uri.is_empty() || uri.contains(&b'#') || uri.iter().any(|b| matches!(b, 0..=32 | 127)) {
            return Err(oauth(400, "invalid_request", "Invalid redirect URI"));
        }
        if !gns.permits_redirect(rp, &uri, hard).await? {
            return Err(oauth(
                400,
                "invalid_request",
                "Redirect URI is not registered in the actual client zone",
            ));
        }
        let state = request
            .parameter(b"state", self.limits.bytes)?
            .unwrap_or(copy(b"")?);
        let response_type = match required(&request, b"response_type", self.limits.bytes) {
            Ok(value) => value,
            Err(error) => {
                return trusted_authorization_error(error, &uri, &state, self.limits.output_bytes);
            }
        };
        if response_type.as_slice() != b"code" {
            return redirect(&location(
                &uri,
                &[(b"error", b"unsupported_response_type"), (b"state", &state)],
                self.limits.output_bytes,
            )?);
        }
        for key in [
            b"display".as_slice(),
            b"max_age",
            b"ui_locales",
            b"id_token_hint",
            b"login_hint",
            b"acr_values",
            b"claims_locales",
            b"request",
            b"request_uri",
            b"response_mode",
        ] {
            if request.parameter(key, self.limits.bytes)?.is_some() {
                return trusted_authorization_error(
                    oauth(
                        400,
                        "invalid_request",
                        "Requested authorization parameter is not supported",
                    ),
                    &uri,
                    &state,
                    self.limits.output_bytes,
                );
            }
        }
        let selection = match claims::Selection::new(&request, self.limits) {
            Ok(value) => value,
            Err(error) => {
                return trusted_authorization_error(error, &uri, &state, self.limits.output_bytes);
            }
        };
        let nonce = request
            .parameter(b"nonce", self.limits.bytes)?
            .unwrap_or(copy(b"")?);
        let challenge = request
            .parameter(b"code_challenge", self.limits.bytes)?
            .unwrap_or(copy(b"")?);
        let method = request.parameter(b"code_challenge_method", self.limits.bytes)?;
        if !challenge.is_empty() && method.as_deref().map(Vec::as_slice) != Some(b"S256") {
            return trusted_authorization_error(
                oauth(
                    400,
                    "invalid_request",
                    "Only S256 code challenges are supported",
                ),
                &uri,
                &state,
                self.limits.output_bytes,
            );
        }
        if challenge.is_empty() && method.is_some() {
            return trusted_authorization_error(
                oauth(400, "invalid_request", "Missing code challenge"),
                &uri,
                &state,
                self.limits.output_bytes,
            );
        }
        let identity = cookie_identity(request.cookie.as_deref().map(Vec::as_slice))?;
        if identity == Some(b"Denied") {
            return redirect(&location(
                &uri,
                &[(b"error", b"access_denied"), (b"state", &state)],
                self.limits.output_bytes,
            )?);
        }
        let now = provider.now()?;
        let subject = identity.map(public).transpose()?.filter(|subject| {
            provider
                .state
                .borrow()
                .sessions
                .iter()
                .flatten()
                .any(|s| s.subject == *subject && s.bound.live(now))
        });
        let Some(subject) = subject else {
            if request
                .parameter(b"prompt", self.limits.bytes)?
                .is_some_and(|v| v.as_slice() == b"none")
            {
                return redirect(&location(
                    &uri,
                    &[(b"error", b"login_required"), (b"state", &state)],
                    self.limits.output_bytes,
                )?);
            }
            let mut owned = Vec::new();
            owned.try_reserve_exact(9).map_err(|_| Fault::Capacity)?;
            for key in [
                b"response_type".as_slice(),
                b"client_id",
                b"redirect_uri",
                b"scope",
                b"state",
                b"nonce",
                b"claims",
                b"code_challenge",
                b"code_challenge_method",
            ] {
                if let Some(value) = request.parameter(key, self.limits.bytes)? {
                    owned.push((key, value))
                }
            }
            let mut pairs = Vec::new();
            pairs
                .try_reserve_exact(owned.len())
                .map_err(|_| Fault::Capacity)?;
            for (key, value) in &owned {
                pairs.push((*key, value.as_slice()));
            }
            return redirect(&location(
                &provider.login_ui,
                &pairs,
                self.limits.output_bytes,
            )?);
        };
        let directory = self.directory(hard).await?;
        let Some(key) = directory
            .egos()
            .find(|e| e.public_key().is_ok_and(|p| p == subject.to_wire()))
            .map(|e| e.secret().try_clone_secret())
        else {
            return trusted_authorization_error(
                oauth(
                    400,
                    "login_required",
                    "The logged in identity is no longer present",
                ),
                &uri,
                &state,
                self.limits.output_bytes,
            );
        };
        let reservation = provider.reserve()?;
        let selected = self
            .oidc_attributes(key.view()?, &selection, until, hard)
            .await?;
        let all = AttributeList::new(&selected.all, provider.limits.code.lists)?;
        let idtoken = AttributeList::new(&selected.idtoken, provider.limits.code.lists)?;
        let mut client_handle = Client::new(
            self.instances.reclaim,
            self.sources.reclaim.duplicate()?,
            self.limits.reclaim,
        )?;
        let operation = client_handle.issue_ticket(key.view()?, Uri::new(&client)?, all, until)?;
        let reply = crate::reclaim::reclaim_reply(&mut client_handle, operation, hard).await?;
        let (ticket, presentations) = match reply.view()? {
            ipc::Response::Ticket {
                ticket: Some(ticket),
                presentations,
                ..
            } => (ticket, presentations),
            _ => {
                return trusted_authorization_error(
                    oauth(
                        502,
                        "server_error",
                        "Actual RECLAIM provider did not issue a ticket",
                    ),
                    &uri,
                    &state,
                    self.limits.output_bytes,
                );
            }
        };
        let code = oidc::Code {
            ticket,
            nonce: &nonce,
            challenge: &challenge,
            attributes: idtoken,
            presentations,
        };
        let mut scratch = bytes(provider.limits.code.bytes)?;
        let mut raw = bytes(code.encoded_len(provider.limits.code)?)?;
        let n = code.sign(key.view()?, &mut scratch, &mut raw, provider.limits.code)?;
        raw.truncate(n);
        let mut encoded = bytes(base64::encoded_len(n, false)?)?;
        base64::encode(&raw, &mut encoded, true, false)?;
        // Do not expose an authorization code larger than this same server's
        // original token-request envelope can accept. Worst-case percent form
        // expansion includes the configured secret and exact redirect URI.
        let form_overhead = uri
            .len()
            .checked_mul(3)
            .and_then(|n| {
                n.checked_add(
                    provider
                        .client_secret
                        .as_ref()
                        .map_or(0, |s| s.len().saturating_mul(3)),
                )
            })
            .and_then(|n| n.checked_add(client.len()))
            .and_then(|n| n.checked_add(8192))
            .ok_or(Fault::Overflow)?;
        if encoded
            .len()
            .checked_add(form_overhead)
            .is_none_or(|n| n > self.limits.bytes)
        {
            return Err(Fault::Capacity.into());
        }
        let destination = location(
            &uri,
            &[(b"code", &encoded), (b"state", &state)],
            self.limits.output_bytes,
        )?;
        reservation
            .publish(encoded, client, uri, subject, until, hard)
            .await?;
        redirect(&destination)
    }
    async fn oidc_token(
        &self,
        request: OwnedRequest,
        provider: &Provider,
        until: u64,
        hard: Instant,
    ) -> Result<Response, Error> {
        if required(&request, b"grant_type", self.limits.bytes)?.as_slice() != b"authorization_code"
        {
            return Err(oauth(
                400,
                "unsupported_grant_type",
                "Only authorization_code is supported",
            ));
        }
        let code = required(&request, b"code", self.limits.bytes)?;
        let verifier = request.parameter(b"code_verifier", self.limits.bytes)?;
        let posted_client = request.parameter(b"client_id", self.limits.bytes)?;
        let posted_secret = request.parameter(b"client_secret", self.limits.bytes)?;
        let basic = basic_credentials(
            request.authorization.as_deref().map(Vec::as_slice),
            self.limits.bytes,
        )?;
        if basic.is_some() && posted_secret.is_some() {
            return Err(oauth(
                400,
                "invalid_request",
                "Multiple client authentication methods",
            ));
        }
        let (client, secret) = match basic {
            Some(Credentials { client, secret }) => {
                if posted_client.as_ref().is_some_and(|v| !equal(v, &client)) {
                    return Err(client_authentication("Client identifiers conflict"));
                }
                (client, Some(secret))
            }
            None => (
                posted_client.ok_or_else(|| client_authentication("Missing client identifier"))?,
                posted_secret,
            ),
        };
        // This identifier is the token request's authentication principal.
        // Its pure shape/type refusal is invalid_client in this flow; provider,
        // clock and resource failures elsewhere retain their original cause.
        let zone = public(&client).map_err(|error| match error {
            Error::Core(
                Fault::Malformed | Fault::Truncated | Fault::InvalidInput | Fault::Unsupported,
            ) => client_authentication("Client identifier is not a supported public identity"),
            error => error,
        })?;
        if let Some(secret) = secret {
            let expected = provider
                .client_secret
                .as_ref()
                .ok_or_else(|| client_authentication("Confidential clients are not configured"))?;
            if !equal(expected, &secret) {
                return Err(client_authentication("Client authentication failed"));
            }
            let directory = self.directory(hard).await?;
            if !directory
                .egos()
                .any(|e| e.public_key().is_ok_and(|p| p == zone.to_wire()))
            {
                return Err(client_authentication(
                    "Client is not a local confidential identity",
                ));
            }
        } else if verifier.is_none() {
            return Err(client_authentication("Public clients require PKCE"));
        }
        let now = provider.now()?;
        let (row, grant_serial, subject, expected_redirect) = {
            let state = provider.state.borrow();
            let (row, grant) = state
                .grants
                .iter()
                .enumerate()
                .find_map(|(i, r)| {
                    r.as_ref()
                        .filter(|g| g.bound.live(now))
                        .and_then(|g| match &g.state {
                            GrantState::Issued {
                                code: old,
                                client: old_client,
                                ..
                            } if equal(old, &code) && equal(old_client, &client) => Some((i, g)),
                            _ => None,
                        })
                })
                .ok_or_else(|| {
                    oauth(
                        400,
                        "invalid_grant",
                        "Authorization code is unknown, expired or already redeemed",
                    )
                })?;
            match &grant.state {
                GrantState::Issued {
                    subject, redirect, ..
                } => (row, grant.serial, *subject, copy(redirect)?),
                _ => return Err(Fault::Stale.into()),
            }
        };
        let redirect = request
            .parameter(b"redirect_uri", self.limits.bytes)?
            .ok_or_else(|| oauth(400, "invalid_grant", "Missing original redirect URI"))?;
        if !equal(&expected_redirect, &redirect) {
            return Err(oauth(
                400,
                "invalid_grant",
                "Redirect URI differs from original authorization",
            ));
        }
        let mut raw = bytes(base64::decoded_len(&code, true)?)?;
        base64::decode(&code, &mut raw, true)?;
        let verified = oidc::Unverified::decode(&raw, provider.limits.code)?
            .verify(verifier.as_deref().map(Vec::as_slice))?;
        if verified.issuer() != subject {
            return Err(oauth(
                400,
                "invalid_grant",
                "Authorization code issuer mismatch",
            ));
        }
        let fields = verified.code();
        // A public client cannot redeem a code originally issued without PKCE.
        if request
            .parameter(b"client_secret", self.limits.bytes)?
            .is_none()
            && request.authorization.is_none()
            && fields.challenge.is_empty()
        {
            return Err(oauth(
                400,
                "invalid_grant",
                "Authorization code was not PKCE bound",
            ));
        }
        let bound = provider.bound(now, provider.limits.ttl)?;
        let payload = claims::payload(
            fields.attributes,
            fields.presentations,
            subject,
            &provider.origin,
            Some(claims::Token {
                audience: &client,
                nonce: fields.nonce,
                now,
                expires: bound.until,
            }),
            self.limits.output_bytes,
        )?;
        let mut jwt = bytes(self.limits.output_bytes)?;
        let n = provider.signer.sign(&payload, &mut jwt)?;
        jwt.truncate(n);
        let uri = Uri::new(&client)?;
        let mut access = bytes(256 + client.len())?;
        let n = oidc::access_token(fields.ticket, uri, &mut access)?;
        access.truncate(n);
        provider.now()?;
        let access_slot = {
            let state = provider.state.borrow();
            state
                .accesses
                .iter()
                .position(|a| {
                    a.as_ref()
                        .is_some_and(|a| a.subject == subject && equal(&a.token, &access))
                })
                .or_else(|| state.accesses.iter().position(Option::is_none))
                .ok_or(Fault::Capacity)?
        };
        let released = {
            let state = provider.state.borrow();
            let grant = state.grants[row].as_ref().ok_or(Fault::Stale)?;
            let GrantState::Issued {
                code,
                client,
                redirect,
                ..
            } = &grant.state
            else {
                return Err(Fault::Stale.into());
            };
            code.len()
                .checked_add(client.len())
                .and_then(|n| n.checked_add(redirect.len()))
                .and_then(|n| {
                    n.checked_add(
                        state.accesses[access_slot]
                            .as_ref()
                            .map_or(0, |a| a.token.len()),
                    )
                })
                .ok_or(Fault::Overflow)?
        };
        if provider
            .retained()
            .checked_sub(released)
            .and_then(|n| n.checked_add(access.len()))
            .is_none_or(|n| n > provider.limits.bytes)
        {
            return Err(Fault::Capacity.into());
        }
        let mut json = Json::new(self.limits.output_bytes)?;
        json.raw(b"{\"access_token\":")?;
        json.string(&access)?;
        json.raw(b",\"token_type\":\"Bearer\",\"expires_in\":")?;
        json.number(provider.limits.ttl.as_secs())?;
        json.raw(b",\"id_token\":")?;
        json.string(&jwt)?;
        json.raw(b"}")?;
        let response_access = copy(&access)?;
        let completed_now = provider.now()?;
        if !provider.state.borrow().grants[row].as_ref().is_some_and(|g|g.serial==grant_serial&&g.bound.live(completed_now)&&matches!(&g.state,GrantState::Issued{code:old,client:old_client,..} if equal(old,&code)&&equal(old_client,&client))) {return Err(oauth(400,"invalid_grant","Original authorization code expired during processing"));}
        if let Some(port) = &provider.persistent {
            port.submit(
                provider,
                persistence::Change::Exchange {
                    row,
                    serial: grant_serial,
                    access_row: access_slot,
                    access: Access {
                        bound,
                        token: access,
                        subject,
                    },
                },
                until,
                hard,
            )
            .await?;
            let now = provider.now()?;
            if !provider.state.borrow().accesses.iter().flatten().any(|a| {
                a.subject == subject && a.bound.live(now) && equal(&a.token, &response_access)
            }) {
                return Err(oauth(
                    400,
                    "invalid_grant",
                    "Original access token expired before response",
                ));
            }
        } else {
            let mut state = provider.state.borrow_mut();
            state.grants[row] = None;
            state.accesses[access_slot] = Some(Access {
                bound,
                token: access,
                subject,
            });
        }
        let completed_now = provider.now()?;
        if completed_now >= until || Instant::now() >= hard {
            return Err(Error::Deadline);
        }
        if !provider.state.borrow().accesses[access_slot]
            .as_ref()
            .is_some_and(|a| {
                a.subject == subject
                    && a.bound.live(completed_now)
                    && equal(&a.token, &response_access)
            })
        {
            return Err(oauth(
                400,
                "invalid_grant",
                "Original access token expired during commit",
            ));
        }
        let remaining = u64::try_from(
            bound
                .hard
                .saturating_duration_since(Instant::now())
                .as_micros(),
        )
        .unwrap_or(u64::MAX)
        .min(bound.until.saturating_sub(completed_now))
            / 1_000_000;
        json.bytes.as_mut_slice().fill(0);
        json.bytes.clear();
        json.raw(b"{\"access_token\":")?;
        json.string(&response_access)?;
        json.raw(b",\"token_type\":\"Bearer\",\"expires_in\":")?;
        json.number(remaining)?;
        json.raw(b",\"id_token\":")?;
        json.string(&jwt)?;
        json.raw(b"}")?;
        Response::json(json.bytes)
            .header(b"Cache-Control", b"no-store")?
            .header(b"Pragma", b"no-cache")
    }
    async fn oidc_userinfo(
        &self,
        request: OwnedRequest,
        provider: &Provider,
        until: u64,
        hard: Instant,
    ) -> Result<Response, Error> {
        let parameter = request.parameter(b"access_token", self.limits.bytes)?;
        let bearer = match request.authorization.as_deref().map(Vec::as_slice) {
            None => None,
            Some(value) => {
                let (scheme, token) =
                    value.split_at(value.iter().position(|b| *b == b' ').ok_or_else(|| {
                        bearer_authentication("Malformed Bearer authorization", None)
                    })?);
                if !scheme.eq_ignore_ascii_case(b"Bearer") || token.len() < 2 {
                    return Err(bearer_authentication("Expected Bearer authorization", None));
                }
                Some(copy(&token[1..])?)
            }
        };
        if bearer.is_some() && parameter.is_some() {
            return Err(oauth(
                400,
                "invalid_request",
                "Access token supplied more than once",
            ));
        }
        let token = bearer
            .or(parameter)
            .ok_or_else(|| bearer_authentication("Missing access token", None))?;
        let now = provider.now()?;
        let subject = provider
            .state
            .borrow()
            .accesses
            .iter()
            .flatten()
            .find(|r| r.bound.live(now) && equal(&r.token, &token))
            .map(|r| r.subject)
            .ok_or_else(|| bearer_authentication("Access token is unknown or expired", None))?;
        let mut ticket_bytes = Zeroizing::new([0u8; 128]);
        let (ticket, uri) = oidc::parse_access_token(&token, &mut ticket_bytes)?;
        if oidc::issuer(ticket)? != subject {
            return Err(bearer_authentication("Ticket issuer mismatch", None));
        }
        let mut client = Client::new(
            self.instances.reclaim,
            self.sources.reclaim.duplicate()?,
            self.limits.reclaim,
        )?;
        let operation = client.consume_ticket(ticket, uri, until)?;
        let reply = crate::reclaim::reclaim_reply(&mut client, operation, hard).await?;
        match reply.view()? {
            ipc::Response::Consumed {
                result,
                identity,
                attributes,
                presentations,
                ..
            } => {
                match self.consume_profile.validate(result, identity, subject) {
                    Ok(()) => {}
                    Err(Error::Consume {
                        cause: crate::ConsumeFailure::Denied,
                        ..
                    }) => {
                        return Err(bearer_authentication(
                            "Actual ticket authorization was denied",
                            Some(result),
                        ));
                    }
                    Err(error) => return Err(error),
                }
                let response = (|| -> Result<Response, Error> {
                    let completed_now = provider.now()?;
                    if !provider.state.borrow().accesses.iter().flatten().any(|r| {
                        r.bound.live(completed_now)
                            && equal(&r.token, &token)
                            && r.subject == subject
                    }) {
                        return Err(bearer_authentication(
                            "Original access token expired during processing",
                            Some(result),
                        ));
                    }
                    let body = claims::payload(
                        attributes,
                        presentations,
                        subject,
                        &provider.origin,
                        None,
                        self.limits.output_bytes,
                    )?;
                    let mut response =
                        Response::json(body).header(b"Cache-Control", b"no-store")?;
                    response.service_status = Some(i64::from(result));
                    Ok(response)
                })();
                response.map_err(|original| Error::ConsumeReply {
                    raw: result,
                    original: Box::new(original),
                })
            }
            _ => Err(Fault::Malformed.into()),
        }
    }
}
fn cookie_identity(cookie: Option<&[u8]>) -> Result<Option<&[u8]>, Error> {
    let mut found = None;
    for pair in cookie.unwrap_or(&[]).split(|b| *b == b';') {
        let pair = pair.trim_ascii();
        let Some(eq) = pair.iter().position(|b| *b == b'=') else {
            continue;
        };
        if &pair[..eq] == b"Identity" {
            if found.is_some() {
                return Err(Fault::Conflict.into());
            }
            found = Some(&pair[eq + 1..]);
        }
    }
    Ok(found)
}
struct Credentials {
    client: Zeroizing<Vec<u8>>,
    secret: Zeroizing<Vec<u8>>,
}
fn basic_credentials(input: Option<&[u8]>, cap: usize) -> Result<Option<Credentials>, Error> {
    let Some(input) = input else { return Ok(None) };
    let at = input
        .iter()
        .position(|b| *b == b' ')
        .ok_or_else(|| client_authentication("Malformed Basic client authentication"))?;
    if !input[..at].eq_ignore_ascii_case(b"Basic") {
        return Err(client_authentication(
            "Expected Basic client authentication",
        ));
    }
    let mut raw = bytes(cap)?;
    let n = crate::http::decode_basic(&input[at + 1..], &mut raw)
        .ok_or_else(|| client_authentication("Malformed Basic client authentication"))?;
    let colon = raw[..n]
        .iter()
        .position(|b| *b == b':')
        .ok_or_else(|| client_authentication("Malformed Basic client authentication"))?;
    Ok(Some(Credentials {
        client: copy(&raw[..colon])?,
        secret: copy(&raw[colon + 1..n])?,
    }))
}

#[cfg(test)]
mod lifecycle_tests;
