//! Actual shared mature HTTP/HTTPS IGD transport. The original caller Gate,
//! Resolver and retained mutation progress remain owned by the NAT job; no pools,
//! default DNS, automatic SOAP redirects or mutation replay are introduced.
use crate::{Error, deadline::Gate};
use gnunet_client_host::resolution::SharedResolution;
use gnunet_http_host::{Client, Instance, Progress, Redirects, Request, Tls};
pub use gnunet_http_host::{Response, Snapshot as Exposure};
use gnunet_types::Error as Fault;
use std::{cell::RefCell, rc::Rc};

/// Explicit original IGD resources. Existing byte/address meanings are retained.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum request/status/header bytes; mature parser requires at least8192.
    pub headers: usize,
    /// Maximum bounded decoded response and SOAP request body bytes.
    pub body: usize,
    /// Actual native bytes per direction, including TLS handshake/ciphertext.
    pub wire: usize,
    /// Maximum actual original Resolver address/socket attempts.
    pub addresses: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            headers: 8192,
            body: 65536,
            wire: 262144,
            addresses: 32,
        }
    }
}
/// Validated absolute HTTP or HTTPS device target. Userinfo/control input is
/// refused; ordinary HTTPS always validates the actual hostname/certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Url {
    canonical: String,
    host: String,
    port: u16,
    target: String,
}
impl Url {
    /// Parse a bounded device URL with the shared mature URL implementation.
    pub fn parse(input: &str) -> Result<Self, Error> {
        if input.len() > 2048 {
            return Err(Fault::TooLarge.into());
        }
        let mut parsed = gnunet_http_host::validate_uri(input.as_bytes())?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(Fault::InvalidInput.into());
        }
        parsed.set_fragment(None);
        let host = parsed.host_str().ok_or(Fault::Malformed)?;
        let host = if host.starts_with('[') && host.ends_with(']') {
            &host[1..host.len() - 1]
        } else {
            host
        };
        let port = parsed.port_or_known_default().ok_or(Fault::Malformed)?;
        if host.is_empty() || host.len() > 253 || port == 0 {
            return Err(Fault::InvalidInput.into());
        }
        let mut target = parsed.path().to_owned();
        if target.is_empty() {
            target.push('/')
        }
        if let Some(query) = parsed.query() {
            target.push('?');
            target.push_str(query)
        }
        Ok(Self {
            canonical: parsed.as_str().to_owned(),
            host: host.to_owned(),
            port,
            target,
        })
    }
    /// Resolve the actual descriptor's URLBase/controlURL, preserving HTTPS.
    pub fn join(&self, relative: &str) -> Result<Self, Error> {
        if relative.len() > 2048 || relative.chars().any(|c| c.is_control() || c == ' ') {
            return Err(Fault::InvalidInput.into());
        }
        let base = gnunet_http_host::validate_uri(self.canonical.as_bytes())?;
        let result = base.join(relative).map_err(gnunet_http_host::Error::from)?;
        Self::parse(result.as_str())
    }
    /// Actual canonical hostname used by the explicit shared Resolver.
    pub fn host(&self) -> &str {
        &self.host
    }
    /// Actual original HTTP(S) destination TCP port.
    pub const fn port(&self) -> u16 {
        self.port
    }
    /// Actual bounded origin-form target, including query.
    pub fn target(&self) -> &str {
        &self.target
    }
    /// Exact canonical original target; no implicit resolver/connection is run.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}
/// Retained original mutation evidence. A single immutable HTTP owner binds once;
/// cancellation does not reset it or convert TLS buffering into a TCP write ACK.
#[derive(Clone, Default)]
pub struct Written(Rc<RefCell<Option<Progress>>>);
impl Written {
    fn bind(&self, progress: Progress) -> Result<(), Error> {
        let mut slot = self.0.borrow_mut();
        if slot.is_some() {
            return Err(Fault::Conflict.into());
        }
        *slot = Some(progress);
        Ok(())
    }
    /// Exact actual native socket bytes after original HTTP dispatch; under TLS
    /// these are ciphertext/framing, never an exact HTTP plaintext prefix.
    pub fn bytes(&self) -> usize {
        self.exposure().map_or(0, |e| e.socket_after_dispatch)
    }
    /// Original stages remain distinct: owner queue, dispatch call, actual write
    /// attempt, TLS/plaintext acceptance, native socket count and full response.
    pub fn exposure(&self) -> Option<Exposure> {
        self.0.borrow().as_ref().map(Progress::snapshot)
    }
    /// Possible application outcome even when no TCP count was returned. This
    /// preserves conservative unknown cleanup after TLS accepted plaintext or an
    /// opaque stream write was actually polled; queueing alone is not exposure.
    pub fn may_have_exposed(&self) -> bool {
        self.exposure().is_some_and(Exposure::may_have_exposed)
    }
}
/// Concrete original exchange using an explicitly owned standard verified TLS
/// config. SOAP POST never follows redirects/retries, including307/308. GET also
/// preserves the previous NAT no-redirect policy and its descriptor base target.
pub async fn exchange_with_tls(
    resolver: &SharedResolution,
    gate: &mut Gate,
    url: &Url,
    soap: Option<(&str, &[u8])>,
    written: &Written,
    limits: Limits,
    tls: Tls,
) -> Result<Response, Error> {
    observed_with_tls(
        resolver,
        gate,
        Exchange { url, soap },
        written,
        limits,
        tls,
        &mut |_| {},
    )
    .await?
    .into_result()
}
pub(crate) struct ObservedResponse {
    pub response: Response,
    pub post_guard: Option<Error>,
}
impl ObservedResponse {
    fn into_result(self) -> Result<Response, Error> {
        match self.post_guard {
            Some(error) => Err(error),
            None => Ok(self.response),
        }
    }
}
struct Exchange<'a> {
    url: &'a Url,
    soap: Option<(&'a str, &'a [u8])>,
}
async fn observed_with_tls(
    resolver: &SharedResolution,
    gate: &mut Gate,
    request: Exchange<'_>,
    written: &Written,
    limits: Limits,
    tls: Tls,
    observe: &mut impl FnMut(&Response),
) -> Result<ObservedResponse, Error> {
    let Exchange { url, soap } = request;
    gate.check()?;
    if !std::sync::Arc::ptr_eq(&resolver.clock(), gate.clock()) {
        return Err(Fault::InvalidInput.into());
    }
    let bounds = gate.bounds();
    let domain = Instance::new();
    let request = if let Some((action, body)) = soap {
        if body.len() > limits.body {
            return Err(Fault::Capacity.into());
        }
        Request::soap(
            &domain,
            url.as_str().as_bytes(),
            bounds.expires,
            action.as_bytes(),
            body,
        )?
    } else {
        Request::get(
            &domain,
            url.as_str().as_bytes(),
            bounds.expires,
            Redirects::None,
        )?
    };
    let profile = gnunet_http_host::HttpLimits {
        uri_bytes: 2048,
        body_bytes: limits.body,
        request_body_bytes: limits.body.min(1024 * 1024),
        wire_bytes: limits.wire,
        probes: limits.addresses,
        headers: 64,
        header_bytes: limits.headers,
        frames: limits.wire.clamp(1, 65536),
        redirects: 0,
    };
    let mut client = Client::new(request, resolver.clone(), tls, None, profile, bounds.hard)?;
    written.bind(client.progress())?;
    // Borrowed exchange future lives inside the original NAT Job future. Dropping
    // it actually drops this exclusive Client/connection, with evidence retained
    // in Written. Its hard/until are exactly the supplied parent's targets.
    let observed = std::future::poll_fn(|cx| client.poll_observed(cx, observe)).await?;
    let post_guard = match observed.post_guard {
        Some(error) => Some(Error::from(error)),
        None => gate.check().err(),
    };
    Ok(ObservedResponse {
        response: observed.response,
        post_guard,
    })
}
/// Same original driver/bounds; the callback only observes complete bytes and
/// must not perform IO, sample clocks or infer permission to continue.
pub(crate) async fn exchange_observed(
    resolver: &SharedResolution,
    gate: &mut Gate,
    url: &Url,
    soap: Option<(&str, &[u8])>,
    written: &Written,
    limits: Limits,
    observe: &mut impl FnMut(&Response),
) -> Result<ObservedResponse, Error> {
    gate.check()?;
    observed_with_tls(
        resolver,
        gate,
        Exchange { url, soap },
        written,
        limits,
        Tls::new()?,
        observe,
    )
    .await
}
/// Actual GET/SOAP exchange with a fresh owned normal wall-clock TLS config.
/// The caller may reuse an explicit config through exchange_with_tls; neither
/// entry installs global providers, client keys, tasks, pools or default DNS.
pub async fn exchange(
    resolver: &SharedResolution,
    gate: &mut Gate,
    url: &Url,
    soap: Option<(&str, &[u8])>,
    written: &Written,
    limits: Limits,
) -> Result<Response, Error> {
    gate.check()?;
    exchange_with_tls(resolver, gate, url, soap, written, limits, Tls::new()?).await
}
