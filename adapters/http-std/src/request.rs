use crate::{Error, Fault};
use bytes::Bytes;
use std::{cell::Cell, fmt, rc::Rc};
use zeroize::Zeroizing;

/// Caller-owned allocation domain. Slots may reuse it without reviving an old job.
pub struct Instance {
    domain: Rc<()>,
    next: Cell<u64>,
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
impl Instance {
    /// New independent domain with checked serial allocation and no global state.
    pub fn new() -> Self {
        Self {
            domain: Rc::new(()),
            next: Cell::new(1),
        }
    }
    fn allocate(&self) -> Result<Job, Error> {
        let serial = self.next.get();
        let next = serial.checked_add(1).ok_or(Fault::Overflow)?;
        self.next.set(next);
        Ok(Job {
            domain: self.domain.clone(),
            serial,
        })
    }
}
/// Original request identity, never reconstructed from a URL or replacement IO.
#[derive(Clone)]
pub struct Job {
    domain: Rc<()>,
    serial: u64,
}
impl PartialEq for Job {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &other.domain) && self.serial == other.serial
    }
}
impl Eq for Job {}
impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HttpJob")
            .field(&Rc::as_ptr(&self.domain))
            .field(&self.serial)
            .finish()
    }
}
/// Only operations used by this library's concrete consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    /// Safe GET with a bounded response body.
    Get,
    /// HEAD, with no entity body consumed regardless of Content-Length.
    Head,
    /// Bounded SOAP POST. Never automatically redirected or replayed.
    SoapPost,
}
impl Method {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::SoapPost => "POST",
        }
    }
}
/// Explicit safe-method redirect policy. POST rejects Follow at construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Redirects {
    /// Return the original actual response, including redirect status/body.
    None,
    /// GET/HEAD only: at most the configured transport cap, no HTTPS downgrade.
    Follow,
}
struct Body(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for Body {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
pub(crate) struct Data {
    pub job: Job,
    pub uri: Zeroizing<Vec<u8>>,
    pub until: u64,
    pub method: Method,
    pub redirects: Redirects,
    pub action: Option<Zeroizing<Vec<u8>>>,
    pub body: Bytes,
    pub admitted: Cell<bool>,
}
/// Immutable bounded original request. Clone shares exactly one zeroizing body,
/// URI and allocation identity; it does not replay or renew the original request.
#[derive(Clone)]
pub struct Request(pub(crate) Rc<Data>);
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("job", &self.0.job)
            .field("method", &self.0.method)
            .field("until", &self.0.until)
            .field("uri", &"[redacted]")
            .field("body_bytes", &self.0.body.len())
            .finish()
    }
}
fn copy(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut data = Vec::new();
    data.try_reserve_exact(input.len())
        .map_err(|_| Fault::Capacity)?;
    data.extend_from_slice(input);
    Ok(Zeroizing::new(data))
}
impl Request {
    fn build(
        instance: &Instance,
        uri: &[u8],
        until: u64,
        method: Method,
        redirects: Redirects,
        soap: Option<(&[u8], &[u8])>,
    ) -> Result<Self, Error> {
        if until == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        crate::validate_uri(uri)?;
        let (action, body) = if let Some((action, body)) = soap {
            if action.is_empty()
                || action.len() > 256
                || !action
                    .iter()
                    .all(|b| b.is_ascii_graphic() && *b != b'"' && *b != b'\\')
                || body.len() > 1024 * 1024
            {
                return Err(Fault::InvalidInput.into());
            }
            (Some(copy(action)?), Bytes::from_owner(Body(copy(body)?)))
        } else {
            (None, Bytes::new())
        };
        let uri = copy(uri)?;
        let job = instance.allocate()?;
        Ok(Self(Rc::new(Data {
            job,
            uri,
            until,
            method,
            redirects,
            action,
            body,
            admitted: Cell::new(false),
        })))
    }
    /// New actual GET intent. A later Client owns its single transport admission.
    pub fn get(
        instance: &Instance,
        uri: &[u8],
        until: u64,
        redirects: Redirects,
    ) -> Result<Self, Error> {
        Self::build(instance, uri, until, Method::Get, redirects, None)
    }
    /// New actual HEAD intent, with the same explicit safe redirect policy.
    pub fn head(
        instance: &Instance,
        uri: &[u8],
        until: u64,
        redirects: Redirects,
    ) -> Result<Self, Error> {
        Self::build(instance, uri, until, Method::Head, redirects, None)
    }
    /// New SOAP POST intent. The exact original action/body are copied once into
    /// zeroizing owners. Even a 307/308 response cannot authorize automatic replay.
    pub fn soap(
        instance: &Instance,
        uri: &[u8],
        until: u64,
        action: &[u8],
        body: &[u8],
    ) -> Result<Self, Error> {
        Self::build(
            instance,
            uri,
            until,
            Method::SoapPost,
            Redirects::None,
            Some((action, body)),
        )
    }
    /// Original allocation identity.
    pub fn job(&self) -> &Job {
        &self.0.job
    }
    /// Explicit raw configured URL; never implicitly printed or persisted.
    pub fn uri(&self) -> &[u8] {
        &self.0.uri
    }
    /// Original absolute logical target, not a relative TTL.
    pub fn until(&self) -> u64 {
        self.0.until
    }
    /// Actual immutable method.
    pub fn method(&self) -> Method {
        self.0.method
    }
    /// Explicit safe-method redirect policy.
    pub fn redirects(&self) -> Redirects {
        self.0.redirects
    }
}
