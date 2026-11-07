use gnunet_types::Error as Fault;
use zeroize::Zeroizing;
/// Authentication challenge selected by the actual OAuth flow owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthChallenge {
    /// Client authentication at the token endpoint.
    ClientBasic,
    /// Access-token authentication at the protected UserInfo endpoint.
    ResourceBearer,
}
/// Original handler failure. Sensitive input and backend replies are redacted.
#[derive(Debug)]
pub enum Error {
    /// Pure validation/resource/clock failure.
    Core(Fault),
    /// Original shared canonical clock failure, requiring all host jobs to close.
    Clock(Fault),
    /// Exact shared CONFIG validation/serialization failure.
    Configuration(gnunet_config::Error),
    /// Original CONFIG job publication/visible state is uncertain.
    ConfigurationUnknown,
    /// Original shared file writer cause and independently reported cleanup.
    ConfigurationWrite(std::sync::Arc<crate::config::worker::Failure>),
    /// Retained original CONFIG uncertainty even when its HTTP callback dropped.
    ConfigurationFailure(std::sync::Arc<Error>),
    /// Exact owned OIDC snapshot/source failure, without private operands.
    #[cfg(feature = "oidc")]
    OidcPersistence(std::sync::Arc<crate::oidc::persistence::Failure>),
    /// The original name does not resolve to a configured GNS zone.
    GnsNotFound,
    /// Original GNS native query source loss, without replay.
    GnsSource(gnunet_gns_client_host::LossCause),
    /// Original IDENTITY physical source failure.
    IdentitySource(gnunet_identity_client_host::LossCause),
    /// Original NAMESTORE physical source failure.
    NamestoreSource(gnunet_namestore_client_host::LossCause),
    /// Original RECLAIM physical source failure.
    ReclaimSource(gnunet_reclaim_client_host::LossCause),
    /// Actual locally retired IDENTITY operation with original exposure.
    IdentityRetired {
        /// Actual original local retirement reason.
        reason: gnunet_identity_client_host::LocalReason,
        /// Actual exposure of the original native request.
        submission: gnunet_identity_client_host::Submission,
        /// Actual late service result, if one was received.
        result_code: Option<u32>,
    },
    /// Actual locally retired NAMESTORE operation with original exposure.
    NamestoreRetired {
        /// Actual original local retirement reason.
        reason: gnunet_namestore_client_host::LocalReason,
        /// Actual exposure of the original native request.
        submission: gnunet_namestore_client_host::Submission,
    },
    /// Actual locally retired RECLAIM operation with original exposure.
    ReclaimRetired {
        /// Actual original local retirement reason.
        reason: gnunet_reclaim_client_host::LocalReason,
        /// Actual exposure of the original native request.
        submission: gnunet_reclaim_client_host::Submission,
    },
    /// Actual raw RECLAIM service failure word, without byte normalization.
    Status(i64),
    /// Actual original consume reply, retaining its complete raw result word.
    Consume {
        /// Original BE32-decoded service word, without normalization.
        raw: u32,
        /// Exact selected-source classification or issuer mismatch.
        cause: crate::ConsumeFailure,
    },
    /// A real consume reply was received before subsequent local processing
    /// failed. This is never constructed for a source failure without a reply.
    ConsumeReply {
        /// Complete original raw result word from that actual reply.
        raw: u32,
        /// Original formatting, resource or clock cause, without replacement.
        original: Box<Error>,
    },
    /// Actual HTTP socket I/O failure, independent of native service outcomes.
    Io(std::io::Error),
    /// Actual native connection/client error.
    Native(gnunet_client_host::ConnectError),
    /// An actual source stopped; no replacement source is used by this job.
    SourceLost,
    /// Original finite native or logical deadline expired.
    Deadline,
    /// Actual service error code, preserved without a fabricated success.
    Service(u32),
    /// An actual native completion was local retirement, not a service reply.
    Retired,
    /// Original OAuth endpoint error without private operands.
    OAuth {
        /// Actual endpoint-selected HTTP status.
        status: u16,
        /// Public OAuth error identifier, without private operands.
        error: &'static str,
        /// Public bounded explanation, without private operands.
        description: &'static str,
        /// Challenge selected by the original token/resource flow, if any.
        challenge: Option<OAuthChallenge>,
        /// Original consume service word, when an actual reply was received.
        service_status: Option<i64>,
    },
    /// A public route requires an explicitly unconnected capability.
    Capability,
    /// Original credential plugin family/type/stage failure, without payload.
    Credential(gnunet_reclaim_credentials::Failure),
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Core(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Native(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "REST handler: {self:?}")
    }
}
impl Error {
    pub(crate) fn service_status(&self) -> Option<i64> {
        match self {
            Self::Status(raw) => Some(*raw),
            Self::Consume { raw, .. } | Self::ConsumeReply { raw, .. } => Some(i64::from(*raw)),
            Self::OAuth { service_status, .. } => *service_status,
            _ => None,
        }
    }
    pub(crate) fn clock_failure(&self) -> Option<Fault> {
        match self {
            Self::Clock(error) => Some(*error),
            Self::ConsumeReply { original, .. } => original.clock_failure(),
            _ => None,
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConsumeReply { original, .. } => Some(original.as_ref()),
            _ => None,
        }
    }
}
pub(crate) fn bytes(n: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    v.resize(n, 0);
    Ok(Zeroizing::new(v))
}
pub(crate) fn copy(b: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut v = bytes(b.len())?;
    v.copy_from_slice(b);
    Ok(v)
}
pub(crate) fn decoded(s: gnunet_json::JsonString<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = bytes(s.decoded_len()?)?;
    s.decode(&mut out)?;
    Ok(out)
}
pub(crate) struct Json {
    pub bytes: Zeroizing<Vec<u8>>,
    cap: usize,
}
impl Json {
    pub fn new(cap: usize) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(cap).map_err(|_| Fault::Capacity)?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            cap,
        })
    }
    pub fn raw(&mut self, b: &[u8]) -> Result<(), Error> {
        let n = self
            .bytes
            .len()
            .checked_add(b.len())
            .ok_or(Fault::Overflow)?;
        if n > self.cap {
            return Err(Fault::Capacity.into());
        }
        self.bytes.extend_from_slice(b);
        Ok(())
    }
    pub fn string(&mut self, b: &[u8]) -> Result<(), Error> {
        let s = std::str::from_utf8(b).map_err(|_| Fault::Malformed)?;
        let n = gnunet_json::string_len(s)?;
        let start = self.bytes.len();
        let end = start.checked_add(n).ok_or(Fault::Overflow)?;
        if end > self.cap {
            return Err(Fault::Capacity.into());
        }
        self.bytes.resize(end, 0);
        gnunet_json::write_string(s, &mut self.bytes[start..])?;
        Ok(())
    }
    pub fn number(&mut self, mut n: u64) -> Result<(), Error> {
        if n == u64::MAX {
            return self.raw(b"-1");
        }
        let mut out = [0u8; 20];
        let mut start = out.len();
        loop {
            start -= 1;
            out[start] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.raw(&out[start..])
    }
    pub fn base32(&mut self, b: &[u8]) -> Result<(), Error> {
        let mut out = bytes(gnunet_rest::text::encoded_len(b.len())?)?;
        let n = gnunet_rest::text::encode(b, &mut out)?;
        self.string(&out[..n])
    }
    pub fn boolean(&mut self, b: bool) -> Result<(), Error> {
        self.raw(if b { b"true" } else { b"false" })
    }
}
pub(crate) fn service(code: u32) -> Error {
    Error::Service(code)
}

pub(crate) fn parse<T>(
    input: &[u8],
    limits: gnunet_json::Limits,
    f: impl for<'v> FnOnce(gnunet_json::Value<'v>) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut payload = bytes(limits.bytes)?;
    let mut tokens = Vec::new();
    tokens
        .try_reserve_exact(limits.nodes)
        .map_err(|_| Fault::Capacity)?;
    tokens.resize(limits.nodes, gnunet_json::Token::EMPTY);
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(limits.depth)
        .map_err(|_| Fault::Capacity)?;
    stack.resize(limits.depth, gnunet_json::Nest::EMPTY);
    let mut workspace = gnunet_json::Workspace::new(&mut payload, &mut tokens, &mut stack);
    let doc = workspace.parse(input, limits)?;
    f(doc.root())
}

impl From<gnunet_reclaim_credentials::Failure> for Error {
    fn from(e: gnunet_reclaim_credentials::Failure) -> Self {
        Self::Credential(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<gnunet_config::Error> for Error {
    fn from(e: gnunet_config::Error) -> Self {
        Self::Configuration(e)
    }
}
