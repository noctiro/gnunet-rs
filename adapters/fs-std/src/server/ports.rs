//! Retained native dependencies for an independently driven Rust FS service.
//!
//! One original DATASTORE GET or PILS LOC signature belongs to its port until
//! an actual terminal result or physical retirement. Dropped poll waits do not
//! replace streams, recreate requests, replay signatures or manufacture END.
use gnunet_client_host::ConnectError;
use gnunet_datastore_host::{
    Client as DatastoreClient, Interruption, Loss as DatastoreLoss, Operation, Outcome, Step,
};
use gnunet_fs::{Content, Location};
use gnunet_pils::client::{Completion, Failure, Identity, Inbound, KeyTarget, OperationId};
use gnunet_pils_host::client::{Client as PilsClient, LossCause, Progress as PilsProgress};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::{Duration as Timeout, Error as ProtocolError};
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::{Request, Response},
};
use std::{
    fmt,
    future::Future,
    task::{Context, Poll},
};

/// Original dependency refusal. Wire absence is never inferred from these errors.
#[derive(Debug)]
pub enum Error {
    /// Actual DATASTORE configuration, native or protocol failure.
    Datastore(ConnectError),
    /// Actual PILS configuration, native or protocol failure.
    Signer(ConnectError),
    /// Explicit local admission or original-owner invariant refusal.
    Protocol(ProtocolError),
    /// The actual original DATASTORE connection was physically retired.
    DatastoreLost(DatastoreLoss),
    /// One DATASTORE GET settled without an uninterrupted actual DATA/END reply.
    DatastoreOperation {
        /// Original typed outcome, independent of a later retry or new lookup.
        outcome: Outcome,
        /// Original timeout/cancellation, even if a real late reply was received.
        interruption: Option<Interruption>,
        /// Original socket/connection attempt cause, when there was one.
        cause: Option<Box<Error>>,
        /// Actual late/terminal reply bytes, including interrupted STATUS results.
        reply: Option<RetainedReply>,
    },
    /// Actual cleanup STATUS did not confirm successful removal.
    RemoveRefused(RetainedReply),
    /// Original PILS MQ loss; an admitted signature is not sent again.
    SignerLost {
        /// Actual source of physical or validation retirement.
        cause: LossCause,
        /// Actual crypto requests retained by PILS before this port retires them.
        retained_crypto: usize,
    },
    /// Actual typed PILS completion refusal.
    SigningRefused(Failure),
    /// Physical cleanup independently failed while preserving the original cause.
    Retirement {
        /// Original failed operation/driver cause.
        cause: Box<Error>,
        /// Independent physical retirement or original completion cleanup failure.
        cleanup: Box<Error>,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Datastore(error) => write!(formatter, "FS DATASTORE: {error}"),
            Self::Signer(error) => write!(formatter, "FS PILS signer: {error}"),
            Self::Protocol(error) => write!(formatter, "FS dependency port: {error}"),
            Self::DatastoreLost(cause) => write!(formatter, "FS DATASTORE MQ retired: {cause:?}"),
            Self::DatastoreOperation {
                outcome,
                interruption,
                cause,
                ..
            } => {
                write!(
                    formatter,
                    "FS DATASTORE lookup {outcome:?}, interruption {interruption:?}"
                )?;
                if let Some(cause) = cause {
                    write!(formatter, ": {cause}")?;
                }
                Ok(())
            }
            Self::RemoveRefused(reply) => match reply.response() {
                Ok(Response::Status(status)) => {
                    write!(formatter, "FS on-demand cleanup STATUS {}", status.code)
                }
                _ => formatter.write_str("FS on-demand cleanup malformed STATUS"),
            },
            Self::SignerLost {
                cause,
                retained_crypto,
            } => write!(
                formatter,
                "FS PILS MQ retired ({retained_crypto} retained crypto requests): {cause:?}"
            ),
            Self::SigningRefused(reason) => {
                write!(formatter, "FS PILS signature refused: {reason:?}")
            }
            Self::Retirement { cause, cleanup } => {
                write!(formatter, "{cause}; original dependency cleanup: {cleanup}")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Datastore(error) | Self::Signer(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::DatastoreLost(DatastoreLoss::Io(error)) => Some(error),
            Self::DatastoreLost(DatastoreLoss::Protocol(error)) => Some(error),
            Self::DatastoreOperation { cause, .. } => cause
                .as_deref()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            Self::SignerLost {
                cause: LossCause::Io(error),
                ..
            } => Some(error),
            Self::SignerLost {
                cause: LossCause::Protocol(error) | LossCause::Resource(error),
                ..
            } => Some(error),
            Self::SignerLost {
                cause: LossCause::Setup(error),
                ..
            } => Some(error),
            Self::Retirement { cause, .. } => Some(cause.as_ref()),
            _ => None,
        }
    }
}
impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Original owned DATASTORE reply, retained without another allocation.
pub struct RetainedReply(OwnedFrame);
impl fmt::Debug for RetainedReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedReply")
            .field("bytes", &self.0.len())
            .finish()
    }
}
impl RetainedReply {
    /// Retain original received bytes without asserting authenticity or success.
    /// The enclosing provider remains responsible for its original operation.
    #[must_use]
    pub fn from_frame(frame: OwnedFrame) -> Self {
        Self(frame)
    }
    /// Original immutable official frame bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }
    /// Borrow actual service fields; no backend error is inferred from STATUS0.
    pub fn response(&self) -> Result<Response<'_>, ProtocolError> {
        Response::decode(self.bytes())
    }
}
impl Error {
    /// Actual original operation certainty, through independent cleanup errors.
    #[must_use]
    pub fn outcome(&self) -> Option<Outcome> {
        match self {
            Self::DatastoreOperation { outcome, .. } => Some(*outcome),
            Self::Retirement { cause, cleanup } => cause.outcome().or_else(|| cleanup.outcome()),
            _ => None,
        }
    }
}

/// Owned public DATASTORE selection. It contains no FS client/query authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lookup {
    /// Exact original query key; some block types do not use a ciphertext hash.
    pub key: [u8; 64],
    /// Actual DATASTORE type; zero permits on-demand fallback/wildcard selection.
    pub kind: u32,
    /// Inclusive stable backend UID cursor, without implicit wraparound.
    pub next_uid: u64,
}
/// A bounded native lookup step; only an actual DATA_END yields Complete(None).
pub enum LookupProgress {
    /// Actual native connection, I/O, retry or original deadline progress.
    Activity,
    /// Original actual DATA frame, or None for its actual DATA_END response.
    Complete(Option<OwnedFrame>),
    /// Actual terminal STATUS for one exact original key/value removal.
    Removed(RetainedReply),
}
/// Original local store-port lifecycle, independent of native connectivity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreState {
    /// This custom port supplies no lifecycle observation; not proof of health.
    Unreported,
    /// This local owner has not been permanently retired. It may be busy,
    /// disconnected or retrying; no query success or socket readiness is implied.
    Open,
    /// The original owner was permanently physically retired and cannot admit
    /// future work. Reusing it requires explicit replacement by its supervisor.
    Closed,
}
/// One serialized store dependency, driven by its enclosing FS owner.
pub trait StorePort {
    /// Observe original local lifecycle without IO, recovery or a fabricated
    /// connection/success claim. Custom ports may explicitly leave it unknown.
    fn state(&self) -> StoreState {
        StoreState::Unreported
    }
    /// Admit one original lookup; Conflict leaves any existing original untouched.
    fn start(&mut self, lookup: Lookup) -> Result<(), Error>;
    /// Admit exact service-owned invalid type6 cleanup. Readonly custom ports
    /// may refuse explicitly; no successful removal is fabricated.
    fn start_remove(&mut self, _key: &[u8; 64], _value: &[u8]) -> Result<(), Error> {
        Err(ProtocolError::Unsupported.into())
    }
    /// Drive original work. No active lookup is Pending rather than invented END.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<LookupProgress, Error>>;
    /// Physically close original I/O and explicitly retire its original result.
    fn close(&mut self) -> Result<(), Error>;
}
struct ActiveLookup<'id> {
    operation: Operation<'id>,
    lookup: Option<Lookup>,
    cause: Option<Box<Error>>,
}
/// Dedicated existing official DATASTORE client, retaining its actual GET token.
/// Normal MQ loss settles that token before a later explicit start may reconnect.
/// Faulty setup/driver invariants are physically closed and require a new port.
pub struct Datastore<'id, 'slots, 'buffers> {
    client: DatastoreClient<'id, 'slots, 'buffers>,
    timeout: Timeout,
    active: Option<ActiveLookup<'id>>,
    closed: bool,
}
impl<'id, 'slots, 'buffers> Datastore<'id, 'slots, 'buffers> {
    /// Consume one independent idle client and its finite per-lookup timeout.
    /// This opens no socket and creates no Resolver, task or replacement clock.
    pub fn new(
        client: DatastoreClient<'id, 'slots, 'buffers>,
        timeout: Timeout,
    ) -> Result<Self, Error> {
        if client.pending() != 0 || client.retained_replies() != (0, 0) {
            return Err(ProtocolError::Conflict.into());
        }
        if timeout.0 == 0
            || timeout.0 == u64::MAX
            || timeout.0 > client.protocol_limits().max_lifetime.0
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        Ok(Self {
            client,
            timeout,
            active: None,
            closed: false,
        })
    }
    /// Original retained selection, without granting the enclosing query identity.
    #[must_use]
    pub fn active(&self) -> Option<Lookup> {
        self.active.as_ref().and_then(|active| active.lookup)
    }
    fn completed(&mut self) -> Result<Option<LookupProgress>, Error> {
        let Some(operation) = self.active.as_ref().map(|active| active.operation) else {
            return Ok(None);
        };
        let taken = match self.client.take(operation) {
            Ok(taken) => taken,
            Err(ConnectError::Protocol(ProtocolError::NotReady)) => return Ok(None),
            Err(error) => return Err(Error::Datastore(error)),
        };
        let active = self.active.take().ok_or(ProtocolError::Stale)?;
        let outcome = taken.completion.outcome;
        let interruption = taken.completion.interruption;
        let expected = if active.lookup.is_some() {
            matches!(outcome, Outcome::Data { .. } | Outcome::NotFound)
        } else {
            matches!(outcome, Outcome::Status { .. })
        };
        if interruption.is_some() || !expected {
            return Err(Error::DatastoreOperation {
                outcome,
                interruption,
                cause: active.cause,
                reply: taken.into_frame().map(RetainedReply),
            });
        }
        let frame = taken.into_frame().ok_or(ProtocolError::Malformed)?;
        match (
            active.lookup.is_some(),
            outcome,
            Response::decode(frame.bytes())?,
        ) {
            (true, Outcome::Data { .. }, Response::Data(_)) => {
                Ok(Some(LookupProgress::Complete(Some(frame))))
            }
            (true, Outcome::NotFound, Response::End) => Ok(Some(LookupProgress::Complete(None))),
            (false, Outcome::Status { code, .. }, Response::Status(status))
                if code == status.code =>
            {
                Ok(Some(LookupProgress::Removed(RetainedReply(frame))))
            }
            _ => Err(ProtocolError::Malformed.into()),
        }
    }
    fn fail_closed(&mut self, mut cause: Error) -> Error {
        self.closed = true;
        let active = self.active.take();
        if let Err(error) = self.client.close() {
            cause = Error::Retirement {
                cause: Box::new(cause),
                cleanup: Box::new(Error::Datastore(error)),
            };
        }
        if let Some(active) = active {
            match self.client.take(active.operation) {
                Ok(taken) => {
                    return Error::DatastoreOperation {
                        outcome: taken.completion.outcome,
                        interruption: taken.completion.interruption,
                        cause: Some(Box::new(cause)),
                        reply: taken.into_frame().map(RetainedReply),
                    };
                }
                Err(error) => {
                    cause = Error::Retirement {
                        cause: Box::new(cause),
                        cleanup: Box::new(Error::Datastore(error)),
                    }
                }
            }
        }
        cause
    }
}
impl StorePort for Datastore<'_, '_, '_> {
    fn state(&self) -> StoreState {
        if self.closed {
            StoreState::Closed
        } else {
            StoreState::Open
        }
    }
    fn start(&mut self, lookup: Lookup) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if self.active.is_some() {
            return Err(ProtocolError::Conflict.into());
        }
        let operation = self
            .client
            .submit(
                Request::Get {
                    key: Some(&lookup.key),
                    kind: lookup.kind,
                    next_uid: lookup.next_uid,
                    random: false,
                },
                None,
                self.timeout,
            )
            .map_err(Error::Datastore)?;
        self.active = Some(ActiveLookup {
            operation,
            lookup: Some(lookup),
            cause: None,
        });
        Ok(())
    }
    fn start_remove(&mut self, key: &[u8; 64], value: &[u8]) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if self.active.is_some() {
            return Err(ProtocolError::Conflict.into());
        }
        let operation = self
            .client
            .submit(Request::Remove { key, value }, None, self.timeout)
            .map_err(Error::Datastore)?;
        self.active = Some(ActiveLookup {
            operation,
            lookup: None,
            cause: None,
        });
        Ok(())
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<LookupProgress, Error>> {
        if self.active.is_none() {
            return Poll::Pending;
        }
        match self.completed() {
            Ok(Some(result)) => return Poll::Ready(Ok(result)),
            Ok(None) => {}
            Err(error @ Error::DatastoreOperation { .. }) => return Poll::Ready(Err(error)),
            Err(error) => return Poll::Ready(Err(self.fail_closed(error))),
        }
        let step = {
            let mut driving = std::pin::pin!(self.client.drive(None));
            driving.as_mut().poll(cx)
        };
        match step {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail_closed(Error::Datastore(error)))),
            Poll::Ready(Ok(Step::Connected(_))) => {
                if let Some(active) = &mut self.active {
                    active.cause = None;
                }
                Poll::Ready(Ok(LookupProgress::Activity))
            }
            Poll::Ready(Ok(Step::ConnectRetry { error, .. })) => {
                if let Some(active) = &mut self.active
                    && active.cause.is_none()
                {
                    active.cause = Some(Box::new(Error::Datastore(ConnectError::Io(error))));
                }
                Poll::Ready(Ok(LookupProgress::Activity))
            }
            Poll::Ready(Ok(Step::Lost { cause, .. })) => {
                if let Some(active) = &mut self.active {
                    active.cause = Some(Box::new(Error::DatastoreLost(cause)));
                }
                // retire() already destroyed the actual original MQ. Preserve
                // the exact completion before a replacement lookup is admitted.
                match self.completed() {
                    Ok(Some(result)) => Poll::Ready(Ok(result)),
                    Ok(None) => Poll::Ready(Ok(LookupProgress::Activity)),
                    Err(error @ Error::DatastoreOperation { .. }) => Poll::Ready(Err(error)),
                    Err(error) => Poll::Ready(Err(self.fail_closed(error))),
                }
            }
            Poll::Ready(Ok(Step::Unavailable(error))) => {
                Poll::Ready(Err(self.fail_closed(Error::Datastore(error))))
            }
            Poll::Ready(Ok(Step::Closed)) => match self.completed() {
                Ok(Some(result)) => Poll::Ready(Ok(result)),
                Ok(None) => Poll::Ready(Err(self.fail_closed(ProtocolError::Closed.into()))),
                Err(error) => Poll::Ready(Err(error)),
            },
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(LookupProgress::Activity)),
        }
    }
    fn close(&mut self) -> Result<(), Error> {
        self.closed = true;
        let active = self.active.take();
        let physical = self.client.close().map_err(Error::Datastore);
        let completion = active
            .map(|active| {
                let taken = self
                    .client
                    .take(active.operation)
                    .map_err(Error::Datastore)?;
                if active.lookup.is_none() {
                    return Err(Error::DatastoreOperation {
                        outcome: taken.completion.outcome,
                        interruption: taken.completion.interruption,
                        cause: active.cause,
                        reply: taken.into_frame().map(RetainedReply),
                    });
                }
                Ok(())
            })
            .transpose();
        match (physical, completion) {
            (Err(cause), Err(cleanup)) => Err(Error::Retirement {
                cause: Box::new(cause),
                cleanup: Box::new(cleanup),
            }),
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(()), Ok(_)) => Ok(()),
        }
    }
}

/// Bounded native signer progress; only an actual verified result yields Signed.
#[expect(
    clippy::large_enum_variant,
    reason = "Return bounded verified placement bytes without allocating after consuming the original signature"
)]
pub enum SignProgress {
    /// Actual request admission, service connection, announcement or I/O progress.
    Activity,
    /// Actual purpose5 signature, verified over the original 184-byte region.
    Signed(Location),
}
/// One serialized LOC signer with caller-selected actual identity ownership.
pub trait LocationSigner {
    /// Retain the exact CHK and requested expiration; no signature is inferred.
    fn start(&mut self, content: Content, expiration: AbsoluteTime) -> Result<(), Error>;
    /// Drive original PILS work; no active signature produces no fabricated result.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<SignProgress, Error>>;
    /// Physically stop original I/O and retire all signer authority.
    fn close(&mut self);
}
struct ActiveSign<'id> {
    content: Content,
    expiration: AbsoluteTime,
    identity: Option<Identity<'id>>,
    operation: Option<OperationId<'id>>,
}
/// Real PILS-backed LOC signer. It waits for a verified original-MQ identity,
/// then uses Exact identity intent. An admitted sign lost with its MQ is retired
/// rather than reissued by PILS's general crypto-reconnect policy.
pub struct PilsSigner<'id, const O: usize = 32> {
    client: PilsClient<'id, O>,
    active: Option<ActiveSign<'id>>,
    closed: bool,
}
impl<'id, const O: usize> PilsSigner<'id, O> {
    /// Consume one dedicated idle PILS owner; no service, key or task is created.
    pub fn new(client: PilsClient<'id, O>) -> Result<Self, Error> {
        if client.pending() != 0 {
            return Err(ProtocolError::Conflict.into());
        }
        Ok(Self {
            client,
            active: None,
            closed: false,
        })
    }
    fn admit(&mut self) -> Result<bool, Error> {
        let Some(active) = &mut self.active else {
            return Ok(false);
        };
        if active.operation.is_some() {
            return Ok(false);
        }
        let Some(identity) = self.client.identity() else {
            return Ok(false);
        };
        let region = Location::signing_region(active.content, identity.peer(), active.expiration);
        let operation = self
            .client
            .sign(&region, KeyTarget::Exact(identity))
            .map_err(Error::Signer)?;
        active.identity = Some(identity);
        active.operation = Some(operation);
        Ok(true)
    }
    fn stop(&mut self) {
        let _retired = self.client.close();
        self.active = None;
        self.closed = true;
    }
    fn completion(&mut self, completion: Completion<'id>) -> Result<SignProgress, Error> {
        let active = self.active.take().ok_or(ProtocolError::Stale)?;
        if active.operation != Some(completion.operation()) {
            return Err(ProtocolError::Stale.into());
        }
        match completion {
            Completion::Signature {
                peer, signature, ..
            } => {
                if active
                    .identity
                    .is_none_or(|identity| identity.peer() != peer)
                {
                    return Err(Error::SigningRefused(Failure::KeyChanged));
                }
                Ok(SignProgress::Signed(Location::from_signed(
                    active.content,
                    peer,
                    signature,
                    active.expiration,
                )?))
            }
            Completion::Failed { reason, .. } => Err(Error::SigningRefused(reason)),
            _ => Err(ProtocolError::Malformed.into()),
        }
    }
}
impl<const O: usize> LocationSigner for PilsSigner<'_, O> {
    fn start(&mut self, content: Content, expiration: AbsoluteTime) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if self.active.is_some() {
            return Err(ProtocolError::Conflict.into());
        }
        let expiration = AbsoluteTime::from_micros(expiration.as_micros() / 1_000_000 * 1_000_000);
        self.active = Some(ActiveSign {
            content,
            expiration,
            identity: None,
            operation: None,
        });
        Ok(())
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<SignProgress, Error>> {
        if self.active.is_none() {
            return Poll::Pending;
        }
        match self.admit() {
            Ok(true) => return Poll::Ready(Ok(SignProgress::Activity)),
            Ok(false) => {}
            Err(error) => {
                self.stop();
                return Poll::Ready(Err(error));
            }
        }
        let progress = {
            let mut driving = std::pin::pin!(self.client.drive(None));
            driving.as_mut().poll(cx)
        };
        match progress {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.stop();
                Poll::Ready(Err(Error::Signer(error)))
            }
            Poll::Ready(Ok(PilsProgress::Inbound(Inbound::Identity { identity, .. }))) => {
                if self
                    .active
                    .as_ref()
                    .and_then(|active| active.identity)
                    .is_some_and(|old| old.peer() != identity.peer())
                {
                    self.stop();
                    return Poll::Ready(Err(Error::SigningRefused(Failure::KeyChanged)));
                }
                Poll::Ready(Ok(SignProgress::Activity))
            }
            Poll::Ready(Ok(PilsProgress::Inbound(Inbound::Complete(completion)))) => {
                let result = self.completion(completion);
                if matches!(result, Err(Error::Protocol(_))) {
                    self.stop();
                }
                Poll::Ready(result)
            }
            Poll::Ready(Ok(PilsProgress::Lost { cause, report, .. })) => {
                let admitted = self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.operation.is_some());
                self.active = None;
                let retained_crypto = report.retained();
                if admitted {
                    self.stop();
                }
                Poll::Ready(Err(Error::SignerLost {
                    cause,
                    retained_crypto,
                }))
            }
            Poll::Ready(Ok(PilsProgress::Unavailable(error))) => {
                self.stop();
                Poll::Ready(Err(Error::Signer(error)))
            }
            Poll::Ready(Ok(PilsProgress::Closed)) => {
                self.stop();
                Poll::Ready(Err(ProtocolError::Closed.into()))
            }
            // Before any actual MQ/identity, retrying its original connection
            // attempt is safe: no signature request has yet been admitted.
            Poll::Ready(Ok(PilsProgress::ConnectRetry { error, .. })) => {
                let admitted = self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.operation.is_some());
                self.active = None;
                if admitted {
                    self.stop();
                }
                Poll::Ready(Err(Error::Signer(ConnectError::Io(error))))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(SignProgress::Activity)),
        }
    }
    fn close(&mut self) {
        self.stop();
    }
}
/// Explicit unavailable signer for a caller that does not provide identity access.
/// A LOC request fails Unsupported; no random identity or fake signature is used.
#[derive(Default)]
pub struct NoSigner;
impl LocationSigner for NoSigner {
    fn start(&mut self, _content: Content, _expiration: AbsoluteTime) -> Result<(), Error> {
        Err(ProtocolError::Unsupported.into())
    }
    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<Result<SignProgress, Error>> {
        Poll::Pending
    }
    fn close(&mut self) {}
}
