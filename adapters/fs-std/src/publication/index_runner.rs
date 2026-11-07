//! Original INDEX_START native receipt ownership, independent of PUT replies.
use super::*;
use crate::{
    ipc,
    network::{IndexRegistration, RegistrationFailure, publish::IndexAnswer},
};
use gnunet_wire::official::fs::{Request as IndexRequest, Response as IndexResponse};

/// An actual original FS registration result bound to one task and intent.
/// Its private provenance can reconcile the original WAL without another request.
pub struct NativeIndexResult {
    task: [u8; 32],
    attempt: Attempt,
    registration: IndexRegistration,
    response: Option<ipc::Received>,
    failure: Option<Box<RegistrationFailure>>,
    retirement_error: Option<ConnectError>,
    interruption: Option<Interruption>,
    requested_cancel: bool,
}
impl fmt::Debug for NativeIndexResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeIndexResult")
            .field("attempt", &self.attempt)
            .field("registration", &self.registration)
            .field("failure", &self.failure)
            .field("retirement_error", &self.retirement_error)
            .field("interruption", &self.interruption)
            .field("requested_cancel", &self.requested_cancel)
            .field("reply_bytes", &self.response_bytes().map(<[u8]>::len))
            .finish()
    }
}
impl NativeIndexResult {
    /// Actual known registration outcome, never inferred from DATASTORE contents.
    #[must_use]
    pub const fn registration(&self) -> IndexRegistration {
        self.registration
    }
    /// Original exact task-source coordinate and intent generation.
    #[must_use]
    pub const fn attempt(&self) -> Attempt {
        self.attempt
    }
    /// Complete original FS response bytes, without synthesized re-encoding.
    #[must_use]
    pub fn response_bytes(&self) -> Option<&[u8]> {
        self.response
            .as_ref()
            .or_else(|| self.failure.as_ref().and_then(|e| e.response.as_ref()))
            .map(ipc::Received::bytes)
    }
    /// Parse the original response, retaining raw non-UTF8 failure diagnostics.
    pub fn response(&self) -> Result<Option<IndexResponse<'_>>, ProtocolError> {
        self.response_bytes().map(IndexResponse::decode).transpose()
    }
    /// Original typed registration error and independent preceding/native facts.
    #[must_use]
    pub fn failure(&self) -> Option<&RegistrationFailure> {
        self.failure.as_deref()
    }
    /// Independent physical retirement failure after an actual reply or refusal.
    #[must_use]
    pub fn retirement_error(&self) -> Option<&ConnectError> {
        self.retirement_error.as_ref().or_else(|| {
            self.failure
                .as_ref()
                .and_then(|e| e.retirement_error.as_ref())
        })
    }
    /// Original native caller interruption, separate from its effect certainty.
    #[must_use]
    pub const fn interruption(&self) -> Option<Interruption> {
        self.interruption
    }
    /// The controlled native run requested cancellation of this original owner.
    #[must_use]
    pub const fn requested_cancel(&self) -> bool {
        self.requested_cancel
    }
    /// Record only this actual original receipt, never another INDEX_START or PUT.
    pub fn record(&self, task: &mut Task) -> Result<Effect, Cause> {
        if task.active {
            return Err(Cause::State("publication task already running"));
        }
        self.record_inner(&mut task.store, &mut task.state)
    }
    pub(super) fn answer(task: [u8; 32], attempt: Attempt, answer: IndexAnswer) -> Self {
        Self {
            task,
            attempt,
            registration: IndexRegistration::Acknowledged,
            response: Some(answer.response),
            failure: None,
            retirement_error: answer.retirement_error,
            interruption: None,
            requested_cancel: false,
        }
    }
    pub(super) fn failed(
        task: [u8; 32],
        attempt: Attempt,
        failure: Box<RegistrationFailure>,
        requested_cancel: bool,
    ) -> Self {
        let interruption = failure.failure.as_ref().and_then(|f| match f.cause {
            ProtocolError::Cancelled => Some(Interruption::Cancelled),
            ProtocolError::Deadline => Some(Interruption::TimedOut),
            _ => None,
        });
        Self {
            task,
            attempt,
            registration: failure.registration,
            response: None,
            failure: Some(failure),
            retirement_error: None,
            interruption,
            requested_cancel,
        }
    }
    pub(super) fn record_inner(
        &self,
        store: &mut Store,
        state: &mut model::State,
    ) -> Result<Effect, Cause> {
        if &self.task != store.task_id() {
            return Err(Cause::State("registration belongs to another task"));
        }
        if let Some(accepted) = state.indexes.accepted.get(self.attempt.index) {
            let record = store
                .read_record(accepted.record_index)?
                .ok_or(ProtocolError::Stale)?;
            let (attempt, response, interruption) =
                registration::accepted_view(record.kind, record.bytes)?;
            if attempt == self.attempt
                && self.response_bytes() == Some(response)
                && interruption == self.interruption
            {
                return Ok(Effect::Accepted);
            }
            return Err(Cause::State(
                "registration differs from original accepted row",
            ));
        }
        let pending = state
            .indexes
            .pending
            .ok_or(Cause::State("original registration is no longer pending"))?;
        if pending.attempt != self.attempt || pending.disposition != IndexDisposition::Intent {
            return Err(Cause::State(
                "registration belongs to another intent generation or was already settled",
            ));
        }
        let (effect, event) = match (self.registration, self.response()?) {
            (IndexRegistration::Acknowledged, Some(IndexResponse::IndexStarted)) => (
                Effect::Accepted,
                registration::Event::Accepted {
                    attempt: self.attempt,
                    response: self.response_bytes().ok_or(ProtocolError::NotReady)?,
                    interruption: self.interruption,
                },
            ),
            (IndexRegistration::Refused, Some(IndexResponse::IndexFailed { .. })) => (
                Effect::Refused,
                registration::Event::Refused {
                    attempt: self.attempt,
                    response: self.response_bytes().ok_or(ProtocolError::NotReady)?,
                    interruption: self.interruption,
                },
            ),
            (IndexRegistration::NotSubmitted, _) => (
                Effect::NotApplied,
                registration::Event::NotApplied {
                    attempt: self.attempt,
                    reason: NoEffect::UnexposedRegistration,
                    interruption: self.interruption,
                },
            ),
            _ => (
                Effect::Uncertain,
                registration::Event::Unknown {
                    attempt: self.attempt,
                    response: self.response_bytes(),
                    interruption: self.interruption,
                },
            ),
        };
        append(store, state, model::Event::Index(event))?;
        Ok(effect)
    }
}
pub(super) fn request_hash(source: &plan::indexed::Source) -> Result<[u8; 64], Cause> {
    let request = IndexRequest::IndexStart {
        device: 0,
        inode: 0,
        file_id: source.file_id,
        filename: &source.path,
    };
    let mut bytes = vec![0; request.encoded_len()?];
    request.encode(&mut bytes)?;
    Ok(gnunet_crypto::hash512(&bytes))
}
