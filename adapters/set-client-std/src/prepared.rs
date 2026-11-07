//! Offline preparation and original cross-MQ authority; commit is the effect.
use crate::types::Owner;
use crate::{Epoch, Error, OperationType, ResultMode};
use gnunet_types::Error as Fault;
use gnunet_wire::official::set::{ClientRequest, Options};
use std::sync::Arc;
pub(crate) struct Acceptance {
    pub domain: Owner,
    pub epoch: Epoch,
    pub operation: OperationType,
    pub accept_id: u32,
}
pub(crate) struct Evaluation {
    pub target: [u8; 32],
    pub app_id: [u8; 64],
    pub context: Vec<u8>,
}
pub(crate) enum Plan {
    Evaluate(Box<Evaluation>),
    Accept(Arc<Acceptance>),
}
/// Offline prepared exchange. No operation starts until a real Set commits it.
/// Dropping it is local cancellation, not a wire CANCEL or remote acknowledgement.
pub struct Prepared {
    pub(crate) mode: ResultMode,
    pub(crate) options: Options,
    pub(crate) plan: Plan,
}
impl Prepared {
    /// Prepare an outgoing exchange without choosing/creating a Set MQ.
    pub fn evaluate(
        target: [u8; 32],
        app_id: [u8; 64],
        context: &[u8],
        mode: ResultMode,
        options: Options,
    ) -> Result<Self, Error> {
        ClientRequest::Evaluate {
            result_mode: mode as u32,
            target,
            app_id,
            request_id: 0,
            options,
            context,
        }
        .encoded_len()?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(context.len())
            .map_err(|_| Fault::Capacity)?;
        owned.extend_from_slice(context);
        Ok(Self {
            mode,
            options,
            plan: Plan::Evaluate(Box::new(Evaluation {
                target,
                app_id,
                context: owned,
            })),
        })
    }
    /// Select the actual standard options before successful commit admission.
    /// This consumes the same offline preparation: original listener domain,
    /// epoch, accept id and every evaluation byte remain unchanged. A committed
    /// preparation is consumed by Set::commit and cannot be reconfigured.
    #[must_use]
    pub fn with_options(mut self, options: Options) -> Self {
        self.options = options;
        self
    }
    /// Cancel only this not-yet-committed preparation. It transmits no message.
    pub fn cancel(self) {
        drop(self);
    }
    pub(crate) fn request(&self, id: u32) -> ClientRequest<'_> {
        match &self.plan {
            Plan::Evaluate(value) => ClientRequest::Evaluate {
                result_mode: self.mode as u32,
                target: value.target,
                app_id: value.app_id,
                request_id: id,
                options: self.options,
                context: &value.context,
            },
            Plan::Accept(a) => ClientRequest::Accept {
                accept_id: a.accept_id,
                request_id: id,
                result_mode: self.mode as u32,
                options: self.options,
            },
        }
    }
}
/// Original service cookie, consumed once by a new MQ CopyLazyConnect.
/// A cookie grants no proof about remote service restart/processing generations.
pub struct CopyTicket {
    pub(crate) domain: Owner,
    pub(crate) epoch: Epoch,
    pub(crate) operation: OperationType,
    pub(crate) cookie: [u8; 4],
}
