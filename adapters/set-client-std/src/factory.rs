//! One frozen configured selector for related Set and Listener MQs.
use crate::types::Owner;
use crate::{Bounds, CopyTicket, Error, Limits, Listener, OperationType, Set};
use gnunet_client_host::EndpointSource;
use gnunet_types::Error as Fault;
use std::sync::Arc;
/// Caller-owned source domain. Configuration is frozen once; physical sources
/// still have distinct epochs. This is not a remote daemon identity handshake.
pub struct Factory {
    pub(crate) source: EndpointSource,
    pub(crate) domain: Owner,
}
impl Factory {
    /// Freeze the actual selector configuration with its original clock/Resolver.
    /// DNS resolution, socket ownership and remote restart identity are not frozen.
    pub fn new(source: EndpointSource) -> Result<Self, Error> {
        Ok(Self {
            source: source.snapshot()?,
            domain: Arc::new(()),
        })
    }
    /// Create one empty set owner; its Create must actually write before use.
    pub fn set(
        &self,
        operation: OperationType,
        limits: Limits,
        bounds: Bounds,
    ) -> Result<Set, Error> {
        Set::new(
            self.source.duplicate()?,
            self.domain.clone(),
            operation,
            None,
            limits,
            bounds,
        )
    }
    /// Register an application on an independently owned original MQ.
    pub fn listen(
        &self,
        operation: OperationType,
        app_id: [u8; 64],
        limits: Limits,
        bounds: Bounds,
    ) -> Result<Listener, Error> {
        Listener::new(
            self.source.duplicate()?,
            self.domain.clone(),
            operation,
            app_id,
            limits,
            bounds,
        )
    }
    /// Consume an exact original cookie on a new MQ in the same frozen domain.
    pub fn copy(
        &self,
        ticket: CopyTicket,
        limits: Limits,
        bounds: Bounds,
    ) -> Result<Set, CopyFailure> {
        let result = (|| -> Result<Set, Error> {
            if !Arc::ptr_eq(&self.domain, &ticket.domain) || !ticket.epoch.live() {
                return Err(Fault::Stale.into());
            }
            Set::new(
                self.source.duplicate()?,
                self.domain.clone(),
                ticket.operation,
                Some(&ticket),
                limits,
                bounds,
            )
        })();
        match result {
            Ok(mut set) => {
                set.retain_copy(ticket);
                Ok(set)
            }
            Err(error) => Err(CopyFailure { error, ticket }),
        }
    }
    /// Original shared clock for explicit operation budgets; no native IO occurs.
    #[must_use]
    pub fn clock(&self) -> std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.source.clock()
    }
}

/// Failed copy admission returns its unchanged original single-use cookie.
pub struct CopyFailure {
    /// Original local admission error.
    pub error: Error,
    /// Original source/domain-bound cookie for an explicit retry.
    pub ticket: CopyTicket,
}
