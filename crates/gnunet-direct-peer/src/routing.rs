//! Original outbound DV ownership on one validated direct carrier.

use crate::Application;
use core::num::NonZeroU64;
use gnunet_crypto::{Entropy, hash256};
use gnunet_tcp_communicator_core::firmware::Outgoing;
use gnunet_transport::direct::{Link, RoutingFrame, SendProgress, SendSpan};
use gnunet_types::{Error, MonoInstant};

/// The receipts requested for an original routed frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingReceipt {
    /// Observe ordered local admission only.
    Admission,
    /// Also observe the native socket accepting the complete original.
    NativeWrite,
}

/// One original immutable DV frame offered to this carrier.
#[derive(Clone, Copy, Debug)]
pub struct RoutingOffer<'a> {
    /// Caller-owned identifier, exclusive until the requested receipts settle.
    pub id: NonZeroU64,
    /// Structurally checked official DV input retained through admission.
    pub frame: RoutingFrame<'a>,
    /// The receipts needed by the routing owner.
    pub receipt: RoutingReceipt,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Ticket {
    id: NonZeroU64,
    receipt: RoutingReceipt,
}

#[derive(Clone, Copy)]
enum Pending {
    Borrowed { ticket: Ticket, digest: [u8; 32] },
    Fragmented(Ticket),
}

impl Pending {
    fn ticket(self) -> Ticket {
        match self {
            Self::Borrowed { ticket, .. } | Self::Fragmented(ticket) => ticket,
        }
    }
}

#[derive(Default)]
pub(crate) struct Routing {
    pending: Option<Pending>,
    native: Option<NonZeroU64>,
}

impl Routing {
    pub(crate) fn active(&self) -> bool {
        self.pending.is_some() || self.native.is_some()
    }

    pub(crate) fn fragmented(&self) -> bool {
        matches!(self.pending, Some(Pending::Fragmented(_)))
    }

    pub(crate) fn poll<const N: usize>(
        &mut self,
        link: &mut Link<'_, N>,
        application: &mut impl Application,
        now: MonoInstant,
        entropy: &mut impl Entropy,
        admit: &mut Option<impl FnOnce(Outgoing<'_>) -> Result<(), Error>>,
    ) -> Result<bool, Error> {
        let Some(offer) = application.routing_offer(now)? else {
            return if self.pending.is_some() {
                Err(Error::Conflict)
            } else {
                Ok(false)
            };
        };
        let ticket = Ticket {
            id: offer.id,
            receipt: offer.receipt,
        };
        if self
            .pending
            .is_some_and(|pending| pending.ticket() != ticket)
        {
            return Err(Error::Conflict);
        }
        if let Some(Pending::Borrowed { digest, .. }) = self.pending
            && hash256(offer.frame.bytes()) != digest
        {
            return Err(Error::Conflict);
        }
        if let Some(active) = self.native {
            if active == ticket.id {
                return Err(Error::Conflict);
            }
            if ticket.receipt == RoutingReceipt::NativeWrite {
                if self.pending.is_none() {
                    self.pending = Some(Pending::Borrowed {
                        ticket,
                        digest: hash256(offer.frame.bytes()),
                    });
                }
                return Ok(false);
            }
        }

        let result = link.send_routing(now, offer.frame, entropy, |message, span| {
            let outgoing =
                if span == SendSpan::Final && ticket.receipt == RoutingReceipt::NativeWrite {
                    Outgoing::ObserveNative {
                        message,
                        id: ticket.id,
                    }
                } else {
                    Outgoing::Buffered(message)
                };
            admit.take().ok_or(Error::Conflict)?(outgoing)
        });
        match result {
            Ok(SendProgress::Partial(())) => {
                self.pending = Some(Pending::Fragmented(ticket));
            }
            Ok(SendProgress::Complete(())) => {
                self.pending = None;
                if ticket.receipt == RoutingReceipt::NativeWrite {
                    self.native = Some(ticket.id);
                }
                application.routing_admitted(ticket.id, Ok(()));
            }
            Err(Error::WouldBlock) => {
                self.pending = Some(if link.fragmented_send_pending() {
                    Pending::Fragmented(ticket)
                } else {
                    Pending::Borrowed {
                        ticket,
                        digest: hash256(offer.frame.bytes()),
                    }
                });
                return Err(Error::WouldBlock);
            }
            Err(error) => {
                self.pending = None;
                application.routing_admitted(ticket.id, Err(error));
                if link.fragmented_send_pending()
                    || !matches!(
                        error,
                        Error::InvalidInput
                            | Error::Malformed
                            | Error::TooLarge
                            | Error::Unsupported
                    )
                {
                    return Err(error);
                }
            }
        }
        Ok(true)
    }

    pub(crate) fn cancel_pending(&mut self, application: &mut impl Application, error: Error) {
        if let Some(original) = self.pending.take() {
            application.routing_admitted(original.ticket().id, Err(error));
        }
    }

    pub(crate) fn written(
        &mut self,
        application: &mut impl Application,
        id: NonZeroU64,
        outcome: Result<(), Error>,
        elapsed: MonoInstant,
    ) {
        if self.native == Some(id) {
            self.native = None;
            application.routing_written(id, outcome, elapsed);
        }
    }

    pub(crate) fn close(&mut self, application: &mut impl Application, elapsed: MonoInstant) {
        self.cancel_pending(application, Error::Closed);
        if let Some(id) = self.native {
            self.written(application, id, Err(Error::Closed), elapsed);
        }
    }
}
