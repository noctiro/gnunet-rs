//! Consume topology HELLO control at the authenticated CORE boundary.
use crate::Application;
use gnunet_crypto::EddsaPublicKey;
use gnunet_transport::direct_discovery::{
    Book, Limits, SignatureProfile, Snapshot, Update, is_hello_uri,
};
use gnunet_types::{AbsoluteTime, Error};

/// Exclusive bounded address-book storage.
pub struct DiscoveryBuffers<'buf> {
    /// The accepted canonical address set.
    pub retained: &'buf mut [u8],
    /// Parse scratch separate from the accepted set.
    pub scratch: &'buf mut [u8],
    /// Limits of a complete HELLO frame and its addresses.
    pub limits: Limits,
}

/// Change to this authenticated peer's original address set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryChange<'a> {
    /// A newer, nonempty authenticated address set.
    Published(Snapshot<'a>),
    /// A newer empty HELLO. Carries its signed freshness floor.
    Withdrawn(AbsoluteTime),
    /// The published set expired at its signed freshness floor.
    Expired(AbsoluteTime),
}

pub(crate) struct Discovery<'buf> {
    peer: EddsaPublicKey,
    book: Book<'buf>,
    scratch: &'buf mut [u8],
}

impl<'buf> Discovery<'buf> {
    pub(crate) fn new(
        peer: EddsaPublicKey,
        buffers: DiscoveryBuffers<'buf>,
    ) -> Result<Self, Error> {
        if buffers.scratch.len() < buffers.limits.maximum_address_bytes {
            return Err(Error::Capacity);
        }
        Ok(Self {
            peer,
            book: Book::new(peer, buffers.retained, buffers.limits)?,
            scratch: buffers.scratch,
        })
    }

    pub(crate) fn next_expiration(&self) -> Option<AbsoluteTime> {
        self.book.next_expiration()
    }

    pub(crate) fn expire(
        &mut self,
        now: AbsoluteTime,
        application: &mut impl Application,
    ) -> Result<(), Error> {
        if let Some(until) = self.next_expiration()
            && now >= until
            && self.book.expire(now)?
        {
            application.discovered(DiscoveryChange::Expired(until));
        }
        Ok(())
    }

    pub(crate) fn receive(
        &mut self,
        now: AbsoluteTime,
        message: &[u8],
        application: &mut impl Application,
    ) {
        if !is_hello_uri(message) {
            return;
        }
        match self.book.receive_authenticated(
            self.peer,
            message,
            SignatureProfile::Gnunet029,
            now,
            self.scratch,
        ) {
            Ok(Update::Published) => {
                if let Ok(Some(snapshot)) = self.book.current(now) {
                    application.discovered(DiscoveryChange::Published(snapshot));
                }
            }
            Ok(Update::Withdrawn) => {
                if let Some(floor) = self.book.freshness_floor() {
                    application.discovered(DiscoveryChange::Withdrawn(floor));
                }
            }
            _ => {}
        }
    }
}
