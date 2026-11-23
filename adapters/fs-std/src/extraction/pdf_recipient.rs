//! Runtime authorization to open a PDF public-key recipient envelope.

mod cms;

use std::sync::Arc;
use zeroize::Zeroizing;

pub use cms::{PdfCertificateRecipient, PdfKekRecipient, PdfPasswordRecipient};

const MAX_ENVELOPE_BYTES: usize = 1 << 16;

/// Decrypted contents of a PDF CMS recipient envelope.
pub enum PdfRecipientContent {
    /// Seed for an individual stream crypt filter.
    Stream(Zeroizing<[u8; 20]>),
    /// Seed and permission word for an authorized document crypt filter.
    Document {
        /// File-key seed.
        seed: Zeroizing<[u8; 20]>,
        /// Permission word as encoded in the recipient envelope.
        permissions: [u8; 4],
    },
}

impl PdfRecipientContent {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (seed, permissions) = bytes.split_first_chunk::<20>()?;
        match permissions {
            [] => Some(Self::Stream(Zeroizing::new(*seed))),
            &[a, b, c, d] => Some(Self::Document {
                seed: Zeroizing::new(*seed),
                permissions: [a, b, c, d],
            }),
            _ => None,
        }
    }
}

type Opener = dyn Fn(&[u8]) -> Option<PdfRecipientContent> + Send + Sync;

/// An explicitly supplied CMS recipient opener and its stable public identity.
/// Durable extraction stores the public identity and reattaches live authority.
#[derive(Clone)]
pub struct PdfRecipientAuthorization {
    identity: [u8; 32],
    open: Arc<Opener>,
}

impl PdfRecipientAuthorization {
    /// Attach a recipient implementation under its stable, non-secret key ID.
    /// The opener receives one bounded CMS ContentInfo from the PDF. It should
    /// return the decrypted content only when it identifies the admitted
    /// recipient. Calls are synchronous on the extraction worker.
    pub fn new(
        identity: [u8; 32],
        open: impl Fn(&[u8]) -> Option<PdfRecipientContent> + Send + Sync + 'static,
    ) -> Self {
        Self {
            identity,
            open: Arc::new(open),
        }
    }

    /// Stable public identity of the recipient credential.
    #[must_use]
    pub const fn identity(&self) -> &[u8; 32] {
        &self.identity
    }

    pub(super) fn open(&self, envelope: &[u8]) -> Option<PdfRecipientContent> {
        if envelope.is_empty() || envelope.len() > MAX_ENVELOPE_BYTES {
            return None;
        }
        (self.open)(envelope)
    }
}
