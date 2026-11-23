//! CMS password recipients and caller-supplied keying material.

mod derivation;
#[cfg(test)]
mod tests;
mod wrap;

use std::cell::Cell;

use zeroize::Zeroizing;

use crate::extraction::Error;

use super::{
    Ber, CONTEXT_0, Envelope, INTEGER, Item, OpenContentKey, PdfRecipientAuthorization,
    PdfRecipientContent, SEQUENCE,
};
use derivation::{MAX_HMAC_CALLS, Pbkdf2};

const PASSWORD_RECIPIENT: u8 = 0xa3;
const MAX_PASSWORD_BYTES: usize = 4096;

/// A locally supplied CMS PasswordRecipientInfo credential.
pub struct PdfPasswordRecipient {
    identity: [u8; 32],
    secret: Secret,
}

enum Secret {
    Password(Zeroizing<Vec<u8>>),
    WrappingKey(Zeroizing<Vec<u8>>),
}

impl PdfPasswordRecipient {
    /// Bind password bytes under a stable caller-assigned public identity.
    /// PBKDF2 recipient entries share a budget of 1,000,000 HMAC calls per
    /// CMS envelope. Use a distinct identity when replacing the password.
    ///
    /// # Errors
    ///
    /// Returns a limit error for passwords longer than 4096 bytes.
    pub fn from_password(identity: [u8; 32], password: &[u8]) -> Result<Self, Error> {
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(Error::Limit);
        }
        Ok(Self {
            identity,
            secret: Secret::Password(Zeroizing::new(password.to_vec())),
        })
    }

    /// Supply an external wrapping key for entries with no derivation algorithm.
    /// Use a distinct public identity when rotating the key.
    ///
    /// # Errors
    ///
    /// Returns a binding error for key lengths other than 8, 16, 24 and 32
    /// bytes.
    pub fn from_wrapping_key(identity: [u8; 32], key: &[u8]) -> Result<Self, Error> {
        if !matches!(key.len(), 8 | 16 | 24 | 32) {
            return Err(Error::Binding);
        }
        Ok(Self {
            identity,
            secret: Secret::WrappingKey(Zeroizing::new(key.to_vec())),
        })
    }

    /// Transfer this credential to a local PDF extraction authorization.
    #[must_use]
    pub fn into_authorization(self) -> PdfRecipientAuthorization {
        PdfRecipientAuthorization::new(self.identity, move |bytes| self.open(bytes))
    }

    fn open(&self, bytes: &[u8]) -> Option<PdfRecipientContent> {
        let remaining_work = Cell::new(MAX_HMAC_CALLS);
        Envelope::parse(bytes)?.open_any(|entry, _| self.select(entry, &remaining_work))
    }

    fn select<'envelope, 'credential>(
        &'credential self,
        entry: Item<'envelope>,
        remaining_work: &'credential Cell<usize>,
    ) -> Option<Option<Candidate<'envelope, 'credential>>> {
        if entry.tag != PASSWORD_RECIPIENT {
            return Some(None);
        }
        let mut fields = Ber(entry.data);
        if fields.take(INTEGER)?.uint()? != 0 {
            return None;
        }
        let derivation = fields.optional(CONTEXT_0)?;
        let algorithm = fields.take(SEQUENCE)?;
        let encrypted = fields.read()?;
        fields.finish()?;

        let Some(wrapping) = wrap::Key::parse(algorithm, encrypted) else {
            return Some(None);
        };
        let key_size = wrapping.key_size();
        let source = match (&self.secret, derivation) {
            (Secret::Password(password), Some(derivation)) => {
                let Some(params) = Pbkdf2::parse(derivation, key_size) else {
                    return Some(None);
                };
                KeySource::Password {
                    password,
                    params,
                    remaining_work,
                }
            }
            (Secret::WrappingKey(key), None) if key.len() == key_size => KeySource::Direct(key),
            _ => return Some(None),
        };
        Some(Some(Candidate { source, wrapping }))
    }
}

struct Candidate<'envelope, 'credential> {
    source: KeySource<'envelope, 'credential>,
    wrapping: wrap::Key<'envelope>,
}

enum KeySource<'envelope, 'credential> {
    Password {
        password: &'credential [u8],
        params: Pbkdf2<'envelope>,
        remaining_work: &'credential Cell<usize>,
    },
    Direct(&'credential [u8]),
}

impl OpenContentKey for Candidate<'_, '_> {
    fn content_key(self) -> Option<Zeroizing<Vec<u8>>> {
        match self.source {
            KeySource::Password {
                password,
                params,
                remaining_work,
            } => {
                let mut kek = Zeroizing::new([0_u8; 32]);
                let kek = kek.get_mut(..self.wrapping.key_size())?;
                params.derive(password, remaining_work, kek)?;
                self.wrapping.open(kek)
            }
            KeySource::Direct(key) => self.wrapping.open(key),
        }
    }
}
