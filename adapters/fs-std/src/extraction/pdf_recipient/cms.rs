//! Bounded recipient selection and content-key opening for CMS EnvelopedData.

mod agreement;
mod asn1;
mod finite_dh;
mod issuer;
mod kem;
mod kem_recipient;
mod key_agreement;
mod key_wrap;
mod originator;
mod password;
mod payload;
mod pre_shared;
mod rsa_kem;
#[cfg(test)]
mod tests;
mod transport;

use crate::extraction::Error;
use asn1::{Ber, Item};
use rsa::pkcs8::{PrivateKeyInfoRef, der::Decode};
use std::borrow::Cow;
use x509_parser::{
    certificate::X509Certificate, extensions::ParsedExtension, prelude::parse_x509_certificate,
};
use zeroize::Zeroizing;

use super::{MAX_ENVELOPE_BYTES, PdfRecipientAuthorization, PdfRecipientContent};

pub use password::PdfPasswordRecipient;
pub use pre_shared::PdfKekRecipient;

const DATA: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01";
const ENVELOPED_DATA: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03";

const INTEGER: u8 = 0x02;
const OCTETS: u8 = 0x04;
const OID: u8 = 0x06;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const CONTEXT_0: u8 = 0xa0;
const CONTEXT_1: u8 = 0xa1;
const IMPLICIT_OCTETS: u8 = 0x80;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_RECIPIENTS: usize = 128;
const MAX_CIPHERTEXT: usize = 32;
const MAX_KEY_ID: usize = 128;

/// A local X.509 certificate and its matching CMS recipient private key.
pub struct PdfCertificateRecipient {
    key: PrivateKey,
    recipient: RecipientId,
    identity: [u8; 32],
    originators: originator::Store,
}

enum PrivateKey {
    Rsa(Box<transport::Key>),
    Ecdh(agreement::Key),
    Dh(Box<finite_dh::Key>),
    Kem(kem::Key),
    RsaKem(Box<rsa_kem::Key>),
}

#[derive(PartialEq, Eq)]
enum KeySelection {
    Declared,
    RsaKem,
}

struct RecipientId {
    issuer: Box<[u8]>,
    serial: Box<[u8]>,
    subject_key_id: Option<Box<[u8]>>,
}

impl PdfCertificateRecipient {
    /// Import a DER certificate and its unencrypted DER PKCS#8 private key.
    /// Supports RSA transport, restricted RSA-KEM, finite-field and
    /// elliptic-curve agreement, and ML-KEM.
    ///
    /// # Errors
    ///
    /// Returns a limit error for oversized inputs and a binding error for
    /// malformed, unsupported or mismatched credentials.
    pub fn from_der(certificate: &[u8], pkcs8: &[u8]) -> Result<Self, Error> {
        Self::import(certificate, pkcs8, KeySelection::Declared)
    }

    /// Import an X.509 RSA certificate and matching PKCS#8 key for RSA-KEM
    /// only. Use this constructor for a generic rsaEncryption certificate
    /// whose key is assigned to RSA-KEM through out-of-band configuration.
    ///
    /// # Errors
    ///
    /// Returns a limit error for oversized inputs and a binding error for
    /// malformed, incompatible or mismatched RSA credentials.
    pub fn from_rsa_kem_der(certificate: &[u8], pkcs8: &[u8]) -> Result<Self, Error> {
        Self::import(certificate, pkcs8, KeySelection::RsaKem)
    }

    fn import(certificate: &[u8], pkcs8: &[u8], selection: KeySelection) -> Result<Self, Error> {
        if certificate.len() > MAX_CREDENTIAL_BYTES || pkcs8.len() > MAX_CREDENTIAL_BYTES {
            return Err(Error::Limit);
        }
        Self::parse(certificate, pkcs8, selection).ok_or(Error::Binding)
    }

    /// Add an originator certificate for static key agreement when the sender
    /// distributes that certificate separately from the CMS envelope.
    ///
    /// # Errors
    ///
    /// Returns a limit error for oversized inputs or a full certificate set,
    /// and a binding error for a malformed DER certificate.
    pub fn with_originator_der(mut self, certificate: &[u8]) -> Result<Self, Error> {
        self.originators.insert(certificate)?;
        Ok(self)
    }

    /// Transfer the key to a local extraction credential. The public identity
    /// includes the recipient certificate and configured originator certificates.
    #[must_use]
    pub fn into_authorization(self) -> PdfRecipientAuthorization {
        PdfRecipientAuthorization::new(self.originators.identity(self.identity), move |bytes| {
            self.open(bytes)
        })
    }

    fn parse(certificate: &[u8], pkcs8: &[u8], selection: KeySelection) -> Option<Self> {
        let (remaining, parsed) = parse_x509_certificate(certificate).ok()?;
        let public_key = parsed.public_key();
        if !remaining.is_empty() || public_key.subject_public_key.unused_bits != 0 {
            return None;
        }
        let usage = parsed.key_usage().ok()?.map(|usage| usage.value);
        let oid = public_key.algorithm.algorithm.as_bytes();
        let restricted = rsa_kem::supports(oid);
        let generic_rsa = oid == transport::RSA_ENCRYPTION;
        let private_restricted = generic_rsa
            && rsa_kem::supports(
                PrivateKeyInfoRef::from_der(pkcs8)
                    .ok()?
                    .algorithm
                    .oid
                    .as_bytes(),
            );
        let use_kem = restricted || private_restricted || selection == KeySelection::RsaKem;
        let key = match oid {
            _ if use_kem => {
                if !(generic_rsa || restricted)
                    || !usage.is_none_or(|usage| {
                        if restricted {
                            usage.flags == 1 << 2
                        } else {
                            usage.key_encipherment()
                        }
                    })
                {
                    return None;
                }
                PrivateKey::RsaKem(Box::new(rsa_kem::Key::parse(public_key, pkcs8)?))
            }
            transport::RSA_ENCRYPTION | transport::RSA_OAEP
                if usage.is_none_or(|usage| usage.key_encipherment()) =>
            {
                PrivateKey::Rsa(Box::new(transport::Key::parse(public_key, pkcs8)?))
            }
            agreement::EC_PUBLIC_KEY
            | agreement::ECDH_PUBLIC_KEY
            | agreement::ECMQV_PUBLIC_KEY
            | agreement::X25519
            | agreement::X448
                if usage.is_none_or(|usage| usage.key_agreement() && !usage.encipher_only()) =>
            {
                PrivateKey::Ecdh(agreement::Key::parse(public_key, pkcs8)?)
            }
            oid if finite_dh::supports(oid)
                && usage.is_none_or(|usage| usage.key_agreement() && !usage.encipher_only()) =>
            {
                PrivateKey::Dh(Box::new(finite_dh::Key::parse(public_key, pkcs8)?))
            }
            oid if kem::supports(oid) && usage.is_none_or(|usage| usage.flags == 1 << 2) => {
                PrivateKey::Kem(kem::Key::parse(public_key, pkcs8)?)
            }
            _ => return None,
        };
        let identity = match &key {
            PrivateKey::RsaKem(key) => key.identity(certificate),
            _ => gnunet_crypto::hash256_parts(&[certificate]),
        };
        Some(Self {
            key,
            recipient: RecipientId::parse(&parsed)?,
            identity,
            originators: originator::Store::default(),
        })
    }

    fn open(&self, bytes: &[u8]) -> Option<PdfRecipientContent> {
        let envelope = Envelope::parse(bytes)?;
        let originators = self.originators.combine(envelope.originator_info)?;
        envelope.open(|entry, budget| match (&self.key, entry.tag) {
            (PrivateKey::Rsa(key), SEQUENCE) => Some(
                transport::select(key, &self.recipient, entry)?
                    .map(|recipient| Selected::Rsa(key, recipient)),
            ),
            (PrivateKey::Ecdh(key), CONTEXT_1) => Some(
                agreement::select(key, &self.recipient, entry, budget, originators)?
                    .map(|recipient| Selected::Ecdh(key, recipient)),
            ),
            (PrivateKey::Dh(key), CONTEXT_1) => Some(
                finite_dh::select(key, &self.recipient, entry, budget, originators)?
                    .map(|recipient| Selected::Dh(key, recipient)),
            ),
            (PrivateKey::Kem(key), 0xa4) => {
                Some(kem::select(key, &self.recipient, entry)?.map(Selected::Kem))
            }
            (PrivateKey::RsaKem(key), SEQUENCE | 0xa4) => {
                Some(rsa_kem::select(key, &self.recipient, entry)?.map(Selected::RsaKem))
            }
            _ => Some(None),
        })
    }
}

struct Envelope<'a> {
    recipients: Ber<'a>,
    originator_info: Option<Item<'a>>,
    content_cipher: &'a [u8],
    cipher_parameters: Option<Item<'a>>,
    ciphertext: Cow<'a, [u8]>,
}

impl<'a> Envelope<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return None;
        }
        let mut info = Ber::sequence(bytes)?;
        if info.take(OID)?.data != ENVELOPED_DATA {
            return None;
        }
        let mut envelope = Ber::sequence(info.take(CONTEXT_0)?.data)?;
        info.finish()?;
        if !matches!(envelope.take(INTEGER)?.uint()?, 0 | 2..=4) {
            return None;
        }
        let originator_info = envelope.optional(CONTEXT_0)?;
        let recipients = Ber(envelope.take(SET)?.data);
        let mut content = Ber(envelope.take(SEQUENCE)?.data);
        envelope.optional(CONTEXT_1)?;
        envelope.finish()?;
        if content.take(OID)?.data != DATA {
            return None;
        }
        let (content_cipher, cipher_parameters) = algorithm(content.take(SEQUENCE)?)?;
        let ciphertext = content.read()?.octets(IMPLICIT_OCTETS, MAX_CIPHERTEXT)?;
        content.finish()?;
        Some(Self {
            recipients,
            originator_info,
            content_cipher,
            cipher_parameters,
            ciphertext,
        })
    }

    fn open<K: OpenContentKey>(
        self,
        select: impl FnMut(Item<'a>, &mut usize) -> Option<Option<K>>,
    ) -> Option<PdfRecipientContent> {
        let mut selected = None;
        self.visit(select, |candidate| {
            selected.is_none().then(|| selected = Some(candidate))
        })?;
        self.content(selected?)
    }

    fn open_any<K: OpenContentKey>(
        self,
        select: impl FnMut(Item<'a>, &mut usize) -> Option<Option<K>>,
    ) -> Option<PdfRecipientContent> {
        let mut selected = Vec::new();
        self.visit(select, |candidate| {
            selected.try_reserve(1).ok()?;
            selected.push(candidate);
            Some(())
        })?;
        selected
            .into_iter()
            .find_map(|candidate| self.content(candidate))
    }

    fn visit<K>(
        &self,
        mut select: impl FnMut(Item<'a>, &mut usize) -> Option<Option<K>>,
        mut visit: impl FnMut(K) -> Option<()>,
    ) -> Option<()> {
        let mut recipients = self.recipients;
        let mut budget = MAX_RECIPIENTS;
        while !recipients.0.is_empty() {
            budget = budget.checked_sub(1)?;
            let entry = recipients.read()?;
            if !matches!(entry.tag, SEQUENCE | 0xa1..=0xa4) {
                return None;
            }
            if let Some(candidate) = select(entry, &mut budget)? {
                visit(candidate)?;
            }
        }
        Some(())
    }

    fn content(&self, selected: impl OpenContentKey) -> Option<PdfRecipientContent> {
        let key = selected.content_key()?;
        payload::decrypt(
            self.content_cipher,
            self.cipher_parameters,
            &key,
            &self.ciphertext,
        )
    }
}

trait OpenContentKey {
    fn content_key(self) -> Option<Zeroizing<Vec<u8>>>;
}

enum Selected<'a> {
    Rsa(&'a transport::Key, transport::Recipient<'a>),
    Ecdh(&'a agreement::Key, agreement::Recipient<'a>),
    Dh(&'a finite_dh::Key, finite_dh::Recipient<'a>),
    Kem(kem::Recipient<'a>),
    RsaKem(rsa_kem::Recipient<'a>),
}

impl OpenContentKey for Selected<'_> {
    fn content_key(self) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            Self::Rsa(key, recipient) => recipient.open(key),
            Self::Ecdh(key, recipient) => recipient.open(key),
            Self::Dh(key, recipient) => recipient.open(key),
            Self::Kem(recipient) => recipient.open(),
            Self::RsaKem(recipient) => recipient.open(),
        }
    }
}

impl RecipientId {
    fn parse(certificate: &X509Certificate<'_>) -> Option<Self> {
        let mut subject_key_id = None;
        for extension in certificate.extensions() {
            if let ParsedExtension::SubjectKeyIdentifier(identifier) = extension.parsed_extension()
            {
                if subject_key_id.is_some() || !(1..=MAX_KEY_ID).contains(&identifier.0.len()) {
                    return None;
                }
                subject_key_id = Some(Box::from(identifier.0));
            }
        }
        Some(Self {
            issuer: certificate.issuer().as_raw().into(),
            serial: Ber::unsigned(certificate.raw_serial())?.into(),
            subject_key_id,
        })
    }

    fn issuer_and_serial(&self, candidate: Item<'_>) -> Option<bool> {
        if candidate.tag != SEQUENCE {
            return None;
        }
        let mut fields = Ber(candidate.data);
        let name = fields.take(SEQUENCE)?;
        let serial = fields.take(INTEGER)?.positive_integer()?;
        fields.finish()?;
        if serial != self.serial.as_ref() {
            return Some(false);
        }
        issuer::matches(name, &self.issuer)
    }

    fn key_identifier(&self, candidate: Item<'_>, octet_tag: u8) -> Option<bool> {
        let bytes = candidate.octets(octet_tag, MAX_KEY_ID)?;
        Some(self.subject_key_id.as_deref() == Some(bytes.as_ref()))
    }
}

fn algorithm(item: Item<'_>) -> Option<(&[u8], Option<Item<'_>>)> {
    if item.tag != SEQUENCE {
        return None;
    }
    let mut algorithm = Ber(item.data);
    let oid = algorithm.take(OID)?.data;
    let parameters = if algorithm.0.is_empty() {
        None
    } else {
        Some(algorithm.read()?)
    };
    algorithm.finish()?;
    Some((oid, parameters))
}
