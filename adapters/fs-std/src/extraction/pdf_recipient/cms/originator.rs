//! Bounded X.509 lookup for CMS agreement with a static originator.

use x509_parser::{certificate::X509Certificate, prelude::parse_x509_certificate};

use crate::extraction::Error;

use super::{
    Ber, CONTEXT_0, CONTEXT_1, IMPLICIT_OCTETS, Item, MAX_CREDENTIAL_BYTES, RecipientId, SEQUENCE,
};

const MAX_ORIGINATORS: usize = 32;

#[derive(Default)]
pub(super) struct Store {
    certificates: Vec<Box<[u8]>>,
}

impl Store {
    pub(super) fn insert(&mut self, der: &[u8]) -> Result<(), Error> {
        if der.len() > MAX_CREDENTIAL_BYTES {
            return Err(Error::Limit);
        }
        parse(der).ok_or(Error::Binding)?;
        if let Err(position) = self
            .certificates
            .binary_search_by(|item| item.as_ref().cmp(der))
        {
            if self.certificates.len() == MAX_ORIGINATORS {
                return Err(Error::Limit);
            }
            self.certificates.try_reserve(1).map_err(|_| Error::Limit)?;
            self.certificates.insert(position, der.into());
        }
        Ok(())
    }

    pub(super) fn identity(&self, recipient: [u8; 32]) -> [u8; 32] {
        if self.certificates.is_empty() {
            return recipient;
        }
        let mut parts: [&[u8]; MAX_ORIGINATORS + 2] = [&[]; MAX_ORIGINATORS + 2];
        parts[0] = b"GNUnet FS CMS originator certificates\0";
        parts[1] = &recipient;
        for (part, cert) in parts[2..].iter_mut().zip(&self.certificates) {
            // Each DER certificate is independently self-delimiting.
            *part = cert;
        }
        gnunet_crypto::hash256_parts(&parts)
    }

    pub(super) fn combine<'a>(
        &'a self,
        originator_info: Option<Item<'a>>,
    ) -> Option<Certificates<'a>> {
        let embedded = if let Some(info) = originator_info {
            let mut fields = Ber(info.data);
            let certificates = fields.optional(CONTEXT_0)?.map(|item| Ber(item.data));
            fields.optional(CONTEXT_1)?;
            fields.finish()?;
            certificates
        } else {
            None
        };
        Some(Certificates {
            embedded,
            local: &self.certificates,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct Certificates<'a> {
    embedded: Option<Ber<'a>>,
    local: &'a [Box<[u8]>],
}

impl<'a> Certificates<'a> {
    pub(super) fn find(self, identity: Item<'_>) -> Option<X509Certificate<'a>> {
        let mut selected = None;
        let mut remaining = MAX_ORIGINATORS;
        let mut visit = |der| {
            let cert = parse(der)?;
            let selected_id = RecipientId::parse(&cert)?;
            let matches = match identity.tag {
                SEQUENCE => selected_id.issuer_and_serial(identity)?,
                IMPLICIT_OCTETS | CONTEXT_0 => {
                    selected_id.key_identifier(identity, IMPLICIT_OCTETS)?
                }
                _ => return None,
            };
            if matches {
                if let Some(previous) = &selected {
                    let previous: &X509Certificate<'_> = previous;
                    if previous.as_raw() != cert.as_raw() {
                        return None;
                    }
                } else {
                    selected = Some(cert);
                }
            }
            Some(())
        };
        if let Some(mut embedded) = self.embedded {
            while !embedded.0.is_empty() {
                remaining = remaining.checked_sub(1)?;
                let item = embedded.read()?;
                match item.tag {
                    SEQUENCE => visit(item.encoded)?,
                    0xa0..=0xa3 => {}
                    _ => return None,
                }
            }
        }
        for local in self.local {
            visit(local.as_ref())?;
        }
        selected
    }
}

fn parse(der: &[u8]) -> Option<X509Certificate<'_>> {
    if der.len() > MAX_CREDENTIAL_BYTES {
        return None;
    }
    let (rest, certificate) = parse_x509_certificate(der).ok()?;
    rest.is_empty().then_some(certificate)
}
