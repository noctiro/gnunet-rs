use crate::{Attribute, Credential, Identifier, fixed::identifier_label, ipc::Request};
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType};
use gnunet_types::{Error, RelativeTime};
use gnunet_wire::official::identity::SecretKeyView;

#[derive(Clone, Copy)]
enum Object<'a> {
    Attribute(Attribute<'a>),
    Credential(Credential<'a>),
}

/// One original Store request, with its opaque RID and typed private authority.
/// The caller owns the original input bytes and must erase them after use.
#[derive(Clone, Copy)]
pub struct Store<'a> {
    rid: u32,
    key: SecretKeyView<'a>,
    expiration: RelativeTime,
    object: Object<'a>,
}

impl<'a> Store<'a> {
    /// Select an attribute or credential Store without copying its payload.
    #[must_use]
    pub const fn from_request(request: Request<'a>) -> Option<Self> {
        let (rid, key, expiration, object) = match request {
            Request::StoreAttribute {
                rid,
                expiration,
                key,
                attribute,
            } => (rid, key, expiration, Object::Attribute(attribute)),
            Request::StoreCredential {
                rid,
                expiration,
                key,
                credential,
            } => (rid, key, expiration, Object::Credential(credential)),
            _ => return None,
        };
        Some(Self {
            rid,
            key,
            expiration,
            object,
        })
    }

    /// Original opaque request ID.
    #[must_use]
    pub const fn rid(&self) -> u32 {
        self.rid
    }

    /// Original typed private authority for the NAMESTORE operation.
    #[must_use]
    pub const fn key(&self) -> SecretKeyView<'a> {
        self.key
    }

    /// Original object ID. Zero requests assignment by the service.
    #[must_use]
    pub const fn requested_id(&self) -> Identifier {
        match &self.object {
            Object::Attribute(attribute) => attribute.id,
            Object::Credential(credential) => credential.id,
        }
    }

    /// Keep a supplied nonzero ID, or accept a fresh caller-generated nonzero
    /// ID only when the original was zero. The caller must check newly assigned
    /// IDs for collisions in the actual authority before writing.
    pub fn assign_id(mut self, generated: Option<Identifier>) -> Result<AssignedStore<'a>, Error> {
        if self.requested_id().is_zero() {
            let id = generated.ok_or(Error::NotReady)?;
            if id.is_zero() {
                return Err(Error::InvalidInput);
            }
            match &mut self.object {
                Object::Attribute(attribute) => attribute.id = id,
                Object::Credential(credential) => credential.id = id,
            }
        } else if generated.is_some() {
            return Err(Error::InvalidInput);
        }
        Ok(AssignedStore(self))
    }
}

/// Original Store with a selected nonzero ID, ready to encode one NAMESTORE
/// record. Preparing the record does not write it or complete the request.
pub struct AssignedStore<'a>(Store<'a>);

impl<'a> AssignedStore<'a> {
    /// Original opaque request ID.
    #[must_use]
    pub const fn rid(&self) -> u32 {
        self.0.rid()
    }

    /// Original typed private authority for the NAMESTORE operation.
    #[must_use]
    pub const fn key(&self) -> SecretKeyView<'a> {
        self.0.key()
    }

    /// Chosen nonzero object ID.
    #[must_use]
    pub const fn id(&self) -> Identifier {
        self.0.requested_id()
    }

    /// Write the official NAMESTORE record label without a terminator.
    pub fn label(&self, out: &mut [u8]) -> Result<usize, Error> {
        identifier_label(self.id(), out)
    }

    /// Number of caller scratch bytes required for the object payload.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        match self.0.object {
            Object::Attribute(attribute) => attribute.encoded_len(),
            Object::Credential(credential) => credential.encoded_len(),
        }
    }

    /// Encode the object into caller storage and borrow that exact payload in
    /// the corresponding NAMESTORE record. Failure leaves storage unchanged.
    pub fn encode_record<'out>(&self, out: &'out mut [u8]) -> Result<RecordData<'out>, Error> {
        let written = match self.0.object {
            Object::Attribute(attribute) => attribute.encode(out)?,
            Object::Credential(credential) => credential.encode(out)?,
        };
        Ok(self.record(&out[..written]))
    }

    // The allocating engine already owns the exact bytes from encode_record.
    pub(crate) fn record<'wire>(&self, data: &'wire [u8]) -> RecordData<'wire> {
        RecordData {
            record_type: match self.0.object {
                Object::Attribute(_) => RecordType::RECLAIM_ATTRIBUTE,
                Object::Credential(_) => RecordType::RECLAIM_CREDENTIAL,
            },
            expiration_time: self.0.expiration.as_micros(),
            flags: RecordFlags::RELATIVE_EXPIRATION,
            data,
        }
    }
}
