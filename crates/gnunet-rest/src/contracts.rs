//! Actual official REST JSON shapes. This layer allocates nothing and grants no
//! identity, zone, signature, mutation, persistence or service result authority.
use gnunet_gnsrecord::RecordFlags;
use gnunet_json::{JsonString, Value, ValueKind};
use gnunet_types::Error;
use gnunet_wire::official::identity::KeyType;

/// POST /identity JSON, with the actual default ECDSA type.
#[derive(Clone, Copy, Debug)]
pub struct IdentityCreate<'a> {
    /// Required nonempty name, decoded/normalized by its actual owner.
    pub name: JsonString<'a>,
    /// EDDSA when explicitly selected, otherwise the official ECDSA default.
    pub kind: KeyType,
    /// Optional serialized private-key Base32 text; never ordinary Debug data.
    pub private: Option<JsonString<'a>>,
}
impl<'a> IdentityCreate<'a> {
    /// Validate the official required/optional field types. Extra fields are
    /// allowed by this C create contract; omission does not leave type undefined.
    pub fn parse(root: Value<'a>) -> Result<Self, Error> {
        object(root)?;
        let name = nonempty(required(root, b"name")?.string()?)?;
        let kind = match root.get(b"type") {
            None => KeyType::Ecdsa,
            Some(value) => {
                if equal_fold(value.string()?, b"EDDSA") {
                    KeyType::Eddsa
                } else {
                    KeyType::Ecdsa
                }
            }
        };
        let private = root.get(b"privkey").map(Value::string).transpose()?;
        Ok(Self {
            name,
            kind,
            private,
        })
    }
}
/// PUT `/identity/name|pubkey/<selector>` requires exactly newname.
pub fn identity_rename(root: Value<'_>) -> Result<JsonString<'_>, Error> {
    only(root, &[b"newname"])?;
    nonempty(required(root, b"newname")?.string()?)
}
/// Official NAMESTORE record-set JSON envelope: record_name plus data array.
#[derive(Clone, Copy, Debug)]
pub struct RecordSet<'a> {
    /// Required actual label string; the empty apex is valid.
    pub name: JsonString<'a>,
    data: Value<'a>,
}
impl<'a> RecordSet<'a> {
    /// Check the exact official envelope; no private binary/base64 alternative.
    pub fn parse(root: Value<'a>) -> Result<Self, Error> {
        only(root, &[b"record_name", b"data"])?;
        let name = required(root, b"record_name")?.string()?;
        let data = required(root, b"data")?;
        data.elements()?;
        Ok(Self { name, data })
    }
    /// Decode all complete record descriptors in source order, without allocation.
    pub fn records(self) -> Result<impl Iterator<Item = Result<Record<'a>, Error>> + 'a, Error> {
        Ok(self.data.elements()?.map(Record::parse))
    }
}
/// One actual official GNSRECORD REST text descriptor, not a new wire protocol.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    /// Human-readable plugin type (e.g. A/AAAA/TXT), to an explicit text provider.
    pub kind: JsonString<'a>,
    /// Exact decoded text value, to that same provider.
    pub value: JsonString<'a>,
    /// Official microseconds. -1 is the signed-JSON representation of NEVER.
    pub expiration: u64,
    /// Five JSON-exposed flag bits. Critical/unknown bits are not in this API.
    pub flags: RecordFlags,
}
impl<'a> Record<'a> {
    /// Validate the official required boolean flags and corresponding time field.
    /// Valid native-generated JSON always pairs relative flag/time correctly;
    /// contradictory fields and negative nonsentinel dates are refused.
    pub fn parse(root: Value<'a>) -> Result<Self, Error> {
        object(root)?;
        let kind = required(root, b"record_type")?.string()?;
        let value = required(root, b"value")?.string()?;
        let relative = required(root, b"is_relative_expiration")?.boolean()?;
        let time = required(
            root,
            if relative {
                b"relative_expiration"
            } else {
                b"absolute_expiration"
            },
        )?
        .integer()?;
        if time < 0 && time != -1 {
            return Err(Error::InvalidInput);
        }
        let mut bits = if relative {
            RecordFlags::RELATIVE_EXPIRATION.bits()
        } else {
            0
        };
        for (name, flag) in [
            (b"is_maintenance".as_slice(), RecordFlags::MAINTENANCE),
            (b"is_private", RecordFlags::PRIVATE),
            (b"is_supplemental", RecordFlags::SUPPLEMENTAL),
            (b"is_shadow", RecordFlags::SHADOW),
        ] {
            if required(root, name)?.boolean()? {
                bits |= flag.bits();
            }
        }
        Ok(Self {
            kind,
            value,
            expiration: time as u64,
            flags: RecordFlags::from_bits_preserve(bits),
        })
    }
}
/// Actual RECLAIM attribute-store JSON, including optional raw identifier text.
#[derive(Clone, Copy, Debug)]
pub struct Attribute<'a> {
    /// Attribute name; C convenience construction applies lowercase/NFD.
    pub name: JsonString<'a>,
    /// Plugin format name, currently STRING.
    pub kind: JsonString<'a>,
    /// Actual plugin text conversion input.
    pub value: JsonString<'a>,
    /// Optional ID; missing/empty means zero and actual service assignment.
    pub id: Option<JsonString<'a>>,
    /// Optional referenced credential ID; missing/empty means self-asserted.
    pub credential: Option<JsonString<'a>>,
}
impl<'a> Attribute<'a> {
    /// Check the exact official object. Optional flag is a string accepted by C
    /// but not assigned to attribute flags by that producer; it is not invented.
    pub fn parse(root: Value<'a>) -> Result<Self, Error> {
        only(
            root,
            &[b"name", b"type", b"value", b"id", b"credential", b"flag"],
        )?;
        if let Some(flag) = root.get(b"flag") {
            flag.string()?;
        }
        Ok(Self {
            name: required(root, b"name")?.string()?,
            kind: required(root, b"type")?.string()?,
            value: required(root, b"value")?.string()?,
            id: root.get(b"id").map(Value::string).transpose()?,
            credential: root.get(b"credential").map(Value::string).transpose()?,
        })
    }
}
/// Actual RECLAIM credential-store JSON. Value may be a string/object/array;
/// source compact conversion has no top-level JSON scalar ENCODE_ANY flag.
#[derive(Clone, Copy, Debug)]
pub struct Credential<'a> {
    /// Credential name for exact lowercase/NFD construction.
    pub name: JsonString<'a>,
    /// Actual format name, e.g. JWT; opaque values do not establish authenticity.
    pub kind: JsonString<'a>,
    /// Source value, still borrowing the original guarded JSON document.
    pub value: Value<'a>,
    /// Optional raw identifier text.
    pub id: Option<JsonString<'a>>,
}
impl<'a> Credential<'a> {
    /// Validate complete source fields without creating a credential/proof.
    pub fn parse(root: Value<'a>) -> Result<Self, Error> {
        only(root, &[b"name", b"type", b"value", b"id"])?;
        let value = required(root, b"value")?;
        if !matches!(
            value.kind(),
            ValueKind::String | ValueKind::Object | ValueKind::Array
        ) {
            return Err(Error::Malformed);
        }
        Ok(Self {
            name: required(root, b"name")?.string()?,
            kind: required(root, b"type")?.string()?,
            value,
            id: root.get(b"id").map(Value::string).transpose()?,
        })
    }
}
/// Revoke/consume common ticket JSON. Actual authorization comes from selected
/// original identity/source, not from successfully parsing this object.
#[derive(Clone, Copy, Debug)]
pub struct Ticket<'a> {
    /// Required capability GNS name.
    pub name: JsonString<'a>,
    /// Required for consume, optional/ignored for revoke as in the C route.
    pub uri: Option<JsonString<'a>>,
}
impl<'a> Ticket<'a> {
    /// Validate original ticket/URI strings. Extra fields are source-compatible.
    pub fn parse(root: Value<'a>, consume: bool) -> Result<Self, Error> {
        object(root)?;
        let name = required(root, b"gns_name")?.string()?;
        let uri = root.get(b"rp_uri").map(Value::string).transpose()?;
        if consume && uri.is_none() {
            return Err(Error::Malformed);
        }
        Ok(Self { name, uri })
    }
}
/// Decode an exact mandatory public ASCII field without implicit type coercion.
pub fn required<'a>(root: Value<'a>, name: &[u8]) -> Result<Value<'a>, Error> {
    object(root)?;
    root.get(name).ok_or(Error::Malformed)
}
fn object(root: Value<'_>) -> Result<(), Error> {
    if root.kind() != ValueKind::Object {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn nonempty(s: JsonString<'_>) -> Result<JsonString<'_>, Error> {
    if s.decoded_len()? == 0 {
        return Err(Error::InvalidInput);
    }
    Ok(s)
}
fn equal_fold(s: JsonString<'_>, ascii: &[u8]) -> bool {
    s.chars()
        .map(|c| c.to_ascii_uppercase())
        .eq(ascii.iter().map(|b| char::from(b.to_ascii_uppercase())))
}
fn only(root: Value<'_>, names: &[&[u8]]) -> Result<(), Error> {
    for member in root.members()? {
        if !names.iter().any(|name| member.name.eq_ascii(name)) {
            return Err(Error::Malformed);
        }
    }
    Ok(())
}
