//! PDF encryption dispatch and shared object-level cryptography.

mod legacy;
mod modern;
mod public_key;

use std::borrow::Cow;

use super::syntax::{Dict, ObjectId, PdfString, Value};
use zeroize::Zeroizing;

pub(super) const MAX_FILTER_NAME_BYTES: usize = 127;
const MAX_CRYPT_FILTERS: usize = 64;

#[derive(Clone, Copy)]
enum Method {
    Identity,
    Rc4,
    Aes128,
    Aes256,
}

enum Methods {
    Rc4,
    Filtered(CryptFilters),
}

struct CryptFilters {
    stream: Method,
    embedded: Option<Method>,
    string: Method,
    named: Vec<NamedFilter>,
}

struct NamedFilter {
    name: Box<[u8]>,
    handler: Option<FilterHandler>,
}

#[derive(Clone, Copy)]
struct FilterHandler {
    method: Method,
    embedded_only: bool,
}

impl CryptFilters {
    fn parse(dict: Dict<'_>, version: u64) -> Option<Self> {
        let mut named = Vec::<NamedFilter>::new();
        match dict.unique(b"CF").ok()? {
            None | Some(Value::Null) => {}
            Some(Value::Dict(filters)) => {
                for (name, value) in filters.entries() {
                    let name = name.bytes(MAX_FILTER_NAME_BYTES)?;
                    if named.len() == MAX_CRYPT_FILTERS
                        || name.as_ref() == b"Identity"
                        || named.iter().any(|filter| filter.name == name)
                    {
                        return None;
                    }
                    let Value::Dict(filter) = value else {
                        return None;
                    };
                    named.push(NamedFilter {
                        name,
                        handler: filter_handler(filter, version),
                    });
                }
            }
            _ => return None,
        }
        let default = |key: &[u8]| match dict.unique(key).ok()? {
            None | Some(Value::Null) => Some(Method::Identity),
            Some(Value::Name(name)) => {
                let name = name.bytes(MAX_FILTER_NAME_BYTES)?;
                // The standard treats StmF and StrF as document-open filters.
                lookup(&named, &name, true)
            }
            _ => None,
        };
        let stream = default(b"StmF")?;
        let embedded = match dict.unique(b"EFF").ok()? {
            None | Some(Value::Null) => Some(stream),
            Some(Value::Name(name)) => lookup(&named, &name.bytes(MAX_FILTER_NAME_BYTES)?, true),
            _ => None,
        };
        Some(Self {
            stream,
            embedded,
            string: default(b"StrF")?,
            named,
        })
    }
}

fn lookup(filters: &[NamedFilter], name: &[u8], allow_embedded: bool) -> Option<Method> {
    if name == b"Identity" {
        return Some(Method::Identity);
    }
    let handler = filters
        .iter()
        .find(|filter| filter.name.as_ref() == name)?
        .handler?;
    (allow_embedded || !handler.embedded_only).then_some(handler.method)
}

fn filter_handler(dict: Dict<'_>, version: u64) -> Option<FilterHandler> {
    let embedded_only = match dict.unique(b"AuthEvent").ok()? {
        None | Some(Value::Null) => false,
        Some(Value::Name(name)) if name.is(b"DocOpen") => false,
        Some(Value::Name(name)) if name.is(b"EFOpen") => true,
        _ => return None,
    };
    let method = match dict.unique(b"CFM").ok()? {
        None | Some(Value::Null) => Method::Identity,
        Some(Value::Name(name)) if name.is(b"None") => Method::Identity,
        Some(Value::Name(name)) if version == 4 && name.is(b"V2") => Method::Rc4,
        Some(Value::Name(name)) if version == 4 && name.is(b"AESV2") => Method::Aes128,
        Some(Value::Name(name)) if version == 5 && name.is(b"AESV3") => Method::Aes256,
        _ => return None,
    };
    Some(FilterHandler {
        method,
        embedded_only,
    })
}

struct StandardDictionary {
    methods: Methods,
    key: KeyParameters,
    encrypt_metadata: bool,
}

enum KeyParameters {
    Legacy {
        revision: legacy::Revision,
        key_bytes: usize,
        owner: [u8; 32],
        user: [u8; 32],
        permissions: i32,
    },
    Modern {
        revision: modern::Revision,
        owner: [u8; 48],
        user: [u8; 48],
        owner_key: [u8; 32],
        user_key: [u8; 32],
        validation: [u8; 16],
        permissions: i32,
    },
}

impl StandardDictionary {
    pub(super) fn parse(dict: Dict<'_>) -> Option<Self> {
        if !matches!(dict.unique(b"Filter").ok()?, Some(Value::Name(name)) if name.is(b"Standard"))
        {
            return None;
        }
        let unsigned = |name: &[u8]| match dict.unique(name).ok()?? {
            Value::Unsigned(value) => Some(value),
            _ => None,
        };
        let version = unsigned(b"V")?;
        let revision = unsigned(b"R")?;
        let permissions = match dict.unique(b"P").ok()?? {
            Value::Signed(value) => i32::try_from(value).ok()?,
            Value::Unsigned(value) => u32::try_from(value).ok()? as i32,
            _ => return None,
        };
        let encrypt_metadata = if matches!(version, 4 | 5) {
            match dict.unique(b"EncryptMetadata").ok()? {
                None | Some(Value::Null) => true,
                Some(Value::Boolean(value)) => value,
                _ => return None,
            }
        } else {
            true
        };
        let methods = match version {
            1 | 2 => Methods::Rc4,
            4 | 5 => Methods::Filtered(CryptFilters::parse(dict, version)?),
            _ => return None,
        };
        let key = match (version, revision) {
            (1, 2) | (2, 3) | (4, 4) => {
                let (revision, key_bytes) = match revision {
                    2 => (legacy::Revision::R2, 5),
                    3 => {
                        let length = match dict.unique(b"Length").ok()? {
                            None | Some(Value::Null) => 40,
                            Some(Value::Unsigned(length))
                                if (40..=128).contains(&length) && length.is_multiple_of(8) =>
                            {
                                length
                            }
                            _ => return None,
                        };
                        (legacy::Revision::R3, (length / 8) as usize)
                    }
                    _ => (legacy::Revision::R4, 16),
                };
                KeyParameters::Legacy {
                    revision,
                    key_bytes,
                    owner: string(dict, b"O", 32)?,
                    user: string(dict, b"U", 32)?,
                    permissions,
                }
            }
            (5, 5 | 6) => KeyParameters::Modern {
                revision: if revision == 5 {
                    modern::Revision::R5
                } else {
                    modern::Revision::R6
                },
                owner: string(dict, b"O", 128)?,
                user: string(dict, b"U", 128)?,
                owner_key: string(dict, b"OE", 32)?,
                user_key: string(dict, b"UE", 32)?,
                validation: string(dict, b"Perms", 16)?,
                permissions,
            },
            _ => return None,
        };
        Some(Self {
            methods,
            key,
            encrypt_metadata,
        })
    }

    fn unlock(self, id: Option<&[u8]>) -> Option<StandardSecurity> {
        let encrypt_metadata = self.encrypt_metadata;
        let key = match self.key {
            KeyParameters::Legacy {
                revision,
                key_bytes,
                owner,
                user,
                permissions,
            } => FileKey::Legacy(legacy::open(legacy::AuthInput {
                revision,
                key_bytes,
                owner: &owner,
                user: &user,
                permissions,
                id: id?,
                encrypt_metadata,
            })?),
            KeyParameters::Modern {
                revision,
                owner,
                user,
                owner_key,
                user_key,
                validation,
                permissions,
            } => FileKey::Modern(modern::open(modern::AuthInput {
                revision,
                owner: &owner,
                user: &user,
                owner_key: &owner_key,
                user_key: &user_key,
                validation: &validation,
                permissions,
                encrypt_metadata,
            })?),
        };
        Some(StandardSecurity {
            key,
            methods: self.methods,
            encrypt_metadata,
        })
    }
}

enum DeclaredHandler {
    Standard(Box<StandardDictionary>),
    PublicKey(public_key::Dictionary),
}

pub(super) struct Dictionary(DeclaredHandler);

impl Dictionary {
    pub(super) fn parse(dict: Dict<'_>) -> Option<Self> {
        let Value::Name(name) = dict.unique(b"Filter").ok()?? else {
            return None;
        };
        let handler = if name.is(b"Standard") {
            DeclaredHandler::Standard(Box::new(StandardDictionary::parse(dict)?))
        } else if name.is(b"Adobe.PubSec") {
            DeclaredHandler::PublicKey(public_key::Dictionary::parse(dict, 1 << 20)?)
        } else {
            return None;
        };
        Some(Self(handler))
    }

    pub(super) fn unlock(
        self,
        id: Option<&[u8]>,
        authorization: Option<&crate::extraction::PdfRecipientAuthorization>,
    ) -> Option<Security> {
        let handler = match self.0 {
            DeclaredHandler::Standard(dictionary) => {
                Handler::Standard(Box::new(dictionary.unlock(id)?))
            }
            DeclaredHandler::PublicKey(dictionary) => {
                Handler::PublicKey(dictionary.unlock(&mut |envelope| {
                    authorization.and_then(|credential| credential.open(envelope))
                })?)
            }
        };
        Some(Security(handler))
    }
}

enum Handler {
    Standard(Box<StandardSecurity>),
    PublicKey(public_key::Unlocked),
}

pub(super) struct Security(Handler);

impl Security {
    fn stream<'a>(
        &self,
        purpose: StreamPurpose,
        id: ObjectId,
        filter: Option<&[u8]>,
        data: &'a [u8],
    ) -> Option<Cow<'a, [u8]>> {
        match &self.0 {
            Handler::Standard(handler) => handler.stream(purpose, id, filter, data),
            Handler::PublicKey(handler) => handler.stream(purpose, id, filter, data),
        }
    }

    fn bytes<'a>(
        &self,
        id: ObjectId,
        string: PdfString<'a>,
        limit: usize,
    ) -> Option<Cow<'a, [u8]>> {
        match &self.0 {
            Handler::Standard(handler) => handler.bytes(id, string, limit),
            Handler::PublicKey(handler) => handler.bytes(id, string, limit),
        }
    }
}

fn string<const N: usize>(dict: Dict<'_>, name: &[u8], limit: usize) -> Option<[u8; N]> {
    let Value::String(string) = dict.unique(name).ok()?? else {
        return None;
    };
    string.bytes(limit)?.first_chunk().copied()
}

enum FileKey {
    Legacy(legacy::Key),
    Modern(Zeroizing<[u8; 32]>),
}

struct StandardSecurity {
    key: FileKey,
    methods: Methods,
    encrypt_metadata: bool,
}

impl StandardSecurity {
    fn stream<'a>(
        &self,
        purpose: StreamPurpose,
        id: ObjectId,
        filter: Option<&[u8]>,
        data: &'a [u8],
    ) -> Option<Cow<'a, [u8]>> {
        if matches!(purpose, StreamPurpose::Metadata) && !self.encrypt_metadata && filter.is_none()
        {
            return Some(Cow::Borrowed(data));
        }
        let method = match (&self.methods, filter) {
            (Methods::Rc4, None) => Method::Rc4,
            (Methods::Filtered(filters), None)
                if matches!(purpose, StreamPurpose::EmbeddedFile) =>
            {
                filters.embedded?
            }
            (Methods::Filtered(filters), None) => filters.stream,
            (Methods::Filtered(filters), Some(name)) => lookup(
                &filters.named,
                name,
                matches!(purpose, StreamPurpose::EmbeddedFile),
            )?,
            (Methods::Rc4, Some(_)) => return None,
        };
        decrypt(method, &self.key, id, Cow::Borrowed(data))
    }

    fn bytes<'a>(
        &self,
        id: ObjectId,
        string: PdfString<'a>,
        limit: usize,
    ) -> Option<Cow<'a, [u8]>> {
        let method = match &self.methods {
            Methods::Rc4 => Method::Rc4,
            Methods::Filtered(filters) => filters.string,
        };
        decrypt_string(method, &self.key, id, string, limit)
    }
}

fn decrypt<'a>(
    method: Method,
    key: &FileKey,
    id: ObjectId,
    data: Cow<'a, [u8]>,
) -> Option<Cow<'a, [u8]>> {
    if matches!(method, Method::Identity) {
        return Some(data);
    }
    let mut output = data.into_owned();
    match (method, key) {
        (Method::Rc4, FileKey::Legacy(file_key)) => {
            let key = legacy::object_key(file_key, id, false)?;
            legacy::crypt_rc4(&mut output, &key);
        }
        (Method::Aes128, FileKey::Legacy(file_key)) => {
            let key = legacy::object_key(file_key, id, true)?;
            let key = key.as_bytes().try_into().ok()?;
            aes_payload(&mut output, |body, iv| modern::decrypt128(body, key, iv))?;
        }
        (Method::Aes256, FileKey::Modern(file_key)) => {
            aes_payload(&mut output, |body, iv| {
                modern::decrypt256(body, file_key, iv)
            })?;
        }
        _ => return None,
    }
    Some(Cow::Owned(output))
}

fn decrypt_string<'a>(
    method: Method,
    key: &FileKey,
    id: ObjectId,
    string: PdfString<'a>,
    limit: usize,
) -> Option<Cow<'a, [u8]>> {
    let limit_on_disk = if matches!(method, Method::Aes128 | Method::Aes256) {
        limit.saturating_add(32)
    } else {
        limit
    };
    let bytes = decrypt(method, key, id, string.bytes(limit_on_disk)?)?;
    (bytes.len() <= limit).then_some(bytes)
}

fn aes_payload(
    data: &mut Vec<u8>,
    decrypt: impl FnOnce(&mut [u8], &[u8; 16]) -> Option<()>,
) -> Option<()> {
    let (iv, body) = data.split_first_chunk_mut()?;
    if body.is_empty() {
        return None;
    }
    decrypt(body, iv)?;
    let padding = usize::from(*body.last()?);
    let actual = body.len().checked_sub(padding)?;
    if !(1..=16).contains(&padding)
        || !body[actual..]
            .iter()
            .all(|&byte| usize::from(byte) == padding)
    {
        return None;
    }
    data.copy_within(16..16 + actual, 0);
    data.truncate(actual);
    Some(())
}

#[derive(Clone, Copy)]
pub(super) enum ObjectEncryption<'a> {
    Plain,
    Object(&'a Security, ObjectId),
}

#[derive(Clone, Copy)]
pub(super) enum StreamPurpose {
    Objects,
    Metadata,
    EmbeddedFile,
}

impl<'security> ObjectEncryption<'security> {
    pub(super) fn for_object(security: Option<&'security Security>, id: ObjectId) -> Self {
        match security {
            Some(security) => Self::Object(security, id),
            None => Self::Plain,
        }
    }

    pub(super) fn stream<'a>(
        self,
        purpose: StreamPurpose,
        filter: Option<&[u8]>,
        data: &'a [u8],
    ) -> Option<Cow<'a, [u8]>> {
        match self {
            Self::Plain if filter.is_none_or(|name| name == b"Identity") => {
                Some(Cow::Borrowed(data))
            }
            Self::Plain => None,
            Self::Object(security, id) => security.stream(purpose, id, filter, data),
        }
    }

    pub(super) fn bytes<'a>(self, string: PdfString<'a>, limit: usize) -> Option<Cow<'a, [u8]>> {
        let Self::Object(security, id) = self else {
            return string.bytes(limit);
        };
        security.bytes(id, string, limit)
    }
}
