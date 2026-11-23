//! Adobe.PubSec file-key derivation and crypt-filter selection (ISO 32000-2 §7.6.5).

use std::borrow::Cow;

use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::extraction::PdfRecipientContent;

use super::{
    Dict, FileKey, MAX_CRYPT_FILTERS, MAX_FILTER_NAME_BYTES, Method, ObjectId, PdfString,
    StreamPurpose, Value, decrypt, decrypt_string, legacy,
};

const MAX_RECIPIENTS: usize = 256;
const OWNER_PERMISSION: u32 = 1 << 1;
const EXTRACT_PERMISSION: u32 = 1 << 4;

type OpenRecipient<'a> = dyn FnMut(&[u8]) -> Option<PdfRecipientContent> + 'a;

pub(super) struct Dictionary(Protection<Pending>);

pub(super) struct Unlocked(Protection<Authorized>);

enum Protection<T> {
    Whole(T),
    Filtered(Filters<T>),
}

struct Filters<T> {
    named: Vec<Named<T>>,
    stream: Selection,
    string: Selection,
    embedded: Option<Selection>,
}

struct Named<T> {
    name: Box<[u8]>,
    embedded_only: bool,
    state: Option<T>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Selection {
    Identity,
    Named(usize),
}

#[derive(Clone, Copy)]
enum Cipher {
    Rc4 { key_bytes: usize },
    Aes128,
    Aes256,
}

#[derive(Clone, Copy)]
enum FilterUse {
    DefaultStream,
    DocumentObjects,
    EmbeddedDefault,
    Explicit,
}

impl FilterUse {
    fn document(self) -> bool {
        matches!(self, Self::DefaultStream | Self::DocumentObjects)
    }
}

enum Recipients {
    Document(Vec<Box<[u8]>>),
    Stream(Box<[u8]>),
}

struct RecipientBudget {
    bytes: usize,
    entries: usize,
}

struct Pending {
    cipher: Cipher,
    recipients: Recipients,
    clear_metadata: bool,
}

struct Authorized {
    method: Method,
    key: FileKey,
    clear_metadata: bool,
}

impl Dictionary {
    pub(super) fn parse(dict: Dict<'_>, recipient_bytes: usize) -> Option<Self> {
        if !matches!(dict.unique(b"Filter").ok()?, Some(Value::Name(name)) if name.is(b"Adobe.PubSec"))
        {
            return None;
        }
        let Value::Name(subfilter) = dict.unique(b"SubFilter").ok()?? else {
            return None;
        };
        let Value::Unsigned(version) = dict.unique(b"V").ok()?? else {
            return None;
        };
        let mut budget = RecipientBudget {
            bytes: recipient_bytes,
            entries: MAX_RECIPIENTS,
        };
        if subfilter.is(b"adbe.pkcs7.s5") && matches!(version, 4 | 5) {
            return Some(Self(Protection::Filtered(read_filters(
                dict,
                version,
                &mut budget,
            )?)));
        }
        if !subfilter.is(b"adbe.pkcs7.s3") && !subfilter.is(b"adbe.pkcs7.s4") {
            return None;
        }
        let key_bytes = match version {
            1 => 5,
            2 => rc4_bytes(length(dict)?.unwrap_or(40))?,
            _ => return None,
        };
        Some(Self(Protection::Whole(Pending {
            cipher: Cipher::Rc4 { key_bytes },
            recipients: Recipients::read(dict, FilterUse::DocumentObjects, &mut budget)?,
            clear_metadata: false,
        })))
    }

    pub(super) fn unlock(self, open: &mut OpenRecipient<'_>) -> Option<Unlocked> {
        let state = match self.0 {
            Protection::Whole(filter) => Protection::Whole(filter.unlock(open)?),
            Protection::Filtered(Filters {
                named,
                stream,
                string,
                embedded,
            }) => {
                let mut authorized = Vec::with_capacity(named.len());
                for (index, entry) in named.into_iter().enumerate() {
                    let state = entry.state.and_then(|pending| pending.unlock(open));
                    let required = [stream, string].contains(&Selection::Named(index));
                    if required && state.is_none() {
                        return None;
                    }
                    authorized.push(Named {
                        name: entry.name,
                        embedded_only: entry.embedded_only,
                        state,
                    });
                }
                Protection::Filtered(Filters {
                    named: authorized,
                    stream,
                    string,
                    embedded,
                })
            }
        };
        Some(Unlocked(state))
    }
}

fn read_filters(
    dict: Dict<'_>,
    version: u64,
    budget: &mut RecipientBudget,
) -> Option<Filters<Pending>> {
    fn selector(dict: Dict<'_>, key: &[u8]) -> Option<Option<Box<[u8]>>> {
        match dict.unique(key).ok()? {
            None | Some(Value::Null) => Some(None),
            Some(Value::Name(name)) => Some(Some(name.bytes(MAX_FILTER_NAME_BYTES)?)),
            _ => None,
        }
    }
    let stream = selector(dict, b"StmF")?;
    let string = selector(dict, b"StrF")?;
    let embedded = selector(dict, b"EFF")?;
    let mut named = Vec::<Named<Pending>>::new();
    match dict.unique(b"CF").ok()? {
        None | Some(Value::Null) => {}
        Some(Value::Dict(filters)) => {
            for (name, value) in filters.entries() {
                let name = name.bytes(MAX_FILTER_NAME_BYTES)?;
                if name.as_ref() == b"Identity" {
                    continue;
                }
                if named.len() == MAX_CRYPT_FILTERS || named.iter().any(|entry| entry.name == name)
                {
                    return None;
                }
                let Value::Dict(filter) = value else {
                    return None;
                };
                let usage = if stream.as_deref() == Some(name.as_ref()) {
                    FilterUse::DefaultStream
                } else if string.as_deref() == Some(name.as_ref()) {
                    FilterUse::DocumentObjects
                } else if embedded.as_deref() == Some(name.as_ref()) {
                    FilterUse::EmbeddedDefault
                } else {
                    FilterUse::Explicit
                };
                let auth_event = embedded_authorization(filter)
                    .filter(|&embedded| !usage.document() || !embedded);
                let state = auth_event.and_then(|_| Pending::read(filter, version, usage, budget));
                named.push(Named {
                    name,
                    embedded_only: auth_event.unwrap_or(false),
                    state,
                });
            }
        }
        _ => return None,
    }
    let lookup = |name: Option<&[u8]>| match name {
        None | Some(b"Identity") => Some(Selection::Identity),
        Some(name) => named
            .iter()
            .position(|entry| entry.name.as_ref() == name)
            .map(Selection::Named),
    };
    Some(Filters {
        stream: lookup(stream.as_deref())?,
        string: lookup(string.as_deref())?,
        embedded: lookup(embedded.as_deref().or(stream.as_deref())),
        named,
    })
}

fn embedded_authorization(dict: Dict<'_>) -> Option<bool> {
    match dict.unique(b"AuthEvent").ok()? {
        None | Some(Value::Null) => Some(false),
        Some(Value::Name(event)) if event.is(b"DocOpen") => Some(false),
        Some(Value::Name(event)) if event.is(b"EFOpen") => Some(true),
        _ => None,
    }
}

impl Pending {
    fn read(
        dict: Dict<'_>,
        version: u64,
        usage: FilterUse,
        budget: &mut RecipientBudget,
    ) -> Option<Self> {
        match dict.unique(b"Type").ok()? {
            None | Some(Value::Null) => {}
            Some(Value::Name(kind)) if kind.is(b"CryptFilter") => {}
            _ => return None,
        }
        let Value::Name(method) = dict.unique(b"CFM").ok()?? else {
            return None;
        };
        let bits = length(dict)?;
        let cipher = match version {
            4 if method.is(b"V2") => Cipher::Rc4 {
                key_bytes: rc4_bytes(bits?)?,
            },
            4 if method.is(b"AESV2") && bits == Some(128) => Cipher::Aes128,
            5 if method.is(b"AESV3") && bits == Some(256) => Cipher::Aes256,
            _ => return None,
        };
        let clear_metadata = if matches!(usage, FilterUse::DefaultStream) {
            match dict.unique(b"EncryptMetadata").ok()? {
                None | Some(Value::Null) => false,
                Some(Value::Boolean(value)) => !value,
                _ => return None,
            }
        } else {
            false
        };
        Some(Self {
            cipher,
            recipients: Recipients::read(dict, usage, budget)?,
            clear_metadata,
        })
    }

    fn unlock(self, open: &mut OpenRecipient<'_>) -> Option<Authorized> {
        let contents = self.recipients.contents();
        // The first matching CMS group determines the recipient's permissions.
        let content = contents.iter().find_map(|der| open(der))?;
        let seed = match (&self.recipients, content) {
            (Recipients::Document(_), PdfRecipientContent::Document { seed, permissions })
                if allows_extraction(permissions, self.cipher) =>
            {
                seed
            }
            (Recipients::Stream(_), PdfRecipientContent::Stream(seed)) => seed,
            _ => return None,
        };
        let seed = seed.as_slice();
        let (method, key) = match self.cipher {
            Cipher::Rc4 { key_bytes } => (
                Method::Rc4,
                legacy_file_key(seed, contents, self.clear_metadata, key_bytes)?,
            ),
            Cipher::Aes128 => (
                Method::Aes128,
                legacy_file_key(seed, contents, self.clear_metadata, 16)?,
            ),
            Cipher::Aes256 => {
                let mut digest = key_digest::<Sha256>(seed, contents, self.clear_metadata);
                let mut key = Zeroizing::new([0; 32]);
                key.copy_from_slice(&digest);
                digest.as_mut_slice().zeroize();
                (Method::Aes256, FileKey::Modern(key))
            }
        };
        Some(Authorized {
            method,
            key,
            clear_metadata: self.clear_metadata,
        })
    }
}

impl Recipients {
    fn read(dict: Dict<'_>, usage: FilterUse, budget: &mut RecipientBudget) -> Option<Self> {
        match dict.unique(b"Recipients").ok()?? {
            Value::Array(items) if !matches!(usage, FilterUse::Explicit) => {
                let mut recipients = Vec::new();
                for item in items.values() {
                    let Value::String(item) = item else {
                        return None;
                    };
                    recipients.push(budget.copy(item)?);
                }
                (!recipients.is_empty()).then_some(Self::Document(recipients))
            }
            Value::String(item) if !usage.document() => Some(Self::Stream(budget.copy(item)?)),
            _ => None,
        }
    }

    fn contents(&self) -> &[Box<[u8]>] {
        match self {
            Self::Document(contents) => contents,
            Self::Stream(content) => std::slice::from_ref(content),
        }
    }
}

impl RecipientBudget {
    fn copy(&mut self, string: PdfString<'_>) -> Option<Box<[u8]>> {
        self.entries = self.entries.checked_sub(1)?;
        let contents = string.bytes(self.bytes)?;
        if contents.is_empty() {
            return None;
        }
        self.bytes = self.bytes.checked_sub(contents.len())?;
        Some(contents.into_owned().into_boxed_slice())
    }
}

fn length(dict: Dict<'_>) -> Option<Option<u64>> {
    match dict.unique(b"Length").ok()? {
        None | Some(Value::Null) => Some(None),
        Some(Value::Unsigned(bits)) => Some(Some(bits)),
        _ => None,
    }
}

fn rc4_bytes(bits: u64) -> Option<usize> {
    ((40..=128).contains(&bits) && bits.is_multiple_of(8)).then_some((bits / 8) as usize)
}

fn allows_extraction(bytes: [u8; 4], cipher: Cipher) -> bool {
    const RESERVED: u32 = 0xffff_f0c0;
    let big_endian = u32::from_be_bytes(bytes);
    let little_endian = u32::from_le_bytes(bytes);
    // PDF 1.7 specifies little-endian permissions and PDF 2.0 specifies big-endian.
    // The reserved high bytes distinguish the two encodings whenever their grants differ.
    let flags = if big_endian & RESERVED == RESERVED {
        big_endian
    } else if !matches!(cipher, Cipher::Aes256) && little_endian & RESERVED == RESERVED {
        little_endian
    } else {
        return false;
    };
    flags & (OWNER_PERMISSION | EXTRACT_PERMISSION) != 0
}

fn key_digest<D: Digest>(
    seed: &[u8],
    recipients: &[Box<[u8]>],
    clear_metadata: bool,
) -> sha2::digest::Output<D> {
    let mut digest = D::new();
    digest.update(seed);
    for der in recipients {
        digest.update(der);
    }
    if clear_metadata {
        digest.update([0xff; 4]);
    }
    digest.finalize()
}

fn legacy_file_key(
    seed: &[u8],
    contents: &[Box<[u8]>],
    clear_metadata: bool,
    key_bytes: usize,
) -> Option<FileKey> {
    let mut digest = key_digest::<Sha1>(seed, contents, clear_metadata);
    let mut key = Zeroizing::new([0; 16]);
    key.copy_from_slice(&digest[..16]);
    digest.as_mut_slice().zeroize();
    Some(FileKey::Legacy(legacy::Key::from_digest(key, key_bytes)?))
}

impl Unlocked {
    pub(super) fn stream<'a>(
        &self,
        purpose: StreamPurpose,
        id: ObjectId,
        filter: Option<&[u8]>,
        data: &'a [u8],
    ) -> Option<Cow<'a, [u8]>> {
        let key = match (&self.0, filter) {
            (Protection::Whole(key), None) => Some(key),
            (Protection::Whole(_), Some(_)) => return None,
            (Protection::Filtered(filters), name) => filters.stream_key(purpose, name)?,
        };
        match key {
            None => Some(Cow::Borrowed(data)),
            Some(key) => decrypt(key.method, &key.key, id, Cow::Borrowed(data)),
        }
    }

    pub(super) fn bytes<'a>(
        &self,
        id: ObjectId,
        string: PdfString<'a>,
        limit: usize,
    ) -> Option<Cow<'a, [u8]>> {
        let key = match &self.0 {
            Protection::Whole(key) => Some(key),
            Protection::Filtered(filters) => filters.selected(filters.string)?,
        };
        let Some(key) = key else {
            return string.bytes(limit);
        };
        decrypt_string(key.method, &key.key, id, string, limit)
    }
}

impl Filters<Authorized> {
    fn stream_key(
        &self,
        purpose: StreamPurpose,
        name: Option<&[u8]>,
    ) -> Option<Option<&Authorized>> {
        let embedded = matches!(purpose, StreamPurpose::EmbeddedFile);
        match name {
            Some(b"Identity") => Some(None),
            Some(name) => {
                let filter = self
                    .named
                    .iter()
                    .find(|filter| filter.name.as_ref() == name)?;
                (embedded || !filter.embedded_only).then_some(Some(filter.state.as_ref()?))
            }
            None if embedded => self.selected(self.embedded?),
            None => {
                let default = self.selected(self.stream)?;
                if matches!(purpose, StreamPurpose::Metadata)
                    && default.is_some_and(|filter| filter.clear_metadata)
                {
                    Some(None)
                } else {
                    Some(default)
                }
            }
        }
    }

    fn selected(&self, selection: Selection) -> Option<Option<&Authorized>> {
        match selection {
            Selection::Identity => Some(None),
            Selection::Named(index) => Some(Some(self.named.get(index)?.state.as_ref()?)),
        }
    }
}
