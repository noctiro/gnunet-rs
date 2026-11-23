//! PDF document information projected into the GNU metadata registry.

mod filespec;
mod parameters;
mod security;
mod source;
mod stream;
mod syntax;
mod text;
mod xref;

#[cfg(test)]
mod tests;

use super::{Input, xmp};
use security::ObjectEncryption;
use source::{Document, Info, Opened, named};
use syntax::{Dict, Name, ObjectId, Value};

const FORMAT: u32 = 54;
const PAGE_COUNT: u32 = 11;
const VERSIONS: &[&[u8; 3]] = &[
    b"1.0", b"1.1", b"1.2", b"1.3", b"1.4", b"1.5", b"1.6", b"1.7", b"2.0",
];

// The first six fields use PDF text strings. Dates use the GNU UTC projection.
const INFO_FIELDS: [InfoField; 8] = [
    InfoField::text(b"Title", 4),
    InfoField::text(b"Subject", 52),
    InfoField::text(b"Keywords", 49),
    InfoField::text(b"Author", 13),
    InfoField::text(b"Creator", 56),
    InfoField::text(b"Producer", 113),
    InfoField::date(b"CreationDate", 58),
    InfoField::date(b"ModDate", 59),
];

pub(super) fn visit<E>(
    input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(header_version) = input.prefix.get(5..8).and_then(|bytes| {
        VERSIONS
            .iter()
            .position(|version| bytes == version.as_slice())
    }) else {
        return Ok(());
    };
    let Some(Opened { mut document, info }) = Document::open(input, &|dict| {
        info_values(dict, ObjectEncryption::Plain, limit)
    })?
    else {
        return Ok(());
    };
    let Some(catalog) = document.value(document.root(), |value, _| Catalog::from_value(value))?
    else {
        return Ok(());
    };
    let version = catalog
        .version
        .unwrap_or(header_version)
        .max(header_version);
    let values = match info {
        Some(Info::Direct(fields)) => Some(fields),
        Some(Info::Reference(info)) => document.value(info, |value, strings| {
            let Value::Dict(dict) = value else {
                return None;
            };
            Some(info_values(dict, strings, limit))
        })?,
        None => None,
    }
    .unwrap_or([const { None }; INFO_FIELDS.len()]);
    let mut fields = INFO_FIELDS.into_iter().zip(values);
    for (field, value) in fields.by_ref().take(6) {
        if let Some(value) = resolved_text(&mut document, field, value, limit)? {
            emit(field.kind, value.as_bytes())?;
        }
    }
    emit_catalog(&mut document, &catalog, version, limit, emit)?;
    for (field, value) in fields {
        if let Some(value) = resolved_text(&mut document, field, value, limit)? {
            emit(field.kind, value.as_bytes())?;
        }
    }
    if let Some(id) = catalog.metadata
        && let Some(bytes) = document.metadata_stream(id)?
    {
        xmp::visit(&bytes, limit, emit)?;
    }
    Ok(())
}

fn emit_catalog<E>(
    document: &mut Document<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    catalog: &Catalog,
    version: usize,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let mut format = *b"PDF 0.0";
    format[4..].copy_from_slice(VERSIONS[version]);
    if format.len() <= limit {
        emit(FORMAT, &format)?;
    }
    if let Some(count) = document.value(catalog.pages, |value, _| pages_count(value))? {
        let count = count.to_string();
        if count.len() <= limit {
            emit(PAGE_COUNT, count.as_bytes())?;
        }
    }
    Ok(())
}

struct Catalog {
    pages: ObjectId,
    version: Option<usize>,
    metadata: Option<ObjectId>,
}

impl Catalog {
    fn from_value(value: Value<'_>) -> Option<Self> {
        let Value::Dict(dict) = value else {
            return None;
        };
        if !named(dict, b"Type", b"Catalog") {
            return None;
        }
        let Value::Reference(pages) = dict.unique(b"Pages").ok()?? else {
            return None;
        };
        let version = match dict.unique(b"Version").ok()? {
            Some(Value::Name(version)) => version_number(version),
            _ => None,
        };
        let metadata = match dict.unique(b"Metadata") {
            Ok(Some(Value::Reference(id))) if id.number != 0 => Some(id),
            _ => None,
        };
        Some(Self {
            pages,
            version,
            metadata,
        })
    }
}

fn version_number(name: Name<'_>) -> Option<usize> {
    VERSIONS
        .iter()
        .position(|version| name.is(version.as_slice()))
}

fn pages_count(value: Value<'_>) -> Option<u32> {
    let Value::Dict(dict) = value else {
        return None;
    };
    if !named(dict, b"Type", b"Pages") {
        return None;
    }
    let Value::Unsigned(count) = dict.unique(b"Count").ok()?? else {
        return None;
    };
    u32::try_from(count).ok()
}

#[derive(Clone, Copy)]
struct InfoField {
    key: &'static [u8],
    kind: u32,
    is_date: bool,
}

impl InfoField {
    const fn text(key: &'static [u8], kind: u32) -> Self {
        Self {
            key,
            kind,
            is_date: false,
        }
    }

    const fn date(key: &'static [u8], kind: u32) -> Self {
        Self {
            key,
            kind,
            is_date: true,
        }
    }

    fn read(self, value: Value<'_>, strings: ObjectEncryption<'_>, limit: usize) -> Option<String> {
        let Value::String(string) = value else {
            return None;
        };
        if self.is_date {
            text::date(&strings.bytes(string, 32)?, limit)
        } else {
            let bytes = strings.bytes(string, limit.saturating_mul(2).saturating_add(3))?;
            text::metadata(&bytes, limit)
        }
    }
}

enum InfoValue {
    Text(String),
    Reference(ObjectId),
}

type InfoValues = [Option<InfoValue>; INFO_FIELDS.len()];

fn info_values(dict: Dict<'_>, strings: ObjectEncryption<'_>, limit: usize) -> InfoValues {
    INFO_FIELDS.map(|field| {
        let value = dict.unique(field.key).ok()??;
        match value {
            Value::Reference(id) => Some(InfoValue::Reference(id)),
            _ => field.read(value, strings, limit).map(InfoValue::Text),
        }
    })
}

fn resolved_text<E>(
    document: &mut Document<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    field: InfoField,
    value: Option<InfoValue>,
    limit: usize,
) -> Result<Option<String>, E> {
    match value {
        Some(InfoValue::Text(text)) => Ok(Some(text)),
        Some(InfoValue::Reference(id)) => {
            document.value(id, |value, strings| field.read(value, strings, limit))
        }
        None => Ok(None),
    }
}
