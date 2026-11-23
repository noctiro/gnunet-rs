//! File specification names select embedded data or an explicit caller binding.

use crate::extraction::pdf_streams::{MAX_NAME_BYTES, NameKind};

use super::{
    parameters::{Origin, ParameterError, Parameters, Resolved},
    security::{ObjectEncryption, Security},
    syntax::{Dict, ObjectId, PdfString, Value},
    text,
};

pub(super) enum Source {
    Embedded(ObjectId),
    External { kind: NameKind, name: Box<[u8]> },
}

/// String encryption follows the containing independent object, even when a
/// file specification uses indirect parameters or an object-stream member.
#[derive(Clone, Copy)]
pub(super) struct Strings<'a> {
    security: Option<&'a Security>,
    object: Option<ObjectId>,
}

impl<'a> Strings<'a> {
    pub(super) const fn new(security: Option<&'a Security>, object: ObjectId) -> Self {
        Self {
            security,
            object: Some(object),
        }
    }

    fn located(self, value: &Resolved<'_>) -> Self {
        let object = match value.storage {
            None => self.object,
            Some((id, Origin::Uncompressed)) => Some(id),
            Some((_, Origin::Compressed)) => None,
        };
        Self { object, ..self }
    }

    fn key(self, name: PdfString<'_>, kind: NameKind) -> Result<Source, ParameterError> {
        let encryption = self.object.map_or(ObjectEncryption::Plain, |id| {
            ObjectEncryption::for_object(self.security, id)
        });
        let input_limit = match kind {
            NameKind::UnicodeFile => 2 * MAX_NAME_BYTES + 3,
            _ => MAX_NAME_BYTES,
        };
        let bytes = encryption
            .bytes(name, input_limit)
            .ok_or(ParameterError::Invalid)?;
        let name = if kind == NameKind::UnicodeFile {
            text::file_name(&bytes, MAX_NAME_BYTES)
                .ok_or(ParameterError::Invalid)?
                .into_bytes()
                .into_boxed_slice()
        } else {
            if bytes.is_empty()
                || bytes.contains(&0)
                || (kind == NameKind::Url && !bytes.is_ascii())
            {
                return Err(ParameterError::Invalid);
            }
            bytes.into_owned().into_boxed_slice()
        };
        Ok(Source::External { kind, name })
    }
}

const PLATFORM_KEY: &[u8] = if cfg!(windows) {
    b"DOS"
} else if cfg!(target_os = "macos") {
    b"Mac"
} else {
    b"Unix"
};

pub(super) fn parse(
    spec: Resolved<'_>,
    parameters: &Parameters<'_>,
    strings: Strings<'_>,
    allow_external: bool,
) -> Result<Source, ParameterError> {
    let strings = strings.located(&spec);
    let file = match spec.value {
        Value::String(name) if allow_external => return strings.key(name, NameKind::File),
        Value::Dict(file) => file,
        _ => return Err(ParameterError::Invalid),
    };
    let declared_type = parameters.get(file, b"Type")?;
    let has_type = matches!(declared_type, Some(Value::Name(name)) if name.is(b"Filespec"));
    if !has_type && !matches!(declared_type, None | Some(Value::Null)) {
        return Err(ParameterError::Invalid);
    }
    match parameters.get(file, b"EF")? {
        Some(Value::Dict(embedded)) if has_type => {
            return embedded_file_id(file, embedded, parameters).map(Source::Embedded);
        }
        None | Some(Value::Null) if allow_external => {}
        _ => return Err(ParameterError::Invalid),
    }
    let fields: &[(&[u8], NameKind)] = match parameters.get(file, b"FS")? {
        Some(Value::Name(name)) if name.is(b"URL") => &[(b"F", NameKind::Url)],
        None | Some(Value::Null) => &[
            (b"UF", NameKind::UnicodeFile),
            (b"F", NameKind::File),
            (PLATFORM_KEY, NameKind::File),
        ],
        _ => return Err(ParameterError::Invalid),
    };
    for &(key, kind) in fields {
        if let Some(value) = parameters.locate(file, key)? {
            match value.value {
                Value::Null => {}
                Value::String(name) => return strings.located(&value).key(name, kind),
                _ => return Err(ParameterError::Invalid),
            }
        }
    }
    Err(ParameterError::Invalid)
}

fn embedded_file_id(
    file: Dict<'_>,
    embedded: Dict<'_>,
    parameters: &Parameters<'_>,
) -> Result<ObjectId, ParameterError> {
    for key in [b"UF".as_slice(), b"F", PLATFORM_KEY] {
        match embedded.unique(key)? {
            None | Some(Value::Null) => continue,
            Some(Value::Reference(id))
                if id.number != 0
                    && matches!(parameters.get(file, key)?, Some(Value::String(_))) =>
            {
                return Ok(id);
            }
            _ => return Err(ParameterError::Invalid),
        }
    }
    Err(ParameterError::Invalid)
}
