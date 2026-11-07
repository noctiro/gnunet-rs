//! Bounded private extraction-selection snapshot; normal wire stays unchanged.
use super::{MetadataSettings, NativeMetadataLimits, SelectionData};
use crate::extraction::Error;
use gnunet_extractor_host::NativeError;
use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
};
const MAGIC: &[u8; 8] = b"FSMETA01";
const MAXIMUM: usize = 1 << 20;
fn invalid() -> Error {
    Error::MetadataSettings(NativeError::Invalid(
        "automatic metadata selection snapshot",
    ))
}
fn capacity() -> Error {
    Error::MetadataSettings(NativeError::Limit("metadata selection snapshot bytes"))
}
fn add(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let length = out.len().checked_add(bytes.len()).ok_or_else(capacity)?;
    if length > MAXIMUM {
        return Err(capacity());
    }
    out.try_reserve_exact(bytes.len()).map_err(|_| capacity())?;
    if out.capacity() > MAXIMUM {
        return Err(capacity());
    }
    out.extend_from_slice(bytes);
    Ok(())
}
fn number(out: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    add(
        out,
        &u64::try_from(value).map_err(|_| capacity())?.to_be_bytes(),
    )
}
fn blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let n = u32::try_from(bytes.len()).map_err(|_| capacity())?;
    add(out, &n.to_be_bytes())?;
    add(out, bytes)
}
pub(super) fn encode(settings: &MetadataSettings) -> Result<Vec<u8>, Error> {
    if settings.manual.is_some() {
        return Err(Error::MetadataSettings(NativeError::Invalid(
            "automatic extraction snapshot excludes manual publication annotations",
        )));
    }
    let extra = if let SelectionData::Native(config) = &settings.selection {
        64usize
            .checked_add(4)
            .and_then(|n| n.checked_add(config.library.as_os_str().as_bytes().len()))
            .and_then(|n| n.checked_add(1))
            .and_then(|n| {
                config
                    .extractors
                    .as_ref()
                    .map_or(Some(n), |b| n.checked_add(4)?.checked_add(b.len()))
            })
            .ok_or_else(capacity)?
    } else {
        0
    };
    let total = 9usize
        .checked_add(extra)
        .filter(|n| *n <= MAXIMUM)
        .ok_or_else(capacity)?;
    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| capacity())?;
    if out.capacity() > MAXIMUM {
        return Err(capacity());
    }
    add(&mut out, MAGIC)?;
    let tag = match &settings.selection {
        SelectionData::Builtin => 0,
        SelectionData::Disabled => 1,
        SelectionData::FilenameOnly => 2,
        SelectionData::Native(_) => 3,
    };
    add(&mut out, &[tag])?;
    if let SelectionData::Native(config) = &settings.selection {
        let limits = config.limits;
        limits.validate().map_err(Error::MetadataSettings)?;
        add(&mut out, &limits.source_bytes.to_be_bytes())?;
        for limit in [
            limits.memory_input_bytes,
            limits.config_bytes,
            limits.callbacks,
            limits.items,
            limits.value_bytes,
            limits.name_bytes,
            limits.output_bytes,
        ] {
            number(&mut out, limit)?;
        }
        blob(&mut out, config.library.as_os_str().as_bytes())?;
        match &config.extractors {
            None => add(&mut out, &[0])?,
            Some(bytes) => {
                add(&mut out, &[1])?;
                blob(&mut out, bytes)?;
            }
        }
    }
    Ok(out)
}
struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let bytes = self.0.get(..n).ok_or_else(invalid)?;
        self.0 = &self.0[n..];
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn size(&mut self) -> Result<usize, Error> {
        usize::try_from(self.u64()?).map_err(|_| capacity())
    }
    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| invalid())?);
        self.take(usize::try_from(n).map_err(|_| capacity())?)
    }
}
pub(super) fn decode(bytes: &[u8]) -> Result<MetadataSettings, Error> {
    if bytes.len() > MAXIMUM {
        return Err(capacity());
    }
    let mut input = Input(bytes);
    if input.take(8)? != MAGIC {
        return Err(invalid());
    }
    let result = match input.byte()? {
        0 => MetadataSettings::default(),
        1 => MetadataSettings::new(true, None, None)?,
        2 => MetadataSettings::new(false, Some(b"-"), None)?,
        3 => {
            let limits = NativeMetadataLimits {
                source_bytes: input.u64()?,
                memory_input_bytes: input.size()?,
                config_bytes: input.size()?,
                callbacks: input.size()?,
                items: input.size()?,
                value_bytes: input.size()?,
                name_bytes: input.size()?,
                output_bytes: input.size()?,
            };
            limits.validate().map_err(Error::MetadataSettings)?;
            let raw = input.blob()?;
            if raw.len() > limits.config_bytes
                || raw.contains(&0)
                || !std::path::Path::new(std::ffi::OsStr::from_bytes(raw)).is_absolute()
            {
                return Err(invalid());
            }
            let library = PathBuf::from(OsString::from_vec(super::super::copy(raw)?));
            let configured = match input.byte()? {
                0 => None,
                1 => Some(input.blob()?),
                _ => return Err(invalid()),
            };
            if configured == Some(b"-".as_slice()) {
                return Err(invalid());
            }
            // Reuse original selection validation, including exact None/empty
            // configuration and absolute non-UTF8 path behavior.
            MetadataSettings::new_with_limits(false, configured, Some(library), limits)?
        }
        _ => return Err(invalid()),
    };
    if !input.0.is_empty() {
        return Err(invalid());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::{ManualLimits, ManualMetadata};
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn check(ok: bool) -> Result {
        if ok {
            Ok(())
        } else {
            Err("metadata snapshot behavior".into())
        }
    }
    #[test]
    fn restored_selection_preserves_native_config_domain_and_disabled_meanings() -> Result {
        let library = PathBuf::from(OsString::from_vec(
            b"/not-opened/provider-\xff.dylib".to_vec(),
        ));
        let limits = NativeMetadataLimits {
            callbacks: 13,
            items: 7,
            ..NativeMetadataLimits::default()
        };
        for configured in [
            None,
            Some(b"".as_slice()),
            Some(b"pdf:custom:options".as_slice()),
        ] {
            let settings = MetadataSettings::new_with_limits(
                false,
                configured,
                Some(library.clone()),
                limits,
            )?;
            let restored = MetadataSettings::from_snapshot(&settings.snapshot()?)?;
            let SelectionData::Native(actual) = &restored.selection else {
                return Err("native selection lost".into());
            };
            check(
                actual.library == library
                    && actual.extractors.as_deref() == configured
                    && actual.limits.callbacks == 13
                    && actual.limits.items == 7,
            )?;
        }
        for (settings, automatic, format) in [
            (MetadataSettings::default(), true, true),
            (MetadataSettings::new(true, None, None)?, false, false),
            (MetadataSettings::new(false, Some(b"-"), None)?, true, false),
        ] {
            let restored = MetadataSettings::from_snapshot(&settings.snapshot()?)?;
            check(
                restored.automatic_keywords_enabled() == automatic
                    && restored.format_extraction_enabled() == format,
            )?;
        }
        Ok(())
    }
    #[test]
    fn invalid_or_manual_settings_do_not_silently_become_default_extraction() -> Result {
        let mut metadata = ManualMetadata::new(ManualLimits::default())?;
        metadata.push(b"title:explicit")?;
        check(
            MetadataSettings::default()
                .with_manual(metadata)
                .snapshot()
                .is_err(),
        )?;
        let good = MetadataSettings::default().snapshot()?;
        for n in 0..good.len() {
            check(MetadataSettings::from_snapshot(&good[..n]).is_err())?;
        }
        let mut trailing = good.clone();
        trailing.push(0);
        check(MetadataSettings::from_snapshot(&trailing).is_err())?;
        let mut unknown = good;
        unknown[8] = 99;
        check(MetadataSettings::from_snapshot(&unknown).is_err())
    }
}
