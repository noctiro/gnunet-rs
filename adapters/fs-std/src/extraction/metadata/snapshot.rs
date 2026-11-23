//! Bounded private extraction-selection snapshot; normal wire stays unchanged.
use super::{MetadataSettings, NativeMetadataLimits, PdfRecipientAccess, SelectionData};
use crate::extraction::{
    Error, PdfExternalStreams,
    pdf_streams::{MAX_BINDINGS, MAX_NAME_BYTES, MAX_PAYLOAD_BYTES, NameKind},
};
use gnunet_extractor_host::NativeError;
use gnunet_native::filesystem::{FileIdentity, FileInfo, FileTimes};
use std::path::PathBuf;
const MAGIC: &[u8; 8] = b"FSMETA04";
const MAX_SELECTION: usize = 1 << 20;
const DOCUMENT_BYTES: usize = 32 + 8 + 16 + 16 + 64 + 1;
const STREAM_HEADER: usize = 1 + 4 + 4;
const MAXIMUM: usize = MAX_SELECTION
    + 1
    + MAX_PAYLOAD_BYTES
    + MAX_BINDINGS * (DOCUMENT_BYTES + STREAM_HEADER + MAX_NAME_BYTES)
    + 33;
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
pub(super) fn encode(
    settings: &MetadataSettings,
    selected_file: Option<FileInfo>,
) -> Result<Vec<u8>, Error> {
    if settings.manual.is_some() {
        return Err(Error::MetadataSettings(NativeError::Invalid(
            "automatic extraction snapshot excludes manual publication annotations",
        )));
    }
    let extra = if let SelectionData::Native(config) = &settings.selection {
        72usize
            .checked_add(4)
            .and_then(|n| {
                n.checked_add(
                    gnunet_native::os_bytes::encode(config.provider.library().as_os_str()).len(),
                )
            })
            .and_then(|n| n.checked_add(1))
            .and_then(|n| {
                config
                    .provider
                    .configured()
                    .map_or(Some(n), |b| n.checked_add(4)?.checked_add(b.len()))
            })
            .ok_or_else(capacity)?
    } else {
        0
    };
    let selection_bytes = 9usize
        .checked_add(extra)
        .filter(|n| *n <= MAX_SELECTION)
        .ok_or_else(capacity)?;
    let documents = settings
        .pdf_streams
        .as_deref()
        .map_or(&[][..], PdfExternalStreams::documents);
    let selected = || {
        documents
            .iter()
            .filter(|doc| selected_file.is_none_or(|file| file == doc.observed))
    };
    let recipient = settings.pdf_recipient_id();
    let total = selected()
        .try_fold(
            selection_bytes + 2 + recipient.map_or(0, |id| id.len()),
            |size, document| {
                document.streams.iter().try_fold(
                    size.checked_add(DOCUMENT_BYTES)?,
                    |size, stream| {
                        size.checked_add(STREAM_HEADER)?
                            .checked_add(stream.name.len())?
                            .checked_add(stream.payload.len())
                    },
                )
            },
        )
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
        add(&mut out, &limits.mapped_input_bytes.to_be_bytes())?;
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
        blob(
            &mut out,
            &gnunet_native::os_bytes::encode(config.provider.library().as_os_str()),
        )?;
        match config.provider.configured() {
            None => add(&mut out, &[0])?,
            Some(bytes) => {
                add(&mut out, &[1])?;
                blob(&mut out, bytes)?;
            }
        }
    }
    add(
        &mut out,
        &[u8::try_from(selected().count()).map_err(|_| capacity())?],
    )?;
    for document in selected() {
        let observed = document.observed;
        add(&mut out, observed.identity.as_bytes())?;
        add(&mut out, &observed.bytes.to_be_bytes())?;
        add(&mut out, &observed.times.modified.to_be_bytes())?;
        add(&mut out, &observed.times.changed.to_be_bytes())?;
        add(&mut out, &document.digest_for_snapshot()?)?;
        add(
            &mut out,
            &[u8::try_from(document.streams.len()).map_err(|_| capacity())?],
        )?;
        for stream in &document.streams {
            add(&mut out, &[stream.kind.code()])?;
            blob(&mut out, &stream.name)?;
            blob(&mut out, &stream.payload)?;
        }
    }
    match recipient {
        Some(identity) => {
            add(&mut out, &[1])?;
            add(&mut out, &identity)?;
        }
        None => add(&mut out, &[0])?,
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
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| invalid())
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn size(&mut self) -> Result<usize, Error> {
        usize::try_from(self.u64()?).map_err(|_| capacity())
    }
    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let n = u32::from_be_bytes(self.array()?);
        self.take(usize::try_from(n).map_err(|_| capacity())?)
    }

    fn pdf_streams(&mut self) -> Result<PdfExternalStreams, Error> {
        let mut streams = PdfExternalStreams::default();
        let count = usize::from(self.byte()?);
        if count > MAX_BINDINGS {
            return Err(capacity());
        }
        for _ in 0..count {
            let observed = FileInfo {
                identity: FileIdentity::from_bytes(self.array()?).map_err(|_| invalid())?,
                bytes: self.u64()?,
                times: FileTimes {
                    modified: i128::from_be_bytes(self.array()?),
                    changed: i128::from_be_bytes(self.array()?),
                },
            };
            if streams
                .documents()
                .iter()
                .any(|doc| doc.observed == observed)
            {
                return Err(invalid());
            }
            let digest = self.array()?;
            let entries = usize::from(self.byte()?);
            if !(1..=MAX_BINDINGS).contains(&entries) {
                return Err(invalid());
            }
            for _ in 0..entries {
                let kind = NameKind::parse(self.byte()?).ok_or_else(invalid)?;
                let name = self.blob()?;
                let payload = self.blob()?;
                streams.restore_stream(observed, digest, kind, name, payload)?;
            }
        }
        Ok(streams)
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
    let mut result = match input.byte()? {
        0 => MetadataSettings::default(),
        1 => MetadataSettings::new(true, None, None)?,
        2 => MetadataSettings::new(false, Some(b"-"), None)?,
        3 => {
            let limits = NativeMetadataLimits {
                source_bytes: input.u64()?,
                mapped_input_bytes: input.u64()?,
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
            if raw.len() > limits.config_bytes || raw.contains(&0) {
                return Err(invalid());
            }
            let library = PathBuf::from(gnunet_native::os_bytes::decode_owned(
                super::super::copy(raw)?,
            )?);
            if !library.is_absolute() {
                return Err(invalid());
            }
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
    if bytes.len() - input.0.len() > MAX_SELECTION {
        return Err(capacity());
    }
    let streams = input.pdf_streams()?;
    result.pdf_recipient = match input.byte()? {
        0 => PdfRecipientAccess::Unselected,
        1 => PdfRecipientAccess::Required(input.array()?),
        _ => return Err(invalid()),
    };
    if !input.0.is_empty() {
        return Err(invalid());
    }
    Ok(result.with_pdf_external_streams(streams))
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
        #[cfg(unix)]
        let encoded = b"/not-opened/provider-\xff.dylib".as_slice();
        #[cfg(windows)]
        let encoded = b"C:\\not-opened\\provider-\xed\xa0\x80.dll".as_slice();
        let library = PathBuf::from(gnunet_native::os_bytes::decode_owned(encoded.to_vec())?);
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
                actual.provider.library() == library
                    && actual.provider.configured() == configured
                    && actual.limits.mapped_input_bytes == limits.mapped_input_bytes
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
    fn selected_pdf_recipient_requires_the_same_authority_after_restore() -> Result {
        use crate::extraction::PdfRecipientAuthorization;

        let credential = PdfRecipientAuthorization::new([0x17; 32], |_| None);
        let other = PdfRecipientAuthorization::new([0x29; 32], |_| None);
        let approved = MetadataSettings::default().with_pdf_recipient(&credential)?;
        let snapshot = approved.snapshot()?;
        let restored = MetadataSettings::from_snapshot(&snapshot)?;
        check(matches!(
            restored.pdf_recipient(),
            Err(Error::PdfRecipientRequired)
        ))?;
        check(matches!(
            restored.clone().with_pdf_recipient(&other),
            Err(Error::Binding)
        ))?;
        let rebound = restored.with_authorization_from(&approved)?;
        check(
            rebound
                .pdf_recipient()?
                .map(PdfRecipientAuthorization::identity)
                == Some(credential.identity()),
        )?;
        check(rebound.snapshot()? == snapshot)?;
        let unselected = MetadataSettings::default().with_authorization_from(&approved)?;
        check(unselected.pdf_recipient()?.is_none())
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
