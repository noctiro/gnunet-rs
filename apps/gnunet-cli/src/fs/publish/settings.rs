//! Manual publication annotations and bounded record planning.
use super::super::publication_options;
use gnunet::fs::metadata as md;
use gnunet::fs_host::extraction::{ManualMetadata, Policy};
use std::{error::Error, ffi::OsStr};

/// The one bounded manual-metadata grammar for actual KSK/SKS frontdoors.
/// Named options consume their original following value atomically, even when
/// that value looks like -m/--meta/--. Literal -- ends option recognition.
pub(crate) struct MetadataArguments<'a> {
    pub positional: Vec<&'a OsStr>,
    pub manual: ManualMetadata,
    pub compression: Option<md::Compression>,
    pub publication: publication_options::Selection,
    values: Vec<(&'a OsStr, &'a OsStr)>,
}
impl<'a> MetadataArguments<'a> {
    pub fn value(&self, name: &[u8]) -> Option<&'a OsStr> {
        self.values
            .iter()
            .find(|(key, _)| key.as_encoded_bytes() == name)
            .map(|(_, value)| *value)
    }
}
pub(crate) fn metadata_arguments<'a, T: AsRef<OsStr>>(
    args: &'a [T],
    minimum: usize,
    maximum: usize,
    value_options: &[&[u8]],
) -> Result<MetadataArguments<'a>, Box<dyn Error>> {
    let mut positional = Vec::new();
    positional.try_reserve_exact(maximum)?;
    let mut values = Vec::new();
    values.try_reserve_exact(value_options.len())?;
    let mut metadata = ManualMetadata::default();
    let mut compression = None;
    let mut publication = publication_options::Selection::default();
    let mut literal = false;
    let mut at = 0;
    while at < args.len() {
        let arg = args[at].as_ref();
        let raw = arg.as_encoded_bytes();
        if !literal && arg == OsStr::new("--") {
            literal = true;
        } else if !literal
            && (matches!(raw, b"-m" | b"--meta" | b"--metadata-compression")
                || value_options.contains(&raw))
        {
            at += 1;
            let value = args
                .get(at)
                .ok_or("publication option requires a value")?
                .as_ref();
            if matches!(raw, b"-m" | b"--meta") {
                metadata.push(crate::argument::wire_bytes(value)?)?;
            } else if raw == b"--metadata-compression" {
                if compression.is_some() {
                    return Err("--metadata-compression may be specified only once".into());
                }
                compression = Some(match value.as_encoded_bytes() {
                    b"never" => md::Compression::Never,
                    b"adaptive" => md::Compression::Adaptive,
                    b"always" => md::Compression::Always,
                    _ => {
                        return Err("metadata compression must be never, adaptive or always".into());
                    }
                });
            } else {
                if values
                    .iter()
                    .any(|(key, _): &(&OsStr, &OsStr)| key.as_encoded_bytes() == raw)
                {
                    return Err("publication option was specified more than once".into());
                }
                values.push((arg, value));
            }
        } else if !literal && publication.consume(args, &mut at)? {
            continue;
        } else {
            if !literal && raw.starts_with(b"-") {
                return Err("unknown publication option (use -- for a literal argument)".into());
            }
            if positional.len() == maximum {
                return Err("too many publication arguments".into());
            }
            positional.push(arg);
        }
        at += 1;
    }
    if positional.len() < minimum {
        return Err("missing required publication arguments".into());
    }
    Ok(MetadataArguments {
        positional,
        manual: metadata,
        compression,
        publication,
        values,
    })
}
/// Same grammar and absent metadata semantics for existing keyword callers.
pub(crate) fn keyword_arguments<T: AsRef<OsStr>>(
    args: &[T],
    optional_timeout: bool,
) -> Result<MetadataArguments<'_>, Box<dyn Error>> {
    metadata_arguments(args, 3, if optional_timeout { 4 } else { 3 }, &[])
}
/// File/tree task preparation has no record-annotation stage. Reject such
/// annotations instead of accepting and silently discarding them.
pub(crate) fn content_arguments<T: AsRef<OsStr>>(
    args: &[T],
) -> Result<MetadataArguments<'_>, Box<dyn Error>> {
    let parsed = metadata_arguments(args, 2, 2, &[])?;
    if !parsed.manual.is_empty() {
        return Err("content-only task preparation does not accept -m/--meta".into());
    }
    if parsed.compression.is_some() {
        return Err("content-only task preparation has no publication metadata encoding".into());
    }
    Ok(parsed)
}
/// Actual caller buffers for a borrowed standard metadata plan. No source or
/// task is hidden here, and absent -m remains an absent metadata parameter.
pub(crate) struct RecordMetadata {
    manual: ManualMetadata,
    order: Vec<usize>,
    plain: Vec<u8>,
    coded: Vec<u8>,
    compression: md::Compression,
}
impl RecordMetadata {
    pub fn new(
        manual: ManualMetadata,
        compression: Option<md::Compression>,
    ) -> Result<Self, Box<dyn Error>> {
        let compression = compression.unwrap_or(md::Compression::Never);
        let mut order = Vec::new();
        let mut plain = Vec::new();
        let mut coded = Vec::new();
        if !manual.is_empty() {
            order.try_reserve_exact(manual.len())?;
            order.resize(manual.len(), 0);
            plain.try_reserve_exact(Policy::default().max_metadata_bytes)?;
            plain.resize(Policy::default().max_metadata_bytes, 0);
            if compression != md::Compression::Never {
                coded.try_reserve_exact(Policy::default().max_metadata_bytes)?;
                coded.resize(Policy::default().max_metadata_bytes, 0);
            }
        }
        Ok(Self {
            manual,
            order,
            plain,
            coded,
            compression,
        })
    }
    pub fn plan(&mut self) -> Result<Option<gnunet::fs::metadata::Plan<'_>>, Box<dyn Error>> {
        if self.manual.is_empty() {
            return Ok(None);
        }
        let plan = match self.compression {
            md::Compression::Never => {
                self.manual
                    .plan(&mut self.order, &mut self.plain, Policy::default())?
            }
            compression => self.manual.plan_with_codec(
                &mut self.order,
                &mut self.plain,
                &mut self.coded,
                // Planning is synchronous and the plan borrows only the
                // workspaces. Drop codec allocations before native publication.
                &mut gnunet::fs_codec::Compressor::new(),
                Policy::default(),
                compression,
            )?,
        };
        Ok(Some(plan))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet::fs::{Content, ublock};

    type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

    fn check(value: bool, message: &'static str) -> Result {
        value.then_some(()).ok_or_else(|| message.into())
    }

    #[test]
    fn metadata_encoding_grammar_is_explicit_and_not_ignored() -> Result {
        for args in [
            vec!["ds", "ksk", "chk", "--metadata-compression"],
            vec!["ds", "ksk", "chk", "--metadata-compression", "unknown"],
            vec![
                "ds",
                "ksk",
                "chk",
                "--metadata-compression",
                "never",
                "--metadata-compression",
                "always",
            ],
        ] {
            check(
                keyword_arguments(&args, false).is_err(),
                "invalid compression accepted",
            )?;
        }
        let parsed = keyword_arguments(&["--", "--metadata-compression", "ksk", "chk"], false)?;
        check(
            parsed.compression.is_none(),
            "literal option became a selector",
        )?;
        check(
            parsed.positional[0] == OsStr::new("--metadata-compression"),
            "literal option was consumed",
        )?;
        check(
            content_arguments(&["task", "file", "--metadata-compression", "never"]).is_err(),
            "content-only command discarded an encoding selection",
        )?;
        let absent = keyword_arguments(
            &["ds", "ksk", "chk", "--metadata-compression", "always"],
            false,
        )?;
        check(
            RecordMetadata::new(absent.manual, absent.compression)?
                .plan()?
                .is_none(),
            "encoding invented absent manual metadata",
        )
    }

    #[test]
    fn selected_manual_encoding_survives_real_ublock_sealing() -> Result {
        let annotation = format!("description:{}", "Public Unicode café. ".repeat(24));
        let expected = [&annotation.as_bytes()["description:".len()..], b"\0"].concat();
        for selection in [None, Some("never"), Some("adaptive"), Some("always")] {
            let mut args = vec![
                "ds",
                "ksk",
                "chk",
                "-m",
                annotation.as_str(),
                "-m",
                "title:",
            ];
            if let Some(selection) = selection {
                args.extend(["--metadata-compression", selection]);
            }
            let parsed = keyword_arguments(&args, false)?;
            let mut metadata = RecordMetadata::new(parsed.manual, parsed.compression)?;
            let plan = metadata.plan()?.ok_or("lost explicit manual metadata")?;
            check(
                plan.report().compressed == matches!(selection, Some("adaptive" | "always")),
                "selected metadata encoding was not used",
            )?;
            let mut wire = vec![0; 32768];
            let limits = ublock::Limits::default();
            let publisher = ublock::Publisher::keyword(b"alpha", limits)?;
            let content = Content {
                key: [0; 64],
                query: [0; 64],
                size: 0,
            };
            let sealed = publisher.seal(b"", content.uri(), Some(&plan), &mut wire)?;
            let mut plain = vec![0; 32768];
            let context = ublock::Context::keyword(b"alpha", limits)?;
            let opened = context.open(sealed.bytes(), &mut plain)?;
            let mut scratch = vec![0; 32768];
            let record = opened.decode(
                &mut scratch,
                &mut gnunet::fs_codec::Inflate::new(),
                md::Mode::Strict,
            )?;
            let actual = record.metadata().ok_or("missing sealed manual metadata")?;
            check(
                actual.is_complete() && actual.accepted_entries() == 2,
                "metadata omitted entries",
            )?;
            check(
                actual
                    .items()
                    .any(|item| item.kind == 46 && item.data == expected),
                "metadata changed the selected Unicode value",
            )?;
            check(
                actual
                    .items()
                    .any(|item| item.kind == 4 && item.data == b"\0"),
                "metadata discarded an explicit empty value",
            )?;
        }
        Ok(())
    }
}
