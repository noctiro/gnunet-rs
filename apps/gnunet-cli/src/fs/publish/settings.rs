//! Manual publication annotations and bounded record planning.
use super::super::publication_options;
use gnunet::fs_host::extraction::{ManualMetadata, Policy};
use std::{error::Error, ffi::OsStr, os::unix::ffi::OsStrExt};

/// The one bounded manual-metadata grammar for actual KSK/SKS frontdoors.
/// Named options consume their original following value atomically, even when
/// that value looks like -m/--meta/--. Literal -- ends option recognition.
pub(crate) struct MetadataArguments<'a> {
    pub positional: Vec<&'a OsStr>,
    pub manual: ManualMetadata,
    pub publication: publication_options::Selection,
    values: Vec<(&'a OsStr, &'a OsStr)>,
}
impl<'a> MetadataArguments<'a> {
    pub fn value(&self, name: &[u8]) -> Option<&'a OsStr> {
        self.values
            .iter()
            .find(|(key, _)| key.as_bytes() == name)
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
    let mut publication = publication_options::Selection::default();
    let mut literal = false;
    let mut at = 0;
    while at < args.len() {
        let arg = args[at].as_ref();
        let raw = arg.as_bytes();
        if !literal && arg == OsStr::new("--") {
            literal = true;
        } else if !literal && (matches!(raw, b"-m" | b"--meta") || value_options.contains(&raw)) {
            at += 1;
            let value = args
                .get(at)
                .ok_or("publication option requires a value")?
                .as_ref();
            if matches!(raw, b"-m" | b"--meta") {
                metadata.push(value.as_bytes())?;
            } else {
                if values
                    .iter()
                    .any(|(key, _): &(&OsStr, &OsStr)| key.as_bytes() == raw)
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
    Ok(parsed)
}
/// Actual caller buffers for a borrowed standard metadata plan. No source or
/// task is hidden here, and absent -m remains an absent metadata parameter.
pub(crate) struct RecordMetadata {
    manual: ManualMetadata,
    order: Vec<usize>,
    plain: Vec<u8>,
}
impl RecordMetadata {
    pub fn new(manual: ManualMetadata) -> Result<Self, Box<dyn Error>> {
        let mut order = Vec::new();
        let mut plain = Vec::new();
        if !manual.is_empty() {
            order.try_reserve_exact(manual.len())?;
            order.resize(manual.len(), 0);
            plain.try_reserve_exact(Policy::default().max_metadata_bytes)?;
            plain.resize(Policy::default().max_metadata_bytes, 0);
        }
        Ok(Self {
            manual,
            order,
            plain,
        })
    }
    pub fn plan(&mut self) -> Result<Option<gnunet::fs::metadata::Plan<'_>>, Box<dyn Error>> {
        if self.manual.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.manual.plan(
            &mut self.order,
            &mut self.plain,
            Policy::default(),
        )?))
    }
}
