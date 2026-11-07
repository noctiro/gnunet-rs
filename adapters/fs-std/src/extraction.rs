//! Shared bounded descriptor metadata and automatic keyword extraction.
//! No task, publication plan, service endpoint or native scheduler is required.
mod error;
mod inspect;
mod limits;
mod manual;
mod metadata;
use crate::{Control, Progress, input_tree::InputDir};
pub use error::Error;
/// Actual optional native provider callback observation.
pub use gnunet_extractor_host::Observation as MetadataObservation;
use gnunet_fs::{Keyword, metadata as md};
use gnunet_types::AbsoluteTime;
pub use inspect::{ExtractedObject, InspectionFailure, InspectionReport, inspect_with_metadata};
pub use limits::Limits;
pub use manual::{ManualLimits, ManualMetadata};
pub use metadata::{MetadataSettings, NativeMetadataLimits};
use std::{
    cell::{Cell, RefCell},
    fs::{self, File},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
};
use unicode_normalization::UnicodeNormalization;

/// Explicit extraction and workspace policy. UTC is supplied by the same actual
/// service clock as the caller; this module does not sample an implicit clock.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Enable bounded format extraction and automatic keyword selection (-D=false).
    pub extract: bool,
    /// Publication date of this admitted version; None really disables it (-d).
    pub creation_time: Option<AbsoluteTime>,
    /// Maximum prefix bytes inspected per file (ID3v1 adds one fixed 128-byte read).
    pub max_probe_bytes: usize,
    /// Maximum official metadata entries per object.
    pub max_metadata_items: usize,
    /// Maximum serialized official metadata bytes per object.
    pub max_metadata_bytes: usize,
    /// Maximum unique automatic terms per object, including MIME/name terms.
    pub max_keywords: usize,
    /// Maximum decoded bytes in one automatically selected keyword.
    pub max_keyword_bytes: usize,
    /// Owned metadata/DFS storage bound, separate from the bounded reusable
    /// extraction scratch and native provider workspace.
    pub max_retained_bytes: usize,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            extract: true,
            creation_time: None,
            max_probe_bytes: 65536,
            max_metadata_items: 32,
            max_metadata_bytes: 32768,
            max_keywords: 128,
            max_keyword_bytes: 256,
            max_retained_bytes: 64 * 1024 * 1024,
        }
    }
}
impl Policy {
    pub(crate) fn validate(self, limits: Limits) -> Result<(), Error> {
        if self.max_probe_bytes == 0
            || self.max_probe_bytes > 1024 * 1024
            || !(2..=256).contains(&self.max_metadata_items)
            || !(md::HEADER_BYTES..=1024 * 1024).contains(&self.max_metadata_bytes)
            || !(1..=4096).contains(&self.max_keywords)
            || self.max_keyword_bytes == 0
            || self.max_keyword_bytes > limits.max_keyword_bytes
            || self.max_metadata_bytes > limits.metadata.max_coded_bytes
            || self.max_metadata_items > limits.metadata.max_entries
            || !(4096..=512 * 1024 * 1024).contains(&self.max_retained_bytes)
            || self
                .creation_time
                .is_some_and(|t| t.as_micros() > 253_402_300_799_999_999)
        {
            return Err(Error::Policy);
        }
        Ok(())
    }
}
pub(crate) struct Budget {
    pub(crate) used: usize,
    pub(crate) limit: usize,
}
impl Budget {
    pub(crate) fn replace(&mut self, previous: usize, next: usize) -> Result<(), Error> {
        self.used = self
            .used
            .checked_sub(previous)
            .and_then(|n| n.checked_add(next))
            .filter(|n| *n <= self.limit)
            .ok_or(Error::Limit)?;
        Ok(())
    }
    pub(crate) fn add(&mut self, amount: usize) -> Result<(), Error> {
        self.replace(0, amount)
    }
}
pub(crate) struct Context<C> {
    pub(crate) control: RefCell<C>,
    pub(crate) progress: Cell<Progress>,
    pub(crate) budget: RefCell<Budget>,
}
impl<C: FnMut(Progress) -> Control> Context<C> {
    pub(crate) fn check(&self) -> Result<(), Error> {
        if (self.control.borrow_mut())(self.progress.get()) == Control::Cancel {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
    #[cfg(feature = "network")]
    pub(crate) fn report(&self, progress: Progress) -> Control {
        self.progress.set(progress);
        (self.control.borrow_mut())(progress)
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Stamp {
    dev: u64,
    ino: u64,
    bytes: u64,
    mtime: i64,
    mn: i64,
    ctime: i64,
    cn: i64,
}
impl Stamp {
    pub(crate) fn of(file: &File) -> Result<Self, Error> {
        let m = file.metadata()?;
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            bytes: m.len(),
            mtime: m.mtime(),
            mn: m.mtime_nsec(),
            ctime: m.ctime(),
            cn: m.ctime_nsec(),
        })
    }
}
pub(crate) fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Limit)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
pub(crate) fn zeros(n: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Error::Limit)?;
    out.resize(n, 0);
    Ok(out)
}
pub(crate) fn decoded(bytes: &[u8], policy: Policy) -> Result<md::Metadata<'_>, Error> {
    let limits = md::Limits {
        max_coded_bytes: policy.max_metadata_bytes,
        max_plain_bytes: policy.max_metadata_bytes,
        max_entries: policy.max_metadata_items,
    };
    match md::decode_uncompressed(bytes, limits, md::Mode::Strict)? {
        md::Decoded::Present(m) => Ok(m),
        md::Decoded::NullMarker => Err(Error::Binding),
    }
}
fn add_named(
    values: &mut Vec<Value>,
    kind: u32,
    format: md::Format,
    data: &[u8],
    plugin: Option<&[u8]>,
    mime: Option<&[u8]>,
    policy: Policy,
) -> Result<(), Error> {
    if values
        .iter()
        .any(|v| v.kind == kind && v.format == format && v.data == data)
    {
        return Ok(());
    }
    if values.len() >= policy.max_metadata_items || data.len() > policy.max_metadata_bytes {
        return Err(Error::Limit);
    }
    let bytes = copy(data)?;
    values.try_reserve(1).map_err(|_| Error::Limit)?;
    values.push(Value {
        kind,
        format,
        data: bytes,
        plugin: plugin.map(copy).transpose()?,
        mime: mime.map(copy).transpose()?,
    });
    Ok(())
}

fn encode_values(values: &[Value], policy: Policy) -> Result<Vec<u8>, Error> {
    let mut refs = Vec::new();
    refs.try_reserve_exact(values.len())
        .map_err(|_| Error::Limit)?;
    for v in values {
        refs.push(md::Item {
            kind: v.kind,
            format: v.format,
            data: &v.data,
            plugin: v.plugin.as_deref(),
            mime: v.mime.as_deref(),
        });
    }
    let mut order = Vec::new();
    order
        .try_reserve_exact(refs.len())
        .map_err(|_| Error::Limit)?;
    order.resize(refs.len(), 0);
    let mut plain = zeros(policy.max_metadata_bytes)?;
    let limits = md::Limits {
        max_coded_bytes: policy.max_metadata_bytes,
        max_plain_bytes: policy.max_metadata_bytes,
        max_entries: policy.max_metadata_items,
    };
    let plan = md::plan_uncompressed(
        &refs,
        &mut order,
        &mut plain,
        limits,
        md::Options {
            compression: md::Compression::Never,
            max_output_bytes: policy.max_metadata_bytes,
            ..Default::default()
        },
    )?;
    let mut out = zeros(plan.report().wire_bytes)?;
    plan.write(&mut out)?;
    Ok(out)
}

struct Value {
    kind: u32,
    format: md::Format,
    data: Vec<u8>,
    plugin: Option<Vec<u8>>,
    mime: Option<Vec<u8>>,
}
pub(crate) struct Object {
    pub(crate) wire: Vec<u8>,
    pub(crate) provider: Option<gnunet_extractor_host::Observation>,
    // Only the explicitly annotated root needs pre-merge automatic terms.
    pub(crate) query_terms: Option<Vec<Vec<u8>>>,
}
#[cfg(feature = "network")]
pub(crate) fn keyword_bytes(terms: &Option<Vec<Vec<u8>>>) -> Result<usize, Error> {
    let Some(terms) = terms else {
        return Ok(0);
    };
    terms.iter().try_fold(
        terms
            .capacity()
            .checked_mul(std::mem::size_of::<Vec<u8>>())
            .ok_or(Error::Limit)?,
        |n, term| n.checked_add(term.capacity()).ok_or(Error::Limit),
    )
}
pub(crate) struct Extractor<'a, C> {
    pub(crate) context: &'a Context<C>,
    pub(crate) policy: Policy,
    root_name: Vec<u8>,
    probe: Vec<u8>,
    pub(crate) provider: Option<gnunet_extractor_host::Provider>,
    formats_enabled: bool,
    pub(crate) content_file_bytes: u64,
    pub(crate) manual: Option<std::sync::Arc<ManualMetadata>>,
}
impl<'a, C: FnMut(Progress) -> Control> Extractor<'a, C> {
    pub(crate) fn new(
        input: &Path,
        policy: Policy,
        limits: Limits,
        context: &'a Context<C>,
        formats_enabled: bool,
    ) -> Result<Self, Error> {
        let basename = input.file_name().map_or(b"".as_slice(), OsStrExt::as_bytes);
        Ok(Self {
            context,
            policy,
            root_name: copy(basename)?,
            probe: if policy.extract && formats_enabled {
                zeros(policy.max_probe_bytes)?
            } else {
                Vec::new()
            },
            provider: None,
            formats_enabled,
            content_file_bytes: limits.max_file_bytes,
            manual: None,
        })
    }
    fn add(
        values: &mut Vec<Value>,
        kind: u32,
        format: md::Format,
        data: &[u8],
        policy: Policy,
    ) -> Result<(), Error> {
        add_named(
            values,
            kind,
            format,
            data,
            Some(b"<gnunet-rs-auto>\0"),
            None,
            policy,
        )
    }
    fn text(values: &mut Vec<Value>, kind: u32, text: &[u8], policy: Policy) -> Result<(), Error> {
        if text.is_empty() {
            return Ok(());
        }
        let visible = md::c_prefix(text);
        let n = visible.len().checked_add(1).ok_or(Error::Limit)?;
        let mut terminated = zeros(n)?;
        terminated[..visible.len()].copy_from_slice(visible);
        Self::add(
            values,
            kind,
            if std::str::from_utf8(visible).is_ok() {
                md::Format::Utf8
            } else {
                md::Format::CString
            },
            &terminated,
            policy,
        )
    }

    pub(crate) fn extract_one(
        &mut self,
        file: &File,
        relative: &Path,
        directory: bool,
        base: &[u8],
        max_bytes: usize,
    ) -> Result<Object, Error> {
        self.context.check()?;
        let reservation = if self.policy.extract && !directory {
            self.provider
                .as_ref()
                .map_or(0, |p| p.limits().output_bytes)
        } else {
            0
        };
        self.context.budget.borrow_mut().add(reservation)?;
        let result = self.extract_object(file, relative, directory, base, max_bytes);
        let release = self.context.budget.borrow_mut().replace(reservation, 0);
        match result {
            Ok(wire) => {
                release?;
                Ok(wire)
            }
            Err(error) => Err(error),
        }
    }
    fn extract_object(
        &mut self,
        file: &File,
        relative: &Path,
        directory: bool,
        base: &[u8],
        max_bytes: usize,
    ) -> Result<Object, Error> {
        self.context.check()?;
        let before = Stamp::of(file)?;
        let p = self.policy;
        let mut values = Vec::new();
        values
            .try_reserve(p.max_metadata_items)
            .map_err(|_| Error::Limit)?;
        if !base.is_empty() {
            for item in decoded(base, p)?.items() {
                if matches!(item.kind, 2 | 180) {
                    continue;
                }
                add_named(
                    &mut values,
                    item.kind,
                    item.format,
                    item.data,
                    item.plugin,
                    item.mime,
                    p,
                )?;
            }
        }
        {
            let name = relative
                .file_name()
                .map_or(self.root_name.as_slice(), |s| s.as_bytes());
            Self::text(&mut values, 180, name, p)?;
        }
        if directory {
            Self::text(&mut values, 1, b"application/gnunet-directory", p)?;
        }
        if let Some(date) = p.creation_time {
            let mut text = [0u8; 21];
            utc_date(date, &mut text)?;
            values.retain(|v| v.kind != 24);
            Self::text(&mut values, 24, &text[..20], p)?;
        }
        let mut provider_observation = None;
        if p.extract && self.formats_enabled && !directory {
            if before.bytes > self.content_file_bytes {
                return Err(Error::Limit);
            }
            let want = usize::try_from(before.bytes.min(p.max_probe_bytes as u64))
                .map_err(|_| Error::Limit)?;
            let mut got = 0;
            while got < want {
                self.context.check()?;
                match file.read_at(&mut self.probe[got..want], got as u64) {
                    Ok(0) => return Err(Error::SourceChanged),
                    Ok(n) => got += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if let Some(provider) = &mut self.provider {
                let extracted = provider.extract_file(file, || self.context.check())?;
                provider_observation = Some(extracted.metadata.observation());
                // These are real native records from this held descriptor.
                // Type2 is the native pathname; type180 belongs only to the
                // verified source basename installed by this host above.
                for item in extracted.metadata.into_items() {
                    self.context.check()?;
                    if matches!(item.kind, 2 | 180) {
                        continue;
                    }
                    let format =
                        md::Format::try_from(item.format as u32).map_err(|_| Error::Binding)?;
                    if let Some(existing) = values
                        .iter_mut()
                        .find(|v| v.kind == item.kind && v.format == format && v.data == item.data)
                    {
                        if existing.plugin.as_deref() == Some(b"<gnunet-rs-auto>\0".as_slice()) {
                            existing.plugin = item.plugin;
                            existing.mime = item.mime;
                        }
                        continue;
                    }
                    if values.len() >= p.max_metadata_items {
                        return Err(Error::Limit);
                    }
                    values.push(Value {
                        kind: item.kind,
                        format,
                        data: item.data,
                        plugin: item.plugin,
                        mime: item.mime,
                    });
                }
            }
            self.context.check()?;
            let data = &self.probe[..got];
            if let Some(mime) = mime(data) {
                Self::text(&mut values, 1, mime, p)?;
            }
            if let Ok(text) = std::str::from_utf8(data)
                && (ascii_contains(text.as_bytes(), b"<html")
                    || ascii_contains(text.as_bytes(), b"<!doctype html"))
            {
                if let Some(title) = html_title(text) {
                    Self::text(&mut values, 4, title.trim().as_bytes(), p)?;
                }
                for (name, kind) in [
                    ("author", 13),
                    ("description", 46),
                    ("keywords", 49),
                    ("subject", 52),
                ] {
                    if let Some(value) = html_meta(text, name) {
                        Self::text(&mut values, kind, value.as_bytes(), p)?;
                    }
                }
            }
            if before.bytes >= 128 {
                self.context.check()?;
                let mut tag = [0u8; 128];
                let mut n = 0;
                while n < tag.len() {
                    self.context.check()?;
                    match file.read_at(&mut tag[n..], before.bytes - 128 + n as u64) {
                        Ok(0) => return Err(Error::SourceChanged),
                        Ok(k) => n += k,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                if &tag[..3] == b"TAG" {
                    for (range, kind) in [(3..33, 4), (33..63, 130), (63..93, 129)] {
                        let field = &tag[range];
                        let end = field
                            .iter()
                            .rposition(|b| *b != 0 && *b != b' ')
                            .map_or(0, |i| i + 1);
                        Self::text(&mut values, kind, &field[..end], p)?;
                    }
                }
            }
        }
        self.context.check()?;
        if Stamp::of(file)? != before {
            return Err(Error::SourceChanged);
        }
        self.context.check()?;
        let mut wire = encode_values(&values, p)?;
        self.context.check()?;
        let mut query_terms = None;
        if relative.as_os_str().is_empty()
            && let Some(manual) = &self.manual
        {
            // This is the actual root MetadataProvider result consumed by the
            // directory builder before its payload/CHK is formed. Select only
            // the original automatic query terms before adding user metadata.
            if p.extract {
                query_terms = Some(terms(&wire, p)?);
            }
            self.context.check()?;
            let annotated = manual.merge_wire(&wire, p)?;
            wire = annotated;
            self.context.check()?;
        }
        if wire.len() > max_bytes {
            return Err(Error::Limit);
        }
        Ok(Object {
            wire,
            provider: provider_observation,
            query_terms,
        })
    }
}
fn ascii_find(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}
fn ascii_contains(data: &[u8], needle: &[u8]) -> bool {
    ascii_find(data, needle).is_some()
}
fn mime(data: &[u8]) -> Option<&'static [u8]> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(b"image/png")
    } else if data.starts_with(b"\xff\xd8\xff") {
        Some(b"image/jpeg")
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        Some(b"image/gif")
    } else if data.starts_with(b"%PDF-") {
        Some(b"application/pdf")
    } else if data.starts_with(b"OggS") {
        Some(b"application/ogg")
    } else if data.starts_with(b"fLaC") {
        Some(b"audio/flac")
    } else if data.starts_with(b"ID3") {
        Some(b"audio/mpeg")
    } else if data.starts_with(b"PK\x03\x04") {
        Some(b"application/zip")
    } else if data.starts_with(b"\x1f\x8b") {
        Some(b"application/gzip")
    } else if data.starts_with(b"\x7fELF") {
        Some(b"application/x-executable")
    } else if ascii_contains(data, b"<html") || ascii_contains(data, b"<!doctype html") {
        Some(b"text/html")
    } else if !data.is_empty()
        && std::str::from_utf8(data).is_ok()
        && !data.iter().any(|b| *b < 32 && !b"\r\n\t".contains(b))
    {
        Some(b"text/plain")
    } else {
        None
    }
}
fn html_title(text: &str) -> Option<&str> {
    let at = ascii_find(text.as_bytes(), b"<title")?;
    let tail = &text[at + 6..];
    if tail
        .as_bytes()
        .first()
        .is_some_and(|b| *b != b'>' && !b.is_ascii_whitespace())
    {
        return None;
    }
    let start = tail.find('>')? + 1;
    let end = ascii_find(&tail.as_bytes()[start..], b"</title")?;
    let value = &tail[start..start + end];
    (!value.contains('<')).then_some(value)
}
fn attribute<'a>(tag: &'a str, wanted: &str) -> Option<&'a str> {
    let b = tag.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !b"=/<>".contains(&b[i]) {
            i += 1;
        }
        if i == start {
            i += 1;
            continue;
        }
        let name = &tag[start..i];
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if b.get(i) != Some(&b'=') {
            continue;
        }
        i += 1;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let quote = b.get(i).copied().filter(|c| *c == b'\'' || *c == b'"');
        if quote.is_some() {
            i += 1;
        }
        let value = i;
        while i < b.len()
            && match quote {
                Some(q) => b[i] != q,
                None => !b[i].is_ascii_whitespace() && b[i] != b'>',
            }
        {
            i += 1;
        }
        if quote.is_some() && i == b.len() {
            return None;
        }
        let result = &tag[value..i];
        if quote.is_some() {
            i += 1;
        }
        if name.eq_ignore_ascii_case(wanted) {
            return Some(result);
        }
    }
    None
}
fn html_meta<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let mut rest = text;
    while let Some(at) = ascii_find(rest.as_bytes(), b"<meta") {
        rest = &rest[at + 5..];
        if rest
            .as_bytes()
            .first()
            .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'>')
        {
            continue;
        }
        // Find the real closing bracket without ending inside a quoted value.
        let mut quote = None;
        let mut end = None;
        for (i, b) in rest.bytes().enumerate() {
            if let Some(q) = quote {
                if b == q {
                    quote = None;
                }
            } else if b == b'\'' || b == b'"' {
                quote = Some(b);
            } else if b == b'>' {
                end = Some(i);
                break;
            }
        }
        let end = end?;
        let tag = &rest[..end];
        if attribute(tag, "name").is_some_and(|n| n.eq_ignore_ascii_case(name)) {
            return attribute(tag, "content");
        }
        rest = &rest[end + 1..];
    }
    None
}
// Gregorian conversion uses a bounded arithmetic UTC date; no locale, wall-clock
// read or platform timezone affects the original caller-supplied timestamp.
fn utc_date(time: AbsoluteTime, out: &mut [u8; 21]) -> Result<(), Error> {
    let seconds = time.as_micros() / 1_000_000;
    if seconds > 253_402_300_799 {
        return Err(Error::Limit);
    }
    let days = i64::try_from(seconds / 86400).map_err(|_| Error::Limit)? + 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    fn number(mut n: u64, out: &mut [u8]) {
        for b in out.iter_mut().rev() {
            *b = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    *out = *b"0000-00-00T00:00:00Z\0";
    number(year as u64, &mut out[..4]);
    number(month as u64, &mut out[5..7]);
    number(day as u64, &mut out[8..10]);
    let rem = seconds % 86400;
    number(rem / 3600, &mut out[11..13]);
    number(rem % 3600 / 60, &mut out[14..16]);
    number(rem % 60, &mut out[17..19]);
    Ok(())
}
fn add_term(terms: &mut Vec<Vec<u8>>, value: &str, policy: Policy) -> Result<(), Error> {
    if value.chars().count() < 3
        || value.len() > policy.max_keyword_bytes
        || Keyword::new(value.as_bytes(), false).is_err()
        || terms.iter().any(|t| t == value.as_bytes())
    {
        return Ok(());
    }
    if terms.len() >= policy.max_keywords {
        return Err(Error::Limit);
    }
    let value = copy(value.as_bytes())?;
    terms.try_reserve(1).map_err(|_| Error::Limit)?;
    terms.push(value);
    Ok(())
}
// Full Unicode lowercase followed by canonical decomposition, as used for
// automatic C metadata keys. The source value and every expansion are bounded;
// refusal cannot silently turn a missing normalized key into a complete plan.
fn add_normalized(terms: &mut Vec<Vec<u8>>, text: &str, policy: Policy) -> Result<(), Error> {
    if text.chars().count() < 3 {
        return Ok(());
    }
    if text.len() > policy.max_keyword_bytes {
        return Err(Error::Limit);
    }
    add_term(terms, text, policy)?;
    // str lowercase includes contextual Unicode casing (for example final sigma).
    // Its temporary allocation is bounded by this admitted finite source value.
    let lower = text.to_lowercase();
    if lower.len() > policy.max_keyword_bytes {
        return Err(Error::Limit);
    }
    let mut normalized = String::new();
    normalized
        .try_reserve(policy.max_keyword_bytes)
        .map_err(|_| Error::Limit)?;
    for ch in lower.nfd() {
        if normalized
            .len()
            .checked_add(ch.len_utf8())
            .is_none_or(|n| n > policy.max_keyword_bytes)
        {
            return Err(Error::Limit);
        }
        normalized.push(ch);
    }
    add_term(terms, &normalized, policy)
}
fn filename_terms(terms: &mut Vec<Vec<u8>>, text: &str, policy: Policy) -> Result<(), Error> {
    const SEPARATORS: &[u8] = b"_. /-!?#&+@\"'\\;:,()[]{}$<>|";
    for token in text.split(|c: char| c.is_ascii() && SEPARATORS.contains(&(c as u8))) {
        add_normalized(terms, token, policy)?;
    }
    // Each matching bracketed phrase is also a single real query label. Keep
    // spaces inside it; token labels alone cannot substitute for this label.
    for (at, open) in text
        .char_indices()
        .filter(|(_, c)| matches!(c, '(' | '[' | '{'))
    {
        let rest = &text[at + 1..];
        if let Some((end, close)) = rest
            .char_indices()
            .find(|(_, c)| matches!(c, ')' | ']' | '}'))
            && matches!((open, close), ('(', ')') | ('[', ']') | ('{', '}'))
        {
            add_normalized(terms, &rest[..end], policy)?;
        }
    }
    Ok(())
}
pub(crate) fn terms(wire: &[u8], policy: Policy) -> Result<Vec<Vec<u8>>, Error> {
    let mut terms = Vec::new();
    for item in decoded(wire, policy)?.items() {
        let Some(text) = item.text().and_then(|b| std::str::from_utf8(b).ok()) else {
            continue;
        };
        add_normalized(&mut terms, text, policy)?;
        if item.kind == 1
            && let Some((family, _)) = text.split_once('/')
        {
            let mut typed = String::new();
            typed
                .try_reserve(9 + family.len())
                .map_err(|_| Error::Limit)?;
            typed.push_str("mimetype:");
            typed.push_str(family);
            add_term(&mut terms, &typed, policy)?;
        }
        if item.kind == 180 {
            filename_terms(&mut terms, text, policy)?;
        } else if matches!(item.kind, 4 | 13 | 46 | 49 | 52 | 129 | 130) {
            for token in text.split(|c: char| !c.is_alphanumeric()) {
                add_normalized(&mut terms, token, policy)?;
            }
        }
    }
    Ok(terms)
}
/// Reconstruct bounded automatic keywords from one actual stable regular-file
/// descriptor and its selected filename. This read-only preparation creates no
/// Task, WAL, metadata file or socket. It uses the same finite Rust extraction
/// policy as automatic publication; it cannot recover every historically chosen
/// custom keyword. The descriptor position is unchanged (reads use read_at).
/// Synchronous filesystem calls remain ordinary non-preemptible OS boundaries.
pub fn file_keywords(
    file: &File,
    filename: &Path,
    policy: Policy,
    control: impl FnMut(Progress) -> Control,
) -> Result<Vec<Vec<u8>>, Error> {
    file_keywords_with_metadata(file, filename, policy, MetadataSettings::default(), control)
}
/// Same original source/metadata/keyword algorithm with explicitly selected
/// owned provider settings; no network publication is performed here.
pub fn file_keywords_with_metadata(
    file: &File,
    filename: &Path,
    policy: Policy,
    metadata: MetadataSettings,
    control: impl FnMut(Progress) -> Control,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut policy = policy;
    policy.extract &= metadata.automatic_keywords_enabled();
    let limits = Limits::default();
    policy.validate(limits)?;
    let settings_bytes = metadata.retained_bytes()?;
    if settings_bytes > policy.max_retained_bytes {
        return Err(Error::Policy);
    }
    let context = Context {
        control: RefCell::new(control),
        progress: Cell::new(Progress::default()),
        budget: RefCell::new(Budget {
            used: settings_bytes,
            limit: policy.max_retained_bytes,
        }),
    };
    context.check()?;
    if !file.metadata()?.is_file() {
        return Err(Error::Policy);
    }
    context.check()?;
    let original = Stamp::of(file)?;
    let mut extractor = Extractor::new(
        filename,
        policy,
        limits,
        &context,
        metadata.format_extraction_enabled(),
    )?;
    extractor.provider = metadata.open(&context, policy, limits.max_file_bytes)?;
    let result = (|| -> Result<Vec<Vec<u8>>, Error> {
        let object =
            extractor.extract_one(file, Path::new(""), false, &[], policy.max_metadata_bytes)?;
        context.check()?;
        let result = terms(&object.wire, policy)?;
        context.check()?;
        if Stamp::of(file)? != original {
            return Err(Error::SourceChanged);
        }
        Ok(result)
    })();
    metadata::finish(extractor.provider.take(), result)
}

#[cfg(test)]
mod keyword_tests;
