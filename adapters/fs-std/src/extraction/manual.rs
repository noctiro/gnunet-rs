//! Explicit user metadata, separate from extractor observations and query keys.
//! Canonical English names/IDs from GNU libextractor's complete public table.
use super::{Error, Policy, Value, add_named, copy, decoded, encode_values, md};
use std::mem::size_of;

/// Explicit finite user-annotation policy; actual final metadata limits also apply.
#[derive(Clone, Copy, Debug)]
pub struct ManualLimits {
    /// Maximum original -m inputs, including duplicates.
    pub items: usize,
    /// Maximum retained input bytes and canonical serialized metadata bytes.
    pub bytes: usize,
}
impl Default for ManualLimits {
    fn default() -> Self {
        Self {
            items: 32,
            bytes: 32768,
        }
    }
}
struct Entry {
    kind: u32,
    data: Vec<u8>,
}
/// Owned, bounded explicit annotations. No provider/native/clock/file handles.
/// Values are never modified by auto-keyword canonicalization.
#[derive(Default)]
pub struct ManualMetadata {
    limits: ManualLimits,
    inputs: usize,
    entries: Vec<Entry>,
}
impl ManualMetadata {
    /// Create one explicit finite user-metadata owner.
    pub fn new(limits: ManualLimits) -> Result<Self, Error> {
        if limits.items == 0
            || limits.items > 256
            || !(md::HEADER_BYTES..=1048576).contains(&limits.bytes)
        {
            return Err(Error::Limit);
        }
        Ok(Self {
            limits,
            inputs: 0,
            entries: Vec::new(),
        })
    }
    /// Consume one exact UTF-8 TYPE:VALUE argument. C's descending table search
    /// means duplicate canonical names select their highest public type number.
    /// Unknown names keep the entire original argument as real type45. Locale
    /// translations are not guessed; the selected profile is canonical English.
    pub fn push(&mut self, input: &[u8]) -> Result<(), Error> {
        if self.inputs >= self.limits.items || input.len() >= self.limits.bytes {
            return Err(Error::Limit);
        }
        if input.contains(&0) || std::str::from_utf8(input).is_err() {
            return Err(Error::Binding);
        }
        let matched = input.iter().position(|b| *b == b':').and_then(|at| {
            TYPE_NAMES
                .iter()
                .enumerate()
                .rev()
                .find(|(_, name)| name.as_bytes() == &input[..at])
                .map(|(kind, _)| (kind as u32, &input[at + 1..]))
        });
        let (kind, value) = matched.unwrap_or((45, input));
        let mut data = copy(value)?;
        data.try_reserve_exact(1).map_err(|_| Error::Limit)?;
        data.push(0);
        if matches!(kind, 2 | 180) {
            let mut normalized = super::zeros(data.len())?;
            md::normalize_filename(kind, &data, &mut normalized)?;
            data = normalized;
        }
        self.inputs += 1;
        if self
            .entries
            .iter()
            .any(|entry| entry.kind == kind && entry.data == data)
        {
            return Ok(());
        }
        self.entries.try_reserve(1).map_err(|_| Error::Limit)?;
        let projected = self
            .retained_bytes()?
            .checked_add(data.capacity())
            .ok_or(Error::Limit)?;
        if projected > self.limits.bytes {
            return Err(Error::Limit);
        }
        self.entries.push(Entry { kind, data });
        Ok(())
    }
    /// Actual distinct selected entries; no parsed argument is silently dropped.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether no explicit entries were selected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Actual owned capacities, including this value's metadata.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.entries.iter().try_fold(
            self.entries
                .capacity()
                .checked_mul(size_of::<Entry>())
                .and_then(|n| n.checked_add(size_of::<Self>()))
                .ok_or(Error::Limit)?,
            |n, entry| n.checked_add(entry.data.capacity()).ok_or(Error::Limit),
        )
    }
    fn merge(&self, values: &mut Vec<Value>, policy: Policy) -> Result<(), Error> {
        for entry in &self.entries {
            if let Some(existing) = values
                .iter_mut()
                .find(|v| v.kind == entry.kind && v.data == entry.data)
            {
                if existing.format == md::Format::CString {
                    existing.format = md::Format::Utf8;
                }
                if existing.mime.is_none() {
                    existing.mime = Some(copy(b"text/plain\0")?);
                }
                continue;
            }
            add_named(
                values,
                entry.kind,
                md::Format::Utf8,
                &entry.data,
                Some(b"<gnunet>\0"),
                Some(b"text/plain\0"),
                policy,
            )?;
        }
        Ok(())
    }
    /// Canonical standard metadata for an actual keyword re-publication. No
    /// extractor is loaded. Count, retained bytes and final wire size are bounded.
    pub fn encode(&self, policy: Policy) -> Result<Vec<u8>, Error> {
        self.merge_wire(&[], policy)
    }
    /// Materialize the same standard metadata in caller workspaces, for the
    /// existing Task/store_keywords APIs. The returned plan borrows only those
    /// actual scratch buffers; it is never a self-reference or partial artifact.
    pub fn plan<'a>(
        &self,
        order: &'a mut [usize],
        plain: &'a mut [u8],
        mut policy: Policy,
    ) -> Result<md::Plan<'a>, Error> {
        policy.max_metadata_bytes = policy.max_metadata_bytes.min(self.limits.bytes);
        policy.max_metadata_items = policy.max_metadata_items.min(256);
        let mut items = Vec::new();
        items
            .try_reserve_exact(self.entries.len())
            .map_err(|_| Error::Limit)?;
        for entry in &self.entries {
            items.push(md::Item {
                kind: entry.kind,
                format: md::Format::Utf8,
                data: &entry.data,
                plugin: Some(b"<gnunet>\0"),
                mime: Some(b"text/plain\0"),
            });
        }
        Ok(md::plan_uncompressed(
            &items,
            order,
            plain,
            md::Limits {
                max_coded_bytes: policy.max_metadata_bytes,
                max_plain_bytes: policy.max_metadata_bytes,
                max_entries: policy.max_metadata_items,
            },
            md::Options {
                compression: md::Compression::Never,
                max_output_bytes: policy.max_metadata_bytes,
                ..Default::default()
            },
        )?)
    }
    pub(super) fn merge_wire(&self, base: &[u8], mut policy: Policy) -> Result<Vec<u8>, Error> {
        policy.max_metadata_bytes = policy.max_metadata_bytes.min(self.limits.bytes);
        policy.max_metadata_items = policy.max_metadata_items.min(256);
        let mut values = Vec::new();
        values
            .try_reserve_exact(policy.max_metadata_items)
            .map_err(|_| Error::Limit)?;
        if !base.is_empty() {
            for item in decoded(base, policy)?.items() {
                add_named(
                    &mut values,
                    item.kind,
                    item.format,
                    item.data,
                    item.plugin,
                    item.mime,
                    policy,
                )?;
            }
        }
        self.merge(&mut values, policy)?;
        encode_values(&values, policy)
    }
}

// Public facts, not a provider load certificate. Complete selected GNU table,
// 0..=293, source SHA ec0204f29235d83346387fb4463d719dc33f4d755ffb4b6ce686874c3990382f.
const TYPE_NAMES: &[&str] = &[
    "reserved",
    "mimetype",
    "embedded filename",
    "comment",
    "title",
    "book title",
    "book edition",
    "book chapter",
    "journal name",
    "journal volume",
    "journal number",
    "page count",
    "page range",
    "author name",
    "author email",
    "author institution",
    "publisher",
    "publisher's address",
    "publishing institution",
    "publication series",
    "publication type",
    "publication year",
    "publication month",
    "publication day",
    "publication date",
    "bibtex eprint",
    "bibtex entry type",
    "language",
    "creation time",
    "URL",
    "URI",
    "international standard recording code",
    "MD4",
    "MD5",
    "SHA-0",
    "SHA-1",
    "RipeMD160",
    "GPS latitude ref",
    "GPS latitude",
    "GPS longitude ref",
    "GPS longitude",
    "city",
    "sublocation",
    "country",
    "country code",
    "unknown",
    "description",
    "copyright",
    "rights",
    "keywords",
    "abstract",
    "summary",
    "subject",
    "creator",
    "format",
    "format version",
    "created by software",
    "unknown date",
    "creation date",
    "modification date",
    "last printed",
    "last saved by",
    "total editing time",
    "editing cycles",
    "modified by software",
    "revision history",
    "embedded file size",
    "file type",
    "creator",
    "package name",
    "package version",
    "section",
    "upload priority",
    "dependencies",
    "conflicting packages",
    "replaced packages",
    "provides",
    "recommendations",
    "suggestions",
    "maintainer",
    "installed size",
    "source",
    "is essential",
    "target architecture",
    "pre-dependency",
    "license",
    "distribution",
    "build host",
    "vendor",
    "target operating system",
    "software version",
    "target platform",
    "resource type",
    "library search path",
    "library dependency",
    "camera make",
    "camera model",
    "exposure",
    "aperture",
    "exposure bias",
    "flash",
    "flash bias",
    "focal length",
    "focal length 35mm",
    "iso speed",
    "exposure mode",
    "metering mode",
    "macro mode",
    "image quality",
    "white balance",
    "orientation",
    "magnification",
    "image dimensions",
    "produced by software",
    "thumbnail",
    "image resolution",
    "source",
    "character set",
    "line count",
    "paragraph count",
    "word count",
    "character count",
    "page orientation",
    "paper size",
    "template",
    "company",
    "manager",
    "revision number",
    "duration",
    "album",
    "artist",
    "genre",
    "track number",
    "disk number",
    "performer",
    "contact",
    "song version",
    "picture",
    "cover picture",
    "contributor picture",
    "event picture",
    "logo",
    "broadcast television system",
    "source device",
    "disclaimer",
    "warning",
    "page order",
    "writer",
    "product version",
    "contributor",
    "movie director",
    "network",
    "show",
    "chapter name",
    "song count",
    "starting song",
    "play counter",
    "conductor",
    "interpretation",
    "composer",
    "beats per minute",
    "encoded by",
    "original title",
    "original artist",
    "original writer",
    "original release year",
    "original performer",
    "lyrics",
    "popularity",
    "licensee",
    "musician credit list",
    "mood",
    "subtitle",
    "display type",
    "full data",
    "rating",
    "organization",
    "ripper",
    "producer",
    "group",
    "original filename",
    "disc count",
    "codec",
    "video codec",
    "audio codec",
    "subtitle codec",
    "container format",
    "bitrate",
    "nominal bitrate",
    "minimum bitrate",
    "maximum bitrate",
    "serial",
    "encoder",
    "encoder version",
    "track gain",
    "track peak",
    "album gain",
    "album peak",
    "reference level",
    "location name",
    "location elevation",
    "location horizontal error",
    "location movement speed",
    "location movement direction",
    "location capture direction",
    "show episode number",
    "show season number",
    "grouping",
    "device manufacturer",
    "device model",
    "audio language",
    "channels",
    "sample rate",
    "audio depth",
    "audio bitrate",
    "maximum audio bitrate",
    "video dimensions",
    "video depth",
    "frame rate",
    "pixel aspect ratio",
    "video bitrate",
    "maximum video bitrate",
    "subtitle language",
    "video language",
    "table of contents",
    "video duration",
    "audio duration",
    "subtitle duration",
    "audio preview",
    "narinfo",
    "nar",
    "authoring operating system",
    "build date",
    "build identifier",
    "toolchain",
    "debug symbol path",
    "import hash",
    "entry point",
    "subsystem",
    "security mitigations",
    "signer",
    "certificate fingerprint",
    "entropy",
    "product name",
    "target path",
    "working directory",
    "command line",
    "owner user name",
    "owner group name",
    "owner user id",
    "owner group id",
    "permissions",
    "last access date",
    "file attributes",
    "volume name",
    "volume serial number",
    "volume size",
    "block size",
    "file system type",
    "parent image",
    "free space",
    "system identifier",
    "data preparer",
    "expiration date",
    "encryption",
    "application identifier",
    "schema version",
    "change counter",
    "journal mode",
    "entry count",
    "uncompressed size",
    "coordinate reference system",
    "bounding box",
    "distance",
    "message identifier",
    "in reply to",
    "recipient",
    "received from",
    "ip address",
    "encoder settings",
    "bitrate mode",
    "color depth",
    "color profile",
    "compatible brands",
    "purchase account",
    "watermark",
    "isbn",
    "permission",
    "mac address",
    "source host",
    "minimum operating system version",
    "full text",
    "subtitle text",
    "last",
];

#[cfg(test)]
mod tests {
    use super::*;
    fn check(value: bool) -> Result<(), Error> {
        value.then_some(()).ok_or(Error::Binding)
    }
    #[test]
    fn standard_names_descend_and_unknown_retains_original_text() -> Result<(), Error> {
        let mut m = ManualMetadata::default();
        m.push(b"creator:A")?;
        m.push(b"source:B")?;
        m.push(b"not-a-known-type:untouched:Value")?;
        check(
            m.entries
                .first()
                .is_some_and(|v| v.kind == 68 && v.data == b"A\0"),
        )?;
        check(
            m.entries
                .get(1)
                .is_some_and(|v| v.kind == 116 && v.data == b"B\0"),
        )?;
        check(
            m.entries
                .get(2)
                .is_some_and(|v| v.kind == 45 && v.data == b"not-a-known-type:untouched:Value\0"),
        )?;
        check(m.push(b"title:bad\0input").is_err())
    }
    #[test]
    fn actual_standard_plan_preserves_empty_value_and_provenance() -> Result<(), Error> {
        let mut m = ManualMetadata::default();
        m.push(b"title:")?;
        m.push(b"title:")?;
        m.push(b"description:Unicode caf\xc3\xa9")?;
        check(m.len() == 2)?;
        let mut order = [0; 2];
        let mut plain = [0; 1024];
        let policy = Policy {
            max_metadata_bytes: 1024,
            ..Policy::default()
        };
        let p = m.plan(&mut order, &mut plain, policy)?;
        let mut wire = [0; 1024];
        let n = p.write(&mut wire)?;
        let decoded = super::super::decoded(&wire[..n], policy)?;
        check(decoded.items().any(|v| {
            v.kind == 4
                && v.data == b"\0"
                && v.format == md::Format::Utf8
                && v.plugin == Some(b"<gnunet>\0".as_slice())
                && v.mime == Some(b"text/plain\0".as_slice())
        }))?;
        check(
            decoded
                .items()
                .any(|v| v.kind == 46 && v.data == b"Unicode caf\xc3\xa9\0"),
        )
    }
}
