use super::{BLOCK_BYTES, Error, MAGIC};
use crate::{Uri, metadata};

/// Valid present metadata bytes, sealed by a real plan or strict decode.
#[derive(Clone, Copy, Debug)]
pub struct PreparedMetadata<'a> {
    bytes: &'a [u8],
    selection: Option<metadata::Report>,
}
impl<'a> PreparedMetadata<'a> {
    /// Materialize an already computed real metadata plan atomically.
    pub fn materialize(plan: &metadata::Plan<'_>, output: &'a mut [u8]) -> Result<Self, Error> {
        let n = plan.write(output).map_err(Error::Metadata)?;
        Ok(Self {
            bytes: &output[..n],
            selection: Some(plan.report()),
        })
    }
    /// Validate supplied compressed/raw metadata with a caller-selected real codec.
    /// Absence, v1null and recovered prefixes cannot become PreparedMetadata.
    pub fn validate(
        bytes: &'a [u8],
        plain: &mut [u8],
        inflater: &mut impl metadata::Inflater,
        limits: metadata::Limits,
    ) -> Result<Self, Error> {
        u32::try_from(bytes.len()).map_err(|_| Error::Overflow)?;
        match metadata::decode(bytes, plain, inflater, limits, metadata::Mode::Strict)
            .map_err(Error::Metadata)?
        {
            metadata::Decoded::NullMarker => Err(Error::NullMetadata),
            metadata::Decoded::Present(_) => Ok(Self {
                bytes,
                selection: None,
            }),
        }
    }
    /// Exact retained artifact bytes; no MIME or content verification is implied.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Known local plan selection; externally supplied metadata has unknown origin.
    #[must_use]
    pub const fn selection(self) -> Option<metadata::Report> {
        self.selection
    }
    fn omissions(self) -> usize {
        self.selection.map_or(0, |r| r.omitted_entries)
    }
}

/// Complete URI+NUL+length+metadata record over distinct caller arena storage.
#[derive(Clone, Copy, Debug)]
pub struct PreparedEntry<'a> {
    bytes: &'a [u8],
    selection: Option<metadata::Report>,
}
impl<'a> PreparedEntry<'a> {
    /// Canonically encode an entry after all capacity/URI checks. KSK refuses.
    /// Existing FULL_DATA items remain unverified hints; no raw data is invented.
    pub fn prepare(
        uri: Uri<'_>,
        metadata: PreparedMetadata<'_>,
        output: &'a mut [u8],
    ) -> Result<Self, Error> {
        if matches!(uri, Uri::Keywords(_)) {
            return Err(Error::Keyword);
        }
        let uri_len = uri.encoded_len().map_err(Error::Uri)?;
        let md_len = u32::try_from(metadata.bytes.len()).map_err(|_| Error::Overflow)?;
        let length = uri_len
            .checked_add(5)
            .and_then(|n| n.checked_add(metadata.bytes.len()))
            .ok_or(Error::Overflow)?;
        if output.len() < length {
            return Err(Error::Capacity);
        }
        uri.encode(&mut output[..uri_len]).map_err(Error::Uri)?;
        output[uri_len] = 0;
        output[uri_len + 1..uri_len + 5].copy_from_slice(&md_len.to_be_bytes());
        output[uri_len + 5..length].copy_from_slice(metadata.bytes);
        Ok(Self {
            bytes: &output[..length],
            selection: metadata.selection,
        })
    }
    /// Exact prepared bytes.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Explicit local metadata omissions, if prepared from a local plan.
    #[must_use]
    pub const fn selection(self) -> Option<metadata::Report> {
        self.selection
    }
}
/// Entry inclusion, independent of metadata item inclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Inclusion {
    /// Include all input entries or refuse.
    Full,
    /// Greedily retain fitting entries in input order with explicit omissions.
    Partial,
}
/// Checked construction resource and selection policy.
#[derive(Clone, Copy, Debug)]
pub struct BuildOptions {
    /// Complete final extent, including header and padding.
    pub max_output_bytes: u64,
    /// Maximum source entries inspected.
    pub max_source_entries: usize,
    /// Maximum selected entries.
    pub max_entries: usize,
    /// Maximum entry layout attempts; zero refuses any nonempty input.
    pub max_trials: usize,
    /// Full or explicitly reported partial-directory selection.
    pub inclusion: Inclusion,
    /// Accept known local metadata PART selections and report their omissions.
    pub allow_partial_metadata: bool,
}
impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            max_output_bytes: 64 * 1024 * 1024,
            max_source_entries: 4096,
            max_entries: 4096,
            max_trials: 4096,
            inclusion: Inclusion::Full,
            allow_partial_metadata: false,
        }
    }
}
/// Caller placement slot. Only the prefix exposed by a successful plan is valid.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Placement {
    /// Index into the original PreparedEntry slice.
    pub source_index: usize,
    /// Absolute start in the emitted directory.
    pub offset: u64,
}
/// Exact selected subset and whole artifact accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildReport {
    /// Number of input entries, before explicit directory selection.
    pub source_entries: usize,
    /// Number retained in the actual artifact.
    pub selected_entries: usize,
    /// Entries omitted by explicit Partial mode.
    pub omitted_entries: usize,
    /// Known local metadata items omitted across root and selected entries.
    pub metadata_omissions: usize,
    /// Exact output bytes including root header and all zero gaps.
    pub wire_bytes: u64,
    /// Exact zero-padding bytes.
    pub padding_bytes: u64,
    /// Actual entry layout attempts.
    pub trials: usize,
}
/// Materialized checked layout; final output remains separate and atomic.
pub struct BuildPlan<'a> {
    root: PreparedMetadata<'a>,
    entries: &'a [PreparedEntry<'a>],
    placements: &'a [Placement],
    report: BuildReport,
}
impl BuildPlan<'_> {
    /// Whole output/subset accounting.
    #[must_use]
    pub const fn report(&self) -> BuildReport {
        self.report
    }
    /// Selected original indices and exact offsets in output order.
    #[must_use]
    pub const fn placements(&self) -> &[Placement] {
        self.placements
    }
    /// Write after complete checked capacity preflight; refusal changes no output.
    pub fn write(&self, output: &mut [u8]) -> Result<usize, Error> {
        let n = usize::try_from(self.report.wire_bytes).map_err(|_| Error::Overflow)?;
        if output.len() < n {
            return Err(Error::Capacity);
        }
        output[..n].fill(0);
        output[..8].copy_from_slice(MAGIC);
        output[8..12].copy_from_slice(&(self.root.bytes.len() as u32).to_be_bytes());
        output[12..12 + self.root.bytes.len()].copy_from_slice(self.root.bytes);
        for placement in self.placements {
            let bytes = self.entries[placement.source_index].bytes;
            let start = placement.offset as usize;
            output[start..start + bytes.len()].copy_from_slice(bytes);
        }
        Ok(n)
    }
    /// Read a portion of the planned artifact directly into reusable storage.
    /// This supports streaming its blocks without materializing the whole
    /// directory. Padding is generated in place; record lookup is logarithmic
    /// before copying only intersecting records. Bytes after the returned prefix
    /// remain unchanged. An offset beyond the planned extent refuses unchanged.
    pub fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<usize, Error> {
        if offset > self.report.wire_bytes {
            return Err(Error::Input);
        }
        let count = (self.report.wire_bytes - offset).min(output.len() as u64) as usize;
        let end = offset + count as u64;
        let target = &mut output[..count];
        target.fill(0);
        let mut header = [0; 12];
        header[..8].copy_from_slice(MAGIC);
        header[8..].copy_from_slice(&(self.root.bytes.len() as u32).to_be_bytes());
        copy_intersection(0, &header, offset, target);
        copy_intersection(12, self.root.bytes, offset, target);
        let first = self.placements.partition_point(|placement| {
            placement.offset + self.entries[placement.source_index].bytes.len() as u64 <= offset
        });
        for placement in &self.placements[first..] {
            if placement.offset >= end {
                break;
            }
            copy_intersection(
                placement.offset,
                self.entries[placement.source_index].bytes,
                offset,
                target,
            );
        }
        Ok(count)
    }
}
fn copy_intersection(start: u64, bytes: &[u8], offset: u64, output: &mut [u8]) {
    let left = start.max(offset);
    let right = (start + bytes.len() as u64).min(offset + output.len() as u64);
    if left < right {
        let source = (left - start) as usize;
        let destination = (left - offset) as usize;
        let length = (right - left) as usize;
        output[destination..destination + length].copy_from_slice(&bytes[source..source + length]);
    }
}
fn position(start: u64, len: u64) -> Result<u64, Error> {
    let within = start % BLOCK_BYTES;
    if within != 0
        && (len > BLOCK_BYTES || within.checked_add(len).ok_or(Error::Overflow)? > BLOCK_BYTES)
    {
        start
            .checked_add(BLOCK_BYTES - within)
            .ok_or(Error::Overflow)
    } else {
        Ok(start)
    }
}
/// Plan all entries or an explicit fitting subset. A longer-than-block entry
/// begins at a boundary and may span arbitrarily many blocks within the budget.
/// Workspace slots may change on refusal, but final output is not supplied here.
pub fn plan<'a>(
    root: PreparedMetadata<'a>,
    entries: &'a [PreparedEntry<'a>],
    placements: &'a mut [Placement],
    options: BuildOptions,
) -> Result<BuildPlan<'a>, Error> {
    if entries.len() > options.max_source_entries {
        return Err(Error::Limit);
    }
    if root.omissions() != 0 && !options.allow_partial_metadata {
        return Err(Error::PartialMetadata);
    }
    u32::try_from(root.bytes.len()).map_err(|_| Error::Overflow)?;
    let mut end = 12_u64
        .checked_add(u64::try_from(root.bytes.len()).map_err(|_| Error::Overflow)?)
        .ok_or(Error::Overflow)?;
    if end > options.max_output_bytes {
        return Err(Error::Capacity);
    }
    let mut selected = 0;
    let mut padding = 0_u64;
    let mut omissions = root.omissions();
    for (index, entry) in entries.iter().enumerate() {
        if index >= options.max_trials {
            return Err(Error::Limit);
        }
        let lost = entry.selection.map_or(0, |r| r.omitted_entries);
        if lost != 0 && !options.allow_partial_metadata {
            return Err(Error::PartialMetadata);
        }
        let len = u64::try_from(entry.bytes.len()).map_err(|_| Error::Overflow)?;
        let start = position(end, len)?;
        let next = start.checked_add(len).ok_or(Error::Overflow)?;
        if next > options.max_output_bytes || selected == options.max_entries {
            if options.inclusion == Inclusion::Full {
                return Err(Error::Capacity);
            }
            continue;
        }
        if selected == placements.len() {
            return Err(Error::Capacity);
        }
        placements[selected] = Placement {
            source_index: index,
            offset: start,
        };
        selected += 1;
        padding = padding.checked_add(start - end).ok_or(Error::Overflow)?;
        omissions = omissions.checked_add(lost).ok_or(Error::Overflow)?;
        end = next;
    }
    Ok(BuildPlan {
        root,
        entries,
        placements: &placements[..selected],
        report: BuildReport {
            source_entries: entries.len(),
            selected_entries: selected,
            omitted_entries: entries.len() - selected,
            metadata_omissions: omissions,
            wire_bytes: end,
            padding_bytes: padding,
            trials: entries.len(),
        },
    })
}
