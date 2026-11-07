use super::{
    COMPRESSED, CodecError, Deflater, ENTRY_BYTES, Error, HEADER_BYTES, Item, Limits, NoCodec,
};

/// Whether every source item must be included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Inclusion {
    /// Preserve all records or refuse.
    Full,
    /// Try stable descending-data-size suffixes, explicitly reporting omissions.
    Partial,
}
/// Explicit codec/output policy; independent of any previous cache use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compression {
    /// Do not invoke a compressor or emit the compressed flag.
    Never,
    /// Prefer zlib only if it produces a smaller complete body.
    Adaptive,
    /// Require a complete zlib member, even when it is larger than raw input.
    Always,
}
/// Bounded serializer policy. Final output capacity always includes the header.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Full versus explicit partial selection.
    pub inclusion: Inclusion,
    /// Whether and when a codec may be used.
    pub compression: Compression,
    /// Maximum complete artifact bytes, including its twelve-byte header.
    pub max_output_bytes: usize,
    /// Maximum candidate selections, including candidates rejected by workspace.
    pub max_trials: usize,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            inclusion: Inclusion::Full,
            compression: Compression::Adaptive,
            max_output_bytes: 1024 * 1024,
            max_trials: 4097,
        }
    }
}
/// Exact local selection/output result; no storage or publication is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Original source record count, before any semantic Set deduplication.
    pub source_entries: usize,
    /// Number of complete records encoded into this artifact.
    pub selected_entries: usize,
    /// Records omitted by the explicit partial policy.
    pub omitted_entries: usize,
    /// Selected plugin/MIME spans canonicalized to their first C-string prefix.
    pub normalized_names: usize,
    /// Candidate selections tried under the work budget.
    pub trials: usize,
    /// Complete uncompressed body length, including descriptors.
    pub plain_bytes: usize,
    /// Complete final artifact length, including the header.
    pub wire_bytes: usize,
    /// Whether the emitted body is a zlib member.
    pub compressed: bool,
}
/// Fully materialized plan borrowing caller scratch and selected source indices.
/// Final output is written only after all validation, codec and capacity checks.
pub struct Plan<'a> {
    body: &'a [u8],
    selected: &'a [usize],
    report: Report,
}
impl Plan<'_> {
    /// Exact selected/omitted counts and output sizes.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Selected source indices in their exact serialized descriptor order.
    #[must_use]
    pub const fn selected_source_indices(&self) -> &[usize] {
        self.selected
    }
    /// Write one complete official v2 artifact. Refusal leaves output unchanged;
    /// bytes beyond the written prefix are preserved.
    pub fn write(&self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < self.report.wire_bytes {
            return Err(Error::Capacity);
        }
        let version = 2 | if self.report.compressed {
            COMPRESSED
        } else {
            0
        };
        output[..4].copy_from_slice(&version.to_be_bytes());
        output[4..8].copy_from_slice(&(self.report.selected_entries as u32).to_be_bytes());
        output[8..12].copy_from_slice(&(self.report.plain_bytes as u32).to_be_bytes());
        output[HEADER_BYTES..self.report.wire_bytes].copy_from_slice(self.body);
        Ok(self.report.wire_bytes)
    }
    /// Write the standard BIO-style big-endian u32 length and raw v2 blob.
    /// Other FS embeddings may use the raw write operation and their own frame.
    pub fn write_length_prefixed(&self, output: &mut [u8]) -> Result<usize, Error> {
        let length = u32::try_from(self.report.wire_bytes).map_err(|_| Error::Overflow)?;
        let total = self
            .report
            .wire_bytes
            .checked_add(4)
            .ok_or(Error::Overflow)?;
        if output.len() < total {
            return Err(Error::Capacity);
        }
        self.write(&mut output[4..total])?;
        output[..4].copy_from_slice(&length.to_be_bytes());
        Ok(total)
    }
}

fn body_length(items: &[Item<'_>], order: &[usize]) -> Result<usize, Error> {
    order.iter().try_fold(0_usize, |length, index| {
        length
            .checked_add(items[*index].wire_bytes()?)
            .ok_or(Error::Overflow)
    })
}
fn body(items: &[Item<'_>], order: &[usize], output: &mut [u8]) {
    let mut end = output.len();
    for (position, index) in order.iter().enumerate() {
        let item = items[*index];
        let (plugin, mime) = item.names();
        let start = position * ENTRY_BYTES;
        for (offset, value) in [
            item.kind,
            item.format as u32,
            item.data.len() as u32,
            plugin.map_or(0, <[u8]>::len) as u32,
            mime.map_or(0, <[u8]>::len) as u32,
        ]
        .into_iter()
        .enumerate()
        {
            output[start + offset * 4..start + offset * 4 + 4]
                .copy_from_slice(&value.to_be_bytes());
        }
        for bytes in [Some(item.data), plugin, mime].into_iter().flatten() {
            end -= bytes.len();
            output[end..end + bytes.len()].copy_from_slice(bytes);
        }
    }
}

/// Build a complete full/partial plan using caller workspaces. All source items
/// are validated before workspace writes. Workspace contents may change on a
/// later capacity/work/codec refusal; final output is not supplied until write.
/// A real compressor is required for Adaptive/Always, even if uncompressed input
/// would otherwise fit. The core never silently substitutes an unavailable codec.
pub fn plan<'a>(
    items: &[Item<'_>],
    order: &'a mut [usize],
    plain: &'a mut [u8],
    coded: &'a mut [u8],
    deflater: &mut impl Deflater,
    limits: Limits,
    options: Options,
) -> Result<Plan<'a>, Error> {
    if items.len() > limits.max_entries {
        return Err(Error::Limit);
    }
    u32::try_from(items.len()).map_err(|_| Error::Overflow)?;
    if order.len() < items.len() {
        return Err(Error::Capacity);
    }
    let maximum = options.max_output_bytes.min(limits.max_coded_bytes);
    if maximum < HEADER_BYTES {
        return Err(Error::Capacity);
    }
    for item in items {
        item.validate()?;
    }
    let order = &mut order[..items.len()];
    for (index, slot) in order.iter_mut().enumerate() {
        *slot = index;
    }
    order.sort_unstable_by(|a, b| {
        items[*b]
            .data
            .len()
            .cmp(&items[*a].data.len())
            .then_with(|| a.cmp(b))
    });
    let candidates = if options.inclusion == Inclusion::Partial {
        items.len() + 1
    } else {
        1
    };
    for skip in 0..candidates {
        if skip >= options.max_trials {
            return Err(Error::Work);
        }
        let selected = &order[skip..];
        let length = body_length(items, selected)?;
        if length > limits.max_plain_bytes || length > plain.len() || u32::try_from(length).is_err()
        {
            if options.inclusion == Inclusion::Partial {
                continue;
            }
            return Err(if length > limits.max_plain_bytes {
                Error::Limit
            } else {
                Error::Capacity
            });
        }
        body(items, selected, &mut plain[..length]);
        let raw_fits = length <= maximum - HEADER_BYTES;
        let mut compressed_bytes = None;
        if options.compression != Compression::Never {
            let available = coded.len().min(maximum - HEADER_BYTES);
            match deflater.deflate(&plain[..length], &mut coded[..available]) {
                Ok(progress) => {
                    if progress.consumed != length || progress.produced > available {
                        coded[..available].fill(0);
                        return Err(Error::Codec(CodecError::Length));
                    }
                    if options.compression == Compression::Always || progress.produced < length {
                        compressed_bytes = Some(progress.produced);
                    }
                }
                Err(CodecError::Capacity) => {
                    coded[..available].fill(0);
                }
                Err(error) => {
                    coded[..available].fill(0);
                    return Err(Error::Codec(error));
                }
            }
        }
        if compressed_bytes.is_none() && (!raw_fits || options.compression == Compression::Always) {
            if options.inclusion == Inclusion::Partial {
                continue;
            }
            return Err(Error::Capacity);
        }
        let normalized_names = selected
            .iter()
            .map(|index| {
                let item = items[*index];
                let (plugin, mime) = item.names();
                usize::from(plugin != item.plugin) + usize::from(mime != item.mime)
            })
            .sum();
        let compressed = compressed_bytes.is_some();
        let bytes = if let Some(n) = compressed_bytes {
            &coded[..n]
        } else {
            &plain[..length]
        };
        let report = Report {
            source_entries: items.len(),
            selected_entries: selected.len(),
            omitted_entries: skip,
            normalized_names,
            trials: skip + 1,
            plain_bytes: length,
            wire_bytes: HEADER_BYTES + bytes.len(),
            compressed,
        };
        return Ok(Plan {
            body: bytes,
            selected,
            report,
        });
    }
    Err(Error::Capacity)
}

/// Full/partial serialization with the explicit Never compression policy.
pub fn plan_uncompressed<'a>(
    items: &[Item<'_>],
    order: &'a mut [usize],
    plain: &'a mut [u8],
    limits: Limits,
    mut options: Options,
) -> Result<Plan<'a>, Error> {
    options.compression = Compression::Never;
    plan(items, order, plain, &mut [], &mut NoCodec, limits, options)
}

/// Standard optional BIO representation for absent metadata: a zero u32 length.
/// This differs from a present empty v2 container and never emits a v1 blob.
pub fn write_absent(output: &mut [u8]) -> Result<usize, Error> {
    if output.len() < 4 {
        return Err(Error::Capacity);
    }
    output[..4].fill(0);
    Ok(4)
}
