use super::{Error, Format, Item, c_prefix};

/// Normalize filename separators before the first NUL, bounded by the actual
/// supplied bytes even for noncanonical binary input. Only types2/180 change.
/// Capacity refusal leaves output unchanged; the rest of output is preserved.
pub fn normalize_filename(kind: u32, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    if output.len() < input.len() {
        return Err(Error::Capacity);
    }
    let target = &mut output[..input.len()];
    target.copy_from_slice(input);
    if matches!(kind, 2 | 180) {
        let end = c_prefix(input).len();
        for byte in &mut target[..end] {
            if *byte == b'\\' {
                *byte = b'/';
            }
        }
    }
    Ok(input.len())
}

/// Container insertion outcome; duplicate enrichment does not add another entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Insert {
    /// A new item was inserted in stable descending data-size order.
    Added,
    /// Existing type/data matched; optional MIME/format enrichment is explicit.
    Duplicate {
        /// A previously absent MIME field was supplied.
        mime_enriched: bool,
        /// C_STRING was upgraded to UTF8.
        format_upgraded: bool,
    },
}

/// C-compatible value import over caller-owned slots. It does not implement C's
/// linked-list/cache/allocator API. Duplicate identity is type plus exact data,
/// before filename normalization; format/plugin/MIME are not identity fields.
pub struct Set<'a, 's> {
    slots: &'s mut [Option<Item<'a>>],
    length: usize,
}
impl<'a, 's> Set<'a, 's> {
    /// Start an empty container; explicitly clear caller entry slots.
    pub fn new(slots: &'s mut [Option<Item<'a>>]) -> Self {
        slots.fill(None);
        Self { slots, length: 0 }
    }
    /// Number of imported logical items after duplicate coalescing.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }
    /// Whether the logical container is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
    /// Complete logical records in stable descending data-size order.
    pub fn items(&self) -> impl Iterator<Item = Item<'a>> + '_ {
        self.slots[..self.length].iter().filter_map(|item| *item)
    }
    /// Import one raw record. A newly inserted filename needing separator
    /// normalization borrows the supplied buffer; ordinary/duplicate items do
    /// not touch that buffer. Validate/capacity refusal changes no entry state.
    pub fn insert(&mut self, mut item: Item<'a>, filename: &'a mut [u8]) -> Result<Insert, Error> {
        item.validate()?;
        let (plugin, mime) = item.names();
        item.plugin = plugin;
        item.mime = mime;
        for slot in &mut self.slots[..self.length] {
            if let Some(existing) = slot.as_mut()
                && existing.kind == item.kind
                && existing.data == item.data
            {
                let mime_enriched = existing.mime.is_none() && item.mime.is_some();
                let format_upgraded =
                    existing.format == Format::CString && item.format == Format::Utf8;
                if mime_enriched {
                    existing.mime = item.mime;
                }
                if format_upgraded {
                    existing.format = Format::Utf8;
                }
                return Ok(Insert::Duplicate {
                    mime_enriched,
                    format_upgraded,
                });
            }
        }
        if self.length == self.slots.len() {
            return Err(Error::Capacity);
        }
        let needs_copy = matches!(item.kind, 2 | 180) && c_prefix(item.data).contains(&b'\\');
        if needs_copy {
            normalize_filename(item.kind, item.data, filename)?;
            item.data = &filename[..item.data.len()];
        }
        let position = self.slots[..self.length]
            .iter()
            .position(|value| value.is_some_and(|old| old.data.len() < item.data.len()))
            .unwrap_or(self.length);
        self.slots.copy_within(position..self.length, position + 1);
        self.slots[position] = Some(item);
        self.length += 1;
        Ok(Insert::Added)
    }
}
