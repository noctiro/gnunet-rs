use super::Error;
use crate::{
    Content, Uri,
    content::{BlockKey, FileEncoder},
    metadata,
};

/// One unverified raw FULL_DATA item, including empty and non-binary values.
#[derive(Clone, Copy, Debug)]
pub struct InlineHint<'a> {
    /// Zero-based metadata record position in the supplied view.
    pub index: usize,
    /// Complete original item; no content or path trust is implied.
    pub item: metadata::Item<'a>,
}
/// Every type174 in the supplied order; a semantic Set gives C logical order.
pub fn hints<'a>(
    items: impl IntoIterator<Item = metadata::Item<'a>>,
) -> impl Iterator<Item = InlineHint<'a>> {
    items
        .into_iter()
        .enumerate()
        .filter_map(|(index, item)| (item.kind == 174).then_some(InlineHint { index, item }))
}
/// Reusable caller scratch for actual complete CHK tree encoding.
pub struct InlineBuffers<'a> {
    /// Layout-required key slots; zero for a leaf-only file.
    pub keys: &'a mut [BlockKey],
    /// Index plaintext scratch, at most32768bytes per index.
    pub index: &'a mut [u8],
    /// Ciphertext and tag output, at most32784bytes per block.
    pub encoded: &'a mut [u8],
}
/// A bounded hint whose actual full encoding matched contextual Content.
/// Private fields prevent a raw metadata item or public DataSlice minting proof.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedInline<'a> {
    bytes: &'a [u8],
    content: Content,
}
impl<'a> VerifiedInline<'a> {
    /// Verified exact plaintext, with no filesystem/durability claim.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Matched size, plaintext key and encrypted query.
    #[must_use]
    pub const fn content(self) -> Content {
        self.content
    }
    /// Canonical binary FULL_DATA item for an actual metadata plan. The caller
    /// still chooses metadata selection/compression and final directory layout.
    #[must_use]
    pub const fn item(self) -> metadata::Item<'a> {
        metadata::Item {
            kind: 174,
            format: metadata::Format::Binary,
            data: self.bytes,
            plugin: Some(b"<gnunet>\0"),
            mime: None,
        }
    }
}
/// C builder's optional positive-size <=65536/no-extra-entry-block producer
/// heuristic, using actual baseline/augmented metadata wire lengths. This is
/// not a parser limit, file authentication or publication owner policy.
pub fn automatic_inline_fits(
    uri: Uri<'_>,
    hint: VerifiedInline<'_>,
    baseline_metadata_bytes: usize,
    augmented_metadata_bytes: usize,
) -> Result<bool, Error> {
    let content = match uri {
        Uri::Content(value) => value,
        Uri::Location(value) => value.content(),
        Uri::Namespace(_) => return Err(Error::Unresolved),
        Uri::Keywords(_) => return Err(Error::Keyword),
    };
    if hint.content != content {
        return Err(Error::Authentication);
    }
    if hint.bytes.is_empty() || hint.bytes.len() > 65536 {
        return Ok(false);
    }
    let prefix = uri
        .encoded_len()
        .map_err(Error::Uri)?
        .checked_add(5)
        .ok_or(Error::Overflow)?;
    let blocks = |length| {
        prefix
            .checked_add(length)
            .and_then(|n| n.checked_sub(1))
            .map(|n| n / crate::content::BLOCK_BYTES)
            .ok_or(Error::Overflow)
    };
    Ok(blocks(baseline_metadata_bytes)? == blocks(augmented_metadata_bytes)?)
}
/// Encode every actual data/index block and compare the complete expected root.
/// max_encoded_work bounds ciphertext bytes over all nodes, not just file size.
/// Scratch/frontier may change on refusal; no VerifiedInline is returned.
pub fn verify_inline<'a>(
    hint: InlineHint<'a>,
    uri: Uri<'_>,
    buffers: InlineBuffers<'_>,
    max_encoded_work: u128,
) -> Result<VerifiedInline<'a>, Error> {
    let expected = match uri {
        Uri::Content(value) => value,
        Uri::Location(value) => value.content(),
        Uri::Namespace(_) => return Err(Error::Unresolved),
        Uri::Keywords(_) => return Err(Error::Keyword),
    };
    if hint.item.kind != 174 || hint.item.data.len() as u128 != u128::from(expected.size) {
        return Err(Error::Authentication);
    }
    let layout = crate::content::Layout::new(expected.size);
    if layout.encoded_tree_bytes() > max_encoded_work {
        return Err(Error::Limit);
    }
    let mut encoder = FileEncoder::new(expected.size, buffers.keys).map_err(Error::Content)?;
    while let Some(node) = encoder.next() {
        if node.level() == 0 {
            let range = node.range();
            let start = usize::try_from(range.start).map_err(|_| Error::Overflow)?;
            let end = usize::try_from(range.end).map_err(|_| Error::Overflow)?;
            encoder
                .push_data(&hint.item.data[start..end], buffers.encoded)
                .map_err(Error::Content)?;
        } else {
            encoder
                .emit_index(buffers.index, buffers.encoded)
                .map_err(Error::Content)?;
        }
    }
    if encoder.content() != Some(expected) {
        return Err(Error::Authentication);
    }
    Ok(VerifiedInline {
        bytes: hint.item.data,
        content: expected,
    })
}
