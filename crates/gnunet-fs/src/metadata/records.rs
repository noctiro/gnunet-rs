use super::{ENTRY_BYTES, EntryIssue, Error, word};

/// Official metadata value formats. Type identifiers remain open separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Format {
    /// Bytes labelled UTF8, including a final NUL; conversion to str is fallible.
    Utf8 = 1,
    /// Arbitrary bytes, including an empty value or embedded NULs.
    Binary = 2,
    /// A final-NUL string in an unspecified encoding.
    CString = 3,
}
impl TryFrom<u32> for Format {
    type Error = EntryIssue;
    fn try_from(value: u32) -> Result<Self, EntryIssue> {
        match value {
            1 => Ok(Self::Utf8),
            2 => Ok(Self::Binary),
            3 => Ok(Self::CString),
            _ => Err(EntryIssue::Format),
        }
    }
}

/// Exact borrowed record bytes. Name/data spans retain their final terminators.
/// A UTF8 label alone does not create an unchecked Rust string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Item<'a> {
    /// Open libextractor/GNUnet metadata type number.
    pub kind: u32,
    /// One of the three recognized wire formats.
    pub format: Format,
    /// Full data bytes; binary may be empty, text must end with NUL.
    pub data: &'a [u8],
    /// Absent or present terminated plugin name; empty present is one NUL.
    pub plugin: Option<&'a [u8]>,
    /// Absent or present terminated MIME name.
    pub mime: Option<&'a [u8]>,
}
impl<'a> Item<'a> {
    /// Validate field framing without imposing Unicode validity or type closure.
    pub fn validate(self) -> Result<(), Error> {
        if self.format != Format::Binary && self.data.last() != Some(&0) {
            return Err(Error::Invalid);
        }
        for name in [self.plugin, self.mime].into_iter().flatten() {
            if name.last() != Some(&0) {
                return Err(Error::Invalid);
            }
        }
        for length in [
            self.data.len(),
            self.plugin.map_or(0, <[u8]>::len),
            self.mime.map_or(0, <[u8]>::len),
        ] {
            u32::try_from(length).map_err(|_| Error::Overflow)?;
        }
        Ok(())
    }
    /// Visible bounded C-string data prefix; binary has no implicit text view.
    #[must_use]
    pub fn text(self) -> Option<&'a [u8]> {
        (self.format != Format::Binary).then(|| c_prefix(self.data))
    }
    /// Validate the visible text prefix as UTF8; no replacement/lossy conversion.
    pub fn utf8(self) -> Result<Option<&'a str>, core::str::Utf8Error> {
        self.text().map(core::str::from_utf8).transpose()
    }
    pub(super) fn names(self) -> (Option<&'a [u8]>, Option<&'a [u8]>) {
        (self.plugin.map(name), self.mime.map(name))
    }
    pub(super) fn wire_bytes(self) -> Result<usize, Error> {
        let (plugin, mime) = self.names();
        ENTRY_BYTES
            .checked_add(self.data.len())
            .and_then(|n| n.checked_add(plugin.map_or(0, <[u8]>::len)))
            .and_then(|n| n.checked_add(mime.map_or(0, <[u8]>::len)))
            .ok_or(Error::Overflow)
    }
}
/// Bytes before the first NUL, bounded by the supplied slice if none exists.
#[must_use]
pub fn c_prefix(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())]
}
fn name(bytes: &[u8]) -> &[u8] {
    &bytes[..c_prefix(bytes).len() + 1]
}

pub(super) fn read<'a>(
    body: &'a [u8],
    total: usize,
    index: usize,
    left: &mut usize,
) -> Result<Item<'a>, EntryIssue> {
    let table = total.checked_mul(ENTRY_BYTES).ok_or(EntryIssue::Length)?;
    let entry = body
        .get(index * ENTRY_BYTES..(index + 1) * ENTRY_BYTES)
        .ok_or(EntryIssue::Length)?;
    let format = Format::try_from(word(entry, 4))?;
    let payload = body.get(table..).ok_or(EntryIssue::Length)?;
    let mut cursor = *left;
    let mut take = |length: usize| {
        let start = cursor.checked_sub(length).ok_or(EntryIssue::Length)?;
        let bytes = payload.get(start..cursor).ok_or(EntryIssue::Length)?;
        cursor = start;
        Ok(bytes)
    };
    let data = take(word(entry, 8) as usize)?;
    if format != Format::Binary && data.last() != Some(&0) {
        return Err(EntryIssue::Terminator);
    }
    let plugin = take(word(entry, 12) as usize)?;
    if !plugin.is_empty() && plugin.last() != Some(&0) {
        return Err(EntryIssue::Terminator);
    }
    let mime = take(word(entry, 16) as usize)?;
    if !mime.is_empty() && mime.last() != Some(&0) {
        return Err(EntryIssue::Terminator);
    }
    *left = cursor;
    Ok(Item {
        kind: word(entry, 0),
        format,
        data,
        plugin: (!plugin.is_empty()).then_some(plugin),
        mime: (!mime.is_empty()).then_some(mime),
    })
}

/// Iterator over an already validated complete container or accepted prefix.
#[derive(Clone)]
pub struct Items<'a> {
    pub(super) body: &'a [u8],
    pub(super) total: usize,
    pub(super) accepted: usize,
    pub(super) index: usize,
    pub(super) left: usize,
}
impl<'a> Iterator for Items<'a> {
    type Item = Item<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.accepted {
            return None;
        }
        // Construction validated this exact immutable body and accepted prefix.
        let item = read(self.body, self.total, self.index, &mut self.left).ok()?;
        self.index += 1;
        Some(item)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.accepted - self.index;
        (n, Some(n))
    }
}
impl ExactSizeIterator for Items<'_> {}
