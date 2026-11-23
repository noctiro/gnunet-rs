//! Bounded TIFF geometry over the original embedded profile or file.

use super::super::{Input, camera::Rational};
use super::{Container, ProfileKind, panasonic, raw};

// A multiple of both directory row widths. Only native I/O needs read-ahead.
const DIRECTORY_WINDOW: usize = 480;

#[derive(Clone, Copy)]
pub(super) enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    pub(super) fn from_marker(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"II" => Some(Self::Little),
            b"MM" => Some(Self::Big),
            _ => None,
        }
    }

    fn u16(self, bytes: &[u8]) -> Option<u16> {
        Some(self.short(*bytes.first_chunk()?))
    }

    fn short(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }

    fn u32(self, bytes: &[u8]) -> Option<u32> {
        let bytes = *bytes.first_chunk()?;
        Some(match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        })
    }

    fn u64(self, bytes: &[u8]) -> Option<u64> {
        let bytes = *bytes.first_chunk()?;
        Some(match self {
            Self::Little => u64::from_le_bytes(bytes),
            Self::Big => u64::from_be_bytes(bytes),
        })
    }
}

#[derive(Clone, Copy)]
enum Layout {
    Classic,
    Big,
}

#[derive(Clone, Copy)]
pub(super) struct Signature {
    order: ByteOrder,
    layout: Layout,
    container: Container,
    cr2: Option<raw::Cr2Header>,
}

impl Signature {
    pub(super) fn parse(prefix: &[u8]) -> Option<Self> {
        let bytes = prefix.first_chunk::<4>()?;
        let order = ByteOrder::from_marker(&bytes[..2])?;
        let cr2 = raw::Cr2Header::parse(prefix);
        let (container, layout) = match order.u16(&bytes[2..])? {
            42 if cr2.is_some() => (Container::Cr2, Layout::Classic),
            42 => (Container::Tiff, Layout::Classic),
            43 => (Container::Tiff, Layout::Big),
            0x0055 => (panasonic::container(prefix)?, Layout::Classic),
            0x4f52 | 0x5352 => (Container::Orf, Layout::Classic),
            _ => return None,
        };
        Some(Self {
            order,
            layout,
            container,
            cr2,
        })
    }

    pub(super) const fn container(self) -> Container {
        self.container
    }

    fn valid_for(self, profile: ProfileKind) -> bool {
        match profile {
            ProfileKind::Embedded | ProfileKind::RawTiff => matches!(
                (self.container, self.layout),
                (Container::Tiff, Layout::Classic)
            ),
            ProfileKind::Standalone(expected) => self.container == expected,
        }
    }
}

impl Layout {
    const fn header_bytes(self) -> u64 {
        match self {
            Self::Classic => 8,
            Self::Big => 16,
        }
    }

    const fn count_bytes(self) -> usize {
        match self {
            Self::Classic => 2,
            Self::Big => 8,
        }
    }

    const fn offset_bytes(self) -> usize {
        match self {
            Self::Classic => 4,
            Self::Big => 8,
        }
    }

    const fn row_bytes(self) -> usize {
        4 + 2 * self.offset_bytes()
    }

    fn offset(self, order: ByteOrder, bytes: &[u8]) -> Option<u64> {
        match self {
            Self::Classic => order.u32(bytes).map(u64::from),
            Self::Big => order.u64(bytes),
        }
    }

    fn directory_count(self, order: ByteOrder, bytes: &[u8]) -> Option<u64> {
        match self {
            Self::Classic => order.u16(bytes).map(u64::from),
            Self::Big => order.u64(bytes),
        }
    }
}

fn valid_ifd(offset: u64, data_start: u64) -> bool {
    // LibTIFF writes both classic and BigTIFF directories at even offsets.
    offset >= data_start && offset.is_multiple_of(2)
}

/// TIFF geometry and one original bounded read owner.
pub(super) struct Tiff<'a, Read> {
    input: Input<'a, Read>,
    order: ByteOrder,
    layout: Layout,
    first: u64,
    cr2: Option<raw::Cr2Header>,
    data_start: u64,
    window: [u8; DIRECTORY_WINDOW],
    window_at: u64,
    window_len: usize,
}

impl<'a, E, Read: FnMut(u64, &mut [u8]) -> Result<(), E>> Tiff<'a, Read> {
    pub(super) fn open(
        mut input: Input<'a, Read>,
        profile: ProfileKind,
    ) -> Result<Option<Self>, E> {
        let header_bytes = match profile {
            ProfileKind::Standalone(Container::Cr2) => raw::CR2_HEADER_BYTES,
            ProfileKind::Standalone(Container::Rw2) => panasonic::RW2_HEADER_BYTES,
            _ => 8,
        };
        let Some(header) = input.range(0, header_bytes)? else {
            return Ok(None);
        };
        let header = if matches!(profile, ProfileKind::Standalone(Container::PanasonicRaw))
            && let Some(required) = panasonic::identification_bytes(header)
        {
            let Some(header) = input.range(0, required)? else {
                return Ok(None);
            };
            header
        } else {
            header
        };
        let Some(Signature {
            order,
            layout,
            cr2,
            container,
        }) = Signature::parse(header).filter(|signature| signature.valid_for(profile))
        else {
            return Ok(None);
        };
        let first = match layout {
            Layout::Classic => order.u32(&header[4..]).map(u64::from),
            Layout::Big if order.u16(&header[4..]) == Some(8) && header[6..8] == [0, 0] => {
                input.range(8, 8)?.and_then(|bytes| order.u64(bytes))
            }
            Layout::Big => return Ok(None),
        };
        let data_start = match container {
            Container::Cr2 => raw::CR2_HEADER_BYTES as u64,
            Container::Rw2 => panasonic::RW2_HEADER_BYTES as u64,
            _ => layout.header_bytes(),
        };
        Ok(first.and_then(|first| Self::with_layout(input, order, layout, first, cr2, data_start)))
    }

    pub(super) fn open_classic_ifd(
        input: Input<'a, Read>,
        order: ByteOrder,
        first: u64,
        data_start: u64,
    ) -> Option<Self> {
        Self::with_layout(input, order, Layout::Classic, first, None, data_start)
    }

    fn with_layout(
        input: Input<'a, Read>,
        order: ByteOrder,
        layout: Layout,
        first: u64,
        cr2: Option<raw::Cr2Header>,
        data_start: u64,
    ) -> Option<Self> {
        if !valid_ifd(first, data_start) {
            return None;
        }
        Some(Self {
            input,
            order,
            layout,
            first,
            cr2,
            data_start,
            window: [0; DIRECTORY_WINDOW],
            window_at: 0,
            window_len: 0,
        })
    }

    pub(super) const fn first_offset(&self) -> u64 {
        self.first
    }

    pub(super) const fn cr2_header(&self) -> Option<raw::Cr2Header> {
        self.cr2
    }

    pub(super) fn directory(&mut self, offset: u64) -> Result<Option<Directory>, E> {
        if !valid_ifd(offset, self.data_start) {
            return Ok(None);
        }
        self.image_directory(offset)
    }

    pub(super) fn byte_aligned_child(&mut self, offset: u64) -> Result<Option<Directory>, E> {
        if !matches!(self.layout, Layout::Classic) || offset < self.data_start {
            return Ok(None);
        }
        self.image_directory(offset)
    }

    pub(super) fn contains_data(&self, offset: u64, length: u64) -> bool {
        length != 0
            && offset >= self.data_start
            && offset
                .checked_add(length)
                .is_some_and(|end| end <= self.input.extent)
    }

    fn image_directory(&mut self, offset: u64) -> Result<Option<Directory>, E> {
        self.open_directory(
            offset,
            self.input.extent,
            self.order,
            self.layout,
            self.layout.offset_bytes(),
        )
    }

    pub(super) fn maker_directory(&mut self, offset: u64) -> Result<Option<Directory>, E> {
        if !valid_ifd(offset, self.data_start) {
            return Ok(None);
        }
        self.open_directory(offset, self.input.extent, self.order, self.layout, 0)
    }

    /// The MakerNote limits directory rows. Its classic value offsets use the parent TIFF.
    pub(super) fn parent_relative_maker(
        &mut self,
        note: Row,
        displacement: u64,
        order: ByteOrder,
        tail: DirectoryTail,
    ) -> Result<Option<Directory>, E> {
        let Location::External(offset) = note.location else {
            return Ok(None);
        };
        if note.kind != Kind::Undefined {
            return Ok(None);
        }
        let Some(first) = offset.checked_add(displacement) else {
            return Ok(None);
        };
        let link_bytes = match tail {
            DirectoryTail::RowsOnly => 0,
            DirectoryTail::NextOffset => Layout::Classic.offset_bytes(),
        };
        self.open_directory(
            first,
            offset + note.len as u64,
            order,
            Layout::Classic,
            link_bytes,
        )
    }

    fn open_directory(
        &mut self,
        offset: u64,
        bound: u64,
        order: ByteOrder,
        layout: Layout,
        link_bytes: usize,
    ) -> Result<Option<Directory>, E> {
        let count_bytes = layout.count_bytes();
        let Some(rows) = offset
            .checked_add(count_bytes as u64)
            .filter(|end| *end <= bound)
        else {
            return Ok(None);
        };
        let Some(count) = self
            .input
            .range(offset, count_bytes)?
            .and_then(|bytes| layout.directory_count(order, bytes))
            .filter(|&count| count != 0)
        else {
            return Ok(None);
        };
        let Some(rows_end) = count
            .checked_mul(layout.row_bytes() as u64)
            .and_then(|length| rows.checked_add(length))
        else {
            return Ok(None);
        };
        let Some(encoded_end) = rows_end
            .checked_add(link_bytes as u64)
            .filter(|&end| end <= bound)
        else {
            return Ok(None);
        };
        Ok(Some(Directory {
            at: rows,
            end: rows_end,
            encoded_end,
            layout,
            order,
        }))
    }

    pub(super) fn next(&mut self, directory: &mut Directory) -> Result<Option<Row>, E> {
        let width = directory.layout.row_bytes();
        while let Some(next) = directory
            .at
            .checked_add(width as u64)
            .filter(|&next| next <= directory.end)
        {
            let offset = directory.at;
            directory.at = next;
            let (layout, order, extent, data_start) = (
                directory.layout,
                directory.order,
                self.input.extent,
                self.data_start,
            );
            let Some(bytes) = self.row_bytes(offset, directory.end, width)? else {
                directory.at = directory.end;
                return Ok(None);
            };
            if let Some(row) = Row::parse(layout, order, extent, data_start, bytes) {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }

    fn row_bytes(&mut self, offset: u64, end: u64, width: usize) -> Result<Option<&[u8]>, E> {
        if offset + width as u64 <= self.input.prefix.len() as u64 {
            return self.input.range(offset, width);
        }
        let window_end = self.window_at + self.window_len as u64;
        if offset >= self.window_at && offset + width as u64 <= window_end {
            let start = (offset - self.window_at) as usize;
            return Ok(Some(&self.window[start..start + width]));
        }
        let count = ((end - offset) / width as u64)
            .min((DIRECTORY_WINDOW / width) as u64)
            .min((self.input.unread_bytes() / width) as u64);
        let length = count as usize * width;
        if length == 0 {
            return Ok(None);
        }
        let Some(bytes) = self.input.range(offset, length)? else {
            return Ok(None);
        };
        self.window[..length].copy_from_slice(bytes);
        self.window_at = offset;
        self.window_len = length;
        Ok(Some(&self.window[..width]))
    }

    pub(super) fn read_field<'field>(
        &'field mut self,
        row: &'field Row,
    ) -> Result<Option<Entry<'field>>, E> {
        let Some(bytes) = self.read_field_range(row, 0, row.len)? else {
            return Ok(None);
        };
        Ok(Some(row.entry(bytes)))
    }

    pub(super) const fn byte_order(&self) -> ByteOrder {
        self.order
    }

    /// Accesses the file header under the original positioned-read budget.
    pub(super) fn prefix(&mut self, maximum: usize) -> Result<Option<&[u8]>, E> {
        let len = self.input.extent.min(maximum as u64) as usize;
        self.input.range(0, len)
    }

    pub(super) fn read_short_prefix(&mut self, row: &Row, values: &mut [u16]) -> Result<bool, E> {
        if row.kind != Kind::Short {
            return Ok(false);
        }
        let Some(length) = values.len().checked_mul(Kind::Short.width()) else {
            return Ok(false);
        };
        let Some(bytes) = self.read_field_range(row, 0, length)? else {
            return Ok(false);
        };
        for (value, bytes) in values.iter_mut().zip(bytes.as_chunks::<2>().0) {
            *value = row.order.short(*bytes);
        }
        Ok(true)
    }

    /// Read only a checked subrange of a field under the original probe budget.
    pub(super) fn read_field_range<'field>(
        &'field mut self,
        row: &'field Row,
        start: usize,
        len: usize,
    ) -> Result<Option<&'field [u8]>, E> {
        let Some(end) = start.checked_add(len).filter(|&end| end <= row.len) else {
            return Ok(None);
        };
        match &row.location {
            Location::Inline(bytes) => Ok(bytes.get(start..end)),
            Location::External(offset) => {
                let Some(start) = offset.checked_add(start as u64) else {
                    return Ok(None);
                };
                self.input.range(start, len)
            }
        }
    }

    /// Gives an embedded reader only the validated extent of an external field.
    pub(super) fn section_for_field(&mut self, row: Row) -> Option<Input<'_, &mut Read>> {
        self.section_for_field_from(row, 0)
    }

    pub(super) fn section_for_field_from(
        &mut self,
        row: Row,
        start: u64,
    ) -> Option<Input<'_, &mut Read>> {
        let Location::External(offset) = row.location else {
            return None;
        };
        self.section(
            offset.checked_add(start)?,
            (row.len as u64).checked_sub(start)?,
        )
    }

    /// Opens a region referenced by TIFF-relative offsets after the header.
    pub(super) fn section(&mut self, start: u64, length: u64) -> Option<Input<'_, &mut Read>> {
        if start < self.data_start {
            return None;
        }
        self.input.section(start, length)
    }
}

#[derive(Clone, Copy)]
pub(super) enum DirectoryTail {
    RowsOnly,
    NextOffset,
}

/// One finite directory cursor in the layout declared by its owner.
pub(super) struct Directory {
    at: u64,
    end: u64,
    encoded_end: u64,
    layout: Layout,
    order: ByteOrder,
}

impl Directory {
    pub(super) const fn encoded_end(&self) -> u64 {
        self.encoded_end
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Kind {
    Byte,
    Ascii,
    Short,
    Long,
    Rational,
    SByte,
    Undefined,
    SShort,
    SLong,
    SRational,
    Float,
    Double,
    Ifd,
    Long8,
    SLong8,
    Ifd8,
    Utf8,
}

impl Kind {
    fn from_field(layout: Layout, field: u16) -> Option<Self> {
        Some(match field {
            1 => Self::Byte,
            2 => Self::Ascii,
            3 => Self::Short,
            4 => Self::Long,
            5 => Self::Rational,
            6 => Self::SByte,
            7 => Self::Undefined,
            8 => Self::SShort,
            9 => Self::SLong,
            10 => Self::SRational,
            11 => Self::Float,
            12 => Self::Double,
            13 => Self::Ifd,
            16 if matches!(layout, Layout::Big) => Self::Long8,
            17 if matches!(layout, Layout::Big) => Self::SLong8,
            18 if matches!(layout, Layout::Big) => Self::Ifd8,
            129 => Self::Utf8,
            _ => return None,
        })
    }

    const fn width(self) -> usize {
        match self {
            Self::Byte | Self::Ascii | Self::SByte | Self::Undefined | Self::Utf8 => 1,
            Self::Short | Self::SShort => 2,
            Self::Long | Self::SLong | Self::Float | Self::Ifd => 4,
            Self::Rational
            | Self::SRational
            | Self::Double
            | Self::Long8
            | Self::SLong8
            | Self::Ifd8 => 8,
        }
    }
}

#[derive(Clone, Copy)]
enum Location {
    Inline([u8; 8]),
    External(u64),
}

/// Checked directory record. External bytes remain unobserved until requested.
#[derive(Clone, Copy)]
pub(super) struct Row {
    tag: u16,
    kind: Kind,
    count: u64,
    len: usize,
    location: Location,
    order: ByteOrder,
}

impl Row {
    fn parse(
        layout: Layout,
        order: ByteOrder,
        extent: u64,
        data_start: u64,
        bytes: &[u8],
    ) -> Option<Self> {
        let tag = order.u16(bytes)?;
        let kind = Kind::from_field(layout, order.u16(&bytes[2..])?)?;
        let count = layout.offset(order, &bytes[4..])?;
        if count == 0 {
            return None;
        }
        let len = usize::try_from(count).ok()?.checked_mul(kind.width())?;
        let value = &bytes[4 + layout.offset_bytes()..];
        let location = if len <= value.len() {
            let mut bytes = [0; 8];
            bytes[..len].copy_from_slice(&value[..len]);
            Location::Inline(bytes)
        } else {
            let offset = layout.offset(order, value)?;
            let end = offset.checked_add(len as u64)?;
            if offset < data_start || end > extent {
                return None;
            }
            // Positioned byte reads also handle the word-aligned values that
            // LibTIFF emits in BigTIFF, including those outside an 8-byte boundary.
            Location::External(offset)
        };
        Some(Self {
            tag,
            kind,
            count,
            len,
            location,
            order,
        })
    }

    pub(super) const fn tag(self) -> u16 {
        self.tag
    }

    pub(super) const fn kind(self) -> Kind {
        self.kind
    }

    pub(super) const fn count(self) -> u64 {
        self.count
    }

    pub(super) const fn len(self) -> usize {
        self.len
    }

    pub(super) const fn external_offset(self) -> Option<u64> {
        match self.location {
            Location::Inline(_) => None,
            Location::External(offset) => Some(offset),
        }
    }

    pub(super) const fn external_at_or_after(self, start: u64) -> bool {
        matches!(self.location, Location::External(offset) if offset >= start)
    }

    fn entry<'field>(&self, bytes: &'field [u8]) -> Entry<'field> {
        Entry {
            order: self.order,
            kind: self.kind,
            count: self.count,
            bytes,
        }
    }

    pub(super) fn embedded_entry<'field>(
        &'field self,
        profile: &'field [u8],
    ) -> Option<Entry<'field>> {
        let bytes = match &self.location {
            Location::Inline(bytes) => bytes.get(..self.len)?,
            Location::External(offset) => {
                let start = usize::try_from(*offset).ok()?;
                profile.get(start..start.checked_add(self.len)?)?
            }
        };
        Some(self.entry(bytes))
    }
}

#[derive(Clone, Copy)]
pub(super) struct Entry<'profile> {
    order: ByteOrder,
    kind: Kind,
    count: u64,
    bytes: &'profile [u8],
}

impl<'profile> Entry<'profile> {
    pub(super) const fn kind(self) -> Kind {
        self.kind
    }

    pub(super) const fn count(self) -> u64 {
        self.count
    }

    pub(super) const fn bytes(self) -> &'profile [u8] {
        self.bytes
    }

    pub(super) const fn is_little_endian(self) -> bool {
        matches!(self.order, ByteOrder::Little)
    }

    /// Text without the final terminator. Some legacy values contain a second
    /// NUL-separated string, which the owning tag interprets.
    pub(super) fn string(self) -> Option<&'profile str> {
        let text = self.bytes.strip_suffix(&[0])?;
        match self.kind {
            Kind::Ascii if text.is_ascii() => std::str::from_utf8(text).ok(),
            Kind::Utf8 if !text.starts_with(b"\xef\xbb\xbf") => std::str::from_utf8(text).ok(),
            _ => None,
        }
    }

    pub(super) fn unsigned(self, index: u64) -> Option<u64> {
        let bytes = self.value_at(index)?;
        match self.kind {
            Kind::Byte => bytes.first().copied().map(u64::from),
            Kind::Short => self.order.u16(bytes).map(u64::from),
            Kind::Long | Kind::Ifd => self.order.u32(bytes).map(u64::from),
            Kind::Long8 | Kind::Ifd8 => self.order.u64(bytes),
            _ => None,
        }
    }

    pub(super) fn rational(self, index: u64) -> Option<Rational> {
        if !matches!(self.kind, Kind::Rational | Kind::SRational) {
            return None;
        }
        let bytes = self.value_at(index)?;
        let numerator = self.order.u32(bytes)?;
        let denominator = self.order.u32(bytes.get(4..)?)?;
        let (numerator, denominator) = match self.kind {
            Kind::SRational => (i64::from(numerator as i32), i64::from(denominator as i32)),
            _ => (i64::from(numerator), i64::from(denominator)),
        };
        Rational::new(numerator, denominator)
    }

    fn value_at(self, index: u64) -> Option<&'profile [u8]> {
        let width = self.kind.width();
        let start = usize::try_from(index).ok()?.checked_mul(width)?;
        self.bytes.get(start..start.checked_add(width)?)
    }
}
