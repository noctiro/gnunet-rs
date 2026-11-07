use crate::{Arena, Error, Limits, MAX_LABEL_LENGTH, MAX_NAME_LENGTH, MAX_WIRE_NAME_LENGTH};
/// Complete explicit backend; no partial backend is silently selected. Native
/// libidn2 parity needs validity/context/Bidi/version handling, not only Punycode.
/// Implementations may change their scratch output on error and return actual
/// byte length; the library stages separately before committing final output.
/// Explicit complete native IDNA backend contract; no default backend is supplied.
pub trait Idna {
    /// Convert the complete native UTF8 input to ASCII for the selected full profile.
    fn to_ascii(&self, input: &[u8], output: &mut [u8]) -> Result<usize, Error>;
    /// Convert one native wire label; Malformed/InvalidInput permit raw fallback.
    /// Capacity/Unavailable and other capability/resource failures must propagate.
    fn to_unicode_label(&self, label: &[u8], output: &mut [u8]) -> Result<usize, Error>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Validated uncompressed DNS name retaining opaque label octets.
///
/// Equality includes native parse provenance, including compressed-root text
/// and the original packet's native expansion bound. It is not DNS semantic
/// equality; compare `wire()` for exact expanded wire equality. Encoding and
/// constructing a fresh uncompressed name intentionally loses that provenance.
pub struct Name<'a> {
    wire: &'a [u8],
    native_trailing_dot: bool,
    compressed_text_max_len: Option<usize>,
}
impl<'a> Name<'a> {
    /// DNS root name.
    pub const ROOT: Self = Self {
        wire: &[0],
        native_trailing_dot: false,
        compressed_text_max_len: None,
    };
    /// Validate one complete uncompressed DNS wire name without transforming labels.
    pub fn from_wire(wire: &'a [u8]) -> Result<Self, Error> {
        if wire.len() > MAX_WIRE_NAME_LENGTH {
            return Err(Error::TooLarge);
        }
        let mut pos = 0;
        loop {
            let length = usize::from(*wire.get(pos).ok_or(Error::Truncated)?);
            pos += 1;
            if length == 0 {
                return if pos == wire.len() {
                    Ok(Self {
                        wire,
                        native_trailing_dot: false,
                        compressed_text_max_len: None,
                    })
                } else {
                    Err(Error::Malformed)
                };
            }
            if length > MAX_LABEL_LENGTH {
                return Err(Error::Malformed);
            }
            pos = pos.checked_add(length).ok_or(Error::Overflow)?;
            if pos > wire.len() {
                return Err(Error::Truncated);
            }
        }
    }
    pub(crate) const fn with_native_parse_hints(
        mut self,
        trailing_dot: bool,
        maximum_text: Option<usize>,
    ) -> Self {
        self.native_trailing_dot = trailing_dot;
        self.compressed_text_max_len = maximum_text;
        self
    }
    /// Complete uncompressed name bytes, including the root terminator.
    pub const fn wire(self) -> &'a [u8] {
        self.wire
    }
    /// Encoded uncompressed name byte length.
    pub const fn wire_len(self) -> usize {
        self.wire.len()
    }
    /// Preflight and encode the complete value; errors preserve the complete output slice.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < self.wire.len() {
            return Err(Error::Capacity);
        }
        output[..self.wire.len()].copy_from_slice(self.wire);
        Ok(self.wire.len())
    }
    /// Append atomically; errors preserve the complete destination and cursor.
    pub fn encode_at(self, output: &mut [u8], offset: &mut usize) -> Result<usize, Error> {
        let end = offset.checked_add(self.wire.len()).ok_or(Error::Overflow)?;
        if end > output.len() {
            return Err(Error::Capacity);
        }
        self.encode(&mut output[*offset..end])?;
        *offset = end;
        Ok(self.wire.len())
    }
    /// Iterate original label octets without IDNA or UTF8 assumptions.
    pub fn labels(self) -> Labels<'a> {
        Labels {
            remaining: self.wire,
        }
    }
    /// Deep-copy every borrowed name/payload into independent caller arena storage.
    pub fn duplicate_into<'b>(self, arena: &mut Arena<'b>) -> Result<Name<'b>, Error> {
        Ok(Name {
            wire: arena.copy(self.wire)?,
            native_trailing_dot: self.native_trailing_dot,
            compressed_text_max_len: self.compressed_text_max_len,
        })
    }
    /// Standard dotted bytes: root/trailing root dot allowed; interior empty labels
    /// fail. No text/IDNA transformation is implied; original case/bytes remain.
    /// Construct a standard dotted-byte name, preserving case and rejecting interior empty labels.
    pub fn from_dotted(input: &[u8], arena: &mut Arena<'a>) -> Result<Self, Error> {
        Self::from_dotted_impl(input, arena, false)
    }
    pub(crate) fn from_dotted_impl(
        input: &[u8],
        arena: &mut Arena<'a>,
        native: bool,
    ) -> Result<Self, Error> {
        let mut wire = [0; MAX_WIRE_NAME_LENGTH];
        let mut pos: usize = 0;
        if !input.is_empty() && input != b"." {
            let input = input.strip_suffix(b".").unwrap_or(input);
            for label in input.split(|b| *b == b'.') {
                if label.is_empty() {
                    if native {
                        break;
                    }
                    return Err(Error::Malformed);
                }
                if label.len() > MAX_LABEL_LENGTH {
                    return Err(Error::TooLarge);
                }
                let end = pos.checked_add(label.len() + 1).ok_or(Error::Overflow)?;
                if end >= wire.len() {
                    return Err(Error::TooLarge);
                }
                wire[pos] = label.len() as u8;
                wire[pos + 1..end].copy_from_slice(label);
                pos = end;
            }
        }
        wire[pos] = 0;
        Ok(Self {
            wire: arena.copy(&wire[..pos + 1])?,
            native_trailing_dot: false,
            compressed_text_max_len: None,
        })
    }
    /// Native low-level conversion is distinct from check_name. It retains C's
    /// first-empty-label stopping behavior; service strict validation is separate.
    /// Convert through the explicit native IDNA backend, then build the native low-level name representation.
    pub fn from_native_text(
        input: &[u8],
        idna: &impl Idna,
        work: &mut [u8],
        arena: &mut Arena<'a>,
        limits: Limits,
    ) -> Result<Self, Error> {
        check_input(input, limits)?;
        let n = idna.to_ascii(input, work)?;
        let ascii = work.get(..n).ok_or(Error::Malformed)?;
        if !ascii.is_ascii() || ascii.contains(&0) {
            return Err(Error::Malformed);
        }
        Self::from_dotted_impl(ascii, arena, true)
    }
    /// Native per-label Unicode with raw C-string fallback. The separate work
    /// slice may change on failure; output is committed only on complete success.
    /// Stage native Unicode/raw-fallback text in work storage before atomically committing output.
    pub fn write_native_text(
        self,
        idna: &impl Idna,
        work: &mut [u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let mut pos = 0;
        for (index, label) in self.labels().enumerate() {
            if index > 0 {
                *work.get_mut(pos).ok_or(Error::Capacity)? = b'.';
                pos += 1;
            }
            let input = label.split(|b| *b == 0).next().unwrap_or(&[]);
            let tail = work.get_mut(pos..).ok_or(Error::Capacity)?;
            let count = match idna.to_unicode_label(input, tail) {
                Ok(n) if n <= tail.len() => n,
                Ok(_) => return Err(Error::Malformed),
                Err(Error::Malformed | Error::InvalidInput) => {
                    if input.len() > tail.len() {
                        return Err(Error::Capacity);
                    }
                    tail[..input.len()].copy_from_slice(input);
                    input.len()
                }
                Err(error) => return Err(error),
            };
            if tail[..count].contains(&0) {
                return Err(Error::Malformed);
            }
            pos += count;
        }
        if self.native_trailing_dot {
            *work.get_mut(pos).ok_or(Error::Capacity)? = b'.';
            pos += 1;
        }
        if self
            .compressed_text_max_len
            .is_some_and(|limit| pos > limit)
        {
            return Err(Error::Malformed);
        }
        if output.len() < pos {
            return Err(Error::Capacity);
        }
        output[..pos].copy_from_slice(&work[..pos]);
        Ok(pos)
    }
    /// Atomically join original label octets with dots without IDNA conversion.
    pub fn write_dotted(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self
            .labels()
            .try_fold(0_usize, |sum, l| {
                sum.checked_add(l.len() + 1).ok_or(Error::Overflow)
            })?
            .saturating_sub(1);
        if output.len() < n {
            return Err(Error::Capacity);
        }
        let mut pos = 0;
        for (i, label) in self.labels().enumerate() {
            if i > 0 {
                output[pos] = b'.';
                pos += 1;
            }
            output[pos..pos + label.len()].copy_from_slice(label);
            pos += label.len();
        }
        Ok(pos)
    }
}
/// Borrowed iterator over validated label octets.
pub struct Labels<'a> {
    remaining: &'a [u8],
}
impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        let length = usize::from(*self.remaining.first()?);
        if length == 0 {
            self.remaining = &[];
            return None;
        }
        let label = &self.remaining[1..1 + length];
        self.remaining = &self.remaining[1 + length..];
        Some(label)
    }
}
impl core::iter::FusedIterator for Labels<'_> {}
fn check_input(input: &[u8], limits: Limits) -> Result<(), Error> {
    if input.len() > limits.maximum_text_input_bytes {
        return Err(Error::Capacity);
    }
    if input.contains(&0) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
/// Apply the native raw-dot/@ prechecks, then complete IDNA and63-byte checking.
pub fn check_label(
    input: &[u8],
    idna: &impl Idna,
    work: &mut [u8],
    limits: Limits,
) -> Result<(), Error> {
    check_input(input, limits)?;
    if input.contains(&b'.') || input == b"@" {
        return Err(Error::Malformed);
    }
    let n = idna.to_ascii(input, work)?;
    let ascii = work.get(..n).ok_or(Error::Malformed)?;
    if !ascii.is_ascii() || ascii.contains(&0) {
        return Err(Error::Malformed);
    }
    if n > MAX_LABEL_LENGTH {
        return Err(Error::TooLarge);
    }
    Ok(())
}
/// Apply native per-token checks and the complete253-byte converted-name bound.
pub fn check_name(
    input: &[u8],
    idna: &impl Idna,
    work: &mut [u8],
    limits: Limits,
) -> Result<(), Error> {
    check_input(input, limits)?;
    for label in input.split(|b| *b == b'.').filter(|s| !s.is_empty()) {
        check_label(label, idna, work, limits)?;
    }
    let n = idna.to_ascii(input, work)?;
    let ascii = work.get(..n).ok_or(Error::Malformed)?;
    if !ascii.is_ascii() || ascii.contains(&0) {
        return Err(Error::Malformed);
    }
    if n > MAX_NAME_LENGTH {
        return Err(Error::TooLarge);
    }
    Ok(())
}
