//! Unicode 18 NFC, matching the libunistring 1.5 reference profile.
use crate::nfc_data::{CCC, COMPOSE, DECOMP, DECOMP_CHARS};
use gnunet_types::Error;

/// A label normalized to NFC without case folding or IDNA conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Label<'a>(&'a str);
impl<'a> Label<'a> {
    /// Normalize in caller-provided Unicode scalar and UTF-8 storage. NUL is
    /// rejected because the official C APIs consume NUL-terminated strings.
    /// Capacity refusal preserves the byte output; working scalars may change.
    pub fn normalize(
        input: &str,
        scalars: &mut [char],
        output: &'a mut [u8],
    ) -> Result<Self, Error> {
        if input.as_bytes().contains(&0) {
            return Err(Error::InvalidInput);
        }
        let mut count = 0;
        for ch in input.chars() {
            let cp = u32::from(ch);
            if (0xac00..0xd7a4).contains(&cp) {
                let s = cp - 0xac00;
                push(scalars, &mut count, 0x1100 + s / 588)?;
                push(scalars, &mut count, 0x1161 + (s % 588) / 28)?;
                if s % 28 != 0 {
                    push(scalars, &mut count, 0x11a7 + s % 28)?;
                }
            } else if let Ok(index) = DECOMP.binary_search_by_key(&cp, |row| row.0) {
                let (_, start, length) = DECOMP[index];
                for &part in
                    &DECOMP_CHARS[usize::from(start)..usize::from(start) + usize::from(length)]
                {
                    push(scalars, &mut count, part)?;
                }
            } else {
                push(scalars, &mut count, cp)?;
            }
        }
        // Stable canonical ordering; caller's scalar capacity bounds the work.
        for i in 1..count {
            let class = ccc(scalars[i]);
            if class == 0 {
                continue;
            }
            let mut j = i;
            while j > 0 && ccc(scalars[j - 1]) > class {
                scalars.swap(j, j - 1);
                j -= 1;
            }
        }
        let mut length = 0;
        let mut starter = None;
        let mut last_class = 0;
        for index in 0..count {
            let ch = scalars[index];
            let class = ccc(ch);
            if let Some(position) = starter
                && (last_class == 0 || last_class < class)
                && let Some(composed) = compose(scalars[position], ch)
            {
                scalars[position] = composed;
                continue;
            }
            scalars[length] = ch;
            if class == 0 {
                starter = Some(length);
            }
            length += 1;
            last_class = class;
        }
        let required = scalars[..length].iter().try_fold(0_usize, |n, ch| {
            n.checked_add(ch.len_utf8()).ok_or(Error::Overflow)
        })?;
        if required > output.len() {
            return Err(Error::Capacity);
        }
        let mut offset = 0;
        for ch in &scalars[..length] {
            offset += ch.encode_utf8(&mut output[offset..required]).len();
        }
        Ok(Self(
            core::str::from_utf8(&output[..required]).map_err(|_| Error::InvalidInput)?,
        ))
    }
    /// Borrow the normalized UTF-8 label without a trailing NUL.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}
fn push(output: &mut [char], length: &mut usize, cp: u32) -> Result<(), Error> {
    let target = output.get_mut(*length).ok_or(Error::Capacity)?;
    *target = char::from_u32(cp).ok_or(Error::InvalidInput)?;
    *length += 1;
    Ok(())
}
fn ccc(ch: char) -> u8 {
    CCC.binary_search_by_key(&u32::from(ch), |row| row.0)
        .map_or(0, |index| CCC[index].1)
}
fn compose(a: char, b: char) -> Option<char> {
    let a = u32::from(a);
    let b = u32::from(b);
    if (0x1100..0x1113).contains(&a) && (0x1161..0x1176).contains(&b) {
        return char::from_u32(0xac00 + (a - 0x1100) * 588 + (b - 0x1161) * 28);
    }
    if (0xac00..0xd7a4).contains(&a) && (a - 0xac00) % 28 == 0 && (0x11a8..0x11c3).contains(&b) {
        return char::from_u32(a + b - 0x11a7);
    }
    let pair = (u64::from(a) << 21) | u64::from(b);
    COMPOSE
        .binary_search_by_key(&pair, |row| row.0)
        .ok()
        .and_then(|index| char::from_u32(COMPOSE[index].1))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Unicode official conformance assertions."
    )]
    use super::*;
    #[test]
    fn unicode_18_complete_nfc_conformance() -> Result<(), Error> {
        let mut corpus = include_bytes!("../tests/fixtures/normalization-18.bin").as_slice();
        let mut count = 0;
        while !corpus.is_empty() {
            let mut columns = [""; 5];
            for value in &mut columns {
                let length = usize::from(u16::from_be_bytes(
                    corpus
                        .get(..2)
                        .ok_or(Error::Truncated)?
                        .try_into()
                        .map_err(|_| Error::Truncated)?,
                ));
                *value = core::str::from_utf8(corpus.get(2..2 + length).ok_or(Error::Truncated)?)
                    .map_err(|_| Error::Malformed)?;
                corpus = &corpus[2 + length..];
            }
            for (input, expected) in [
                (columns[0], columns[1]),
                (columns[1], columns[1]),
                (columns[2], columns[1]),
                (columns[3], columns[3]),
                (columns[4], columns[3]),
            ] {
                let mut scalars = ['\0'; 128];
                let mut bytes = [0; 512];
                assert_eq!(
                    Label::normalize(input, &mut scalars, &mut bytes)?.as_str(),
                    expected,
                    "row {count}"
                );
            }
            count += 1;
        }
        assert_eq!(count, 20171);
        Ok(())
    }
    #[test]
    fn capacity_case_and_nul_contract() -> Result<(), Error> {
        let mut chars = ['\0'; 20];
        let mut bytes = [0xa5; 16];
        assert_eq!(
            Label::normalize("e\u{301}", &mut chars, &mut bytes)?.as_str(),
            "é"
        );
        assert_eq!(
            Label::normalize("EXAMPLE", &mut chars, &mut bytes)?.as_str(),
            "EXAMPLE"
        );
        let original = bytes;
        assert_eq!(
            Label::normalize("abcdefghijk", &mut chars, &mut bytes[..1]),
            Err(Error::Capacity)
        );
        assert_eq!(bytes, original);
        assert_eq!(
            Label::normalize("a\0b", &mut chars, &mut bytes),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            Label::normalize("é", &mut [], &mut bytes),
            Err(Error::Capacity)
        );
        Ok(())
    }
}
