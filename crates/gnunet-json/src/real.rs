//! Finite binary64 rendering for the Jansson default17-significant-digit profile.
//! Rust core rounds the original value once; bounded rearrangement implements
//! %g style selection/trimming, required .0 and normalized decimal exponents.
use core::{fmt, fmt::Write};
use gnunet_types::Error;
use zeroize::{Zeroize, Zeroizing};

// A sign,17 digits, decimal point, e, exponent sign and at most3 exponent digits
// fit24 bytes. This private zeroizing scratch also holds the normalized exponent.
struct Scientific {
    bytes: Zeroizing<[u8; 32]>,
    len: usize,
}
impl Scientific {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new([0; 32]),
            len: 0,
        }
    }
    fn text(&self) -> Result<&str, Error> {
        core::str::from_utf8(&self.bytes[..self.len]).map_err(|_| Error::Malformed)
    }
    fn clear(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
}
impl fmt::Write for Scientific {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

pub(crate) fn write(
    value: f64,
    mut emit: impl FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    if !value.is_finite() {
        return Err(Error::Overflow);
    }
    let mut scientific = Scientific::new();
    // Scientific precision counts digits AFTER the point:16 gives17 significant
    // digits, including explicit trailing zeroes and signed zero. Formatting
    // performs the original binary64-to-decimal rounding; we never round again.
    write!(&mut scientific, "{value:.16e}").map_err(|_| Error::Overflow)?;
    let text = scientific.text()?;
    let (negative, text) = match text.strip_prefix('-') {
        Some(text) => (true, text),
        None => (false, text),
    };
    let (mantissa, exponent) = text.split_once('e').ok_or(Error::Malformed)?;
    let exponent = exponent.parse::<i32>().map_err(|_| Error::Malformed)?;
    if !(-324..=308).contains(&exponent) {
        return Err(Error::Malformed);
    }
    let mut digits = Zeroizing::new([0_u8; 17]);
    let mut count = 0_usize;
    for byte in mantissa.bytes().filter(|byte| *byte != b'.') {
        if !byte.is_ascii_digit() {
            return Err(Error::Malformed);
        }
        *digits.get_mut(count).ok_or(Error::Malformed)? = byte;
        count += 1;
    }
    if count != digits.len() {
        return Err(Error::Malformed);
    }
    // The rounded scientific exponent decides %g's choice. In particular a
    // decimal carry has already changed that exponent before the threshold test.
    while count > 1 && digits[count - 1] == b'0' {
        count -= 1;
    }
    if negative {
        emit(b"-")?;
    }
    if !(-4..17).contains(&exponent) {
        emit(&digits[..1])?;
        if count > 1 {
            emit(b".")?;
            emit(&digits[1..count])?;
        }
        emit(b"e")?;
        scientific.clear();
        write!(&mut scientific, "{exponent}").map_err(|_| Error::Overflow)?;
        emit(scientific.text()?.as_bytes())?;
    } else if exponent < 0 {
        // The fixed branch has at most3 leading fractional zeroes.
        let zeroes = usize::try_from(-exponent - 1).map_err(|_| Error::Overflow)?;
        emit(b"0.")?;
        emit(&b"000"[..zeroes])?;
        emit(&digits[..count])?;
    } else {
        let point = usize::try_from(exponent + 1).map_err(|_| Error::Overflow)?;
        if point < count {
            emit(&digits[..point])?;
            emit(b".")?;
            emit(&digits[point..count])?;
        } else {
            emit(&digits[..count])?;
            emit(&b"0000000000000000"[..point - count])?;
            // Jansson retains real type when the %g output had neither . nor e.
            emit(b".0")?;
        }
    }
    Ok(())
}
