//! Bounded canonical Hebrew numerals used by native Hebrew calendar pictures.
use super::Budget;
use std::io;
fn digit(unit: u16) -> Option<u16> {
    Some(match unit {
        0x05d0..=0x05d8 => unit - 0x05d0 + 1,
        0x05d9 => 10,
        0x05db => 20,
        0x05dc => 30,
        0x05de => 40,
        0x05e0 => 50,
        0x05e1 => 60,
        0x05e2 => 70,
        0x05e4 => 80,
        0x05e6 => 90,
        0x05e7..=0x05ea => (unit - 0x05e6) * 100,
        _ => return None,
    })
}
fn spelling(value: u16) -> ([u16; 5], usize) {
    let mut letters = [0; 5];
    let mut length = 0;
    let mut push = |value| {
        letters[length] = value;
        length += 1;
    };
    let mut hundreds = value / 100;
    while hundreds >= 4 {
        push(0x05ea);
        hundreds -= 4;
    }
    if hundreds != 0 {
        push(0x05e6 + hundreds);
    }
    let tail = value % 100;
    if matches!(tail, 15 | 16) {
        push(0x05d8);
        push(0x05d0 + tail - 10);
    } else {
        let tens = [
            0, 0x05d9, 0x05db, 0x05dc, 0x05de, 0x05e0, 0x05e1, 0x05e2, 0x05e4, 0x05e6,
        ];
        if tail >= 10 {
            push(tens[usize::from(tail / 10)]);
        }
        if !tail.is_multiple_of(10) {
            push(0x05d0 + tail % 10 - 1);
        }
    }
    (letters, length)
}
pub(super) fn prefix(input: &[u16], budget: &mut Budget) -> io::Result<Option<(u16, usize)>> {
    let mut letters = [0u16; 5];
    let mut length = 0;
    let mut at = 0;
    let mut value = 0;
    let mut quote = None;
    while let Some(&unit) = input.get(at) {
        budget.charge(1)?;
        if let Some(part) = digit(unit) {
            if length == letters.len() {
                return Ok(None);
            }
            letters[length] = unit;
            length += 1;
            value += part;
        } else if matches!(unit, 0x0027 | 0x0022 | 0x05f3 | 0x05f4) {
            if length == 0 || quote.is_some() {
                return Ok(None);
            }
            quote = Some((length, matches!(unit, 0x0027 | 0x05f3)));
        } else {
            break;
        }
        at += 1;
    }
    if length == 0 || value > 999 {
        return Ok(None);
    }
    if let Some((position, single)) = quote
        && ((single && (length != 1 || position != 1))
            || (!single && (length < 2 || position != length - 1)))
    {
        return Ok(None);
    }
    let (expected, count) = spelling(value);
    if length != count || letters[..length] != expected[..count] {
        return Ok(None);
    }
    Ok(Some((value, at)))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Literal independent Hebrew numeral fixtures assert accepted and rejected native spellings"
    )]
    fn native_letters_and_quote_spellings() -> io::Result<()> {
        for (text, value) in [
            ("ט\"ו", 15),
            ("ט״ז", 16),
            ("א׳", 1),
            ("תשפ\"ד", 784),
            ("תתקצ״ט", 999),
        ] {
            let units: Vec<_> = text.encode_utf16().collect();
            assert_eq!(
                prefix(&units, &mut Budget::new())?,
                Some((value, units.len()))
            );
        }
        for text in ["יה", "ו״ט", "א׳ב", "תתת", "ך׳", "\"א", "תש\"פ\"ד"] {
            let units: Vec<_> = text.encode_utf16().collect();
            assert_eq!(prefix(&units, &mut Budget::new())?, None, "{text}");
        }
        Ok(())
    }
}
