//! Byte-oriented PDF filters with bounded, append-only decoding.

use super::super::syntax::{hex, is_space};
use super::Output;

pub(super) fn ascii_hex(input: &[u8], output: &mut Output) -> Option<()> {
    let mut high = None;
    for byte in input.iter().copied().filter(|&byte| !is_space(byte)) {
        if byte == b'>' {
            if let Some(high) = high {
                output.append(&[high << 4])?;
            }
            return Some(());
        }
        let digit = hex(byte)?;
        if let Some(high) = high.take() {
            output.append(&[(high << 4) | digit])?;
        } else {
            high = Some(digit);
        }
    }
    None
}

pub(super) fn ascii85(mut input: &[u8], output: &mut Output) -> Option<()> {
    let mut value = 0_u64;
    let mut digits = 0;
    while let Some((&byte, rest)) = input.split_first() {
        input = rest;
        match byte {
            b'!'..=b'u' => {
                value = value * 85 + u64::from(byte - b'!');
                digits += 1;
                if digits == 5 {
                    output.append(&u32::try_from(value).ok()?.to_be_bytes())?;
                    value = 0;
                    digits = 0;
                }
            }
            b'z' if digits == 0 => output.append(&[0; 4])?,
            b'~' if input.starts_with(b">") => {
                if digits == 0 {
                    return Some(());
                }
                if digits == 1 {
                    return None;
                }
                for _ in digits..5 {
                    value = value * 85 + 84;
                }
                let bytes = u32::try_from(value).ok()?.to_be_bytes();
                return output.append(&bytes[..digits - 1]);
            }
            byte if is_space(byte) => {}
            _ => return None,
        }
    }
    None
}

pub(super) fn run_length(mut input: &[u8], output: &mut Output) -> Option<()> {
    while let Some((&control, rest)) = input.split_first() {
        match control {
            0..=127 => {
                let (literal, next) = rest.split_at_checked(usize::from(control) + 1)?;
                output.append(literal)?;
                input = next;
            }
            128 => return Some(()),
            _ => {
                let (&byte, next) = rest.split_first()?;
                output.fill(257 - usize::from(control), byte)?;
                input = next;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{Output, ascii_hex, ascii85, run_length};

    #[test]
    fn ascii_hex_pads_an_odd_nibble_at_the_marker() {
        let mut output = Output::new(2);
        assert_eq!(ascii_hex(b"4\0F\x0cA >\n", &mut output), Some(()));
        assert_eq!(output.bytes, [0x4f, 0xa0]);
        output.bytes.clear();
        assert_eq!(ascii_hex(b"4FA", &mut output), None);
        assert_eq!(output.bytes, [0x4f]);
    }

    #[test]
    fn ascii85_checks_group_boundaries_and_overflow() {
        let mut output = Output::new(5);
        assert_eq!(ascii85(b"z\rrr~>", &mut output), Some(()));
        assert_eq!(output.bytes, [0, 0, 0, 0, 255]);
        for invalid in [b"uuuuu~>".as_slice(), b"!~>", b"!z~>", b"~ >"] {
            output.bytes.clear();
            assert_eq!(ascii85(invalid, &mut output), None);
            assert!(output.bytes.is_empty());
        }
    }

    #[test]
    fn run_length_checks_the_full_run_before_writing() {
        let mut output = Output::new(5);
        let input = [1, b'a', b'b', 254, b'x', 128];
        assert_eq!(run_length(&input, &mut output), Some(()));
        assert_eq!(output.bytes, b"abxxx");
        let mut short = Output::new(4);
        assert_eq!(run_length(&input, &mut short), None);
        assert_eq!(short.bytes, b"ab");
        output.bytes.clear();
        assert_eq!(run_length(&input[..5], &mut output), None);
        assert_eq!(output.bytes, b"abxxx");
    }
}
