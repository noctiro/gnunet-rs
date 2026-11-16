//! Bounded Windows CRT argument encoding over original UTF-16 code units.
use std::io;
const QUOTE: u16 = b'"' as u16;
const SLASH: u16 = b'\\' as u16;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid or oversized Windows command line",
    )
}

pub(crate) fn encode(
    program: &[u16],
    arguments: &[Vec<u16>],
    maximum: usize,
) -> io::Result<Vec<u16>> {
    if program.iter().any(|unit| *unit == 0 || *unit == QUOTE) {
        return Err(invalid());
    }
    let mut count = program.len().checked_add(3).ok_or_else(invalid)?;
    for argument in arguments {
        if argument.contains(&0) {
            return Err(invalid());
        }
        count = count.checked_add(3).ok_or_else(invalid)?;
        let mut slashes = 0usize;
        for unit in argument {
            match *unit {
                SLASH => slashes += 1,
                QUOTE => {
                    count = count.checked_add(slashes * 2 + 2).ok_or_else(invalid)?;
                    slashes = 0;
                }
                _ => {
                    count = count.checked_add(slashes + 1).ok_or_else(invalid)?;
                    slashes = 0;
                }
            }
        }
        count = count.checked_add(slashes * 2).ok_or_else(invalid)?;
        if count > maximum.min(32767) {
            return Err(invalid());
        }
    }
    if count > maximum.min(32767) {
        return Err(invalid());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    output.push(QUOTE);
    output.extend_from_slice(program);
    output.push(QUOTE);
    for argument in arguments {
        output.extend_from_slice(&[b' ' as u16, QUOTE]);
        let mut slashes = 0usize;
        for unit in argument {
            if *unit == SLASH {
                slashes += 1;
                continue;
            }
            output.extend(std::iter::repeat_n(
                SLASH,
                if *unit == QUOTE {
                    slashes * 2 + 1
                } else {
                    slashes
                },
            ));
            output.push(*unit);
            slashes = 0;
        }
        output.extend(std::iter::repeat_n(SLASH, slashes * 2));
        output.push(QUOTE);
    }
    output.push(0);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::encode;
    use std::io;
    #[test]
    fn crt_quotes_preserve_empty_arguments_quotes_and_trailing_backslashes() -> io::Result<()> {
        let arguments: Vec<Vec<u16>> = ["", "two words", "a\"b", "a\\", "a\\\"b"]
            .map(|text| text.encode_utf16().collect())
            .into();
        let encoded = encode(
            &"C:\\x.exe".encode_utf16().collect::<Vec<_>>(),
            &arguments,
            32767,
        )?;
        let expected: Vec<u16> =
            "\"C:\\x.exe\" \"\" \"two words\" \"a\\\"b\" \"a\\\\\" \"a\\\\\\\"b\"\0"
                .encode_utf16()
                .collect();
        if encoded != expected {
            return Err(io::Error::other("CRT quoting changed an argument"));
        }
        if encode(&[b'x' as u16], &[vec![0]], 32767).is_ok()
            || encode(&[b'x' as u16], &[], 3).is_ok()
        {
            return Err(io::Error::other("invalid command line was accepted"));
        }
        Ok(())
    }
    #[test]
    fn isolated_utf16_units_survive_without_lossy_unicode_conversion() -> io::Result<()> {
        if encode(&[], &[], 3)? != [QUOTE, QUOTE, 0] {
            return Err(io::Error::other("explicit empty argv0 was lost"));
        }
        let encoded = encode(&[b'x' as u16], &[vec![0xd800, SLASH]], 32767)?;
        if encoded
            != [
                QUOTE,
                b'x' as u16,
                QUOTE,
                32,
                QUOTE,
                0xd800,
                SLASH,
                SLASH,
                QUOTE,
                0,
            ]
        {
            return Err(io::Error::other("native UTF-16 argument was altered"));
        }
        Ok(())
    }
    use super::QUOTE;
    use super::SLASH;
}
