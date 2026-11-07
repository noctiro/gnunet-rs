//! Safe typed rendering of translated C-format messages used by these sources.
//! It never calls a variadic C formatter, writes through a format pointer or
//! interprets user argument bytes as a format. Unsupported conversions fail.
use std::io;
/// Explicit argument type corresponding to reviewed source format operands.
#[derive(Clone, Copy)]
pub enum Argument<'a> {
    /// Nonnull C-string prefix, copied as data even when it contains percent signs.
    Bytes(&'a [u8]),
    /// Signed integer value.
    Signed(i64),
    /// Unsigned integer value.
    Unsigned(u64),
    /// Single native unsigned byte.
    Character(u8),
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "translated format/argument contract mismatch",
    )
}
fn integer_bits(length: &[u8]) -> io::Result<usize> {
    Ok(match length {
        b"" | b"h" | b"hh" => std::mem::size_of::<libc::c_int>() * 8,
        b"l" => std::mem::size_of::<libc::c_long>() * 8,
        b"ll" | b"j" => 64,
        b"z" | b"t" => usize::BITS as usize,
        _ => return Err(invalid()),
    })
}
fn signed(value: i64, length: &[u8]) -> io::Result<i64> {
    let bits = integer_bits(length)?;
    if bits < 64 && (value < -(1i64 << (bits - 1)) || value >= (1i64 << (bits - 1))) {
        return Err(invalid());
    }
    Ok(match length {
        b"h" => i64::from(value as i16),
        b"hh" => i64::from(value as i8),
        _ => value,
    })
}
fn unsigned(value: u64, length: &[u8]) -> io::Result<u64> {
    let bits = integer_bits(length)?;
    if bits < 64 && value >= (1u64 << bits) {
        return Err(invalid());
    }
    Ok(match length {
        b"h" => u64::from(value as u16),
        b"hh" => u64::from(value as u8),
        _ => value,
    })
}
fn number(bytes: &[u8], position: &mut usize) -> io::Result<Option<usize>> {
    let first = *position;
    let mut n = 0usize;
    while let Some(&b @ b'0'..=b'9') = bytes.get(*position) {
        n = n
            .checked_mul(10)
            .and_then(|v| v.checked_add(usize::from(b - b'0')))
            .ok_or_else(invalid)?;
        *position += 1;
    }
    Ok((*position != first).then_some(n))
}
fn choose<'a>(
    args: &'a [Argument<'a>],
    position: Option<usize>,
    next: &mut usize,
) -> io::Result<Argument<'a>> {
    let i = if let Some(i) = position {
        i.checked_sub(1).ok_or_else(invalid)?
    } else {
        let i = *next;
        *next = next.checked_add(1).ok_or_else(invalid)?;
        i
    };
    args.get(i).copied().ok_or_else(invalid)
}
/// Render reviewed byte-string/integer/character printf forms, including POSIX
/// positional arguments, ordinary width/precision and literal%%. %n and all
/// pointer/float/unknown conversions are rejected, never simulated successfully.
pub fn render(template: &[u8], args: &[Argument<'_>]) -> io::Result<Vec<u8>> {
    render_limited(template, args, 1024 * 1024)
}
/// Explicit host byte-capacity variant. Capacity is checked before every padded
/// allocation; failure returns no partially rendered output. This is not a new
/// GNUnet option and does not change any wire framing limit.
pub fn render_limited(
    template: &[u8],
    args: &[Argument<'_>],
    maximum: usize,
) -> io::Result<Vec<u8>> {
    let template = &template[..template
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(template.len())];
    if template.len() > maximum {
        return Err(io::Error::other("format byte capacity"));
    }
    let mut out = Vec::new();
    let mut at = 0;
    let mut next = 0;
    let mut positional = None;
    while at < template.len() {
        if template[at] != b'%' {
            if out.len() == maximum {
                return Err(io::Error::other("format byte capacity"));
            }
            out.push(template[at]);
            at += 1;
            continue;
        }
        at += 1;
        if template.get(at) == Some(&b'%') {
            if out.len() == maximum {
                return Err(io::Error::other("format byte capacity"));
            }
            out.push(b'%');
            at += 1;
            continue;
        }
        let saved = at;
        let candidate = number(template, &mut at)?;
        let position = if template.get(at) == Some(&b'$') {
            at += 1;
            candidate
        } else {
            at = saved;
            None
        };
        if positional.is_some_and(|selected| selected != position.is_some()) {
            return Err(invalid());
        }
        positional = Some(position.is_some());
        let mut left = false;
        let mut zero = false;
        let mut plus = false;
        let mut space = false;
        let mut alternate = false;
        while let Some(&b) = template.get(at) {
            match b {
                b'-' => left = true,
                b'0' => zero = true,
                b'+' => plus = true,
                b' ' => space = true,
                b'#' => alternate = true,
                _ => break,
            };
            at += 1;
        }
        let mut dynamic = |at: &mut usize| -> io::Result<i64> {
            *at += 1;
            let begin = *at;
            let choice = number(template, at)?;
            let choice = if template.get(*at) == Some(&b'$') {
                *at += 1;
                choice
            } else {
                *at = begin;
                None
            };
            if positional != Some(choice.is_some()) {
                return Err(invalid());
            }
            match choose(args, choice, &mut next)? {
                Argument::Signed(v) => Ok(i64::from(i32::try_from(v).map_err(|_| invalid())?)),
                _ => Err(invalid()),
            }
        };
        let width = if template.get(at) == Some(&b'*') {
            let width = dynamic(&mut at)?;
            if width < 0 {
                left = true;
            }
            usize::try_from(width.unsigned_abs()).map_err(|_| invalid())?
        } else {
            number(template, &mut at)?.unwrap_or(0)
        };
        let precision = if template.get(at) == Some(&b'.') {
            at += 1;
            if template.get(at) == Some(&b'*') {
                let n = dynamic(&mut at)?;
                if n < 0 {
                    None
                } else {
                    Some(usize::try_from(n).map_err(|_| invalid())?)
                }
            } else {
                Some(number(template, &mut at)?.unwrap_or(0))
            }
        } else {
            None
        };
        if width > maximum || precision.is_some_and(|v| v > maximum) {
            return Err(io::Error::other("format byte capacity"));
        }
        // Keep the reviewed byte-string boundary explicit: wide strings/chars
        // require native wchar ownership and cannot silently use byte operands.
        let length_start = at;
        if matches!(template.get(at), Some(b'h' | b'l')) {
            let b = template[at];
            at += 1;
            if template.get(at) == Some(&b) {
                at += 1;
            }
        } else if matches!(template.get(at), Some(b'j' | b'z' | b't')) {
            at += 1;
        }
        let kind = *template.get(at).ok_or_else(invalid)?;
        let length = &template[length_start..at];
        if matches!(kind, b's' | b'c') && !length.is_empty() {
            return Err(invalid());
        }
        at += 1;
        let value = match choose(args, position, &mut next)? {
            Argument::Signed(value) if matches!(kind, b'd' | b'i') => {
                Argument::Signed(signed(value, length)?)
            }
            Argument::Unsigned(value) if matches!(kind, b'u' | b'x' | b'X' | b'o') => {
                Argument::Unsigned(unsigned(value, length)?)
            }
            value => value,
        };
        let (mut text, numeric, negative) = match (kind, value) {
            (b's', Argument::Bytes(v)) => {
                let v = &v[..v.iter().position(|&b| b == 0).unwrap_or(v.len())];
                if v.len().min(precision.unwrap_or(v.len())) > maximum {
                    return Err(io::Error::other("format byte capacity"));
                }
                let v = v[..v.len().min(precision.unwrap_or(v.len()))].to_vec();
                (v, false, false)
            }
            (b'c', Argument::Character(v)) => (vec![v], false, false),
            (b'd' | b'i', Argument::Signed(v)) => {
                (v.unsigned_abs().to_string().into_bytes(), true, v < 0)
            }
            (b'u', Argument::Unsigned(v)) => (v.to_string().into_bytes(), true, false),
            (b'x', Argument::Unsigned(v)) => (format!("{v:x}").into_bytes(), true, false),
            (b'X', Argument::Unsigned(v)) => (format!("{v:X}").into_bytes(), true, false),
            (b'o', Argument::Unsigned(v)) => (format!("{v:o}").into_bytes(), true, false),
            _ => return Err(invalid()),
        };
        let mut prefix = Vec::new();
        if numeric {
            let is_zero = text == b"0";
            if precision == Some(0) && text == b"0" {
                text.clear();
            }
            if alternate && kind == b'o' && text.is_empty() {
                text.push(b'0');
            }
            if let Some(n) = precision
                && n > text.len()
            {
                let mut padded = vec![b'0'; n - text.len()];
                padded.extend_from_slice(&text);
                text = padded;
            }
            if negative {
                prefix.push(b'-');
            } else if matches!(kind, b'd' | b'i') {
                if plus {
                    prefix.push(b'+');
                } else if space {
                    prefix.push(b' ');
                }
            }
            if alternate && !text.is_empty() && (!is_zero || kind == b'o') {
                match kind {
                    b'x' => prefix.extend_from_slice(b"0x"),
                    b'X' => prefix.extend_from_slice(b"0X"),
                    b'o' if text.first() != Some(&b'0') => prefix.push(b'0'),
                    _ => {}
                }
            }
        }
        let len = prefix.len().checked_add(text.len()).ok_or_else(invalid)?;
        if out
            .len()
            .checked_add(width.max(len))
            .is_none_or(|v| v > maximum)
        {
            return Err(io::Error::other("format byte capacity"));
        }
        let padding = width.saturating_sub(len);
        if !left && (!zero || precision.is_some() || !numeric) {
            out.extend(std::iter::repeat_n(b' ', padding));
        }
        out.extend_from_slice(&prefix);
        if !left && zero && precision.is_none() && numeric {
            out.extend(std::iter::repeat_n(b'0', padding));
        }
        out.extend_from_slice(&text);
        if left {
            out.extend(std::iter::repeat_n(b' ', padding));
        }
    }
    Ok(out)
}

pub(crate) enum Message<'a> {
    Literal(&'a [u8]),
    Translated {
        domain: Option<&'a [u8]>,
        template: &'a [u8],
        arguments: &'a [Argument<'a>],
    },
}
impl Message<'_> {
    pub(crate) fn render(
        self,
        translations: &dyn crate::locale::Translations,
    ) -> io::Result<Vec<u8>> {
        match self {
            Self::Literal(value) => Ok(value.to_vec()),
            Self::Translated {
                domain,
                template,
                arguments,
            } => {
                let template = translations.gettext(domain, template)?;
                render(&template, arguments)
            }
        }
    }
}
