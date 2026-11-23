//! The standalone FS search result and metadata format languages.

use gnunet::{
    fs::{Limits, Uri, directory, metadata},
    fs_host::{extraction::metadata_type_name, search::ResultRecord},
};
use std::io::{self, Write};

const ORIGINAL_NAME: u32 = 180;
const MIME: u32 = 1;
const EXTENSION: &[u8] = b".gnd";
const MAX_FORMAT: usize = 4096;
const MAX_RECORD_OUTPUT: usize = 2 * 1024 * 1024;

pub(super) struct Formats {
    file: Option<Vec<u8>>,
    directory: Option<Vec<u8>>,
    metadata: Option<Vec<u8>>,
    verbose: bool,
}

impl Formats {
    pub(super) fn new(
        file: Option<Vec<u8>>,
        directory: Option<Vec<u8>>,
        metadata: Option<Vec<u8>>,
        verbose: bool,
    ) -> io::Result<Self> {
        if [&file, &directory, &metadata]
            .into_iter()
            .flatten()
            .any(|format| format.len() > MAX_FORMAT || format.contains(&0))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "search format exceeds 4096 bytes or contains NUL",
            ));
        }
        Ok(Self {
            file,
            directory,
            metadata,
            verbose,
        })
    }

    pub(super) fn print(
        &self,
        out: &mut impl Write,
        record: &ResultRecord,
        count: usize,
    ) -> io::Result<()> {
        let mut out = Bounded {
            out,
            remaining: MAX_RECORD_OUTPUT,
        };
        let mut items = record.metadata().iter().map(|owned| owned.item());
        let mime = items
            .clone()
            .find_map(|item| (item.kind == MIME).then(|| item.text()).flatten());
        let directory = mime.is_some_and(|mime| mime.eq_ignore_ascii_case(directory::MIME));
        let name = items
            .find_map(|item| (item.kind == ORIGINAL_NAME).then(|| item.text()).flatten())
            .unwrap_or(if directory { b"collection" } else { b"no-name" });
        let name = &name[..name
            .iter()
            .rposition(|&byte| byte != b'/')
            .map_or(0, |at| at + 1)];
        let custom = if directory {
            self.directory.as_deref().or(self.file.as_deref())
        } else {
            self.file.as_deref()
        };
        if let Some(format) = custom {
            render(format, &mut out, true, |out, field, kind| match field {
                b'a' | b'j' => self.print_metadata(out, record, kind, field == b'j'),
                b'f' => filename(out, name, directory, false),
                b'l' => write!(
                    out,
                    "{}",
                    name.len() + if directory { EXTENSION.len() } else { 0 }
                ),
                b'm' => out.write_all(if directory {
                    directory::MIME
                } else {
                    mime.unwrap_or(b"application/octet-stream")
                }),
                b'n' => write!(out, "{count}"),
                b's' => {
                    let uri = record.uri(Limits::default()).map_err(io::Error::other)?;
                    let size = match uri {
                        Uri::Content(content) => content.size,
                        Uri::Location(location) => location.content().size,
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "search URI has no file size",
                            ));
                        }
                    };
                    write!(out, "{size}")
                }
                b'u' => out.write_all(record.raw_uri()),
                other => out.write_all(&[b'%', other]),
            })?;
        } else {
            write!(out, "#{count}:\ngnunet-download -o \"")?;
            filename(&mut out, name, directory, true)?;
            out.write_all(if directory { b"\" -R " } else { b"\" " })?;
            token(&mut out, record.raw_uri())?;
            out.write_all(b"\n\n")?;
            if self.verbose {
                self.print_metadata(&mut out, record, None, false)?;
                out.write_all(b"\n")?;
            }
        }
        out.flush()
    }

    fn print_metadata(
        &self,
        out: &mut impl Write,
        record: &ResultRecord,
        kind: Option<u32>,
        first: bool,
    ) -> io::Result<()> {
        let format = self.metadata.as_deref().unwrap_or(b"  %t: %p\n");
        let items = record
            .metadata()
            .iter()
            .map(|owned| owned.item())
            .filter_map(|item| {
                (item.kind != ORIGINAL_NAME)
                    .then(|| item.text().map(|data| (item, data)))
                    .flatten()
            });
        for (index, (item, text)) in items.enumerate() {
            if kind.is_some_and(|kind| kind != item.kind) {
                continue;
            }
            render(format, out, false, |out, field, _| match field {
                b'i' => write!(out, "{}", item.kind),
                b'l' => write!(out, "{}", item.data.len()),
                b'n' => write!(out, "{}", index + 1),
                b'p' => out.write_all(text),
                b't' => match metadata_type_name(item.kind) {
                    Some(name) => out.write_all(name.as_bytes()),
                    None => write!(out, "MetaType #{}", item.kind),
                },
                b'w' => out.write_all(item.plugin.map(metadata::c_prefix).unwrap_or_default()),
                other => out.write_all(&[b'%', other]),
            })?;
            if first {
                break;
            }
        }
        Ok(())
    }
}

struct Bounded<'a, W> {
    out: &'a mut W,
    remaining: usize,
}
impl<W: Write> Write for Bounded<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("formatted search result exceeds 2 MiB"));
        }
        let used = self.out.write(bytes)?;
        self.remaining -= used;
        Ok(used)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

fn filename(out: &mut impl Write, name: &[u8], directory: bool, command: bool) -> io::Result<()> {
    let mut start = 0;
    for (at, &byte) in name.iter().enumerate() {
        let invalid = b"/\\:*?\"<>|".contains(&byte)
            || command && (b"$`!%".contains(&byte) || byte.is_ascii_control());
        if invalid {
            out.write_all(&name[start..at])?;
            out.write_all(b"_")?;
            start = at + 1;
        }
    }
    out.write_all(&name[start..])?;
    if directory {
        out.write_all(EXTENSION)?;
    }
    Ok(())
}

fn token(out: &mut impl Write, value: &[u8]) -> io::Result<()> {
    if value
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b".:/_+%-".contains(byte))
    {
        return out.write_all(value);
    }
    out.write_all(b"'")?;
    for &byte in value {
        if byte == b'\'' {
            out.write_all(b"'\\''")?;
        } else {
            out.write_all(&[byte])?;
        }
    }
    out.write_all(b"'")
}

fn render<W: Write>(
    mut format: &[u8],
    out: &mut W,
    filtered: bool,
    mut specifier: impl FnMut(&mut W, u8, Option<u32>) -> io::Result<()>,
) -> io::Result<()> {
    while let Some(at) = format.iter().position(|&byte| matches!(byte, b'%' | b'\\')) {
        out.write_all(&format[..at])?;
        let special = format[at];
        format = &format[at + 1..];
        let Some((&next, tail)) = format.split_first() else {
            return out.write_all(&[special]);
        };
        if special == b'\\' {
            format = escape(format, out)?;
            continue;
        }
        if filtered && let Some((kind, field, tail)) = filtered_metadata(format) {
            specifier(out, field, Some(kind))?;
            format = tail;
            continue;
        }
        if next == b'%' {
            out.write_all(b"%")?;
        } else {
            specifier(out, next, None)?;
        }
        format = tail;
    }
    out.write_all(format)
}

fn filtered_metadata(format: &[u8]) -> Option<(u32, u8, &[u8])> {
    let digits = format
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits == 0 {
        return None;
    }
    let (&field, tail) = format[digits..].strip_prefix(b"#")?.split_first()?;
    if !matches!(field, b'a' | b'j') {
        return None;
    }
    let kind = std::str::from_utf8(&format[..digits])
        .ok()?
        .parse::<u32>()
        .ok()?;
    (kind > 0).then_some((kind, field, tail))
}

fn escape<'a>(format: &'a [u8], out: &mut impl Write) -> io::Result<&'a [u8]> {
    let code = format[0];
    let byte = match code {
        b'\\' => b'\\',
        b'a' => 7,
        b'b' => 8,
        b'e' => 27,
        b'f' => 12,
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'v' => 11,
        b'x' | b'0'..=b'7' => {
            let (digits, radix, width) = if code == b'x' {
                (&format[1..], 16, 2)
            } else {
                (format, 8, 3)
            };
            let mut value = 0u16;
            let mut count = 0;
            for &digit in digits.iter().take(width) {
                let Some(digit) = char::from(digit).to_digit(radix) else {
                    break;
                };
                value = value * radix as u16 + digit as u16;
                count += 1;
            }
            if count != 0
                && let Ok(byte) = u8::try_from(value)
            {
                out.write_all(&[byte])?;
                return Ok(&digits[count..]);
            }
            out.write_all(&[b'\\', code])?;
            return Ok(&format[1..]);
        }
        _ => {
            out.write_all(&[b'\\', code])?;
            return Ok(&format[1..]);
        }
    };
    out.write_all(&[byte])?;
    Ok(&format[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_search_formats_filtered_metadata_and_byte_escapes() -> io::Result<()> {
        let mut bytes = Vec::new();
        render(
            br"%12#j\t%u\041\x41%%\z",
            &mut bytes,
            true,
            |out, field, kind| match (field, kind) {
                (b'j', Some(12)) => out.write_all(b"meta"),
                (b'u', None) => out.write_all(b"uri"),
                _ => Err(io::Error::other("wrong search format selector")),
            },
        )?;
        if bytes.as_slice() != b"meta\turi!A%\\z" {
            return Err(io::Error::other("search format changed its selected bytes"));
        }
        Ok(())
    }
}
