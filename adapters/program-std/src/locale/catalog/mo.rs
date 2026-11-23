//! GNU MO string tables and system-dependent format segments.
use super::{plural::Plural, prefix};
use std::io;

const MAX_ENTRIES: usize = 65536;
const MAX_EXPANDED_BYTES: usize = 1024 * 1024;
const MAX_SEGMENTS: usize = 128;

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid GNU gettext catalog")
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

#[derive(Clone, Copy)]
struct Words<'a> {
    endian: Endian,
    bytes: &'a [u8],
}

impl<'a> Words<'a> {
    fn word(self, at: usize) -> io::Result<usize> {
        let word = self
            .bytes
            .get(at..at.checked_add(4).ok_or_else(malformed)?)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(malformed)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(word),
            Endian::Big => u32::from_be_bytes(word),
        } as usize)
    }

    fn range(self, at: usize, length: usize) -> io::Result<&'a [u8]> {
        self.bytes
            .get(at..at.checked_add(length).ok_or_else(malformed)?)
            .ok_or_else(malformed)
    }

    fn table(self, offset: usize, length: usize, width: usize) -> io::Result<()> {
        if length > MAX_ENTRIES {
            return Err(malformed());
        }
        self.range(offset, length * width).map(|_| ())
    }

    fn string(self, descriptor: usize, length_includes_nul: bool) -> io::Result<&'a [u8]> {
        let length = self.word(descriptor)?;
        let length = if length_includes_nul {
            length
        } else {
            length.checked_add(1).ok_or_else(malformed)?
        };
        self.range(self.word(descriptor + 4)?, length)?
            .strip_suffix(&[0])
            .ok_or_else(malformed)
    }
}

pub(super) struct Catalog {
    bytes: Vec<u8>,
    endian: Endian,
    original: usize,
    translated: usize,
    count: usize,
    dynamic: Vec<Dynamic>,
    expanded: usize,
    plural: Plural,
}

struct Dynamic {
    original: Vec<u8>,
    translated: Vec<u8>,
}

impl Catalog {
    pub(super) fn parse(bytes: Vec<u8>) -> io::Result<Self> {
        let endian = match bytes.get(..4) {
            Some([0xde, 0x12, 0x04, 0x95]) => Endian::Little,
            Some([0x95, 0x04, 0x12, 0xde]) => Endian::Big,
            _ => return Err(malformed()),
        };
        let words = Words {
            endian,
            bytes: &bytes,
        };
        words.range(0, 28)?;
        let revision = words.word(4)?;
        if revision > 1 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported gettext MO revision",
            ));
        }
        let count = words.word(8)?;
        let original = words.word(12)?;
        let translated = words.word(16)?;
        words.table(original, count, 8)?;
        words.table(translated, count, 8)?;
        let mut previous = None;
        let mut metadata = "";
        for index in 0..count {
            let key = words.string(original + index * 8, false)?;
            let value = words.string(translated + index * 8, false)?;
            std::str::from_utf8(key).map_err(io::Error::other)?;
            let value = std::str::from_utf8(value).map_err(io::Error::other)?;
            let key = prefix(key);
            if previous.is_some_and(|previous| previous >= key) {
                return Err(malformed());
            }
            if key.is_empty() {
                metadata = value;
            }
            previous = Some(key);
        }
        let plural = Plural::parse(metadata)?;
        let (dynamic, expanded) = if revision == 1 {
            dynamic(words)?
        } else {
            (Vec::new(), 0)
        };
        Ok(Self {
            bytes,
            endian,
            original,
            translated,
            count,
            dynamic,
            expanded,
            plural,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.bytes.len() + self.expanded
    }

    fn lookup(&self, message: &[u8]) -> Option<&[u8]> {
        let words = Words {
            endian: self.endian,
            bytes: &self.bytes,
        };
        let (mut left, mut right) = (0, self.count);
        while left < right {
            let index = left + (right - left) / 2;
            let original = words.string(self.original + index * 8, false).ok()?;
            match prefix(original).cmp(message) {
                std::cmp::Ordering::Less => left = index + 1,
                std::cmp::Ordering::Greater => right = index,
                std::cmp::Ordering::Equal => {
                    return words.string(self.translated + index * 8, false).ok();
                }
            }
        }
        let index = self
            .dynamic
            .binary_search_by(|entry| prefix(&entry.original).cmp(message))
            .ok()?;
        Some(&self.dynamic[index].translated)
    }

    pub(super) fn message(&self, message: &[u8], count: Option<u64>) -> Option<&[u8]> {
        let translated = self.lookup(message)?;
        let index = match count {
            Some(n) => self.plural.index(n)?,
            None => 0,
        };
        translated
            .split(|byte| *byte == 0)
            .nth(index)
            .filter(|form| !form.is_empty())
    }
}

fn dynamic(words: Words<'_>) -> io::Result<(Vec<Dynamic>, usize)> {
    words.range(0, 48)?;
    let segments = words.word(28)?;
    let segment_table = words.word(32)?;
    let strings = words.word(36)?;
    let originals = words.word(40)?;
    let translations = words.word(44)?;
    words.table(segment_table, segments, 8)?;
    words.table(originals, strings, 4)?;
    words.table(translations, strings, 4)?;
    if segments > MAX_SEGMENTS || strings > MAX_SEGMENTS {
        return Err(malformed());
    }
    let values = (0..segments)
        .map(|index| words.string(segment_table + index * 8, true).map(segment))
        .collect::<io::Result<Vec<_>>>()?;
    let mut dynamic = Vec::new();
    let mut retained = 0;
    for index in 0..strings {
        let (original, ok_original) = expand(
            words,
            words.word(originals + index * 4)?,
            &values,
            &mut retained,
        )?;
        let (translated, ok_translated) = expand(
            words,
            words.word(translations + index * 4)?,
            &values,
            &mut retained,
        )?;
        if ok_original && ok_translated {
            dynamic.push(Dynamic {
                original,
                translated,
            });
        }
    }
    dynamic.sort_unstable_by(|left, right| prefix(&left.original).cmp(prefix(&right.original)));
    if dynamic
        .windows(2)
        .any(|entries| prefix(&entries[0].original) == prefix(&entries[1].original))
    {
        return Err(malformed());
    }
    Ok((dynamic, retained))
}

fn expand(
    words: Words<'_>,
    descriptor: usize,
    segments: &[Option<Vec<u8>>],
    retained: &mut usize,
) -> io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    let mut string = words.word(descriptor)?;
    let mut pair = descriptor.checked_add(4).ok_or_else(malformed)?;
    let mut supported = true;
    for _ in 0..MAX_SEGMENTS {
        let length = words.word(pair)?;
        let reference = words.word(pair + 4)?;
        let mut part = words.range(string, length)?;
        if reference == u32::MAX as usize {
            part = part.strip_suffix(&[0]).ok_or_else(malformed)?;
        }
        append(&mut bytes, part, retained)?;
        if reference == u32::MAX as usize {
            std::str::from_utf8(&bytes).map_err(io::Error::other)?;
            return Ok((bytes, supported));
        }
        match segments.get(reference).ok_or_else(malformed)? {
            Some(segment) => append(&mut bytes, segment, retained)?,
            None => supported = false,
        }
        string += length;
        pair += 8;
    }
    Err(malformed())
}

fn append(bytes: &mut Vec<u8>, part: &[u8], retained: &mut usize) -> io::Result<()> {
    if part.len() > MAX_EXPANDED_BYTES - *retained {
        return Err(malformed());
    }
    bytes.extend_from_slice(part);
    *retained += part.len();
    Ok(())
}

fn segment(name: &[u8]) -> Option<Vec<u8>> {
    let Some((&kind, width)) = name
        .strip_prefix(b"PRI")
        .and_then(|name| name.split_first())
    else {
        return (name == b"I").then(Vec::new);
    };
    if !b"diouxX".contains(&kind) {
        return None;
    }
    let wide = if cfg!(all(
        not(windows),
        not(target_vendor = "apple"),
        target_pointer_width = "64"
    )) {
        b"l".as_slice()
    } else {
        b"ll"
    };
    let length: &[u8] = match width {
        b"8" | b"LEAST8" | b"FAST8" => b"hh",
        b"16" | b"LEAST16" => b"h",
        b"32" | b"LEAST32" => b"",
        b"64" | b"LEAST64" | b"FAST64" | b"MAX" => wide,
        b"PTR" if cfg!(target_pointer_width = "64") => wide,
        b"PTR" => b"",
        b"FAST16" | b"FAST32"
            if cfg!(all(
                target_env = "gnu",
                target_pointer_width = "64",
                target_os = "linux"
            )) =>
        {
            b"l"
        }
        b"FAST16" => b"h",
        b"FAST32" => b"",
        _ => return None,
    };
    let mut value = length.to_vec();
    value.push(kind);
    Some(value)
}
