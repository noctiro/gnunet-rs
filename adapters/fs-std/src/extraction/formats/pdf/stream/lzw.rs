//! PDF LZW codes with a 12-bit dictionary and bounded output.

use super::Output;

const CLEAR: u16 = 256;
const END: u16 = 257;
const FIRST_PHRASE: u16 = 258;
const TABLE_LIMIT: u16 = 4096;

/// How soon the code width grows at each dictionary boundary.
#[derive(Clone, Copy)]
pub(super) enum EarlyChange {
    Late,
    Early,
}

impl EarlyChange {
    const fn advance(self) -> u16 {
        match self {
            Self::Late => 0,
            Self::Early => 1,
        }
    }
}

/// Decode one MSB-first member with the caller's output bound.
pub(super) fn decode(input: &[u8], output: &mut Output, change: EarlyChange) -> Option<()> {
    let mut codes = Codes {
        input,
        bits: 0,
        available: 0,
    };
    let mut table = Table::new(change);
    let mut previous: Option<Phrase> = None;

    loop {
        let code = codes.take(table.width)?;
        match code {
            CLEAR => {
                table.clear();
                previous = None;
                continue;
            }
            END => return (codes.input.is_empty() && codes.bits == 0).then_some(()),
            _ if table.next == TABLE_LIMIT => return None,
            _ => {}
        }

        let known = table.phrase(code);
        let phrase = match (known, previous) {
            (Some(phrase), Some(prefix)) => {
                table.insert(prefix, phrase.first)?;
                phrase
            }
            // The next code can refer to the phrase currently being built.
            (None, Some(prefix)) if code == table.next => table.insert(prefix, prefix.first)?,
            (phrase, None) => phrase?,
            _ => return None,
        };
        table.emit(phrase, output)?;
        previous = Some(phrase);
    }
}

struct Codes<'a> {
    input: &'a [u8],
    bits: u32,
    available: u8,
}

impl Codes<'_> {
    fn take(&mut self, width: u8) -> Option<u16> {
        while self.available < width {
            let (&byte, remaining) = self.input.split_first()?;
            self.input = remaining;
            self.bits = (self.bits << 8) | u32::from(byte);
            self.available += 8;
        }
        self.available -= width;
        let code = (self.bits >> self.available) as u16;
        self.bits &= (1_u32 << self.available) - 1;
        Some(code)
    }
}

#[derive(Clone, Copy)]
struct Phrase {
    code: u16,
    length: u16,
    first: u8,
}

#[derive(Clone, Copy)]
struct Entry {
    prefix: u16,
    length: u16,
    first: u8,
    suffix: u8,
}

struct Table {
    entries: [Entry; (TABLE_LIMIT - FIRST_PHRASE) as usize],
    next: u16,
    width: u8,
    change: EarlyChange,
}

impl Table {
    fn new(change: EarlyChange) -> Self {
        Self {
            entries: [Entry {
                prefix: 0,
                length: 0,
                first: 0,
                suffix: 0,
            }; (TABLE_LIMIT - FIRST_PHRASE) as usize],
            next: FIRST_PHRASE,
            width: 9,
            change,
        }
    }

    fn clear(&mut self) {
        self.next = FIRST_PHRASE;
        self.width = 9;
    }

    fn phrase(&self, code: u16) -> Option<Phrase> {
        if let Ok(first) = u8::try_from(code) {
            return Some(Phrase {
                code,
                length: 1,
                first,
            });
        }
        let entry = self.entry(code)?;
        Some(Phrase {
            code,
            length: entry.length,
            first: entry.first,
        })
    }

    fn entry(&self, code: u16) -> Option<Entry> {
        if code >= self.next {
            return None;
        }
        self.entries
            .get(usize::from(code.checked_sub(FIRST_PHRASE)?))
            .copied()
    }

    fn insert(&mut self, prefix: Phrase, suffix: u8) -> Option<Phrase> {
        let code = self.next;
        let length = prefix.length + 1;
        let first = prefix.first;
        let slot = self.entries.get_mut(usize::from(code - FIRST_PHRASE))?;
        *slot = Entry {
            prefix: prefix.code,
            length,
            first,
            suffix,
        };
        self.next += 1;
        if self.width < 12 && self.next + self.change.advance() == 1 << self.width {
            self.width += 1;
        }
        Some(Phrase {
            code,
            length,
            first,
        })
    }

    fn emit(&self, phrase: Phrase, output: &mut Output) -> Option<()> {
        if phrase.length == 1 {
            return output.append(&[phrase.first]);
        }
        let (first, suffixes) = output
            .fill(usize::from(phrase.length), 0)?
            .split_first_mut()?;
        let mut code = phrase.code;
        for byte in suffixes.iter_mut().rev() {
            let entry = self.entry(code)?;
            *byte = entry.suffix;
            code = entry.prefix;
        }
        *first = phrase.first;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CLEAR, END, EarlyChange, Output, decode};

    #[test]
    fn both_width_schedules_reach_twelve_bits_and_clear_the_full_table() {
        for (change, nine_bit_literals) in [(EarlyChange::Early, 254), (EarlyChange::Late, 255)] {
            let mut codes = vec![(CLEAR, 9)];
            let sections = [
                (9, nine_bit_literals),
                (10, 512),
                (11, 1024),
                (12, 3_839 - nine_bit_literals - 512 - 1024),
            ];
            for (width, count) in sections {
                codes.extend(std::iter::repeat_n((u16::from(b'A') + width, width), count));
            }
            codes.extend([(CLEAR, 12), (u16::from(b'X'), 9), (END, 9)]);
            let mut output = Output::new(3_840);
            assert_eq!(decode(&pack(&codes), &mut output, change), Some(()));
            let mut start = 0;
            for (width, count) in sections {
                assert!(
                    output.bytes[start..start + count]
                        .iter()
                        .all(|&byte| byte == b'A' + width as u8)
                );
                start += count;
            }
            assert_eq!(output.bytes.get(start..), Some(b"X".as_slice()));
        }
    }

    #[test]
    fn next_phrase_reference_and_byte_limit() {
        let codes = [(CLEAR, 9), (u16::from(b'A'), 9), (258, 9), (END, 9)];
        let bytes = pack(&codes);
        let mut output = Output::new(3);
        assert_eq!(decode(&bytes, &mut output, EarlyChange::Early), Some(()));
        assert_eq!(output.bytes, b"AAA");
        let mut short = Output::new(2);
        assert_eq!(decode(&bytes, &mut short, EarlyChange::Early), None);
        assert_eq!(short.bytes, b"A");
    }

    fn pack(codes: &[(u16, u16)]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut bits = 0_u32;
        let mut available = 0_u16;
        for &(code, width) in codes {
            bits = (bits << width) | u32::from(code);
            available += width;
            while available >= 8 {
                available -= 8;
                output.push((bits >> available) as u8);
            }
            bits &= (1_u32 << available) - 1;
        }
        if available > 0 {
            output.push((bits << (8 - available)) as u8);
        }
        output
    }
}
