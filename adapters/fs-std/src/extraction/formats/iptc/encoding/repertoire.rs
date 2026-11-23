//! Registered graphic sets used by the IPTC IIM decoder.

use super::{Area, latin6937, multibyte::DoubleByte94, take};
use encoding_rs::{
    DecoderResult, ISO_8859_2, ISO_8859_3, ISO_8859_4, ISO_8859_5, ISO_8859_6, ISO_8859_7,
    ISO_8859_8, ISO_8859_10, ISO_8859_13, ISO_8859_14, ISO_8859_15, WINDOWS_1254,
};

/// One graphic position after decoding, including compound JIS characters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Glyph {
    Scalar(char),
    Pair(char, char),
}

impl Glyph {
    pub(super) const fn utf8_len(self) -> usize {
        match self {
            Self::Scalar(character) => character.len_utf8(),
            Self::Pair(first, second) => first.len_utf8() + second.len_utf8(),
        }
    }
}

impl From<char> for Glyph {
    fn from(character: char) -> Self {
        Self::Scalar(character)
    }
}

pub(super) enum Graphic {
    Primary(char),
    Glyph(Glyph),
    Diacritic(latin6937::Diacritic),
}

impl Graphic {
    pub(super) fn into_glyph(self) -> Option<Glyph> {
        match self {
            Self::Primary(character) => Some(character.into()),
            Self::Glyph(glyph) => Some(glyph),
            Self::Diacritic(_) => None,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Repertoire {
    Ascii,
    Irv,
    Graphic94(&'static [char; 94]),
    JisKatakana,
    Latin1,
    Latin1Euro,
    Latin6937,
    EcmaCyrillic,
    Graphic96(&'static [char; 96]),
    Greek1987,
    Hebrew1988,
    SingleByte(&'static encoding_rs::Encoding),
    EuroSingleByte(&'static encoding_rs::Encoding),
    DoubleByte94(DoubleByte94),
}

impl Repertoire {
    pub(super) fn set94(final_byte: u8) -> Option<Self> {
        Some(match final_byte {
            b'@' => Self::Irv,
            b'B' => Self::Ascii,
            b'I' => Self::JisKatakana,
            _ => Self::Graphic94(graphic94(final_byte)?),
        })
    }

    pub(super) fn set96(final_byte: u8) -> Option<Self> {
        Some(Self::SingleByte(match final_byte {
            b'@' => return Some(Self::EcmaCyrillic),
            b'A' => return Some(Self::Latin1),
            b'B' => ISO_8859_2,
            b'C' => ISO_8859_3,
            b'D' => ISO_8859_4,
            b'L' => ISO_8859_5,
            b'G' => ISO_8859_6,
            b'F' => return Some(Self::Greek1987),
            b'H' => return Some(Self::Hebrew1988),
            // Windows-1254 has the same graphic assignments above its C1 range.
            b'M' => WINDOWS_1254,
            b'N' => ISO_8859_8, // ISO-IR 198
            b'R' => return Some(Self::Latin6937),
            b'V' => ISO_8859_10,
            b'Y' => ISO_8859_13,
            b'_' => ISO_8859_14,
            b'b' => ISO_8859_15,
            // ISO-IR 204–206 replace the currency sign in Latin alphabets 1, 4 and 7.
            b'c' => return Some(Self::Latin1Euro),
            b'd' => return Some(Self::EuroSingleByte(ISO_8859_4)),
            b'e' => return Some(Self::EuroSingleByte(ISO_8859_13)),
            b'i' => ISO_8859_7,
            _ => return Some(Self::Graphic96(graphic96(final_byte)?)),
        }))
    }

    pub(super) fn is_94(self) -> bool {
        self.single_byte_94() || matches!(self, Self::DoubleByte94(_))
    }

    pub(super) fn single_byte_94(self) -> bool {
        matches!(
            self,
            Self::Ascii | Self::Irv | Self::Graphic94(_) | Self::JisKatakana
        )
    }

    pub(super) fn single_byte(self) -> bool {
        !matches!(self, Self::DoubleByte94(_))
    }

    pub(super) fn unchanged_ascii(self, bytes: &[u8]) -> bool {
        match self {
            Self::Ascii => bytes
                .iter()
                .all(|&byte| matches!(byte, 0x09..=0x0d | 0x20..=0x7e)),
            Self::Irv => bytes.iter().all(|&byte| {
                matches!(byte, 0x09..=0x0d | 0x20..=0x7e) && !matches!(byte, b'$' | b'~')
            }),
            _ => false,
        }
    }

    pub(super) fn graphic(self, first: u8, area: Area, bytes: &mut &[u8]) -> Option<Graphic> {
        if self.is_94() && !(0x21..=0x7e).contains(&first) {
            return None;
        }
        let character = match self {
            Self::Ascii => return Some(Graphic::Primary(char::from(first))),
            Self::Irv => Some(IRV[usize::from(first - 0x21)]),
            Self::Graphic94(table) => {
                let character = table[usize::from(first - 0x21)];
                (character != '\0').then_some(character)
            }
            // ISO-IR 13 assigns only the first 63 positions of the 94-set.
            Self::JisKatakana if first <= 0x5f => char::from_u32(0xff61 + u32::from(first - 0x21)),
            Self::JisKatakana => None,
            Self::Latin1Euro | Self::EuroSingleByte(_) if first == 0x24 => Some('€'),
            Self::Latin1 | Self::Latin1Euro => Some(char::from(first | 0x80)),
            Self::Latin6937 => return latin6937::graphic(first),
            Self::Graphic96(table) => {
                let character = table[usize::from(first - 0x20)];
                (character != '\0').then_some(character)
            }
            Self::EcmaCyrillic => {
                let position = usize::from(first - 0x20);
                Some(ECMA_CYRILLIC[position / 16][position % 16])
            }
            // ISO-IR 227 adds three positions to ISO-IR 126 (ISO 8859-7:1987).
            Self::Greek1987 => match first {
                0x24 | 0x25 | 0x2a => None,
                _ => scalar(ISO_8859_7, &[first | 0x80]),
            },
            // ISO-IR 138 has an overline and predates the direction marks.
            Self::Hebrew1988 => match first {
                0x2f => Some('‾'),
                0x7d | 0x7e => None,
                _ => scalar(ISO_8859_8, &[first | 0x80]),
            },
            Self::SingleByte(encoding) | Self::EuroSingleByte(encoding) => {
                scalar(encoding, &[first | 0x80])
            }
            Self::DoubleByte94(plane) => {
                return plane
                    .glyph(first, area.position(take(bytes)?)?)
                    .map(Graphic::Glyph);
            }
        }?;
        Some(Graphic::Glyph(character.into()))
    }
}

// ISO-IR 111 (ECMA-113:1986), in ISO 2022 graphic position order.
const ECMA_CYRILLIC: [[char; 16]; 6] = [
    [
        '\u{a0}', 'Ё', 'Ђ', 'Ѓ', 'Є', 'Ѕ', 'І', 'Ї', 'Ј', 'Љ', 'Њ', 'Ћ', 'Ќ', '\u{ad}', 'Ў', 'Џ',
    ],
    [
        '№', 'ё', 'ђ', 'ѓ', 'є', 'ѕ', 'і', 'ї', 'ј', 'љ', 'њ', 'ћ', 'ќ', '¤', 'ў', 'џ',
    ],
    [
        'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ж', 'З', 'И', 'Й', 'К', 'Л', 'М', 'Н', 'О', 'П',
    ],
    [
        'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ъ', 'Ы', 'Ь', 'Э', 'Ю', 'Я',
    ],
    [
        'а', 'б', 'в', 'г', 'д', 'е', 'ж', 'з', 'и', 'й', 'к', 'л', 'м', 'н', 'о', 'п',
    ],
    [
        'р', 'с', 'т', 'у', 'ф', 'х', 'ц', 'ч', 'ш', 'щ', 'ъ', 'ы', 'ь', 'э', 'ю', 'я',
    ],
];

pub(super) fn scalar(encoding: &'static encoding_rs::Encoding, bytes: &[u8]) -> Option<char> {
    let mut output = [0; 4];
    let (result, read, written) = encoding
        .new_decoder_without_bom_handling()
        .decode_to_utf8_without_replacement(bytes, &mut output, true);
    if result != DecoderResult::InputEmpty || read != bytes.len() {
        return None;
    }
    let mut characters = std::str::from_utf8(&output[..written]).ok()?.chars();
    let character = characters.next()?;
    characters.next().is_none().then_some(character)
}

pub(super) fn graphic94(final_byte: u8) -> Option<&'static [char; 94]> {
    Some(match final_byte {
        b'A' => &BRITISH,
        b'C' => &NATS_SEFI,
        b'D' => &NATS_SEFI_SECONDARY,
        b'E' => &NATS_DANO,
        b'F' => &NATS_DANO_SECONDARY,
        b'G' => &SWEDISH,
        b'J' => &JAPANESE_ROMAN,
        b'K' => &GERMAN,
        b'L' => &PORTUGUESE_OLIVETTI,
        b'N' => &CYRILLIC,
        b'Y' => &ITALIAN,
        b'Z' => &SPANISH_OLIVETTI,
        b'[' => &GREEK,
        b'`' => &NORWEGIAN,
        b'f' => &FRENCH,
        b'g' => &PORTUGUESE_IBM,
        b'h' => &SPANISH_IBM,
        b'i' => &HUNGARIAN,
        b'w' => &CANADIAN_FIRST,
        b'x' => &CANADIAN_SECOND,
        _ => return None,
    })
}

pub(super) fn graphic96(final_byte: u8) -> Option<&'static [char; 96]> {
    Some(match final_byte {
        b'I' => &CZECH,
        b'P' => &LATIN_SUPPLEMENT,
        b'Q' => &BOX_DRAWING,
        b'T' => &THAI,
        b'X' => &SAMI_SUPPLEMENT,
        b'\\' => &WELSH,
        b']' => &SAMI,
        b'f' => &ROMANIAN,
        b'h' => &SAMI_ROMANI,
        _ => return None,
    })
}

const fn ascii() -> [char; 94] {
    let mut table = ['\0'; 94];
    let mut index = 0;
    while index < table.len() {
        table[index] = (index as u8 + 0x21) as char;
        index += 1;
    }
    table
}

const fn replace(mut table: [char; 94], changes: &[(u8, char)]) -> [char; 94] {
    let mut index = 0;
    while index < changes.len() {
        let (byte, character) = changes[index];
        table[(byte - 0x21) as usize] = character;
        index += 1;
    }
    table
}

const fn range(mut table: [char; 94], start: u8, values: &[char]) -> [char; 94] {
    let mut index = 0;
    while index < values.len() {
        table[(start - 0x21) as usize + index] = values[index];
        index += 1;
    }
    table
}

// ISO-IR 2, 4, 10, 15–17, 21, 60, 69, 84–86, 121 and 122. The national
// editions share the ISO 646 positions outside their registered replacements.
pub(super) const IRV: [char; 94] = replace(ascii(), &[(b'$', '¤'), (b'~', '‾')]);
const BRITISH: [char; 94] = replace(ascii(), &[(b'#', '£'), (b'~', '‾')]);
// ISO-IR 14, JIS X 0201 Roman.
const JAPANESE_ROMAN: [char; 94] = replace(ascii(), &[(b'\\', '¥'), (b'~', '‾')]);
const SWEDISH: [char; 94] = replace(
    IRV,
    &[
        (b'[', 'Ä'),
        (b'\\', 'Ö'),
        (b']', 'Å'),
        (b'{', 'ä'),
        (b'|', 'ö'),
        (b'}', 'å'),
    ],
);
const ITALIAN: [char; 94] = replace(
    ascii(),
    &[
        (b'#', '£'),
        (b'@', '§'),
        (b'[', '°'),
        (b'\\', 'ç'),
        (b']', 'é'),
        (b'`', 'ù'),
        (b'{', 'à'),
        (b'|', 'ò'),
        (b'}', 'è'),
        (b'~', 'ì'),
    ],
);
const PORTUGUESE_OLIVETTI: [char; 94] = replace(
    ascii(),
    &[
        (b'@', '§'),
        (b'[', 'Ã'),
        (b'\\', 'Ç'),
        (b']', 'Õ'),
        (b'{', 'ã'),
        (b'|', 'ç'),
        (b'}', 'õ'),
        (b'~', '°'),
    ],
);
const SPANISH_OLIVETTI: [char; 94] = replace(
    ascii(),
    &[
        (b'#', '£'),
        (b'@', '§'),
        (b'[', '¡'),
        (b'\\', 'Ñ'),
        (b']', '¿'),
        (b'{', '°'),
        (b'|', 'ñ'),
        (b'}', 'ç'),
    ],
);
const GERMAN: [char; 94] = replace(
    ascii(),
    &[
        (b'@', '§'),
        (b'[', 'Ä'),
        (b'\\', 'Ö'),
        (b']', 'Ü'),
        (b'{', 'ä'),
        (b'|', 'ö'),
        (b'}', 'ü'),
        (b'~', 'ß'),
    ],
);
const NORWEGIAN: [char; 94] = replace(
    ascii(),
    &[
        (b'[', 'Æ'),
        (b'\\', 'Ø'),
        (b']', 'Å'),
        (b'{', 'æ'),
        (b'|', 'ø'),
        (b'}', 'å'),
        (b'~', '‾'),
    ],
);
const FRENCH: [char; 94] = replace(
    ascii(),
    &[
        (b'#', '£'),
        (b'@', 'à'),
        (b'[', '°'),
        (b'\\', 'ç'),
        (b']', '§'),
        (b'`', 'µ'),
        (b'{', 'é'),
        (b'|', 'ù'),
        (b'}', 'è'),
        (b'~', '¨'),
    ],
);
const PORTUGUESE_IBM: [char; 94] = replace(PORTUGUESE_OLIVETTI, &[(b'@', '´'), (b'~', '‾')]);
const SPANISH_IBM: [char; 94] = replace(
    ascii(),
    &[
        (b'@', '∙'),
        (b'[', '¡'),
        (b'\\', 'Ñ'),
        (b']', 'Ç'),
        (b'^', '¿'),
        (b'{', '´'),
        (b'|', 'ñ'),
        (b'}', 'ç'),
        (b'~', '¨'),
    ],
);
const HUNGARIAN: [char; 94] = replace(
    ascii(),
    &[
        (b'$', '¤'),
        (b'@', 'Á'),
        (b'[', 'É'),
        (b'\\', 'Ö'),
        (b']', 'Ü'),
        (b'`', 'á'),
        (b'{', 'é'),
        (b'|', 'ö'),
        (b'}', 'ü'),
        (b'~', '˝'),
    ],
);
const CANADIAN_FIRST: [char; 94] = replace(
    ascii(),
    &[
        (b'@', 'à'),
        (b'[', 'â'),
        (b'\\', 'ç'),
        (b']', 'ê'),
        (b'^', 'î'),
        (b'`', 'ô'),
        (b'{', 'é'),
        (b'|', 'ù'),
        (b'}', 'è'),
        (b'~', 'û'),
    ],
);
const CANADIAN_SECOND: [char; 94] = replace(CANADIAN_FIRST, &[(b'^', 'É')]);

// ISO-IR 8-1/2 and 9-1/2. Use the RFC 1345 private-use values for unit spaces A and B.
const NATS_SEFI: [char; 94] = replace(
    ascii(),
    &[
        (b'@', '\u{e002}'),
        (b'[', 'Ä'),
        (b'\\', 'Ö'),
        (b']', 'Å'),
        (b'^', '■'),
        (b'`', '\u{e003}'),
        (b'{', 'ä'),
        (b'|', 'ö'),
        (b'}', 'å'),
        (b'~', '–'),
    ],
);
const NATS_DANO: [char; 94] = replace(
    NATS_SEFI,
    &[
        (b'"', '«'),
        (b'#', '»'),
        (b'[', 'Æ'),
        (b'\\', 'Ø'),
        (b'{', 'æ'),
        (b'|', 'ø'),
    ],
);
const NATS_SEFI_SECONDARY: [char; 94] = replace(
    ['\0'; 94],
    &[
        (b'A', 'À'),
        (b'D', 'Đ'),
        (b'E', 'É'),
        (b'P', 'Þ'),
        (b'U', 'Ü'),
        (b'[', 'Æ'),
        (b'\\', 'Ø'),
        (b'a', 'à'),
        (b'd', 'đ'),
        (b'e', 'é'),
        (b'p', 'þ'),
        (b'u', 'ü'),
        (b'{', 'æ'),
        (b'|', 'ø'),
    ],
);
const NATS_DANO_SECONDARY: [char; 94] = replace(
    NATS_SEFI_SECONDARY,
    &[(b'[', 'Ä'), (b'\\', 'Ö'), (b'{', 'ä'), (b'|', 'ö')],
);

// ISO-IR 18. Spacing Greek marks use their current Unicode assignments.
const GREEK: [char; 94] = range(
    replace(ascii(), &[(b'#', '£')]),
    0x40,
    &[
        '´', 'α', 'β', 'ψ', 'δ', 'ε', 'φ', 'γ', 'η', 'ι', 'ξ', 'κ', 'λ', 'μ', 'ν', 'ο', 'π', 'ͺ',
        'ρ', 'σ', 'τ', 'θ', 'ω', 'ς', 'χ', 'υ', 'ζ', '῏', '᾿', '῎', '~', '_', '`', 'Α', 'Β', 'Ψ',
        'Δ', 'Ε', 'Φ', 'Γ', 'Η', 'Ι', 'Ξ', 'Κ', 'Λ', 'Μ', 'Ν', 'Ο', 'Π', '\0', 'Ρ', 'Σ', 'Τ', 'Θ',
        'Ω', '·', 'Χ', 'Υ', 'Ζ', '῟', '῾', '῞', '¨',
    ],
);

// ISO-IR 37 is the two-case ISO 5427 graphic set in the register. The
// similarly named single-case KOI-7 conversion loses the lowercase columns.
const CYRILLIC: [char; 94] = range(
    IRV,
    0x40,
    &[
        'ю', 'а', 'б', 'ц', 'д', 'е', 'ф', 'г', 'х', 'и', 'й', 'к', 'л', 'м', 'н', 'о', 'п', 'я',
        'р', 'с', 'т', 'у', 'ж', 'в', 'ь', 'ы', 'з', 'ш', 'э', 'щ', 'ч', 'ъ', 'Ю', 'А', 'Б', 'Ц',
        'Д', 'Е', 'Ф', 'Г', 'Х', 'И', 'Й', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Я', 'Р', 'С', 'Т', 'У',
        'Ж', 'В', 'Ь', 'Ы', 'З', 'Ш', 'Э', 'Щ', 'Ч',
    ],
);

// ISO-IR 139 (CSN 369103), from the ECMA registration as listed in RFC 1345.
pub(super) const CZECH: [char; 96] = [
    '\u{a0}', 'Ą', '˘', 'Ł', '$', 'Ľ', 'Ś', '§', '¨', 'Š', 'Ş', 'Ť', 'Ź', '\u{ad}', 'Ž', 'Ż', '°',
    'ą', '˛', 'ł', '´', 'ľ', 'ś', 'ˇ', '¸', 'š', 'ş', 'ť', 'ź', '˝', 'ž', 'ż', 'Ŕ', 'Á', 'Â', 'Ă',
    'Ä', 'Ĺ', 'Ć', 'Ç', 'Č', 'É', 'Ę', 'Ë', 'Ě', 'Í', 'Î', 'Ď', 'Đ', 'Ń', 'Ň', 'Ó', 'Ô', 'Ő', 'Ö',
    '×', 'Ř', 'Ů', 'Ú', 'Ű', 'Ü', 'Ý', 'Ţ', 'ß', 'ŕ', 'á', 'â', 'ă', 'ä', 'ĺ', 'ć', 'ç', 'č', 'é',
    'ę', 'ë', 'ě', 'í', 'î', 'ď', 'đ', 'ń', 'ň', 'ó', 'ô', 'ő', 'ö', '÷', 'ř', 'ů', 'ú', 'ű', 'ü',
    'ý', 'ţ', '˙',
];

// ISO-IR 154, the additional Latin set of ISO/IEC 10367.
const LATIN_SUPPLEMENT: [char; 96] = [
    '\0', '\0', 'Ā', 'Ĉ', 'Ċ', '\0', 'Ė', 'Ē', 'Ĝ', '‘', '“', '™', '←', '↑', '→', '↓', '\0', '\0',
    'ā', 'ĉ', 'ċ', 'ð', 'ė', 'ē', 'ĝ', '’', '”', '♪', '⅛', '⅜', '⅝', '⅞', '\0', 'Ğ', 'Ġ', 'Ģ', 'Ĥ',
    'Ħ', 'Ĩ', 'İ', 'Ī', 'Į', 'Ĳ', 'Ĵ', 'Ķ', 'Ļ', 'Ŀ', 'Ņ', '―', 'Ŋ', 'Ō', 'Œ', 'Ŗ', 'Ŝ', 'Ŧ', 'Þ',
    'Ũ', 'Ŭ', 'Ū', 'Ų', 'Ŵ', 'Ý', 'Ŷ', 'Ÿ', '\u{2126}', 'ğ', 'ġ', 'ģ', 'ĥ', 'ħ', 'ĩ', 'ı', 'ī',
    'į', 'ĳ', 'ĵ', 'ķ', 'ļ', 'ŀ', 'ņ', 'ĸ', 'ŋ', 'ō', 'œ', 'ŗ', 'ŝ', 'ŧ', 'þ', 'ũ', 'ŭ', 'ū', 'ų',
    'ŵ', 'ý', 'ŷ', 'ŉ',
];

// ISO-IR 155 assigns heavy single lines at 4/0–4/10 and an upper half block at 4/11.
const BOX_DRAWING: [char; 96] = {
    let mut table = ['\0'; 96];
    let assigned = [
        '┃', '━', '┏', '┓', '┗', '┛', '┣', '┫', '┳', '┻', '╋', '▀', '▄', '█', '▪', '\0', '│', '─',
        '┌', '┐', '└', '┘', '├', '┤', '┬', '┴', '┼', '░', '▒', '▓',
    ];
    let mut index = 0;
    while index < assigned.len() {
        table[0x20 + index] = assigned[index];
        index += 1;
    }
    table
};

// ISO-IR 166 uses TIS 620-2533 with NO-BREAK SPACE at position 2/00.
const THAI: [char; 96] = {
    let mut table = ['\0'; 96];
    table[0] = '\u{a0}';
    let mut index = 1;
    while index < 92 {
        if index <= 58 || index >= 63 {
            table[index] = char::from_u32(0x0e00 + index as u32).unwrap();
        }
        index += 1;
    }
    table
};

const fn latin1_with_replacements(replacements: &[(u8, char)]) -> [char; 96] {
    let mut table = ['\0'; 96];
    let mut index = 0;
    while index < table.len() {
        table[index] = (0xa0 + index as u8) as char;
        index += 1;
    }
    let mut index = 0;
    while index < replacements.len() {
        let (byte, character) = replacements[index];
        table[(byte - 0xa0) as usize] = character;
        index += 1;
    }
    table
}

// ISO-IR 158 complements Latin-6. RFC 1345 maps HIGH OGONEK to U+02BF.
const SAMI_SUPPLEMENT: [char; 96] = {
    let mut table = ['\0'; 96];
    table[0] = '´';
    table[0x10] = 'ʿ';
    let uppercase: [char; 16] = [
        'Ă', 'À', 'Ǟ', 'Ǡ', 'Ǣ', 'Ĕ', 'È', 'Ǥ', 'Ǧ', 'Ǩ', 'Ŏ', 'Ò', 'Ǫ', 'Ǭ', 'Ʒ', 'Ǯ',
    ];
    let lowercase: [char; 16] = [
        'ă', 'à', 'ǟ', 'ǡ', 'ǣ', 'ĕ', 'è', 'ǥ', 'ǧ', 'ǩ', 'ŏ', 'ò', 'ǫ', 'ǭ', 'ʒ', 'ǯ',
    ];
    let mut index = 0;
    while index < uppercase.len() {
        table[0x20 + index] = uppercase[index];
        table[0x40 + index] = lowercase[index];
        index += 1;
    }
    table
};

// ISO-IR 182 replaces thirteen Latin-1 characters with Welsh letters.
const WELSH: [char; 96] = latin1_with_replacements(&[
    (0xa8, 'Ẁ'),
    (0xaa, 'Ẃ'),
    (0xac, 'Ỳ'),
    (0xaf, 'Ÿ'),
    (0xb8, 'ẁ'),
    (0xba, 'ẃ'),
    (0xbc, 'ỳ'),
    (0xbd, 'Ẅ'),
    (0xbe, 'ẅ'),
    (0xd0, 'Ŵ'),
    (0xde, 'Ŷ'),
    (0xf0, 'ŵ'),
    (0xfe, 'ŷ'),
]);

// ISO-IR 197 replaces these positions of the ISO-IR 100 supplementary set.
const SAMI: [char; 96] = latin1_with_replacements(&[
    (0xa1, 'Č'),
    (0xa2, 'č'),
    (0xa3, 'Đ'),
    (0xa4, 'đ'),
    (0xa5, 'Ǥ'),
    (0xa6, 'ǥ'),
    (0xa8, 'Ǧ'),
    (0xaa, 'ǧ'),
    (0xac, 'Ǩ'),
    (0xae, 'ǩ'),
    (0xaf, 'Ŋ'),
    (0xb1, 'ŋ'),
    (0xb2, 'Š'),
    (0xb3, 'š'),
    (0xb4, '´'),
    (0xb5, 'Ŧ'),
    (0xb8, 'ŧ'),
    (0xb9, 'Ž'),
    (0xba, 'ž'),
    (0xbc, 'Ʒ'),
    (0xbd, 'ʒ'),
    (0xbe, 'Ǯ'),
    (0xbf, 'ǯ'),
]);

// ISO-IR 209 adds H with caron for Finnish Romani at the quotation marks.
const SAMI_ROMANI: [char; 96] = {
    let mut table = SAMI;
    table[0xab - 0xa0] = 'Ȟ';
    table[0xbb - 0xa0] = 'ȟ';
    table
};

// ISO-IR 226 (SR 14111:1998), also published as ISO 8859-16 (Latin-10).
const ROMANIAN: [char; 96] = [
    '\u{a0}', 'Ą', 'ą', 'Ł', '€', '„', 'Š', '§', 'š', '©', 'Ș', '«', 'Ź', '\u{ad}', 'ź', 'Ż', '°',
    '±', 'Č', 'ł', 'Ž', '”', '¶', '·', 'ž', 'č', 'ș', '»', 'Œ', 'œ', 'Ÿ', 'ż', 'À', 'Á', 'Â', 'Ă',
    'Ä', 'Ć', 'Æ', 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï', 'Đ', 'Ń', 'Ò', 'Ó', 'Ô', 'Ő', 'Ö',
    'Ś', 'Ű', 'Ù', 'Ú', 'Û', 'Ü', 'Ę', 'Ț', 'ß', 'à', 'á', 'â', 'ă', 'ä', 'ć', 'æ', 'ç', 'è', 'é',
    'ê', 'ë', 'ì', 'í', 'î', 'ï', 'đ', 'ń', 'ò', 'ó', 'ô', 'ő', 'ö', 'ś', 'ű', 'ù', 'ú', 'û', 'ü',
    'ę', 'ț', 'ÿ',
];

#[cfg(test)]
mod tests {
    use super::super::Encoding;

    #[test]
    fn regional_latin_sets_preserve_registered_assignments() {
        let mut output = String::new();
        let sami = Encoding::declared(b"\x1b-V\x1b.X");
        assert_eq!(
            sami.decode(
                b"\xc0\x1bN \x1bN0\x1bNB\x1bNC\x1bND\x1bNM\x1bNN\x1bNO\x1bNb\x1bNc\x1bNd\x1bNm\x1bNn\x1bNo",
                &mut output,
                128,
            ),
            Some("Ā´ʿǞǠǢǬƷǮǟǡǣǭʒǯ".as_bytes()),
        );
        assert_eq!(sami.decode(b"\x1bN!", &mut output, 128), None);
        assert_eq!(sami.decode(b"\x1bNP", &mut output, 128), None);

        let welsh = Encoding::declared(b"\x1b-\\");
        assert_eq!(
            welsh.decode(
                b"\xa4\xa8\xaa\xac\xaf\xb8\xba\xbc\xbd\xbe\xd0\xde\xf0\xfe\xff",
                &mut output,
                128,
            ),
            Some("¤ẀẂỲŸẁẃỳẄẅŴŶŵŷÿ".as_bytes()),
        );
    }

    #[test]
    fn iso_10367_supplements_preserve_graphics_and_unassigned_positions() {
        let mut output = String::new();
        let latin = Encoding::declared(b"\x1b/P");
        assert_eq!(
            latin.decode(
                b"\x1bO)\x1bO*\x1bO9\x1bO:\x1bO5\x1bO;\x1bO`",
                &mut output,
                32
            ),
            Some("‘“’”ð♪\u{2126}".as_bytes()),
        );
        assert_eq!(latin.decode(b"\x1bO@", &mut output, 32), None);

        let boxes = Encoding::declared(b"\x1b-Q");
        assert_eq!(
            boxes.decode(b"\xc0\xca\xcb\xd0\xda\xdd", &mut output, 32),
            Some("┃╋▀│┼▓".as_bytes()),
        );
        assert_eq!(boxes.decode(b"\xcf", &mut output, 32), None);
        assert_eq!(boxes.decode(b"\xde", &mut output, 32), None);
    }

    #[test]
    fn euro_designations_replace_only_the_base_currency_sign() {
        let cases: &[(&[u8], &[u8], &str)] = &[
            (b"\x1b-A", b"\xa4\x1b-c\xa4\xa8\xe9", "¤€¨é"),
            (b"\x1b-d", b"\xa1\xa4\xbd", "Ą€Ŋ"),
            (b"\x1b-e", b"\xa1\xa4\xaa", "”€Ŗ"),
            (b"\x1b.d", b"\x1bN$\x1bN=", "€Ŋ"),
            (b"\x1b/e", b"\x1bO$\x1bO!", "€”"),
        ];
        let mut output = String::new();
        for &(controls, data, expected) in cases {
            output.clear();
            assert_eq!(
                Encoding::declared(controls).decode(data, &mut output, 128),
                Some(expected.as_bytes()),
            );
        }
    }

    #[test]
    fn sami_designations_keep_the_two_registered_repertoires_distinct() {
        let cases: &[(&[u8], &[u8], &str)] = &[
            (
                b"\x1b-]",
                b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa8\xaa\xab\xac\xad\xae\xaf\xb1\xb2\xb3\xb4\xb5\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xff",
                "\u{a0}ČčĐđǤǥǦǧ«Ǩ\u{ad}ǩŊŋŠš´ŦŧŽž»ƷʒǮǯÀÿ",
            ),
            (b"\x1b-]", b"\xaa\xab\xbb\x1b-h\xaa\xab\xbb", "ǧ«»ǧȞȟ"),
            (b"\x1b.h", b"\x1bN+\x1bN;", "Ȟȟ"),
        ];
        let mut output = String::new();
        for &(controls, data, expected) in cases {
            output.clear();
            assert_eq!(
                Encoding::declared(controls).decode(data, &mut output, 128),
                Some(expected.as_bytes()),
            );
        }
    }
}
