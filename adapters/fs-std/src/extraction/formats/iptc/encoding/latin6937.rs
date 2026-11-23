//! ISO-IR 156 supplementary graphics and ISO/IEC 6937 accented letters.

use super::repertoire::{Glyph, Graphic};

#[derive(Clone, Copy)]
struct Accent {
    bases: &'static [u8],
    letters: &'static [char],
}

impl Accent {
    const fn new<const N: usize>(bases: &'static [u8; N], letters: &'static [char; N]) -> Self {
        Self { bases, letters }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Diacritic(Accent);

impl Diacritic {
    pub(super) fn compose(self, base: Graphic) -> Option<Glyph> {
        let Graphic::Primary(base) = base else {
            return None;
        };
        let base = u8::try_from(base).ok()?;
        let index = self.0.bases.iter().position(|&byte| byte == base)?;
        Some(Glyph::Scalar(self.0.letters[index]))
    }
}

pub(super) fn graphic(first: u8) -> Option<Graphic> {
    let position = usize::from(first - 0x20);
    let row = position / 16;
    let column = position % 16;
    if row == 2 {
        return Some(Graphic::Diacritic(Diacritic(ACCENTS[column]?)));
    }
    let character = SUPPLEMENT[row][column];
    (character != '\0').then_some(Graphic::Glyph(Glyph::Scalar(character)))
}

// ISO-IR 156 positions 2/00 to 7/15. Row 4 contains non-spacing marks.
const SUPPLEMENT: [[char; 16]; 6] = [
    [
        '\u{a0}', '¡', '¢', '£', '\0', '¥', '\0', '§', '¤', '‘', '“', '«', '←', '↑', '→', '↓',
    ],
    [
        '°', '±', '²', '³', '×', 'µ', '¶', '·', '÷', '’', '”', '»', '¼', '½', '¾', '¿',
    ],
    ['\0'; 16],
    [
        '―', '¹', '®', '©', '™', '♪', '¬', '¦', '\0', '\0', '\0', '\0', '⅛', '⅜', '⅝', '⅞',
    ],
    [
        'Ω', 'Æ', 'Đ', 'ª', 'Ħ', '\0', 'Ĳ', 'Ŀ', 'Ł', 'Ø', 'Œ', 'º', 'Þ', 'Ŧ', 'Ŋ', 'ŉ',
    ],
    [
        'ĸ', 'æ', 'đ', 'ð', 'ħ', 'ı', 'ĳ', 'ŀ', 'ł', 'ø', 'œ', 'ß', 'þ', 'ŧ', 'ŋ', '\u{ad}',
    ],
];

// ISO/IEC 6937 table 4 and Annex C. Space selects the spacing mark where
// assigned. Acute plus small g names g with cedilla (clause 8.3, note 11).
const ACCENTS: [Option<Accent>; 16] = [
    None,
    Some(Accent::new(
        b"AEIOUaeiou",
        &['À', 'È', 'Ì', 'Ò', 'Ù', 'à', 'è', 'ì', 'ò', 'ù'],
    )),
    Some(Accent::new(
        b" ACEILNORSUYZacegilnorsuyz",
        &[
            '´', 'Á', 'Ć', 'É', 'Í', 'Ĺ', 'Ń', 'Ó', 'Ŕ', 'Ś', 'Ú', 'Ý', 'Ź', 'á', 'ć', 'é', 'ģ',
            'í', 'ĺ', 'ń', 'ó', 'ŕ', 'ś', 'ú', 'ý', 'ź',
        ],
    )),
    Some(Accent::new(
        b"ACEGHIJOSUWYaceghijosuwy",
        &[
            'Â', 'Ĉ', 'Ê', 'Ĝ', 'Ĥ', 'Î', 'Ĵ', 'Ô', 'Ŝ', 'Û', 'Ŵ', 'Ŷ', 'â', 'ĉ', 'ê', 'ĝ', 'ĥ',
            'î', 'ĵ', 'ô', 'ŝ', 'û', 'ŵ', 'ŷ',
        ],
    )),
    Some(Accent::new(
        b"AINOUainou",
        &['Ã', 'Ĩ', 'Ñ', 'Õ', 'Ũ', 'ã', 'ĩ', 'ñ', 'õ', 'ũ'],
    )),
    Some(Accent::new(
        b" AEIOUaeiou",
        &['¯', 'Ā', 'Ē', 'Ī', 'Ō', 'Ū', 'ā', 'ē', 'ī', 'ō', 'ū'],
    )),
    Some(Accent::new(
        b" AGUagu",
        &['˘', 'Ă', 'Ğ', 'Ŭ', 'ă', 'ğ', 'ŭ'],
    )),
    Some(Accent::new(
        b" CEGIZcegz",
        &['˙', 'Ċ', 'Ė', 'Ġ', 'İ', 'Ż', 'ċ', 'ė', 'ġ', 'ż'],
    )),
    Some(Accent::new(
        b" AEIOUYaeiouy",
        &[
            '¨', 'Ä', 'Ë', 'Ï', 'Ö', 'Ü', 'Ÿ', 'ä', 'ë', 'ï', 'ö', 'ü', 'ÿ',
        ],
    )),
    None,
    Some(Accent::new(b" AUau", &['˚', 'Å', 'Ů', 'å', 'ů'])),
    Some(Accent::new(
        b" CGKLNRSTcklnrst",
        &[
            '¸', 'Ç', 'Ģ', 'Ķ', 'Ļ', 'Ņ', 'Ŗ', 'Ş', 'Ţ', 'ç', 'ķ', 'ļ', 'ņ', 'ŗ', 'ş', 'ţ',
        ],
    )),
    None,
    Some(Accent::new(b" OUou", &['˝', 'Ő', 'Ű', 'ő', 'ű'])),
    Some(Accent::new(
        b" AEIUaeiu",
        &['˛', 'Ą', 'Ę', 'Į', 'Ų', 'ą', 'ę', 'į', 'ų'],
    )),
    Some(Accent::new(
        b" CDELNRSTZcdelnrstz",
        &[
            'ˇ', 'Č', 'Ď', 'Ě', 'Ľ', 'Ň', 'Ř', 'Š', 'Ť', 'Ž', 'č', 'ď', 'ě', 'ľ', 'ň', 'ř', 'š',
            'ť', 'ž',
        ],
    )),
];
