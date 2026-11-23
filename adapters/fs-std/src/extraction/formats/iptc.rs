//! IPTC IIM datasets projected to the GNU image metadata registry.

mod encoding;

use std::ops::Range;

use encoding::Encoding;

const KEYWORDS: u32 = 49;
const KEYWORD_DATASET: u8 = 25;
const LOCATIONS: [(u8, u32); 3] = [(90, 41), (92, 42), (101, 43)];

/// A complete IIM packet with the first occurrence of each location field.
pub(super) struct Profile<'a> {
    keywords: &'a [u8],
    locations: [Option<&'a [u8]>; LOCATIONS.len()],
    encoding: Encoding,
}

impl<'a> Profile<'a> {
    pub(super) fn parse(bytes: &'a [u8], max_zero_padding: usize) -> Option<Self> {
        let mut remaining = bytes;
        let mut keywords: Option<Range<usize>> = None;
        let mut locations = [None; LOCATIONS.len()];
        let mut encoding = None;
        while !remaining.is_empty() {
            if remaining.len() <= max_zero_padding.min(3) && remaining.iter().all(|&b| b == 0) {
                break;
            }
            let start = bytes.len() - remaining.len();
            let dataset = Dataset::take(&mut remaining)?;
            match (dataset.record, dataset.number) {
                (1, 90) => {
                    encoding.get_or_insert_with(|| Encoding::declared(dataset.data));
                }
                (2, KEYWORD_DATASET) => {
                    let end = bytes.len() - remaining.len();
                    keywords.get_or_insert(start..end).end = end;
                }
                (2, number) => {
                    if let Some(index) = LOCATIONS.iter().position(|&(tag, _)| tag == number) {
                        locations[index].get_or_insert(dataset.data);
                    }
                }
                _ => {}
            }
        }
        if remaining.len() == bytes.len() {
            return None;
        }
        Some(Self {
            keywords: keywords.map_or(&[], |range| &bytes[range]),
            locations,
            encoding: encoding.unwrap_or(Encoding::DEFAULT),
        })
    }

    pub(super) fn emit<E>(
        &self,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut output = String::new();
        let mut keywords = self.keywords;
        while let Some(dataset) = Dataset::take(&mut keywords) {
            if (dataset.record, dataset.number) == (2, KEYWORD_DATASET)
                && let Some(text) = self.encoding.decode(dataset.data, &mut output, limit)
            {
                emit(KEYWORDS, text)?;
            }
        }
        for ((_, kind), bytes) in LOCATIONS.into_iter().zip(self.locations) {
            if let Some(bytes) = bytes
                && let Some(text) = self.encoding.decode(bytes, &mut output, limit)
            {
                emit(kind, text)?;
            }
        }
        Ok(())
    }
}

struct Dataset<'a> {
    record: u8,
    number: u8,
    data: &'a [u8],
}

impl<'a> Dataset<'a> {
    fn take(bytes: &mut &'a [u8]) -> Option<Self> {
        let slice = *bytes;
        let &[0x1c, record, number, high, low] = slice.first_chunk::<5>()? else {
            return None;
        };
        let mut remaining = slice.get(5..)?;
        let size = u16::from_be_bytes([high, low]);
        let length = if size & 0x8000 == 0 {
            usize::from(size)
        } else {
            let width = usize::from(size & 0x7fff);
            if !(1..=4).contains(&width) {
                return None;
            }
            let (encoded, tail) = remaining.split_at_checked(width)?;
            remaining = tail;
            let length = encoded
                .iter()
                .fold(0u32, |length, &byte| (length << 8) | u32::from(byte));
            usize::try_from(length).ok()?
        };
        let (data, tail) = remaining.split_at_checked(length)?;
        *bytes = tail;
        Some(Self {
            record,
            number,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Profile;

    #[test]
    fn retains_repeatable_keywords_and_one_each_of_the_gnu_location_fields()
    -> Result<(), &'static str> {
        let bytes = [
            b"\x1c\x01\x5a\x00\x03\x1b%G".as_slice(),
            b"\x1c\x02\x65\x00\x05Japan",
            b"\x1c\x02\x19\x00\x07 \xe6\x98\x9f\xe5\x85\x89",
            b"\x1c\x02\x5a\x00\x05Tokyo",
            b"\x1c\x02\x19\x00\x06garden",
            b"\x1c\x02\x5a\x00\x05Osaka",
            b"\x1c\x02\x5c\x00\x04Ueno",
        ]
        .concat();
        let profile = Profile::parse(&bytes, 0).ok_or("expected complete IIM packet")?;
        let mut fields = Vec::new();
        profile.emit(32, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok::<(), &'static str>(())
        })?;
        let expected = [
            (49, "星光".as_bytes().to_vec()),
            (49, b"garden".to_vec()),
            (41, b"Tokyo".to_vec()),
            (42, b"Ueno".to_vec()),
            (43, b"Japan".to_vec()),
        ];
        if fields != expected {
            return Err("unexpected IPTC metadata");
        }
        Ok(())
    }

    #[test]
    fn validates_extended_lengths_and_applies_only_carrier_padding() -> Result<(), &'static str> {
        let bytes =
            b"\x1c\x01\x5a\x00\x03\x1b-A\x1c\x02\x19\x80\x04\x00\x00\x00\x04caf\xe9\x00\x00\x00";
        if Profile::parse(bytes, 0).is_some()
            || Profile::parse(&bytes[..11], 3).is_some()
            || Profile::parse(b"\x1c\x02\x19\x80\x00", 3).is_some()
        {
            return Err("invalid framing accepted");
        }
        let profile = Profile::parse(bytes, 3).ok_or("expected zero-padded IIM packet")?;
        let mut emitted = false;
        profile.emit(5, &mut |kind, value| {
            if kind != 49 || value != "café".as_bytes() {
                return Err("expected a UTF-8 keyword");
            }
            emitted = true;
            Ok(())
        })?;
        if !emitted {
            return Err("expected one keyword");
        }
        profile.emit(4, &mut |_, _| Err("decoded length must fit"))
    }

    #[test]
    fn a_declared_character_set_selects_the_exact_encoding() -> Result<(), &'static str> {
        let latin = Profile::parse(b"\x1c\x01\x5a\x00\x03\x1b-A\x1c\x02\x19\x00\x02\xc3\xa9", 0)
            .ok_or("expected a Latin-1 packet")?;
        let invalid_utf8 = Profile::parse(b"\x1c\x01\x5a\x00\x03\x1b%G\x1c\x02\x19\x00\x01\xe9", 0)
            .ok_or("expected a packet with invalid UTF-8 text")?;
        let mut fields = Vec::new();
        latin.emit(16, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok::<(), &'static str>(())
        })?;
        if fields != [(49, "Ã©".as_bytes().to_vec())] {
            return Err("expected the declared Latin-1 decoding");
        }
        invalid_utf8.emit(16, &mut |_, _| Err("invalid declared UTF-8 was emitted"))
    }

    #[test]
    fn undeclared_text_uses_irv_and_dv_initial_state() -> Result<(), String> {
        for (declared, data, expected) in [
            (None, b" ~$".as_slice(), Some("‾¤")),
            (None, b"caf\xc3\xa9", None),
            (None, b"caf\xe9", None),
            (None, b"\x1b-A$caf\xe9", Some("¤café")),
            (None, b"x\x1b)K\x0e{\x0fy", Some("xäy")),
            (None, b"\x1b-K\x0e\xe9", None),
            (None, b"\x1b.B\x8e?", None),
            (None, b"\x1b\"G\x1b.B\x8e?", Some("ż")),
            (None, b"a\x1bEb", None),
            (None, b"a\x1b\"C\x1bEb", Some("a\nb")),
            (None, b"\x1b Ktext", None),
            (Some(b"".as_slice()), b"text", None),
        ] {
            let mut packet = Vec::new();
            if let Some(controls) = declared {
                packet.extend_from_slice(&[0x1c, 1, 90, 0, controls.len() as u8]);
                packet.extend_from_slice(controls);
            }
            packet.extend_from_slice(&[0x1c, 2, 25, 0, data.len() as u8]);
            packet.extend_from_slice(data);
            let profile = Profile::parse(&packet, 0).ok_or("expected a complete packet")?;
            let mut seen = None;
            profile.emit(32, &mut |kind, value| {
                if kind != 49 || seen.is_some() {
                    return Err("expected one keyword");
                }
                seen = Some(value.to_vec());
                Ok(())
            })?;
            if seen.as_deref() != expected.map(str::as_bytes) {
                return Err(format!("default IIM text {data:02x?} yielded {seen:?}"));
            }
        }
        Ok(())
    }

    #[test]
    fn declared_initial_repertoires_and_right_side_invocations() -> Result<(), String> {
        check_declarations(&[
            (b"\x1b(B", b"ASCII", Some("ASCII")),
            (b"\x1b(A", b"#10", Some("£10")),
            (b"\x1b(@", b"$10~", Some("¤10‾")),
            (b"\x1b(C", b"@[{^`~", Some("\u{e002}Ää■\u{e003}–")),
            (b"\x1b*D", b"\x1bNE", Some("É")),
            (b"\x1b(E", b"\"[\\]#", Some("«ÆØÅ»")),
            (b"\x1b)F", b"x\xc1\xdb", Some("xÀÄ")),
            (b"\x1b(D", b"B", None),
            (b"\x1b(G", b"V}rby$", Some("Vårby¤")),
            (b"\x1b(K", b"M}nchen", Some("München")),
            (b"\x1b(L", b"S{o", Some("São")),
            (b"\x1b(N", b"mOSKWA", Some("Москва")),
            (b"\x1b(Y", b"Universit{", Some("Università")),
            (b"\x1b(Z", b"\\and|", Some("Ñandñ")),
            (b"\x1b([", b"auhna", Some("ΑΘΗΝΑ")),
            (b"\x1b([", b"q", None),
            (b"\x1b(`", b"Troms|", Some("Tromsø")),
            (b"\x1b(f", b"{t{", Some("été")),
            (b"\x1b(g", b"@|", Some("´ç")),
            (b"\x1b(h", b"^[", Some("¿¡")),
            (b"\x1b(i", b"@~", Some("Á˝")),
            (b"\x1b(w", b"^le", Some("île")),
            (b"\x1b(x", b"^t{", Some("Été")),
            (b"\x1b(B\x1b-B", b"Za\xbf\xf3\xb3\xe6", Some("Zażółć")),
            (b"\x1b-G\x1b~", b"\xc7\xe4", Some("ال")),
            (b"\x1b-I", b"\xa4\xc8\xe8", Some("$Čč")),
            (b"\x1b.@\x1b}", b"\xcc\xee\xf1\xea\xe2\xe0", Some("Москва")),
            (b"\x1b.L\x1b}", b"\xbc\xde\xe1\xda\xd2\xd0", Some("Москва")),
            (b"\x1b/F\x1b|", b"\xc1\xe8\xde\xed\xe1", Some("Αθήνα")),
            (b"\x1b-F", b"\xa4", None),
            (b"\x1b-F", b"\xa5", None),
            (b"\x1b-F", b"\xaa", None),
            (b"\x1b.F", b"\x1bN$", None),
            (b"\x1b-i", b"\xa4\xa5\xaa", Some("€₯ͺ")),
            (b"\x1b.i", b"\x1bN$", Some("€")),
            (b"\x1b-H", b"\xaf\xe0\xe1", Some("‾אב")),
            (b"\x1b-H", b"\xfd", None),
            (b"\x1b-H", b"\xfe", None),
            (b"\x1b.H", b"\x1bN/", Some("‾")),
            (b"\x1b-N", b"\xaf\xfd\xfe", Some("¯\u{200e}\u{200f}")),
            (b"\x1b-b", b"\xa4", Some("€")),
            (b"\x1b(J", b"\\~", Some("¥‾")),
            (b"\x1b)I", b"\xa1\xb6\xc5\xdf", Some("｡ｶﾅﾟ")),
            (b"\x1b)I", b"\xe0", None),
            (b"\x1b$B", b"F|K\x5c", Some("日本")),
            (b"\x1b$@", b"2*", Some("鷗")),
            (b"\x1b$)@", b"\x0e15\x0f", Some("欝\u{e0101}")),
            (b"\x1b$(D", b"\"/\"70!", Some("˘~丂")),
            (b"\x1b$)D", b"\xa2\xaf", Some("˘")),
            (b"\x1b$+D", b"\x1bO\"/A", Some("˘A")),
            (b"\x1b$(D", b"!!", None),
            (b"\x1b$(D", b"\"", None),
            (b"\x1b$D", b"\"/", None),
            (b"\x1b$A", b"VP9z!$!*", Some("中国・―")),
            (b"\x1b$)A", b"x\xd6\xd0\xb9\xfa", Some("x中国")),
            (b"\x1b$*A", b"x\x1bNVPz", Some("x中z")),
            (b"\x1b$A", b"\"!", None),
            (b"\x1b$A", b"Wz", None),
            (b"\x1b$(C", b"GQ19$T", Some("한국\u{3164}")),
            (b"\x1b$)C", b"x\xc7\xd1\xb1\xb9", Some("x한국")),
            (b"\x1b$+C", b"\x1bOGQA", Some("한A")),
            (b"\x1b$(C", b"\"f", None),
            (b"\x1b$)C", b"\xa2\xe7", None),
            (b"\x1b$)C", b"\xc7", None),
            (b"\x1b$C", b"GQ", None),
            (b"\x1b.B\x1b~", b"\xbf", None),
            (b"\x1b.-", b"\xbf", None),
            (b"\x1b%G\x1b(B", b"ASCII", None),
            (b"\x1b-G", b"\xa1", None),
            (b"\x1b-B", b"\x1b-Acaf\xe9", Some("café")),
            (b"\x1b)K", b"x\x0e{\x0fy", Some("xäy")),
            (
                b"\x1b-A\x1b.B\x1b/F",
                b"\xe9\x1b}\xbf\x1b|\xe8",
                Some("éżθ"),
            ),
            (b"\x1b.B\x1b/A", b"\x1bN?\x1bOiA", Some("żéA")),
            (b"\x1b.B\x1b/A", b"\x8e?\x8fiA", Some("żéA")),
            (b"\x1b.B\x1b/A", b"\x1bN?\x8fiA", None),
            (b"\x1b \\\x1b/A", b"\x8f\xe9A", Some("éA")),
            (b"\x1b A\x1b(K\x1b*K", b"M\x1bN{l", Some("Mäl")),
            (b"\x1b A\x1b-A", b"\xe9", None),
            (b"\x1b A", b"a\x0fb", None),
            (b"\x1b B\x1b)K", b"x\x0e{\x0fy", Some("xäy")),
            (b"\x1b B\x1b)K", b"\xfb", None),
            (b"\x1b B\x1b)K", b"\x1b~{", None),
            (b"\x1b C\x1b-A", b"Caf\xe9", Some("Café")),
            (b"\x1b C\x1b-A", b"\x1b-B\xbf", Some("ż")),
            (b"\x1b C\x1b-A", b"\x0ei", None),
            (b"\x1b J\x1b C", b"text", None),
            (b"\x1b C\x1b J", b"text", None),
            (b"\x1b A\x1b C", b"text", None),
            (b"\x1b G\x1b J\x1b.B", b"\x1bN?", Some("ż")),
            (b"\x1b J\x1b G\x1b.B", b"\x8e?", None),
            (b"\x1b C\x1b G\x1b.B", b"\x8e?", Some("ż")),
            (b"\x1b C\x1b G\x1b.B", b"\x1bN?", None),
            (b"\x1b H\x1b(K", b"{x", Some("äx")),
            (b"\x1b H\x1b-A", b"text", None),
            (b"\x1b-A\x1b H", b"text", None),
            (b"\x1b H\x1b I", b"\x1b-A\xe9", None),
            (b"\x1b I\x1b-A", b"caf\xe9", Some("café")),
            (b"\x1b I\x1b$A", b"VP", None),
            (b"\x1b I", b"\x1b$BF|", None),
            (b"\x1b F\x1b\"C", b"a\x1bEb", Some("a\nb")),
            (b"\x1b G\x1b\"C", b"a\x85b", Some("a\nb")),
            (b"\x1b F\x1b\"C", b"a\x85b", None),
            (b"\x1b\"G", b"a\x1bEb", None),
            (b"\x1b\"C", b"a\x1b\"G\x1bEb", None),
            (b"\x1b\"G", b"a\x1b\"C\x1bEb", Some("a\nb")),
            (b"\x1b\"C\x1bE", b"text", None),
            (b"\x1b!D\x1b*K", b"\x1c{x", Some("äx")),
            (b"\x1b!D\x1b*K", b"\x19{x", None),
            (b"\x1b!D\x1b.B", b"\x1c?x", None),
            (b"\x1b!L\x1b.I", b"\x19hx", Some("čx")),
            (b"\x1b!L\x1b.I", b"\x1chx", None),
            (b"\x1b(B", b"\x1b$*B\x1bNF|", Some("日")),
            (b"\x1b.B", b"\x1bN", None),
            (b"\x1b.A", b"\x1bN\xe9", None),
            (b"\x1b*A", b"\x1bN\x20", None),
            (b"\x1b-A", b"\x1b-A", None),
            (b"\x1b$B", b"F", None),
            (b"\x1b%G", b"\x1b(Babc", None),
        ])
    }

    #[test]
    fn announced_width_and_ecma43_levels_constrain_invocations() -> Result<(), String> {
        check_declarations(&[
            (b"\x1b D\x1b)K", b"x\x0e{\x0fy", Some("xäy")),
            (b"\x1b D\x1b-A", b"Caf\xe9", Some("Café")),
            (b"\x1b D\x1b-A", b"\xe9\x0ei", None),
            (b"\x1b D\x1b-A", b"\x0ei\xe9", None),
            (b"\x1b D\x1b P", b"text", None),
            (b"\x1b U\x1b C", b"text", None),
            (b"\x1b E\x1b G\x1b\"C", b"a\x1bEb", Some("a\nb")),
            (b"\x1b G\x1b\"C\x1b-A", b"a\x1bE\xe9", None),
            (b"\x1b F\x1b\"C\x1b-A", b"a\x1bE\xe9", Some("a\né")),
            (b"\x1b U\x1b.B", b"\x1b}\xbf", Some("ż")),
            (b"\x1b U\x1b.B", b"\x1bn?", Some("ż")),
            (b"\x1b K\x1b U\x1b.B", b"\x1bn?", None),
            (b"\x1b J\x1b U\x1b.B", b"\x1bn?", Some("ż")),
            (b"\x1b J\x1b U\x1b.B", b"\x1b}?", None),
            (b"\x1b Z\x1b [\x1b.A\x1b/A", b"\x1bNi\x1bOi", Some("éé")),
            (b"\x1b \\\x1b J", b"text", None),
            (b"\x1b O", b"text", None),
            (b"\x1b L\x1b-A", b"Caf\xe9", Some("Café")),
            (b"\x1b-A\x1b L", b"\x1b-B\xbf", None),
            (b"\x1b L\x1b G", b"text", None),
            (b"\x1b L\x1b(K", b"text", None),
            (b"\x1b.B\x1b L", b"text", None),
            (b"\x1b M\x1b-A\x1b.B", b"text", None),
            (b"\x1b M\x1b\"G\x1b-A\x1b.B", b"\xe9\x8e?", Some("éż")),
            (b"\x1b M\x1b\"G\x1b-A\x1b.B", b"\x1b}\xbf", None),
            (b"\x1b N\x1b\"G\x1b-A\x1b.B", b"\xe9\x1b}\xbf", Some("éż")),
            (b"\x1b N\x1b\"G\x1b-A\x1b.B", b"\x1bn?", None),
        ])
    }

    #[test]
    fn registered_graphics_and_returning_utf8_preserve_the_iso2022_state() -> Result<(), String> {
        check_declarations(&[
            (b"\x1b-T", b"\xa0\xa1\xdf\xfb", Some("\u{a0}ก฿๛")),
            (b"\x1b-T", b"\xdb", None),
            (b"\x1b-f", b"\xaa\xba\xde\xfe", Some("ȘșȚț")),
            (b"\x1b$B", b"t%", None),
            (b"\x1b&@\x1b$B", b"t%t&", Some("凜熙")),
            (b"\x1b&@\x1b$*B", b"\x1bNt&!", Some("熙!")),
            (b"\x1b&A\x1b$B", b"t%", None),
            (b"\x1b%G", b"\xe6\x9d\xb1\x1b%@A", None),
            (b"\x1b-A\x1b%G", b"\xe6\x9d\xb1", None),
            (
                b"\x1b J\x1b)K",
                b"x\x0e{\x1b%G \xe6\x9d\xb1\x1b%@{\x0fy",
                Some("xä 東äy"),
            ),
            (b"\x1b(B", b"a\x1b%G\xc3\xa9", Some("aé")),
            (b"\x1b(B", b"a\x1b%G\xc3\xa9\x1b(B", None),
            (b"\x1b(B", b"a\x1b%G\xc3\x1b%@b", None),
            (b"\x1b(B", b"a\x1b%@b", None),
        ])
    }

    #[test]
    fn iso6937_projects_only_registered_accented_graphics() -> Result<(), String> {
        check_declarations(&[
            (b"\x1b-R", b"Caf\xc2e", Some("Café")),
            (b"\x1b-R", b"\xc2g\xcdU\xcbG\xcf ", Some("ģŰĢˇ")),
            (b"\x1b-R", b"\xa0\xd0\xe0\xe2\xff", Some("\u{a0}―ΩĐ\u{ad}")),
            (b"\x1b.R", b"Caf\x1bNBe", Some("Café")),
            (b"\x1b J\x1b-R", b"Caf\x0eB\x0fe", Some("Café")),
            (b"\x1b-R", b"Caf\xc2\x1b(Be", Some("Café")),
            (b"\x1b-R", b"\xc2 ", Some("´")),
            (b"\x1b-R", b"\xc1 ", None),
            (b"\x1b-R", b"\xc2x", None),
            (b"\x1b-R", b"\xc2\xc2e", None),
            (b"\x1b-R", b"Caf\xc2", None),
            (b"\x1b-R", b"\xc2\x1b(Ke", None),
            (b"\x1b-R", b"\xc2\x1b%Ge\x1b%@", None),
            (b"\x1b-R", b"\xc2\x7fe", None),
            (b"\x1b-R", b"\xc2\ne", None),
            (b"\x1b-R", b"\xa4", None),
            (b"\x1b-R", b"\xccA", None),
        ])
    }

    #[test]
    fn declared_unicode_codings_use_whole_code_units() -> Result<(), String> {
        check_declarations(&[
            (b"\x1b%/I", b"\xef\xbb\xbfe\xcc\x81", Some("e\u{301}")),
            (b"\x1b%/I", b"\x1b%@abc", None),
            (b"\x1b%/I\x1b(B", b"text", None),
            (b"\x1b%/E", b"\x00 \x67\x71\x01\x1b", Some("東ě")),
            (b"\x1b%/E", b"\xff\xfe\x71\x67", Some("東")),
            (b"\x1b%/E", b"\xd8\x3d\xde\x80", None),
            (b"\x1b%/L", b"\xd8\x3d\xde\x80", Some("🚀")),
            (b"\x1b%/L", b"\xff\xfe\x3d\xd8\x80\xde", Some("🚀")),
            (b"\x1b%/L", b"\xfe\xff\x00A", Some("A")),
            (b"\x1b%/L", b"\x00A\xd8\x3d", None),
            (b"\x1b%/L", b"\x00A\x00\x00\x00B", None),
            (b"\x1b%/L", b"\x00\x1b\x00%\x00@\x00A", None),
            (b"\x1b%/F", b"\x00\x01\xf6\x80", Some("🚀")),
            (b"\x1b%/F", b"\xff\xfe\x00\x00\x80\xf6\x01\x00", Some("🚀")),
            (b"\x1b%/F", b"\x00\x00\xfe\xff\x00\x00\x00A", Some("A")),
            (b"\x1b%/F", b"\x00\x11\x00\x00", None),
            (b"\x1b%/F", b"\x00\x00\x00A\x00\x00", None),
        ])
    }

    fn check_declarations(cases: &[(&[u8], &[u8], Option<&str>)]) -> Result<(), String> {
        for &(controls, data, expected) in cases {
            let mut packet = vec![0x1c, 1, 90, 0, controls.len() as u8];
            packet.extend_from_slice(controls);
            packet.extend_from_slice(&[0x1c, 2, 25, 0, data.len() as u8]);
            packet.extend_from_slice(data);
            let profile = Profile::parse(&packet, 0).ok_or("expected a complete IIM packet")?;
            let mut seen = None;
            profile.emit(expected.map_or(32, str::len), &mut |kind, value| {
                if kind != 49 || seen.is_some() {
                    return Err("expected a single keyword");
                }
                seen = Some(value.to_vec());
                Ok(())
            })?;
            if seen.as_deref() != expected.map(str::as_bytes) {
                return Err(format!(
                    "IIM declaration {controls:02x?} and text {data:02x?} yielded {seen:?}, expected {expected:?}"
                ));
            }
            if let Some(expected) = expected {
                profile.emit(expected.len() - 1, &mut |_, _| {
                    Err("decoded text exceeds limit")
                })?;
            }
        }
        Ok(())
    }

    #[test]
    fn separate_datasets_restart_at_the_declared_state() -> Result<(), &'static str> {
        let bytes = [
            b"\x1c\x01\x5a\x00\x03\x1b(B".as_slice(),
            b"\x1c\x02\x19\x00\x04\x1b(K{",
            b"\x1c\x02\x19\x00\x01{",
            b"\x1c\x02\x5a\x00\x01{",
        ]
        .concat();
        let profile = Profile::parse(&bytes, 0).ok_or("expected complete IIM packet")?;
        let mut fields = Vec::new();
        profile.emit(2, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok::<(), &'static str>(())
        })?;
        if fields
            != [
                (49, "ä".as_bytes().to_vec()),
                (49, b"{".to_vec()),
                (41, b"{".to_vec()),
            ]
        {
            return Err("IIM state crossed a dataset boundary");
        }
        Ok(())
    }
}
