use super::super::Expansion;
use crate::extraction::formats::pdf::syntax::{Cursor, Value};

fn decode(parameters: &[u8], codes: &str, limit: usize) -> Option<Vec<u8>> {
    let mut dict = b"<< /Filter /CCITTFaxDecode /DecodeParms << ".to_vec();
    dict.extend_from_slice(parameters);
    dict.extend_from_slice(b" >> >>");
    let Value::Dict(dict) = Cursor::complete(&dict).one_value().ok()? else {
        return None;
    };
    let mut coded = Vec::<u8>::new();
    for (index, bit) in codes
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .enumerate()
    {
        if index % 8 == 0 {
            coded.push(0);
        }
        match bit {
            b'1' => coded[index / 8] |= 0x80 >> (index % 8),
            b'0' => {}
            _ => return None,
        }
    }
    Some(
        Expansion::new(limit)
            .decode(dict, &coded, None)?
            .into_owned(),
    )
}

#[test]
fn group3_without_eol_accepts_byte_alignment_and_pdf_polarity() {
    let parameters = b"/Columns 8 /Rows 2 /EndOfBlock false /EncodedByteAlign true";
    // White(0), black(8), two alignment bits, white(8).
    assert_eq!(
        decode(parameters, "00110101 000101 00 10011", 2),
        Some(vec![0, 255])
    );
    assert_eq!(decode(parameters, "00110101 000101 00 10011", 1), None);
}

#[test]
fn group3_mixed_uses_row_tags_and_rtc_overrides_rows() {
    let parameters = b"/K 5 /Columns 8 /Rows 1 /EndOfLine true /BlackIs1 true";
    let codes = "000000000001 1 00110101 000101
                 000000000001 0 11
                 000000000001 1 000000000001 1 000000000001 1
                 000000000001 1 000000000001 1 000000000001 1";
    assert_eq!(decode(parameters, codes, 2), Some(vec![255; 2]));
}

#[test]
fn group3_mixed_aligns_the_row_tag_after_a_filled_eol() {
    let parameters = b"/K 2 /Columns 8 /Rows 2 /EndOfLine true /EncodedByteAlign true \
                       /EndOfBlock false /BlackIs1 true";
    // Fill puts each EOL's end on the next byte boundary, before its tag.
    let codes = "0000 000000000001 1 00110101 000101
                 00000 000000000001 0 11";
    assert_eq!(decode(parameters, codes, 2), Some(vec![255; 2]));
}

#[test]
fn group4_tracks_horizontal_vertical_and_pass_changes() {
    let parameters = b"/K -1 /Columns 8 /BlackIs1 true";
    let codes = "001 0111 011 1
                 010 010 1
                 0001 1
                 000000000001 000000000001";
    assert_eq!(decode(parameters, codes, 3), Some(vec![0x3c, 0x78, 0]));
}

#[test]
fn group3_damaged_rows_use_previous_good_row_then_white() {
    let recovered = b"/Columns 8 /EndOfLine true /Rows 4 /EndOfBlock false \
                      /BlackIs1 true /DamagedRowsBeforeError 2";
    let strict = b"/Columns 8 /EndOfLine true /Rows 4 /EndOfBlock false /BlackIs1 true";
    // The second row is missing its delimiter, and White(9) overflows the third.
    let codes = "000000000001 00110101 000101
                 10100
                 000000000001 10100
                 000000000001 10011";
    assert_eq!(decode(recovered, codes, 4), Some(vec![255, 255, 0, 0]));
    assert_eq!(decode(strict, codes, 4), None);
}

#[test]
fn group4_literal_pattern_can_cross_row_boundaries() {
    let parameters = b"/K -1 /Columns 3 /BlackIs1 true";
    let codes = "0000001111 00001 01 00000010 1 000000000001 000000000001";
    assert_eq!(decode(parameters, codes, 3), Some(vec![0, 0x40, 0x80]));
}

#[test]
fn group4_literal_five_white_pixels_and_empty_exit() {
    let parameters = b"/K -1 /Columns 5 /BlackIs1 true";
    let codes = "0000001111 000001 00000010 000000000001 000000000001";
    assert_eq!(decode(parameters, codes, 1), Some(vec![0]));
}
