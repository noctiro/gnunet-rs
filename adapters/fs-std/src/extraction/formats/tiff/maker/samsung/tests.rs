use super::{EXPOSURE_TIME, F_NUMBER, FIRMWARE_NAME, camera};
use crate::extraction::formats::tiff::visit_exif;
use std::convert::Infallible;

#[test]
fn paired_rationals_use_the_first_value_and_require_the_full_note_extent() {
    const FIRMWARE_AT: u32 = 2 + 6 * 12 + 4;
    const EXPOSURE_AT: u32 = FIRMWARE_AT + 30;
    const APERTURE_AT: u32 = EXPOSURE_AT + 16;
    let mut note = 6_u16.to_be_bytes().to_vec();
    for (tag, kind, count, value) in [
        (1, 7, 4, u32::from_be_bytes(*b"0100")),
        (2, 4, 1, 0x2000),
        (3, 4, 1, 0x0100_101c),
        (FIRMWARE_NAME, 2, 30, FIRMWARE_AT),
        (EXPOSURE_TIME, 5, 2, EXPOSURE_AT),
        (F_NUMBER, 5, 2, APERTURE_AT),
    ] {
        note.extend_from_slice(&row(tag, kind, count, value));
    }
    note.extend_from_slice(&[0; 4]);
    note.extend_from_slice(b"NX10_FW_X_F1110111");
    note.resize(EXPOSURE_AT as usize, 0);
    note.extend(
        [1_u32, 320, 1, 640, 63, 10, 8, 1]
            .into_iter()
            .flat_map(u32::to_be_bytes),
    );

    assert_eq!(
        project(&note, note.len()),
        [
            (camera::EXPOSURE, b"1/320 s".to_vec()),
            (camera::APERTURE, b"F6.3".to_vec())
        ]
    );
    // The parent TIFF still contains both values, but the second aperture
    // rational is outside the declared MakerNote. Its row must be ignored.
    assert_eq!(
        project(&note, note.len() - 8),
        [(camera::EXPOSURE, b"1/320 s".to_vec())]
    );
}

fn row(tag: u16, kind: u16, count: u32, value: u32) -> [u8; 12] {
    let mut bytes = [0; 12];
    bytes[..2].copy_from_slice(&tag.to_be_bytes());
    bytes[2..4].copy_from_slice(&kind.to_be_bytes());
    bytes[4..8].copy_from_slice(&count.to_be_bytes());
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn project(note: &[u8], declared_len: usize) -> Vec<(u32, Vec<u8>)> {
    let mut file = b"MM\0*\0\0\0\x08\0\x03".to_vec();
    file.extend_from_slice(&row(0x010f, 2, 8, 50));
    file.extend_from_slice(&row(0x0110, 2, 5, 58));
    file.extend_from_slice(&row(0x8769, 4, 1, 64));
    file.extend_from_slice(b"\0\0\0\0SAMSUNG\0NX10\0\0\0\x01");
    file.extend_from_slice(&row(0x927c, 7, declared_len as u32, 82));
    file.extend_from_slice(&[0; 4]);
    file.extend_from_slice(note);
    let mut fields = Vec::new();
    let result = visit_exif(&file, 128, &mut |kind, bytes| {
        if matches!(kind, camera::EXPOSURE | camera::APERTURE) {
            fields.push((kind, bytes.to_vec()));
        }
        Ok::<_, Infallible>(())
    });
    assert_eq!(result, Ok(()));
    fields
}
