use super::{
    EXPOSURE_PROGRAM, FLASH, FOCAL_LENGTH_35MM, IMAGE_QUALITY, ISO_SPEED, MACRO_MODE,
    METERING_MODE, RATING, WHITE_BALANCE,
};
use crate::extraction::formats::camera::{APERTURE, EXPOSURE, FOCAL_LENGTH};
use crate::extraction::formats::tiff::{ExifOverlay, visit_exif};
use std::convert::Infallible;

#[test]
fn epson_uses_the_parent_byte_order_and_owns_its_software_value() {
    const MAKE: &[u8] = b"SEIKO EPSON CORP.\0";
    let mut note = b"EPSON\0\x01\x00\x00\x02".to_vec();
    note.extend_from_slice(&row(0x0201, 3, 1, 0x10 << 16));
    note.extend_from_slice(&row(0x020d, 2, 6, 0));
    let mut file = exif(MAKE, &note);
    let data_start = file.len();
    file[data_start - 4..].copy_from_slice(&(data_start as u32).to_be_bytes());
    file.extend_from_slice(b"SS-30\0");
    // An external value in the parent TIFF still needs to fit the MakerNote.
    assert_eq!(project(&file), [(IMAGE_QUALITY, b"RAW".to_vec())]);
    let note_count = 14 + 2 * 12 + 2 + 4;
    file[note_count..note_count + 4].copy_from_slice(&((note.len() + 6) as u32).to_be_bytes());
    assert_eq!(
        project(&file),
        [(IMAGE_QUALITY, b"RAW".to_vec()), (113, b"SS-30".to_vec())]
    );
    let start = data_start - note.len();
    file[start + 6] = 2;
    assert!(project(&file).is_empty());
}

#[test]
fn kodak_linked_settings_are_typed_and_suppress_duplicate_keys() {
    let text = b"ISO Speed:  160\r\nAperture: f9.5\nShutter: 1/350\nExposure Mode: P\nMeter Mode: Matrix metering\nFlash Fired: No\nFocal Length: 35\nWhite balance: Auto\0";
    let build = |make: &[u8], version: u32, text: &[u8]| {
        let make_at = 38;
        let ifd = (make_at + make.len()).next_multiple_of(2) as u32;
        let mut result = b"MM\0*\0\0\0\x08\x00\x02".to_vec();
        result.extend_from_slice(&row(0x010f, 2, make.len() as u32, make_at as u32));
        result.extend_from_slice(&row(0x8290, 4, 1, ifd));
        result.extend_from_slice(&[0; 4]);
        result.extend_from_slice(make);
        result.resize(ifd as usize, 0);
        result.extend_from_slice(&[0, 2]);
        result.extend_from_slice(&row(0, 1, 4, version));
        result.extend_from_slice(&row(0x03f1, 2, text.len() as u32, ifd + 30));
        result.extend_from_slice(&[0; 4]);
        result.extend_from_slice(text);
        result
    };
    let make = b"Kodak\0";
    let version = 1 << 24;
    let settings = [
        (ISO_SPEED, b"160".to_vec()),
        (APERTURE, b"F9.5".to_vec()),
        (EXPOSURE, b"1/350 s".to_vec()),
        (EXPOSURE_PROGRAM, b"Auto".to_vec()),
        (METERING_MODE, b"Multi-segment".to_vec()),
        (FLASH, b"No flash".to_vec()),
        (FOCAL_LENGTH, b"35.0 mm".to_vec()),
        (WHITE_BALANCE, b"Auto".to_vec()),
    ];
    assert_eq!(project(&build(make, version, text)), settings);
    assert!(project(&build(b"Kodak-like\0", version, text)).is_empty());
    assert!(project(&build(make, 0, text)).is_empty());
    assert!(project(&build(make, version, &text[..text.len() - 1])).is_empty());
    let mut ambiguous = b"ISO: 800\n".to_vec();
    ambiguous.extend_from_slice(text);
    assert_eq!(project(&build(make, version, &ambiguous)), &settings[1..]);
}

#[test]
fn kodak_p_series_camera_info_uses_its_own_order_and_owns_its_child() {
    let expected = [
        (APERTURE, b"F5.6".to_vec()),
        (EXPOSURE, b"1/125 s".to_vec()),
        (ISO_SPEED, b"200".to_vec()),
    ];
    let make = b"EASTMAN KODAK COMPANY\0";
    for (model, little) in [
        (b"KODAK P712 ZOOM DIGITAL CAMERA\0".as_slice(), false),
        (b"KODAK P850 ZOOM DIGITAL CAMERA\0", false),
        (b"KODAK P880 ZOOM DIGITAL CAMERA\0", true),
    ] {
        let file = kodak_camera_info(make, model, little, &[]);
        assert_eq!(project(&file), expected);
    }
    let model = b"KODAK P880 ZOOM DIGITAL CAMERA\0";
    assert!(project(&kodak_camera_info(b"Kodak-like\0", model, true, &[])).is_empty());
    assert!(project(&kodak_camera_info(make, b"P8800\0", true, &[])).is_empty());

    const CAMERA_BYTES: usize = 2 + 12 * 3 + 4;
    let mut escaped = kodak_camera_info(make, model, true, &[]);
    let end = escaped.len();
    let root = end - CAMERA_BYTES - 18;
    escaped[root + 10..root + 14].copy_from_slice(&(end as u32).to_le_bytes());
    escaped.extend_from_within(end - CAMERA_BYTES..end);
    assert!(project(&escaped).is_empty());
}

#[test]
fn kodak_camera_info_fills_missing_capture_fields_after_standard_exif() {
    let file = kodak_camera_info(b"Kodak\0", b"P880\0", true, &[row(0x8827, 3, 1, 100 << 16)]);
    let expected = [
        (ISO_SPEED, b"100".to_vec()),
        (APERTURE, b"F5.6".to_vec()),
        (EXPOSURE, b"1/125 s".to_vec()),
    ];
    assert_eq!(project(&file), expected);

    let mut block = vec![0; 4];
    block.extend(file);
    let mut overlay = ExifOverlay::new(block.len());
    assert!(overlay.add_block(&block));
    let mut fields = Vec::new();
    let Ok(()) = overlay.visit(128, &mut |kind, bytes| {
        if matches!(kind, ISO_SPEED | APERTURE | EXPOSURE) {
            fields.push((kind, bytes.to_vec()));
        }
        Ok::<_, Infallible>(())
    });
    assert_eq!(fields, expected);
}

fn kodak_camera_info(make: &[u8], model: &[u8], little: bool, photo_rows: &[[u8; 12]]) -> Vec<u8> {
    let short = |value: u16| {
        if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    };
    let setting = |tag, kind, value| {
        if little {
            little_row(tag, kind, value)
        } else {
            row(tag, kind, 1, if kind == 3 { value << 16 } else { value })
        }
    };
    let mut note = short(1).to_vec();
    note.extend(setting(0xff00, 4, 0));
    note.extend([0; 4]);
    let camera = note.len();
    note.extend(short(3));
    note.extend(setting(0xfd04, 3, 560));
    note.extend(setting(0xfd05, 4, 8000));
    note.extend(setting(0xfd06, 3, 200));
    note.extend([0; 4]);

    let mut file = exif_with_photo(make, Some(model), &note, photo_rows);
    let note_start = file.len() - note.len();
    let camera_at = (note_start + camera) as u32;
    let offset = if little {
        camera_at.to_le_bytes()
    } else {
        camera_at.to_be_bytes()
    };
    file[note_start + 10..note_start + 14].copy_from_slice(&offset);
    file
}

#[test]
fn canon_maker_directory_and_values_have_distinct_bounds() {
    let mut note = 1_u16.to_be_bytes().to_vec();
    note.extend_from_slice(&row(1, 3, 21, 0));
    let mut file = exif(b"Canon\0", &note);
    let values_at = file.len() as u32;
    let offset_slot = file.len() - 4;
    file[offset_slot..].copy_from_slice(&values_at.to_be_bytes());
    let mut settings = [0_u16; 21];
    settings[0] = 42;
    settings[1] = 2;
    settings[3] = 7;
    settings[20] = 4;
    file.extend(settings.into_iter().flat_map(u16::to_be_bytes));
    assert_eq!(
        project(&file),
        [
            (MACRO_MODE, b"Off".to_vec()),
            (IMAGE_QUALITY, b"CRAW".to_vec()),
            (EXPOSURE_PROGRAM, b"Manual (M)".to_vec()),
        ]
    );

    // The classic directory ends at the MakerNote boundary, before its values.
    let count = values_at as usize - note.len();
    file[count..count + 2].copy_from_slice(&2_u16.to_be_bytes());
    assert!(project(&file).is_empty());
}

#[test]
fn maker_notes_use_their_vendor_and_declared_offset_base() {
    let mut fuji = b"FUJIFILM\x10\0\0\0\0\0\0\0".to_vec();
    fuji.extend_from_slice(&3_u16.to_le_bytes());
    fuji.extend_from_slice(&[
        0x00, 0x10, 2, 0, 5, 0, 0, 0, 58, 0, 0, 0, // Quality, external ASCII
        0x02, 0x10, 3, 0, 1, 0, 0, 0, 1, 3, 0, 0, // White balance, 769
        0x20, 0x10, 3, 0, 1, 0, 0, 0, 1, 0, 0, 0, // Macro, 1
        0, 0, 0, 0, // No next IFD
    ]);
    assert_eq!(fuji.len(), 58);
    fuji.extend_from_slice(b"FINE\0");

    let file = exif(b"FUJIFILM\0", &fuji);
    assert_eq!(
        project(&file),
        [
            (IMAGE_QUALITY, b"FINE".to_vec()),
            (WHITE_BALANCE, b"Fluorescent (warm white)".to_vec()),
            (MACRO_MODE, b"On".to_vec()),
        ]
    );
    assert!(project(&exif(b"OTHER\0", &fuji)).is_empty());

    // An otherwise valid ASCII value immediately beyond the MakerNote is invisible.
    fuji[26] = fuji.len() as u8;
    let mut file = exif(b"FUJIFILM\0", &fuji);
    file.extend_from_slice(b"FAKE\0");
    assert!(
        project(&file)
            .iter()
            .all(|&(kind, _)| kind != IMAGE_QUALITY)
    );

    let mut nikon = b"Nikon\0\x02\x10\0\0MM\0*\0\0\0\x08\0\x03".to_vec();
    nikon.extend_from_slice(&[
        0, 2, 0, 3, 0, 0, 0, 2, 0, 0, 1, 144, // ISO, second SHORT is 400
        0, 4, 0, 2, 0, 0, 0, 5, 0, 0, 0, 50, // Quality, external ASCII
        0, 5, 0, 2, 0, 0, 0, 4, b'A', b'U', b'T', 0, // White balance
        0, 0, 0, 0, // No next IFD
    ]);
    assert_eq!(nikon.len(), 60);
    nikon.extend_from_slice(b"FINE\0");
    assert_eq!(
        project(&exif(b"NIKON CORPORATION\0", &nikon)),
        [
            (ISO_SPEED, b"400".to_vec()),
            (IMAGE_QUALITY, b"FINE".to_vec()),
            (WHITE_BALANCE, b"AUT".to_vec()),
        ]
    );
}

#[test]
fn nikon_classic_maker_notes_keep_parent_value_offsets() {
    let mut bare = 1_u16.to_be_bytes().to_vec();
    bare.extend_from_slice(&row(4, 2, 5, 0));
    let mut file = exif(b"NIKON\0", &bare);
    let value_at = file.len() as u32;
    file[(value_at as usize - 4)..].copy_from_slice(&value_at.to_be_bytes());
    file.extend_from_slice(b"FINE\0");
    assert_eq!(project(&file), [(IMAGE_QUALITY, b"FINE".to_vec())]);

    let mut numeric = b"Nikon\0\x01\0\0\x03".to_vec();
    numeric.extend_from_slice(&row(3, 3, 1, 6 << 16));
    numeric.extend_from_slice(&row(6, 3, 1, 2 << 16));
    numeric.extend_from_slice(&row(7, 3, 1, 5 << 16));
    assert_eq!(
        project(&exif(b"NIKON\0", &numeric)),
        [
            (IMAGE_QUALITY, b"SXGA Fine".to_vec()),
            (ISO_SPEED, b"160".to_vec()),
            (WHITE_BALANCE, b"Cloudy".to_vec()),
        ]
    );
    numeric[6] = 3;
    assert!(project(&exif(b"NIKON\0", &numeric)).is_empty());
}

#[test]
fn olympus_camera_settings_keep_their_owner_byte_order_and_bounds() {
    let mut old = b"OLYMP\0\x01\0\x02\0".to_vec();
    old.extend_from_slice(&little_row(0x0201, 3, 2));
    old.extend_from_slice(&little_row(0x0202, 3, 1));
    assert_eq!(
        project(&exif(b"OLYMPUS\0", &old)),
        [
            (IMAGE_QUALITY, b"HQ".to_vec()),
            (MACRO_MODE, b"On".to_vec())
        ]
    );

    for (make, header) in [
        (b"OLYMPUS\0".as_slice(), b"OLYMPUS\0II\x03\0".as_slice()),
        (b"OM Digital Solutions\0", b"OM SYSTEM\0\0\0II\x04\0"),
    ] {
        let mut modern = header.to_vec();
        modern.extend_from_slice(&2_u16.to_le_bytes());
        modern.extend_from_slice(&little_row(0x0201, 3, 2));
        let settings_offset = (modern.len() + 12) as u32;
        modern.extend_from_slice(&little_row(0x2020, 4, settings_offset));
        modern.extend_from_slice(&3_u16.to_le_bytes());
        modern.extend_from_slice(&little_row(0x0300, 3, 2));
        modern.extend_from_slice(&little_row(0x0500, 3, 67));
        modern.extend_from_slice(&little_row(0x0603, 3, 4));
        assert_eq!(
            project(&exif(make, &modern)),
            [
                (MACRO_MODE, b"Super Macro".to_vec()),
                (WHITE_BALANCE, b"Underwater".to_vec()),
                (IMAGE_QUALITY, b"RAW".to_vec()),
            ]
        );

        let mut file = exif(make, &modern[..settings_offset as usize]);
        file.extend_from_slice(&modern[settings_offset as usize..]);
        assert_eq!(project(&file), [(IMAGE_QUALITY, b"HQ".to_vec())]);
    }
}

#[test]
fn panasonic_ifd_uses_tiff_byte_order_and_requires_no_next_link() {
    let mut note = b"Panasonic\0\0\0\0\x03".to_vec();
    note.extend_from_slice(&row(0x0001, 3, 1, 6 << 16));
    note.extend_from_slice(&row(0x0003, 3, 1, 19 << 16));
    note.extend_from_slice(&row(0x001c, 3, 1, 0x201 << 16));
    let expected = [
        (IMAGE_QUALITY, b"Very High".to_vec()),
        (WHITE_BALANCE, b"Auto (cool)".to_vec()),
        (MACRO_MODE, b"Macro zoom".to_vec()),
    ];
    for make in [b"Panasonic\0".as_slice(), b"LEICA CAMERA AG\0"] {
        assert_eq!(project(&exif(make, &note)), expected);
    }

    let end = note.len() - 12;
    let mut truncated = exif(b"Panasonic\0", &note[..end]);
    truncated.extend_from_slice(&note[end..]);
    assert!(project(&truncated).is_empty());
    note[0] = b'X';
    assert!(project(&exif(b"Panasonic\0", &note)).is_empty());
}

#[test]
fn pentax_ifds_use_their_declared_byte_order_and_note_geometry() {
    let mut classic = b"AOC\0MM\0\x04".to_vec();
    classic.extend_from_slice(&row(0x0008, 3, 1, 4 << 16));
    classic.extend_from_slice(&row(0x0014, 4, 1, 267));
    classic.extend_from_slice(&row(0x0017, 3, 1, 2 << 16));
    classic.extend_from_slice(&row(0x0019, 3, 1, 10 << 16));
    classic.extend_from_slice(&[0; 4]);
    assert_eq!(
        project(&exif(b"PENTAX Corporation\0", &classic)),
        [
            (IMAGE_QUALITY, b"RAW".to_vec()),
            (ISO_SPEED, b"1100".to_vec()),
            (METERING_MODE, b"Spot".to_vec()),
            (WHITE_BALANCE, b"Cloudy".to_vec()),
        ]
    );

    let mut relative = b"PENTAX \0II\x04\0".to_vec();
    relative.extend_from_slice(&little_row(0x0008, 3, 5));
    relative.extend_from_slice(&little_row(0x0014, 3, 12));
    relative.extend_from_slice(&little_row(0x0017, 3, 1));
    relative.extend_from_slice(&little_row(0x0019, 3, 17));
    relative.extend_from_slice(&[0; 4]);
    assert_eq!(
        project(&exif(b"RICOH IMAGING COMPANY, LTD.\0", &relative)),
        [
            (IMAGE_QUALITY, b"Premium".to_vec()),
            (ISO_SPEED, b"400".to_vec()),
            (METERING_MODE, b"Center weighted average".to_vec()),
            (WHITE_BALANCE, b"Kelvin".to_vec()),
        ]
    );
    assert!(project(&exif(b"OTHER\0", &relative)).is_empty());

    for note in [classic, relative] {
        let end = note.len() - 4;
        let mut file = exif(b"PENTAX\0", &note[..end]);
        file.extend_from_slice(&note[end..]);
        assert!(project(&file).is_empty());
    }
}

#[test]
fn sony_ifds_follow_header_geometry_and_use_declared_scalar_widths() {
    let mut directory = 4_u16.to_be_bytes().to_vec();
    directory.extend_from_slice(&row(0x0102, 4, 1, 6));
    directory.extend_from_slice(&row(0x0115, 4, 1, 0x30));
    directory.extend_from_slice(&row(0x2002, 4, 1, 5));
    directory.extend_from_slice(&row(0xb040, 3, 1, 2 << 16));
    let expected = [
        (IMAGE_QUALITY, b"RAW + JPEG/HEIF".to_vec()),
        (WHITE_BALANCE, b"Shade".to_vec()),
        (RATING, b"5".to_vec()),
        (MACRO_MODE, b"Close Focus".to_vec()),
    ];
    for header in [b"SONY DSC \0\0\0", b"SONY CAM \0\0\0"] {
        let mut note = header.to_vec();
        note.extend_from_slice(&directory);
        assert_eq!(project(&exif(b"SONY\0", &note)), expected);
        assert!(project(&exif(b"Canon\0", &note)).is_empty());
    }

    let mut truncated = exif(b"SONY\0", &directory);
    truncated.extend_from_slice(&[0; 4]);
    assert!(project(&truncated).is_empty());
    directory.extend_from_slice(&[0; 4]);
    assert_eq!(project(&exif(b"SONY\0", &directory)), expected);

    let mut invalid = b"SONY DSC \0\0\0\0\x04".to_vec();
    invalid.extend_from_slice(&row(0x0102, 3, 1, 6 << 16));
    invalid.extend_from_slice(&row(0x0115, 4, 1, 0x1_0030));
    invalid.extend_from_slice(&row(0x2002, 4, 1, u32::MAX));
    invalid.extend_from_slice(&row(0xb040, 3, 1, 0xffff_0000));
    assert!(project(&exif(b"SONY\0", &invalid)).is_empty());
}

#[test]
fn ricoh_gr_keeps_native_and_pentax_compatible_directories_distinct() {
    let mut native = b"Ricoh\0\x02\x01\0\x04".to_vec();
    native.extend_from_slice(&row(0x1001, 3, 1, 5 << 16));
    native.extend_from_slice(&row(0x1003, 3, 1, 8 << 16));
    native.extend_from_slice(&row(0x1009, 3, 1, 1 << 16));
    native.extend_from_slice(&row(0x100a, 3, 1, 8 << 16));
    let expected = [
        (EXPOSURE_PROGRAM, b"Shutter/aperture priority AE".to_vec()),
        (WHITE_BALANCE, b"Cool White Fluorescent".to_vec()),
        (MACRO_MODE, b"On".to_vec()),
        (FLASH, b"Auto, did not fire".to_vec()),
    ];
    for make in [b"RICOH\0".as_slice(), b"PENTAX RICOH IMAGING\0"] {
        assert_eq!(project(&exif(make, &native)), expected);
    }
    // On other models the same tag number stores a structured ImageInfo value.
    native[10..22].copy_from_slice(&row(0x1001, 4, 1, 5));
    assert_eq!(
        project(&exif(b"RICOH\0", &native)).as_slice(),
        &expected[1..]
    );

    let mut modern = b"RICOH\0II\x03\0".to_vec();
    modern.extend_from_slice(&little_row(0x0008, 3, 4));
    modern.extend_from_slice(&little_row(0x0014, 3, 12));
    modern.extend_from_slice(&little_row(0x0019, 3, 10));
    let mut truncated = exif(b"RICOH\0", &modern);
    truncated.extend_from_slice(&[0; 4]);
    assert!(project(&truncated).is_empty());
    modern.extend_from_slice(&[0; 4]);
    assert_eq!(
        project(&exif(b"RICOH IMAGING COMPANY, LTD.\0", &modern)),
        [
            (IMAGE_QUALITY, b"RAW".to_vec()),
            (ISO_SPEED, b"400".to_vec()),
            (WHITE_BALANCE, b"Cloudy".to_vec()),
        ]
    );
    assert!(project(&exif(b"PENTAX\0", &modern)).is_empty());
}

#[test]
fn minolta_decodes_parent_tiff_fields_before_legacy_settings() {
    let mut note = 3_u16.to_be_bytes().to_vec();
    note.extend_from_slice(&row(1, 7, 36, 0));
    note.extend_from_slice(&row(0x0102, 4, 1, 5));
    note.extend_from_slice(&row(0x0115, 4, 1, 0x30));
    let mut file = exif(b"Minolta Co., Ltd.\0", &note);
    let start = file.len() - note.len();
    let settings_at = file.len() as u32;
    file[start + 10..start + 14].copy_from_slice(&settings_at.to_be_bytes());
    let expected = [
        (IMAGE_QUALITY, b"Extra Fine".to_vec()),
        (WHITE_BALANCE, b"Shade".to_vec()),
        (EXPOSURE_PROGRAM, b"Aperture Priority".to_vec()),
        (FLASH, b"Wireless".to_vec()),
        (METERING_MODE, b"Spot".to_vec()),
        (ISO_SPEED, b"400".to_vec()),
    ];
    let settings = [0_u32, 1, 3, 3, 0, 0, 0, 2, 64];
    file.extend(settings.into_iter().flat_map(u32::to_be_bytes));
    assert_eq!(project(&file), expected);
    file.pop();
    assert_eq!(project(&file), &expected[..2]);
}

#[test]
fn minolta_7d_settings_stay_big_endian_under_a_little_endian_ifd() {
    let mut note = 2_u16.to_le_bytes().to_vec();
    let mut version = little_row(0, 7, u32::from_le_bytes(*b"MLT0"));
    version[4..8].copy_from_slice(&4_u32.to_le_bytes());
    note.extend_from_slice(&version);
    let mut settings = little_row(4, 7, 0);
    settings[4..8].copy_from_slice(&58_u32.to_le_bytes());
    note.extend_from_slice(&settings);
    let mut file = exif(b"KONICA MINOLTA\0", &note);
    let offset = file.len();
    file[offset - 4..offset].copy_from_slice(&(offset as u32).to_le_bytes());
    let mut values = [0_u16; 29];
    values[0] = 3;
    values[3] = 34;
    values[4] = 0x100;
    values[0x15] = 1;
    values[0x1c] = 5;
    file.extend(values.into_iter().flat_map(u16::to_be_bytes));
    assert_eq!(
        project(&file),
        [
            (EXPOSURE_PROGRAM, b"Manual".to_vec()),
            (IMAGE_QUALITY, b"RAW+JPEG".to_vec()),
            (WHITE_BALANCE, b"Kelvin".to_vec()),
            (FLASH, b"On".to_vec()),
            (ISO_SPEED, b"800".to_vec()),
        ]
    );
}

#[test]
fn minolta_classic_and_5d_settings_use_the_ifd0_model() {
    let make = b"KONICA MINOLTA\0";
    let mut five_d = 2_u16.to_le_bytes().to_vec();
    let mut version = little_row(0, 7, u32::from_le_bytes(*b"MLT0"));
    version[4..8].copy_from_slice(&4_u32.to_le_bytes());
    five_d.extend_from_slice(&version);
    let mut settings = little_row(0x0114, 7, 0);
    settings[4..8].copy_from_slice(&78_u32.to_le_bytes());
    five_d.extend_from_slice(&settings);
    let mut values = [0_u16; 39];
    values[0x0a] = 2;
    values[0x0d] = 34;
    values[0x0e] = 2;
    values[0x1f] = 1;
    values[0x25] = 2;
    values[0x26] = 10;
    let five_d_file = |model| {
        let mut file = exif_with_model(make, Some(model), &five_d);
        let offset = file.len();
        file[offset - 4..offset].copy_from_slice(&(offset as u32).to_le_bytes());
        file.extend(values.into_iter().flat_map(u16::to_be_bytes));
        file
    };
    let overlay_has_balance = |files: &[&[u8]]| {
        let mut overlay = ExifOverlay::new(files.iter().map(|file| file.len() + 4).sum());
        for file in files {
            let mut block = vec![0; 4];
            block.extend_from_slice(file);
            assert!(overlay.add_block(&block));
        }
        let mut balance = false;
        let Ok(()) = overlay.visit(128, &mut |kind, value| {
            balance |= kind == WHITE_BALANCE && value == b"Cloudy";
            Ok::<_, Infallible>(())
        });
        balance
    };
    for model in [
        b"DYNAX 5D\0".as_slice(),
        b"MAXXUM 5D\0",
        b"ALPHA SWEET DIGITAL\0",
    ] {
        let file = five_d_file(model);
        assert_eq!(
            project(&file),
            [
                (EXPOSURE_PROGRAM, b"Shutter Priority".to_vec()),
                (IMAGE_QUALITY, b"RAW+JPEG".to_vec()),
                (WHITE_BALANCE, b"Cloudy".to_vec()),
                (FLASH, b"Fired".to_vec()),
                (METERING_MODE, b"Spot".to_vec()),
                (ISO_SPEED, b"80".to_vec()),
            ]
        );
    }
    let other = five_d_file(b"DYNAX 7D\0");
    assert!(project(&other).is_empty());
    assert!(!overlay_has_balance(&[&other]));
    let supported = five_d_file(b"DYNAX 5D\0");
    assert!(overlay_has_balance(&[&supported]));
    let mut replacement_model = exif_with_model(make, Some(b"DYNAX 5D\0"), &[]);
    // Replace the IFD0 photo pointer with an unknown tag to overlay only identity.
    let photo_pointer = 10 + 2 * 12;
    replacement_model[photo_pointer..photo_pointer + 2].copy_from_slice(&[0xff, 0xff]);
    assert!(!overlay_has_balance(&[&other, &replacement_model]));

    let mut classic = 1_u16.to_be_bytes().to_vec();
    classic.extend_from_slice(&row(0x0003, 7, 36, 0));
    let project_classic = |model| {
        let mut file = exif_with_model(make, model, &classic);
        let offset = file.len();
        file[offset - 4..offset].copy_from_slice(&(offset as u32).to_be_bytes());
        let values = [0_u32, 1, 3, 3, 0, 2, 0, 2, 64];
        file.extend(values.into_iter().flat_map(u32::to_be_bytes));
        project(&file)
    };
    assert_eq!(
        project_classic(Some(b"DiMAGE A2\0")),
        [
            (EXPOSURE_PROGRAM, b"Aperture Priority".to_vec()),
            (FLASH, b"Wireless".to_vec()),
            (WHITE_BALANCE, b"Tungsten".to_vec()),
            (IMAGE_QUALITY, b"Fine".to_vec()),
            (METERING_MODE, b"Spot".to_vec()),
            (ISO_SPEED, b"400".to_vec()),
        ]
    );
    assert!(project_classic(Some(b"DiMAGE X31\0")).is_empty());
    assert!(project_classic(None).is_empty());
}

#[test]
fn minolta_olympus_compatible_notes_use_their_ifd_byte_order() {
    let expected = [
        (IMAGE_QUALITY, b"HQ".to_vec()),
        (MACRO_MODE, b"On".to_vec()),
    ];
    for signature in [b"MINOL\0", b"CAMER\0"] {
        let mut note = signature.to_vec();
        note.extend_from_slice(&[0, 1, 2, 0]);
        note.extend_from_slice(&little_row(0x0201, 3, 2));
        note.extend_from_slice(&little_row(0x0202, 3, 1));
        assert_eq!(project(&exif(b"Konica Minolta\0", &note)), expected);
    }
    assert!(project(&exif(b"MINOLTA\0", b"MLY0\0\0\0\0\0\0\0\0\0\0")).is_empty());
}

#[test]
fn samsung_uses_type2_version_for_native_fields_and_preserves_pentax() {
    let mut big = 3_u16.to_be_bytes().to_vec();
    big.extend_from_slice(&row(1, 7, 4, u32::from_be_bytes(*b"0100")));
    big.extend_from_slice(&row(0xa014, 4, 1, 1600));
    big.extend_from_slice(&row(0xa01a, 4, 1, 263));
    big.extend_from_slice(&[0; 4]);
    let mut little = 3_u16.to_le_bytes().to_vec();
    let mut version = little_row(1, 7, u32::from_le_bytes(*b"0100"));
    version[4..8].copy_from_slice(&4_u32.to_le_bytes());
    little.extend_from_slice(&version);
    little.extend_from_slice(&little_row(0xa014, 4, 1600));
    little.extend_from_slice(&little_row(0xa01a, 4, 263));
    little.extend_from_slice(&[0; 4]);
    for mut note in [big, little] {
        assert_eq!(
            project(&exif(b"Samsung\0", &note)),
            [
                (ISO_SPEED, b"1600".to_vec()),
                (FOCAL_LENGTH_35MM, b"26.3 mm".to_vec()),
            ]
        );
        let end = note.len() - 4;
        let mut truncated = exif(b"Samsung\0", &note[..end]);
        truncated.extend_from_slice(&note[end..]);
        assert!(project(&truncated).is_empty());
        note[11] = b'2';
        assert!(project(&exif(b"Samsung\0", &note)).is_empty());
    }
    let mut pentax = b"AOC\0MM\0\x01".to_vec();
    pentax.extend_from_slice(&row(0x0008, 3, 1, 4 << 16));
    pentax.extend_from_slice(&[0; 4]);
    assert_eq!(
        project(&exif(b"SAMSUNG\0", &pentax)),
        [(IMAGE_QUALITY, b"RAW".to_vec())]
    );
}

#[test]
fn samsung_nx10_raw_values_require_an_owned_offset_profile() {
    const TABLE_END: u32 = 2 + 7 * 12 + 4;
    const EXPOSURE_AT: u32 = TABLE_END + 30;
    const APERTURE_AT: u32 = EXPOSURE_AT + 8;
    let mut note = 7_u16.to_be_bytes().to_vec();
    for entry in [
        row(1, 7, 4, u32::from_be_bytes(*b"0100")),
        row(2, 4, 1, 0x2000),
        row(3, 4, 1, 0x0100_101c),
        row(0xa001, 2, 30, TABLE_END),
        row(0xa014, 4, 1, 800),
        row(0xa018, 5, 1, EXPOSURE_AT),
        row(0xa019, 5, 1, APERTURE_AT),
    ] {
        note.extend_from_slice(&entry);
    }
    note.extend_from_slice(&[0; 4]);
    note.extend_from_slice(b"NX10_FW_X_F1110111\0\0\0\0\0\0\0\0\0\0\0\0");
    note.extend([1_u32, 320, 63, 10].into_iter().flat_map(u32::to_be_bytes));
    let make = b"SAMSUNG        \0";
    let nx10 = b"NX10           \0";
    let only_inline = [(ISO_SPEED, b"800".to_vec())];
    assert_eq!(
        project(&exif_with_model(make, Some(nx10), &note)),
        [
            only_inline[0].clone(),
            (EXPOSURE, b"1/320 s".to_vec()),
            (APERTURE, b"F6.3".to_vec()),
        ]
    );
    assert_eq!(
        project(&exif_with_model(make, Some(b"NX11\0"), &note)),
        only_inline
    );
    let mut incompatible = note.clone();
    incompatible[34..38].copy_from_slice(&0x0100_1327_u32.to_be_bytes());
    assert_eq!(
        project(&exif_with_model(make, Some(nx10), &incompatible)),
        only_inline
    );
    incompatible[34..38].copy_from_slice(&0x0100_101d_u32.to_be_bytes());
    incompatible[TABLE_END as usize] = b'X';
    assert_eq!(
        project(&exif_with_model(make, Some(nx10), &incompatible)),
        only_inline
    );

    // One rational points into the directory and the other is outside the note.
    note[70..74].copy_from_slice(&10_u32.to_be_bytes());
    let aperture = APERTURE_AT as usize;
    let mut outside = exif_with_model(make, Some(nx10), &note[..aperture]);
    outside.extend_from_slice(&note[aperture..]);
    assert_eq!(project(&outside), only_inline);
}

#[test]
fn samsung_models_qualify_firmware_before_reading_srw_values() {
    const VERSION_AT: u32 = 2 + 9 * 12 + 4;
    const FIRMWARE_AT: u32 = VERSION_AT + 8;
    const EXPOSURE_AT: u32 = FIRMWARE_AT + 30;
    const APERTURE_AT: u32 = EXPOSURE_AT + 8;
    const BIAS_AT: u32 = APERTURE_AT + 8;
    let check = |model: &[u8],
                 device,
                 id,
                 firmware: &[u8],
                 padding,
                 focal,
                 expected_focal: Option<&[u8]>| {
        let mut note = 9_u16.to_be_bytes().to_vec();
        for entry in [
            row(1, 7, 4, u32::from_be_bytes(*b"0100")),
            row(2, 4, 1, device),
            row(3, 4, 1, id),
            row(0xa000, 5, 1, VERSION_AT),
            row(0xa001, 2, 30, FIRMWARE_AT),
            row(0xa013, 10, 1, BIAS_AT),
            row(0xa018, 5, 1, EXPOSURE_AT),
            row(0xa019, 5, 1, APERTURE_AT),
            row(0xa01a, 4, 1, focal),
        ] {
            note.extend_from_slice(&entry);
        }
        note.extend_from_slice(&[0; 4]);
        note.extend([100_u32, 100].into_iter().flat_map(u32::to_be_bytes));
        note.extend_from_slice(firmware);
        note.push(0);
        note.resize(EXPOSURE_AT as usize, padding);
        note.extend(
            [1_u32, 80, 63, 10, 0, 1]
                .into_iter()
                .flat_map(u32::to_be_bytes),
        );
        let make = b"SAMSUNG\0";
        let mut expected = Vec::new();
        if let Some(focal) = expected_focal {
            expected.push((FOCAL_LENGTH_35MM, <[u8]>::to_vec(focal)));
        }
        expected.extend([(EXPOSURE, b"1/80 s".to_vec()), (APERTURE, b"F6.3".to_vec())]);
        assert_eq!(
            project(&exif_with_model(make, Some(model), &note)),
            expected
        );
        note[FIRMWARE_AT as usize] = b'!';
        let unqualified = project(&exif_with_model(make, Some(model), &note));
        assert!(
            unqualified
                .iter()
                .all(|(kind, _)| *kind == FOCAL_LENGTH_35MM)
        );
    };
    check(
        b"NX5 \0",
        0x2000,
        0x0100_101d,
        b"NX5_FW_X_F1211191",
        0,
        693,
        Some(b"69.3 mm"),
    );
    check(
        b"NX11\0",
        0x2000,
        0x0100_1327,
        b"NX11_FW_X_F1102151",
        0,
        847,
        Some(b"84.7 mm"),
    );
    check(
        b"NX100\0",
        0x2000,
        0x0100_130c,
        b"NX100_FW_X_F1110111",
        0,
        462,
        Some(b"46.2 mm"),
    );
    for model in [
        b"NX20\0".as_slice(),
        b"NX200\0",
        b"NX210\0",
        b"NX1000\0",
        b"NX1100\0",
    ] {
        check(model, 0x2000, 0x0500_0000, b"NX200_01.11", 0xee, 1, None);
    }
    for model in [b"NX300\0".as_slice(), b"NX300M\0"] {
        check(
            model,
            0x2000,
            0x0500_1038,
            b"1.43",
            0xff,
            63,
            Some(b"63.0 mm"),
        );
    }
    check(
        b"NX500\0",
        0x2000,
        0x0500_1038,
        b"1.00",
        0xff,
        690,
        Some(b"69.0 mm"),
    );
    check(
        b"WB2000\0",
        0x1000,
        0x0500_1038,
        b"FM1_104301",
        0xff,
        24,
        Some(b"24.0 mm"),
    );
    check(
        b"EX2F\0",
        0x1000,
        0x0500_0000,
        b"FM1_305224",
        0xff,
        28,
        Some(b"28.0 mm"),
    );
}

#[test]
fn casio_and_concord_use_their_directory_and_canonical_field_priorities() {
    let mut classic = 5_u16.to_be_bytes().to_vec();
    for (tag, value) in [(2, 3), (3, 2), (4, 2), (7, 4), (0x14, 160)] {
        classic.extend_from_slice(&row(tag, 3, 1, value << 16));
    }
    assert_eq!(
        project(&exif(b"CASIO COMPUTER CO.,LTD.\0", &classic)),
        [
            (IMAGE_QUALITY, b"Fine".to_vec()),
            (MACRO_MODE, b"On".to_vec()),
            (FLASH, b"On".to_vec()),
            (WHITE_BALANCE, b"Fluorescent".to_vec()),
            (ISO_SPEED, b"160".to_vec()),
        ]
    );
    assert!(project(&exif(b"Concord\0", &classic)).is_empty());

    for (signature, make) in [(b"QVC\0", b"CASIO\0".as_slice()), (b"DCI\0", b"Concord\0")] {
        let mut note = signature.to_vec();
        note.extend_from_slice(&[0, 0]);
        note.extend_from_slice(&8_u16.to_le_bytes());
        for (tag, value) in [
            (0x0008, 0),
            (0x0014, 9),
            (0x0019, 0),
            (0x2012, 2),
            (0x3000, 4),
            (0x3002, 3),
            (0x3003, 8),
            (0x3014, 0),
        ] {
            note.extend_from_slice(&little_row(tag, 3, value));
        }
        note.extend_from_slice(&[0; 4]);
        assert_eq!(
            project(&exif(make, &note)),
            [
                (IMAGE_QUALITY, b"Fine".to_vec()),
                (MACRO_MODE, b"Super Macro".to_vec()),
                (WHITE_BALANCE, b"Cloudy".to_vec()),
                (EXPOSURE_PROGRAM, b"Aperture Priority".to_vec()),
                (ISO_SPEED, b"200".to_vec()),
            ]
        );
        let end = note.len() - 4;
        let mut truncated = exif(make, &note[..end]);
        truncated.extend_from_slice(&note[end..]);
        assert!(project(&truncated).is_empty());
    }
}

#[test]
fn sanyo_uses_inline_short_fields_in_its_own_directory_order() {
    let mut big = b"SANYO\0\x01\0\0\x04".to_vec();
    big.extend_from_slice(&row(0x0100, 7, 120, u32::MAX));
    big.extend_from_slice(&row(0x0201, 3, 1, 0x0104 << 16));
    big.extend_from_slice(&row(0x0202, 3, 1, 1 << 16));
    big.extend_from_slice(&row(0x0225, 3, 1, 3 << 16));
    let mut little = b"SANYO\0\x01\0\x03\0".to_vec();
    little.extend_from_slice(&little_row(0x0201, 3, 0x0104));
    little.extend_from_slice(&little_row(0x0202, 3, 1));
    little.extend_from_slice(&little_row(0x0225, 3, 3));
    let expected = [
        (IMAGE_QUALITY, b"Fine/Medium High".to_vec()),
        (MACRO_MODE, b"Macro".to_vec()),
        (FLASH, b"Red eye".to_vec()),
    ];
    for note in [big, little] {
        assert_eq!(
            project(&exif(b"SANYO Electric Co., Ltd.\0", &note)),
            expected
        );
        assert!(project(&exif(b"OLYMPUS\0", &note)).is_empty());
        let last = note.len() - 1;
        let mut truncated = exif(b"SANYO\0", &note[..last]);
        truncated.push(note[last]);
        assert!(project(&truncated).is_empty());
    }
}

fn little_row(tag: u16, kind: u16, value: u32) -> [u8; 12] {
    let mut row = [0; 12];
    row[..2].copy_from_slice(&tag.to_le_bytes());
    row[2..4].copy_from_slice(&kind.to_le_bytes());
    row[4..8].copy_from_slice(&1_u32.to_le_bytes());
    row[8..].copy_from_slice(&value.to_le_bytes());
    row
}

fn exif(make: &[u8], note: &[u8]) -> Vec<u8> {
    exif_with_model(make, None, note)
}

fn exif_with_model(make: &[u8], model: Option<&[u8]>, note: &[u8]) -> Vec<u8> {
    exif_with_photo(make, model, note, &[])
}

fn exif_with_photo(
    make: &[u8],
    model: Option<&[u8]>,
    note: &[u8],
    photo_rows: &[[u8; 12]],
) -> Vec<u8> {
    let rows = 2 + u16::from(model.is_some());
    let photo_offset = 14 + 12 * u32::from(rows);
    let photo_count = 1 + photo_rows.len() as u16;
    let make_offset = photo_offset + 6 + 12 * u32::from(photo_count);
    let make_end = make_offset + make.len() as u32;
    let model_end = model.map_or(make_end, |model| {
        make_end.next_multiple_of(2) + model.len() as u32
    });
    let note_offset = model_end.next_multiple_of(2);
    // IFD0 and its Exif child use big-endian offsets. Each MakerNote declares its own layout.
    let mut bytes = b"MM\0*\0\0\0\x08".to_vec();
    bytes.extend_from_slice(&rows.to_be_bytes());
    bytes.extend_from_slice(&row(0x010f, 2, make.len() as u32, make_offset));
    if let Some(model) = model {
        bytes.extend_from_slice(&row(
            0x0110,
            2,
            model.len() as u32,
            make_end.next_multiple_of(2),
        ));
    }
    bytes.extend_from_slice(&row(0x8769, 4, 1, photo_offset));
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&photo_count.to_be_bytes());
    for entry in photo_rows {
        bytes.extend_from_slice(entry);
    }
    bytes.extend_from_slice(&row(super::TAG, 7, note.len() as u32, note_offset));
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(make);
    if let Some(model) = model {
        bytes.resize(make_end.next_multiple_of(2) as usize, 0);
        bytes.extend_from_slice(model);
    }
    bytes.resize(note_offset as usize, 0);
    bytes.extend_from_slice(note);
    bytes
}

fn row(tag: u16, kind: u16, count: u32, value: u32) -> [u8; 12] {
    let mut row = [0; 12];
    row[..2].copy_from_slice(&tag.to_be_bytes());
    row[2..4].copy_from_slice(&kind.to_be_bytes());
    row[4..8].copy_from_slice(&count.to_be_bytes());
    row[8..].copy_from_slice(&value.to_be_bytes());
    row
}

fn project(file: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let mut projected = Vec::new();
    let Ok(()) = visit_exif(file, 128, &mut |kind, bytes| {
        if matches!(
            kind,
            ISO_SPEED
                | APERTURE
                | EXPOSURE
                | FOCAL_LENGTH
                | 113
                | IMAGE_QUALITY
                | MACRO_MODE
                | METERING_MODE
                | WHITE_BALANCE
                | RATING
                | EXPOSURE_PROGRAM
                | FLASH
                | FOCAL_LENGTH_35MM
        ) {
            projected.push((kind, bytes.to_vec()));
        }
        Ok::<_, Infallible>(())
    });
    projected
}
