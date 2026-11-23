use super::super::Format;
use super::{Container, Input, visit_exif};
use std::convert::Infallible;

struct Fixture {
    bytes: Vec<u8>,
    little: bool,
}

impl Fixture {
    fn new(little: bool) -> Self {
        Self {
            bytes: if little {
                b"II*\0\0\0\0\0"
            } else {
                b"MM\0*\0\0\0\0"
            }
            .to_vec(),
            little,
        }
    }

    fn short(&self, value: u16) -> [u8; 2] {
        if self.little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    }

    fn long(&self, value: u32) -> [u8; 4] {
        if self.little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    }

    fn ratios(&self, values: &[(i32, i32)]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|&(numerator, denominator)| {
                [self.long(numerator as u32), self.long(denominator as u32)]
            })
            .flatten()
            .collect()
    }

    fn aligned_offset(&mut self) -> u32 {
        if !self.bytes.len().is_multiple_of(2) {
            self.bytes.push(0);
        }
        self.bytes.len() as u32
    }

    fn entry(&mut self, tag: u16, kind: u16, count: u32, data: &[u8]) -> [u8; 12] {
        let mut entry = [0; 12];
        entry[..2].copy_from_slice(&self.short(tag));
        entry[2..4].copy_from_slice(&self.short(kind));
        entry[4..8].copy_from_slice(&self.long(count));
        if data.len() <= 4 {
            entry[8..8 + data.len()].copy_from_slice(data);
        } else {
            let at = self.aligned_offset();
            self.bytes.extend_from_slice(data);
            entry[8..].copy_from_slice(&self.long(at));
        }
        entry
    }

    fn directory(&mut self, entries: &[[u8; 12]]) -> u32 {
        self.aligned_offset();
        self.write_directory(entries)
    }

    fn write_directory(&mut self, entries: &[[u8; 12]]) -> u32 {
        let at = self.bytes.len() as u32;
        self.bytes
            .extend_from_slice(&self.short(entries.len() as u16));
        self.bytes.extend_from_slice(entries.as_flattened());
        self.bytes.extend_from_slice(&[0; 4]);
        at
    }
}

#[test]
fn profile_projects_typed_fields_once_in_both_byte_orders() {
    for little in [true, false] {
        let mut tiff = Fixture::new(little);
        let photo = [
            tiff.entry(0x829a, 5, 1, &tiff.ratios(&[(1, 125)])),
            tiff.entry(0x829d, 5, 1, &tiff.ratios(&[(28, 10)])),
            tiff.entry(0x8827, 3, 1, &tiff.short(u16::MAX)),
            tiff.entry(0x8833, 4, 1, &tiff.long(102_400)),
            tiff.entry(0x9003, 2, 20, b"2026:04:05 06:07:08\0"),
            tiff.entry(0x9204, 10, 1, &tiff.ratios(&[(-2, 6)])),
            // Invalid focal length must not affect other tags.
            tiff.entry(0x920a, 5, 1, &tiff.ratios(&[(42, 0)])),
            tiff.entry(0x9286, 7, 14, b"UNICODE\0\xfe\xff\x96\xea\0\0"),
        ];
        let photo = tiff.directory(&photo);
        let gps = [
            tiff.entry(1, 2, 2, b"N\0"),
            tiff.entry(2, 5, 3, &tiff.ratios(&[(12, 1), (30, 1), (1, 2)])),
        ];
        let gps = tiff.directory(&gps);
        let image = [
            tiff.entry(0x010f, 2, 4, b"Cam\0"),
            tiff.entry(0x010f, 2, 10, b"Duplicate\0"),
            tiff.entry(0x0112, 3, 1, &tiff.short(6)),
            tiff.entry(0x8769, 4, 1, &tiff.long(photo)),
            tiff.entry(0x8825, 4, 1, &tiff.long(gps)),
        ];
        let first = tiff.directory(&image);
        let offset = tiff.long(first);
        tiff.bytes[4..8].copy_from_slice(&offset);

        let mut fields = Vec::new();
        let Ok(()) = visit_exif(&tiff.bytes, 64, &mut |kind,
                                                       text|
         -> Result<(), Infallible> {
            fields.push((kind, String::from_utf8_lossy(text).into_owned()));
            Ok(())
        });
        assert_eq!(
            fields
                .iter()
                .map(|(kind, value)| (*kind, value.as_str()))
                .collect::<Vec<_>>(),
            [
                (95, "Cam"),
                (110, "right, top"),
                (97, "1/125 s"),
                (98, "F2.8"),
                (58, "2026:04:05 06:07:08"),
                (99, "-1/3 EV"),
                (3, "雪"),
                (104, "102400"),
                (37, "North"),
                (38, "12 deg 30' 0.50\""),
            ]
        );
    }
}

#[test]
fn exif_three_uses_declared_utf8_fields_and_unicode_comments() {
    let mut tiff = Fixture::new(false);
    let comment = [b"UNICODE\0".as_slice(), "短い注釈".as_bytes()].concat();
    let photo = [
        tiff.entry(0x9000, 7, 4, b"0310"),
        tiff.entry(0x9286, 7, comment.len() as u32, &comment),
        tiff.entry(0xa436, 129, 7, "夜景\0".as_bytes()),
    ];
    let photo = tiff.directory(&photo);
    let image = [
        tiff.entry(0x010f, 129, 4, "星\0".as_bytes()),
        tiff.entry(0x0110, 129, 5, b"\xef\xbb\xbfX\0"),
        tiff.entry(0x8769, 4, 1, &tiff.long(photo)),
    ];
    let first = tiff.directory(&image);
    let offset = tiff.long(first);
    tiff.bytes[4..8].copy_from_slice(&offset);

    let mut fields = Vec::new();
    let Ok(()) = visit_exif(&tiff.bytes, 64, &mut |kind,
                                                   text|
     -> Result<(), Infallible> {
        fields.push((kind, String::from_utf8_lossy(text).into_owned()));
        Ok(())
    });
    assert_eq!(
        fields,
        [
            (95, "星".into()),
            (3, "短い注釈".into()),
            (4, "夜景".into())
        ]
    );
}

#[test]
fn jis_comments_use_the_declared_encoding_and_fit_the_text_limit() {
    let text = "東京 A";
    for (bytes, limit, expected) in [
        (b"\x1b$BEl5~\x1b(B A\0".as_slice(), text.len(), Some(text)),
        (b"\x1b$BEl5~\x1b(B A".as_slice(), text.len() - 1, None),
        (b"\x1b$B!A!B!]\x1b(B".as_slice(), 9, Some("〜‖−")),
        (b"\x1b$B-!\x1b(B".as_slice(), text.len(), None),
        (b"\x1b(I!\x1b(B".as_slice(), text.len(), None),
        (b"\x1b$BE".as_slice(), text.len(), None),
        (b"\x93\x8c\x8b\x9e".as_slice(), text.len(), None),
    ] {
        let mut tiff = Fixture::new(false);
        let comment = [b"JIS\0\0\0\0\0".as_slice(), bytes].concat();
        let photo = tiff.entry(0x9286, 7, comment.len() as u32, &comment);
        let photo = tiff.directory(&[photo]);
        let image = tiff.entry(0x8769, 4, 1, &tiff.long(photo));
        let first = tiff.directory(&[image]);
        let offset = tiff.long(first);
        tiff.bytes[4..8].copy_from_slice(&offset);

        let mut output = Vec::new();
        let Ok(()) = visit_exif(&tiff.bytes, limit, &mut |kind, value| {
            output.push((kind, value.to_vec()));
            Ok::<_, Infallible>(())
        });
        assert_eq!(
            output,
            expected
                .into_iter()
                .map(|value| (3, value.as_bytes().to_vec()))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn olympus_raw_headers_use_classic_directories_for_standalone_metadata() {
    const IPTC: &[u8] = b"\x1c\x02\x19\0\x07Archive";
    const XMP: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:x="http://ns.adobe.com/xap/1.0/"><r:Description x:CreatorTool="Editor"/></r:RDF>"#;

    for (little, signature) in [(true, 0x4f52), (false, 0x5352)] {
        let mut tiff = Fixture::new(little);
        let magic = tiff.short(signature);
        tiff.bytes[2..4].copy_from_slice(&magic);
        let image = [
            tiff.entry(256, 3, 1, &tiff.short(320)),
            tiff.entry(257, 3, 1, &tiff.short(240)),
            tiff.entry(0x010f, 2, 8, b"Olympus\0"),
            tiff.entry(700, 1, XMP.len() as u32, XMP),
            tiff.entry(33723, 1, IPTC.len() as u32, IPTC),
        ];
        let first = tiff.directory(&image);
        let offset = tiff.long(first);
        tiff.bytes[4..8].copy_from_slice(&offset);

        let prefix = &tiff.bytes[..8];
        assert!(matches!(Container::detect(prefix), Some(Container::Orf)));
        let mut scratch = [0; 512];
        let input = Input::new(
            prefix,
            tiff.bytes.len() as u64,
            &mut scratch,
            |offset, output: &mut [u8]| {
                let start = offset as usize;
                output.copy_from_slice(&tiff.bytes[start..start + output.len()]);
                Ok::<_, Infallible>(())
            },
        );
        let mut fields = Vec::new();
        let Ok(()) = Container::Orf.visit(input, 64, &mut |kind, text| {
            fields.push((kind, text.to_vec()));
            Ok(())
        });
        assert_eq!(
            fields,
            [
                (1, b"image/x-olympus-orf".to_vec()),
                (112, b"320x240".to_vec()),
                (95, b"Olympus".to_vec()),
                (49, b"Archive".to_vec()),
                (56, b"Editor".to_vec()),
            ],
        );

        let result = visit_exif(&tiff.bytes, 64, &mut |_, _| {
            Err("embedded ORF was accepted")
        });
        assert_eq!(result, Ok(()));
    }
}

#[test]
fn bigtiff_reads_directories_and_values_above_four_gibibytes() {
    const DIRECTORY: u64 = (1_u64 << 32) + 2;
    const CAMERA: u64 = DIRECTORY + 100;
    const CAMERA_BYTES: &[u8] = b"Large format\0";
    let mut header = b"MM\0+\0\x08\0\0".to_vec();
    header.extend_from_slice(&DIRECTORY.to_be_bytes());
    let mut directory = 1_u64.to_be_bytes().to_vec();
    directory.extend_from_slice(&[0x01, 0x0f, 0x00, 0x02]); // Make, ASCII
    directory.extend_from_slice(&(CAMERA_BYTES.len() as u64).to_be_bytes());
    directory.extend_from_slice(&CAMERA.to_be_bytes());
    directory.extend_from_slice(&0_u64.to_be_bytes());

    let mut scratch = [0; 64];
    let input = Input::new(
        &header,
        CAMERA + CAMERA_BYTES.len() as u64,
        &mut scratch,
        |offset, output: &mut [u8]| {
            for (begin, bytes) in [(DIRECTORY, directory.as_slice()), (CAMERA, CAMERA_BYTES)] {
                if let Some(start) = offset
                    .checked_sub(begin)
                    .and_then(|n| usize::try_from(n).ok())
                    && let Some(end) = start.checked_add(output.len())
                    && let Some(range) = bytes.get(start..end)
                {
                    output.copy_from_slice(range);
                    return Ok(());
                }
            }
            Err("unexpected read outside the original TIFF fields")
        },
    );
    let mut fields = Vec::new();
    let result = Container::Tiff.visit(input, 64, &mut |kind, text| {
        fields.push((kind, text.to_vec()));
        Ok(())
    });
    assert_eq!(result, Ok(()));
    assert_eq!(
        fields,
        [(1, b"image/tiff".to_vec()), (95, b"Large format".to_vec())]
    );
}

#[test]
fn panasonic_profiles_share_sensor_fields_and_supplemental_preview_exif() -> Result<(), &'static str>
{
    let mut preview = Fixture::new(true);
    let entries = [
        preview.entry(0x010f, 2, 5, b"JPEG\0"),
        preview.entry(0x0110, 2, 6, b"Lumix\0"),
    ];
    let root = preview.directory(&entries);
    preview.bytes[4..8].copy_from_slice(&root.to_le_bytes());
    let mut jpeg = b"\xff\xd8\xff\xfe\0\x09preview\xff\xe1".to_vec();
    jpeg.extend_from_slice(&((2 + 6 + preview.bytes.len()) as u16).to_be_bytes());
    jpeg.extend_from_slice(b"Exif\0\0");
    jpeg.extend_from_slice(&preview.bytes);
    jpeg.extend_from_slice(b"\xff\xd9");

    for (extension, mime) in [
        (&b""[..], &b"image/x-panasonic-raw"[..]),
        (
            &b"\x88\xe7\x74\xd8\xf8\x25\x1d\x4d\x94\x7a\x6e\x77\x82\x2b\x5d\x6a"[..],
            &b"image/x-panasonic-rw2"[..],
        ),
    ] {
        for copies in [1, 2] {
            let mut tiff = Fixture::new(true);
            tiff.bytes[2] = 0x55;
            tiff.bytes.extend_from_slice(extension);
            let entries = [
                tiff.entry(0x0002, 3, 1, &6000_u16.to_le_bytes()),
                tiff.entry(0x0003, 3, 1, &4000_u16.to_le_bytes()),
                tiff.entry(0x0017, 3, 1, &100_u16.to_le_bytes()),
                tiff.entry(0x010f, 2, 4, b"RAW\0"),
            ];
            let mut entries = entries.to_vec();
            let image = tiff.entry(0x002e, 7, jpeg.len() as u32, &jpeg);
            entries.extend(std::iter::repeat_n(image, copies));
            let root = tiff.directory(&entries);
            tiff.bytes[4..8].copy_from_slice(&root.to_le_bytes());
            let expected: &[(u32, &[u8])] = &[
                (1, mime),
                (112, b"6000x4000"),
                (95, b"RAW"),
                (104, b"100"),
                (96, b"Lumix"),
            ];
            verify_raw(&tiff.bytes, &expected[..if copies == 1 { 5 } else { 4 }])?;
        }
    }
    Ok(())
}

#[test]
fn panasonic_type_requires_the_complete_rw2_extension() {
    let legacy = b"IIU\0\x08\0\0\0";
    assert!(matches!(
        Container::detect(legacy),
        Some(Container::PanasonicRaw)
    ));
    assert_eq!(Format::identification_len(legacy, 64), 8);

    let rw2 = b"IIU\0\x18\0\0\0\x88\xe7\x74\xd8\xf8\x25\x1d\x4d\x94\x7a\x6e\x77\x82\x2b\x5d\x6a";
    assert_eq!(Format::identification_len(&rw2[..8], 64), 24);
    assert!(Container::detect(&rw2[..23]).is_none());
    assert!(matches!(Container::detect(rw2), Some(Container::Rw2)));
}

#[test]
fn dng_uses_one_raw_identity_and_retains_ifd0_metadata() -> Result<(), &'static str> {
    let mut tiff = Fixture::new(true);
    let raw = [
        tiff.entry(254, 4, 1, &0_u32.to_le_bytes()),
        tiff.entry(256, 3, 1, &6000_u16.to_le_bytes()),
        tiff.entry(257, 3, 1, &4000_u16.to_le_bytes()),
        tiff.entry(262, 3, 1, &32803_u16.to_le_bytes()),
        tiff.entry(0x010f, 2, 6, b"Child\0"),
    ];
    let raw = tiff.directory(&raw);
    let image = [
        tiff.entry(254, 4, 1, &1_u32.to_le_bytes()),
        tiff.entry(256, 3, 1, &160_u16.to_le_bytes()),
        tiff.entry(257, 3, 1, &120_u16.to_le_bytes()),
        tiff.entry(330, 4, 1, &raw.to_le_bytes()),
        tiff.entry(0xc612, 1, 4, &[1, 7, 1, 0]),
        tiff.entry(0x010f, 2, 4, b"Cam\0"),
    ];
    let root = tiff.directory(&image);
    tiff.bytes[4..8].copy_from_slice(&root.to_le_bytes());
    verify_raw(
        &tiff.bytes,
        &[(1, b"image/x-adobe-dng"), (112, b"6000x4000"), (95, b"Cam")],
    )
}

#[test]
fn cr2_prefers_photo_size_then_the_raw_image_over_ifd0_preview() -> Result<(), &'static str> {
    for photo in [true, false] {
        let mut tiff = Fixture::new(true);
        tiff.bytes.extend_from_slice(b"CR\x02\0\0\0\0\0");
        let image = [
            tiff.entry(256, 3, 1, &160_u16.to_le_bytes()),
            tiff.entry(257, 3, 1, &120_u16.to_le_bytes()),
            // External values cannot read the extended CR2 header.
            [0x0f, 0x01, 2, 0, 6, 0, 0, 0, 8, 0, 0, 0],
        ];
        let raw = [
            tiff.entry(256, 3, 1, &6024_u16.to_le_bytes()),
            tiff.entry(257, 3, 1, &4024_u16.to_le_bytes()),
        ];
        let raw = tiff.directory(&raw);
        tiff.bytes[12..16].copy_from_slice(&raw.to_le_bytes());
        let mut image = image.to_vec();
        if photo {
            let photo = [
                tiff.entry(0xa002, 4, 1, &6000_u32.to_le_bytes()),
                tiff.entry(0xa003, 4, 1, &4000_u32.to_le_bytes()),
            ];
            let photo = tiff.directory(&photo);
            image.push(tiff.entry(0x8769, 4, 1, &photo.to_le_bytes()));
        }
        let root = tiff.directory(&image);
        tiff.bytes[4..8].copy_from_slice(&root.to_le_bytes());
        let size: &[u8] = if photo { b"6000x4000" } else { b"6024x4024" };
        verify_raw(&tiff.bytes, &[(1, b"image/x-canon-cr2"), (112, size)])?;
    }
    Ok(())
}

#[test]
fn sony_raw_notes_identify_sr2_and_arw_without_overriding_tiff_or_dng() -> Result<(), &'static str>
{
    for (version, entries, make, dng, mime) in [
        (
            [1, 0, 0, 0],
            1,
            b"SONY\0".as_slice(),
            false,
            b"image/x-sony-sr2".as_slice(),
        ),
        (
            [2, 0, 0, 0],
            1,
            b"SONY           \0",
            false,
            b"image/x-sony-arw",
        ),
        ([0, 0, 0, 2], 1, b"SONY\0", false, b"image/tiff"),
        ([1, 0, 0, 0], 2, b"SONY\0", false, b"image/tiff"),
        ([1, 0, 0, 0], 1, b"SONY Inc\0", false, b"image/tiff"),
        ([1, 0, 0, 0], 1, b"SONY\0", true, b"image/x-adobe-dng"),
    ] {
        let mut tiff = Fixture::new(true);
        let raw = [
            tiff.entry(256, 4, 1, &3984_u32.to_le_bytes()),
            tiff.entry(257, 4, 1, &2608_u32.to_le_bytes()),
            tiff.entry(262, 3, 1, &32803_u16.to_le_bytes()),
        ];
        let raw = tiff.directory(&raw);
        let mut maker = Vec::new();
        if version[0] == 2 {
            maker.extend_from_slice(b"SONY DSC \0\0\0");
        }
        maker.extend_from_slice(&u16::to_le_bytes(entries));
        let row = tiff.entry(0xb000, 1, 4, &version);
        for _ in 0..entries {
            maker.extend_from_slice(&row);
        }
        if version[0] != 2 {
            maker.extend_from_slice(&[0; 4]);
        }
        let photo = [
            tiff.entry(0x8827, 3, 1, &160_u16.to_le_bytes()),
            tiff.entry(0x927c, 7, maker.len() as u32, &maker),
        ];
        let photo = tiff.directory(&photo);
        let mut image = vec![
            tiff.entry(0x010f, 2, make.len() as u32, make),
            tiff.entry(0x014a, 4, 1, &raw.to_le_bytes()),
            tiff.entry(0x8769, 4, 1, &photo.to_le_bytes()),
        ];
        if dng {
            image.push(tiff.entry(0xc612, 1, 4, &[1, 7, 1, 0]));
        }
        let dimensions: &[u8] = if version[0] == 2 {
            image.push(tiff.entry(256, 4, 1, &3872_u32.to_le_bytes()));
            image.push(tiff.entry(257, 4, 1, &2592_u32.to_le_bytes()));
            b"3872x2592"
        } else {
            b"3984x2608"
        };
        let root = tiff.directory(&image);
        tiff.bytes[4..8].copy_from_slice(&root.to_le_bytes());
        verify_raw(
            &tiff.bytes,
            &[
                (1, mime),
                (112, dimensions),
                (95, &make[..make.len() - 1]),
                (104, b"160"),
            ],
        )?;
    }
    Ok(())
}

#[test]
fn srf_identity_requires_a_known_model_and_owned_directory_link() -> Result<(), &'static str> {
    for (model, displacement, mime) in [
        (b"DSC-F828\0".as_slice(), 20, b"image/x-sony-srf".as_slice()),
        (b"DSC-V3\0", 20, b"image/x-sony-srf"),
        (b"DSC-F828\0", 24, b"image/tiff"),
        (b"DSC-F828\0", 16, b"image/tiff"),
        (b"DSC-R1\0", 20, b"image/tiff"),
    ] {
        let mut tiff = Fixture::new(true);
        let start = tiff.aligned_offset();
        let mut maker = b"\x01\0\x03\0\x04\0\x01\0\0\0\0\0\0\x01".to_vec();
        maker.extend_from_slice(&(start + displacement).to_le_bytes());
        maker.extend_from_slice(&[0; 4]);
        let photo = tiff.entry(0x927c, 7, maker.len() as u32, &maker);
        let photo = tiff.directory(&[photo]);
        let image = [
            tiff.entry(0x0100, 4, 1, &3360_u32.to_le_bytes()),
            tiff.entry(0x0101, 4, 1, &2460_u32.to_le_bytes()),
            tiff.entry(0x010f, 2, 5, b"SONY\0"),
            tiff.entry(0x0110, 2, model.len() as u32, model),
            tiff.entry(0x8769, 4, 1, &photo.to_le_bytes()),
        ];
        let root = tiff.directory(&image);
        tiff.bytes[4..8].copy_from_slice(&root.to_le_bytes());
        verify_raw(
            &tiff.bytes,
            &[
                (1, mime),
                (112, b"3360x2460"),
                (95, b"SONY"),
                (96, &model[..model.len() - 1]),
            ],
        )?;
    }
    Ok(())
}

#[test]
fn raw_compression_uses_the_selected_sensor_and_original_camera_make() -> Result<(), &'static str> {
    for little in [true, false] {
        for (make, compression, photometric, mime, dimensions) in [
            ("SAMSUNG", 32769, 32803, "image/x-samsung-srw", "6000x4000"),
            ("EPSON", 32769, 32803, "image/x-epson-erf", "6000x4000"),
            ("Camera", 32769, 32803, "image/tiff", "6000x4000"),
            ("SAMSUNG", 32772, 32803, "image/x-samsung-srw", "6000x4000"),
            ("SAMSUNG", 32773, 32803, "image/x-samsung-srw", "6000x4000"),
            ("SAMSUNG", 32773, 2, "image/tiff", "160x120"),
            ("Camera", 32773, 2, "image/tiff", "160x120"),
            ("KODAK", 32867, 32803, "image/x-kodak-kdc", "6000x4000"),
        ] {
            let mut tiff = Fixture::new(little);
            let raw = [
                tiff.entry(256, 3, 1, &tiff.short(6000)),
                tiff.entry(257, 3, 1, &tiff.short(4000)),
                tiff.entry(259, 3, 1, &tiff.short(compression)),
                tiff.entry(262, 3, 1, &tiff.short(photometric)),
                tiff.entry(271, 2, 6, b"Child\0"),
            ];
            let selected = tiff.directory(&raw);
            let mut make_field = make.as_bytes().to_vec();
            make_field.push(0);
            let image = [
                tiff.entry(254, 4, 1, &tiff.long(1)),
                tiff.entry(256, 3, 1, &tiff.short(160)),
                tiff.entry(257, 3, 1, &tiff.short(120)),
                tiff.entry(271, 2, make_field.len() as u32, &make_field),
                tiff.entry(330, 4, 1, &tiff.long(selected)),
            ];
            let root = tiff.directory(&image);
            let encoded = tiff.long(root);
            tiff.bytes[4..8].copy_from_slice(&encoded);
            verify_raw(
                &tiff.bytes,
                &[
                    (1, mime.as_bytes()),
                    (112, dimensions.as_bytes()),
                    (95, make.as_bytes()),
                ],
            )?;
        }
    }
    Ok(())
}

#[test]
fn samsung_subifds_identify_sensor_geometry_and_skip_previews() -> Result<(), &'static str> {
    let samsung = b"SAMSUNG\0\xd8\xcb\xf2\xb0\x06\0\0\0\x36\xc7\0\0".as_slice();
    let similar_make = b"SAMSUNGER\0\xff".as_slice();
    for (make, model, odd, valid_strip, found) in [
        (samsung, "NX500", true, true, true),
        (samsung, "NX1100", true, true, true),
        (samsung, "NX300", true, true, true),
        (samsung, "EX2F", false, true, true),
        (samsung, "EX2F", true, true, false),
        (samsung, "NX500", true, false, false),
        (similar_make, "NX500", true, true, false),
    ] {
        let mut tiff = Fixture::new(false);
        let strip = tiff.aligned_offset();
        tiff.bytes.extend_from_slice(&[0; 8]);
        if odd {
            tiff.bytes.push(0);
        }
        let jpeg = [
            tiff.entry(0x0100, 4, 1, &160_u32.to_be_bytes()),
            tiff.entry(0x0101, 4, 1, &120_u32.to_be_bytes()),
            tiff.entry(0x0201, 4, 1, &strip.to_be_bytes()),
        ];
        let preview = tiff.write_directory(&jpeg);
        let (width, height, dimensions) = if model == "EX2F" {
            (4176_u32, 3058_u32, b"4176x3058".as_slice())
        } else {
            (6496, 4336, b"6496x4336".as_slice())
        };
        let compression = if model == "NX500" { 32773_u32 } else { 32769 };
        let strip_length = if valid_strip { 8_u32 } else { u32::MAX };
        let sensor = [
            tiff.entry(0x00fe, 4, 1, &0_u32.to_be_bytes()),
            tiff.entry(0x0100, 4, 1, &width.to_be_bytes()),
            tiff.entry(0x0101, 4, 1, &height.to_be_bytes()),
            tiff.entry(0x0102, 3, 1, &12_u16.to_be_bytes()),
            tiff.entry(0x0103, 4, 1, &compression.to_be_bytes()),
            tiff.entry(0x0111, 4, 1, &strip.to_be_bytes()),
            tiff.entry(0x0117, 4, 1, &strip_length.to_be_bytes()),
            tiff.entry(0x828d, 3, 2, &[0, 2, 0, 2]),
            tiff.entry(0x828e, 1, 4, &[0, 1, 1, 2]),
        ];
        let sensor = tiff.write_directory(&sensor);
        let offsets = [preview.to_be_bytes(), sensor.to_be_bytes()];
        let mut model_field = model.as_bytes().to_vec();
        model_field.extend_from_slice(&[0; 2]);
        let image = [
            tiff.entry(0x010f, 2, make.len() as u32, make),
            tiff.entry(0x0110, 2, model_field.len() as u32, &model_field),
            tiff.entry(0x014a, 4, 2, offsets.as_flattened()),
        ];
        let root = tiff.directory(&image);
        tiff.bytes[4..8].copy_from_slice(&root.to_be_bytes());
        let mut expected = vec![(
            1,
            if found {
                b"image/x-samsung-srw".as_slice()
            } else {
                b"image/tiff"
            },
        )];
        if found {
            expected.push((112, dimensions));
        }
        if make == samsung {
            expected.push((95, b"SAMSUNG"));
        }
        expected.push((96, model.as_bytes()));
        verify_raw(&tiff.bytes, &expected)?;
    }
    Ok(())
}

#[test]
fn recognizes_both_dc120_encodings_from_owned_kodak_directories() -> Result<(), &'static str> {
    let dc120 = b"Kodak DC120 ZOOM Digital Camera\0".as_slice();
    let make = b"Eastman Kodak Company\0";
    for (compression, version, model, expected_mime) in [
        (1, [1, 1, 0, 0], dc120, b"image/x-kodak-kdc".as_slice()),
        (7, [1, 1, 0, 0], dc120, b"image/x-kodak-kdc"),
        (7, [1, 0, 0, 0], dc120, b"image/tiff"),
        (1, [1, 1, 0, 0], b"Kodak DC1200\0", b"image/tiff"),
    ] {
        let mut tiff = Fixture::new(false);
        let sensor = [
            tiff.entry(0x00fe, 4, 1, &0_u32.to_be_bytes()),
            tiff.entry(0x0100, 3, 1, &1280_u16.to_be_bytes()),
            tiff.entry(0x0101, 3, 1, &960_u16.to_be_bytes()),
            tiff.entry(0x0102, 3, 1, &8_u16.to_be_bytes()),
            tiff.entry(0x0103, 3, 1, &tiff.short(compression)),
            tiff.entry(0x0106, 3, 1, &32803_u16.to_be_bytes()),
        ];
        let sensor = tiff.directory(&sensor);
        let version = tiff.entry(0, 1, 4, &version);
        let shooting = tiff.directory(&[version]);
        let image = [
            tiff.entry(0x00fe, 4, 1, &1_u32.to_be_bytes()),
            tiff.entry(0x0100, 3, 1, &80_u16.to_be_bytes()),
            tiff.entry(0x0101, 3, 1, &60_u16.to_be_bytes()),
            tiff.entry(0x010f, 2, make.len() as u32, make),
            tiff.entry(0x0110, 2, model.len() as u32, model),
            tiff.entry(0x014a, 4, 1, &sensor.to_be_bytes()),
            tiff.entry(0x8290, 4, 1, &shooting.to_be_bytes()),
        ];
        let root = tiff.directory(&image);
        tiff.bytes[4..8].copy_from_slice(&root.to_be_bytes());
        verify_raw(
            &tiff.bytes,
            &[
                (1, expected_mime),
                (112, b"1280x960"),
                (95, &make[..make.len() - 1]),
                (96, &model[..model.len() - 1]),
            ],
        )?;
    }
    Ok(())
}

#[test]
fn kodak_kdc_white_balance_requires_a_qualified_root_link() -> Result<(), &'static str> {
    for make in ["EASTMAN KODAK COMPANY", "KODAK-LIKE"] {
        let mut tiff = Fixture::new(true);
        let balance = tiff.entry(0xfa0d, 1, 1, &[3]);
        let kdc = tiff.directory(&[balance]);
        let mut make_field = make.as_bytes().to_vec();
        make_field.push(0);
        let image = [
            tiff.entry(271, 2, make_field.len() as u32, &make_field),
            tiff.entry(0xfe00, 4, 1, &kdc.to_le_bytes()),
        ];
        let root = tiff.directory(&image);
        tiff.bytes[4..8].copy_from_slice(&root.to_le_bytes());
        let expected: &[(u32, &[u8])] = if make.starts_with("EASTMAN") {
            &[
                (1, b"image/x-kodak-kdc"),
                (95, make.as_bytes()),
                (109, b"Daylight"),
            ]
        } else {
            &[(1, b"image/tiff"), (95, make.as_bytes())]
        };
        verify_raw(&tiff.bytes, expected)?;
    }
    Ok(())
}

#[test]
fn recognizes_mamiya_zd_sensor_without_reclassifying_its_rgb_tiff() -> Result<(), &'static str> {
    for (photometric, model, mime, dimensions) in [
        (32803, "MAMIYA ZD", "image/x-mamiya-mef", "5344x4016"),
        (2, "MAMIYA ZD", "image/tiff", "660x500"),
        (32803, "Other Model", "image/tiff", "5344x4016"),
    ] {
        let mut tiff = Fixture::new(false);
        let sensor = [
            tiff.entry(256, 3, 1, &tiff.short(5344)),
            tiff.entry(257, 3, 1, &tiff.short(4016)),
            tiff.entry(258, 3, 1, &tiff.short(12)),
            tiff.entry(259, 3, 1, &tiff.short(1)),
            tiff.entry(262, 3, 1, &tiff.short(photometric)),
        ];
        let sensor = tiff.directory(&sensor);
        let mut model_field = model.as_bytes().to_vec();
        model_field.push(0);
        let image = [
            tiff.entry(254, 4, 1, &tiff.long(1)),
            tiff.entry(256, 3, 1, &tiff.short(660)),
            tiff.entry(257, 3, 1, &tiff.short(500)),
            tiff.entry(271, 2, 7, b"Mamiya\0"),
            tiff.entry(272, 2, model_field.len() as u32, &model_field),
            tiff.entry(330, 4, 1, &tiff.long(sensor)),
        ];
        let root = tiff.directory(&image);
        tiff.bytes[4..8].copy_from_slice(&root.to_be_bytes());
        verify_raw(
            &tiff.bytes,
            &[
                (1, mime.as_bytes()),
                (112, dimensions.as_bytes()),
                (95, b"Mamiya"),
                (96, model.as_bytes()),
            ],
        )?;
    }
    Ok(())
}

fn verify_raw(bytes: &[u8], expected: &[(u32, &[u8])]) -> Result<(), &'static str> {
    let base = bytes.get(..8).ok_or("invalid fixture header")?;
    let prefix = &bytes[..Format::identification_len(base, bytes.len())];
    let format = Format::detect(prefix).ok_or("missing RAW identification")?;
    let mut scratch = [0; 640];
    let input = Input::new(
        prefix,
        bytes.len() as u64,
        &mut scratch,
        |at, out: &mut [u8]| {
            let at = at as usize;
            let data = bytes
                .get(at..at + out.len())
                .ok_or("read outside RAW field")?;
            out.copy_from_slice(data);
            Ok(())
        },
    );
    let mut fields = Vec::new();
    format.visit_text(input, 32, &mut |kind, text| {
        fields.push((kind, text.to_vec()));
        Ok(())
    })?;
    if fields
        .iter()
        .map(|(kind, text)| (*kind, text.as_slice()))
        .ne(expected.iter().copied())
    {
        return Err("unexpected RAW metadata");
    }
    Ok(())
}
