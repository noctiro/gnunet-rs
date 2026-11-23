use super::*;
use crate::extraction::formats::Format;
use gnunet_fs::metadata::Deflater;
use gnunet_fs_codec::Compressor;
use std::convert::Infallible;

#[test]
fn reads_separate_classic_tiff_roles_and_top_level_xmp_over_sparse_media() {
    const FILE_TYPE: &[u8] = b"\0\0\0\x18ftypcrx \0\0\0\0crx iso2";
    const XMP: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Paris"/></r:RDF>"#;
    const MEDIA: &[u8; 8] = b"\0\x01\0\0mdat";
    let meta_offset = FILE_TYPE.len() as u64 + 65_536;
    assert!(detect(FILE_TYPE));
    assert!(!detect(b"\0\0\0\x18ftypmp42\0\0\0\0crx iso2"));

    let photo = directory(&[
        (0x0112, 3, 1, 8_u32.to_le_bytes()), // Orientation belongs to CMT1.
        (0x8827, 3, 1, 320_u32.to_le_bytes()),
        (0xa002, 4, 1, 4032_u32.to_le_bytes()),
        (0xa003, 3, 1, 3024_u32.to_le_bytes()),
    ]);
    let mut settings = [0_u16; 21];
    settings[0] = 42; // Byte size of the SHORT array, including the size word.
    settings[1] = 2; // Macro off
    settings[3] = 7; // CRAW quality
    settings[20] = 4; // Manual exposure
    let mut shot = [0_u16; 16];
    shot[0] = 32;
    shot[2] = 224; // Canon EV 7 -> ISO 400
    shot[7] = 8; // Shade
    shot[15] = 0xfff4; // -0.33 EV flash bias
    let mut maker = directory(&[
        (0x0001, 3, settings.len() as u32, 38_u32.to_le_bytes()),
        (0x0004, 3, shot.len() as u32, 80_u32.to_le_bytes()),
    ]);
    maker.extend(settings.into_iter().chain(shot).flat_map(u16::to_le_bytes));
    let gps = directory(&[(0x0001, 2, 2, *b"N\0\0\0")]);
    for make_crosses_boundary in [false, true] {
        let make = if make_crosses_boundary {
            (0x010f, 2, 8, 38_u32.to_le_bytes())
        } else {
            (0x010f, 2, 4, *b"Cam\0")
        };
        let image = directory(&[make, (0x0112, 3, 1, 6_u32.to_le_bytes())]);
        let mut canon = CANON_UUID.to_vec();
        append_box(&mut canon, b"CMT1", &image);
        append_box(&mut canon, b"CMT2", &photo);
        append_box(&mut canon, b"CMT3", &maker);
        append_box(&mut canon, b"CMT4", &gps);
        let mut movie = Vec::new();
        append_box(&mut movie, b"uuid", &canon);
        let mut meta = Vec::new();
        append_box(&mut meta, b"moov", &movie);
        append_box(&mut meta, b"uuid", &[xmp::UUID.as_slice(), XMP].concat());
        let mut scratch = [0; 768];
        let mut fields = Vec::new();
        let input = Input::new(
            FILE_TYPE,
            meta_offset + meta.len() as u64,
            &mut scratch,
            |offset, output: &mut [u8]| {
                if offset == FILE_TYPE.len() as u64 {
                    output.copy_from_slice(MEDIA);
                } else {
                    assert!(offset >= meta_offset);
                    let at = (offset - meta_offset) as usize;
                    output.copy_from_slice(&meta[at..at + output.len()]);
                }
                Ok::<_, Infallible>(())
            },
        );
        let Ok(()) = visit(input, 32, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        });
        let mut expected = Vec::new();
        if !make_crosses_boundary {
            expected.push((95, b"Cam".to_vec()));
        }
        expected.extend([
            (110, b"right, top".to_vec()),
            (112, b"4032x3024".to_vec()),
            (104, b"320".to_vec()),
            (107, b"Off".to_vec()),
            (108, b"CRAW".to_vec()),
            (105, b"Manual (M)".to_vec()),
            (104, b"400".to_vec()),
            (109, b"Shade".to_vec()),
            (101, b"-0.33 EV".to_vec()),
            (37, b"North".to_vec()),
            (41, b"Paris".to_vec()),
        ]);
        assert_eq!(fields, expected);
    }
}

#[test]
fn timed_metadata_fills_missing_kinds_from_checked_frame_samples() {
    const FILE_TYPE: &[u8] = b"\0\0\0\x18ftypcrx \0\0\0\0crx iso2";
    let canonical_photo = directory(&[(0x8827, 3, 1, 320_u32.to_le_bytes())]);
    let frame_photo = directory(&[
        (0x8827, 3, 1, 800_u32.to_le_bytes()),
        (0xa002, 4, 1, 6000_u32.to_le_bytes()),
        (0xa003, 4, 1, 4000_u32.to_le_bytes()),
    ]);
    let mut first = Vec::new();
    record(&mut first, 1, &[0, 0, 0xe8, 7, 2, 29, 12, 34, 56, 78]);
    record(&mut first, 4, &[45, 0, 1, 0]);
    let mut nested = Vec::new();
    exif_record(&mut nested, 0x8769, &frame_photo);
    // This MakerNote claims a payload beyond the enclosing CTMD record.
    nested.extend_from_slice(&99_u32.to_le_bytes());
    nested.extend_from_slice(&0x927c_u32.to_le_bytes());
    record(&mut first, 7, &nested);

    let mut shot = [0_u16; 8];
    shot[0] = 16;
    shot[2] = 224;
    shot[7] = 8;
    let mut maker = directory(&[(4, 3, 8, 26_u32.to_le_bytes())]);
    maker.extend(shot.into_iter().flat_map(u16::to_le_bytes));
    let mut second = Vec::new();
    record(&mut second, 5, &[56, 0, 10, 0, 1, 0, 80, 0, 64, 6, 0, 128]);
    let mut nested = Vec::new();
    exif_record(&mut nested, 0x927c, &maker);
    record(&mut second, 8, &nested);

    let mut bytes = FILE_TYPE.to_vec();
    let media_start = bytes.len() + 8;
    let omitted = media_start..media_start + 32;
    let mut media = vec![0x55; omitted.len()];
    media.extend_from_slice(&first);
    media.extend_from_slice(&second);
    append_box(&mut bytes, b"mdat", &media);
    let mut movie = Vec::new();
    let mut canon = CANON_UUID.to_vec();
    append_box(&mut canon, b"CMT2", &canonical_photo);
    append_box(&mut movie, b"uuid", &canon);
    append_box(
        &mut movie,
        b"trak",
        &track(
            [media_start as u32, omitted.end as u32],
            [
                omitted.len() as u32,
                first.len() as u32,
                second.len() as u32,
            ],
        ),
    );
    append_box(&mut bytes, b"moov", &movie);

    let mut scratch = [0; 2048];
    let input = Input::new(FILE_TYPE, bytes.len() as u64, &mut scratch, |at, out| {
        let at = at as usize;
        let end = at + out.len();
        assert!(end <= omitted.start || at >= omitted.end);
        out.copy_from_slice(&bytes[at..end]);
        Ok::<_, Infallible>(())
    });
    let mut fields = Vec::new();
    let Ok(()) = visit(input, 32, &mut |kind, value| {
        fields.push((kind, value.to_vec()));
        Ok(())
    });
    assert_eq!(
        fields,
        [
            (104, b"320".to_vec()),
            (58, b"2024:02:29 12:34:56.78".to_vec()),
            (102, b"45.0 mm".to_vec()),
            (112, b"6000x4000".to_vec()),
            (98, b"F5.6".to_vec()),
            (97, b"1/80 s".to_vec()),
            (109, b"Shade".to_vec()),
        ]
    );
}

#[test]
fn fragmented_timed_metadata_uses_the_original_track_and_media_range() {
    const FILE_TYPE: &[u8] = b"\0\0\0\x18ftypcrx \0\0\0\0crx iso2";
    const TRACK: u32 = 4;

    let mut frame = Vec::new();
    record(&mut frame, 4, &[45, 0, 1, 0]);
    let length = frame.len() as u32;
    let mut sample_table = Vec::new();
    append_box(&mut sample_table, b"stsc", &words([0, 0]));
    append_box(&mut sample_table, b"stco", &words([0, 0]));
    append_box(&mut sample_table, b"stsz", &words([0, 0, 0]));

    let movie = fragmented_movie(TRACK, length, sample_table);

    for (wrong_track, outside_media) in [(false, false), (true, false), (false, true)] {
        let mut bytes = FILE_TYPE.to_vec();
        append_box(&mut bytes, b"moov", &movie);
        let track = if wrong_track { TRACK + 1 } else { TRACK };
        let mut fragment_track = Vec::new();
        append_box(&mut fragment_track, b"tfhd", &words([0x020000, track]));
        // moof, mfhd, traf, tfhd, trun and the mdat header consume 76 bytes.
        let data_offset = if outside_media { 0 } else { 76 };
        append_box(&mut fragment_track, b"trun", &words([1, 1, data_offset]));
        let mut fragment = Vec::new();
        append_box(&mut fragment, b"mfhd", &words([0, 1]));
        append_box(&mut fragment, b"traf", &fragment_track);
        assert_eq!(fragment.len() + 16, 76);
        append_box(&mut bytes, b"moof", &fragment);
        append_box(&mut bytes, b"mdat", &frame);

        let mut scratch = [0; 2048];
        let input = Input::new(FILE_TYPE, bytes.len() as u64, &mut scratch, |at, out| {
            let at = at as usize;
            out.copy_from_slice(&bytes[at..at + out.len()]);
            Ok::<_, Infallible>(())
        });
        let mut fields = Vec::new();
        let Ok(()) = visit(input, 32, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        });
        if wrong_track || outside_media {
            assert!(fields.is_empty());
        } else {
            assert_eq!(fields, [(102, b"45.0 mm".to_vec())]);
        }
    }
}

#[test]
fn compressed_moof_translates_absolute_ctmd_sample_offsets() -> Result<(), &'static str> {
    const COMP_TYPE: &[u8] = b"\0\0\0\x14ftypcomp\0\0\0\0comp";
    const ORIGINAL_TYPE: &[u8] = b"\0\0\0\x18ftypcrx \0\0\0\0crx iso2";
    const TRACK: u32 = 4;

    let mut classic = Vec::new();
    record(&mut classic, 4, &[45, 0, 1, 0]);
    let mut fragment_sample = Vec::new();
    record(
        &mut fragment_sample,
        5,
        &[56, 0, 10, 0, 1, 0, 80, 0, 0, 0, 0, 0],
    );

    let movie = |offset| {
        let mut table = Vec::new();
        append_box(&mut table, b"stsc", &words([0, 1, 1, 1, 1]));
        append_box(&mut table, b"stco", &words([0, 1, offset]));
        append_box(&mut table, b"stsz", &words([0, classic.len() as u32, 1]));
        fragmented_movie(TRACK, fragment_sample.len() as u32, table)
    };
    let fragment = |offset| {
        let mut track = Vec::new();
        append_box(&mut track, b"tfhd", &words([1, TRACK, 0, offset]));
        append_box(&mut track, b"trun", &words([0, 1]));
        let mut movie = Vec::new();
        append_box(&mut movie, b"mfhd", &words([0, 1]));
        // Keep the expanded fragment substantially larger than the compressed envelope.
        append_box(&mut movie, b"free", &[0; 160]);
        append_box(&mut movie, b"traf", &track);
        movie
    };
    let logical_media = ORIGINAL_TYPE.len() + movie(0).len() + fragment(0).len() + 24;
    let mut bytes = COMP_TYPE.to_vec();
    append_box(&mut bytes, b"otyp", ORIGINAL_TYPE);
    append_box(&mut bytes, b"moov", &movie(logical_media as u32));

    let expanded = fragment((logical_media + classic.len()) as u32);
    let mut compressed = [0; 512];
    let progress = Compressor::new()
        .deflate(&expanded, &mut compressed)
        .map_err(|_| "compress CR3 fragment fixture")?;
    // Omit the zlib header and checksum, leaving a single RFC 1951 stream.
    append_box(&mut bytes, b"!mof", &compressed[2..progress.produced - 4]);
    if bytes.len() + 8 == logical_media {
        return Err("fixture needs distinct physical and logical data offsets");
    }
    append_box(&mut bytes, b"mdat", &[classic, fragment_sample].concat());

    let format = Format::detect(COMP_TYPE).ok_or("identify compressed BMFF")?;
    if !matches!(format, Format::CompressedBmff) {
        return Err("compressed BMFF incorrectly identified");
    }
    let mut scratch = [0; 2048];
    let input = Input::new(COMP_TYPE, bytes.len() as u64, &mut scratch, |at, out| {
        let at = at as usize;
        out.copy_from_slice(&bytes[at..at + out.len()]);
        Ok::<_, Infallible>(())
    });
    let mut fields = Vec::new();
    let Ok(()) = format.visit_text(input, 32, &mut |kind, value| {
        fields.push((kind, value.to_vec()));
        Ok(())
    });
    if fields
        != [
            (1, b"image/x-canon-cr3".to_vec()),
            (102, b"45.0 mm".to_vec()),
            (98, b"F5.6".to_vec()),
            (97, b"1/80 s".to_vec()),
        ]
    {
        return Err("wrong metadata from reconstructed CR3 sample offsets");
    }
    Ok(())
}

fn fragmented_movie(track: u32, length: u32, table: Vec<u8>) -> Vec<u8> {
    let mut movie = Vec::new();
    append_box(&mut movie, b"trak", &sample_track(track, &[b"CTMD"], table));
    let mut defaults = Vec::new();
    append_box(&mut defaults, b"trex", &words([0, track, 1, 1, length, 0]));
    append_box(&mut movie, b"mvex", &defaults);
    movie
}

fn record(output: &mut Vec<u8>, tag: u16, payload: &[u8]) {
    output.extend_from_slice(&((payload.len() + 12) as u32).to_le_bytes());
    output.extend_from_slice(&tag.to_le_bytes());
    output.extend_from_slice(&[0; 6]);
    output.extend_from_slice(payload);
}

fn exif_record(output: &mut Vec<u8>, tag: u32, payload: &[u8]) {
    output.extend_from_slice(&((payload.len() + 8) as u32).to_le_bytes());
    output.extend_from_slice(&tag.to_le_bytes());
    output.extend_from_slice(payload);
}

fn track(offsets: [u32; 2], sizes: [u32; 3]) -> Vec<u8> {
    let mut sample_table = Vec::new();
    append_box(&mut sample_table, b"stsc", &words([0, 2, 1, 1, 1, 2, 2, 2]));
    append_box(
        &mut sample_table,
        b"stco",
        &words([0, 2].into_iter().chain(offsets)),
    );
    append_box(
        &mut sample_table,
        b"stsz",
        &words([0, 0, 3].into_iter().chain(sizes)),
    );
    sample_track(1, &[b"data", b"CTMD"], sample_table)
}

fn sample_track(id: u32, kinds: &[&[u8; 4]], tables: Vec<u8>) -> Vec<u8> {
    let mut descriptions = words([0, kinds.len() as u32]);
    for kind in kinds {
        append_box(&mut descriptions, kind, &1_u64.to_be_bytes());
    }
    let mut sample_table = Vec::new();
    append_box(&mut sample_table, b"stsd", &descriptions);
    sample_table.extend(tables);
    let mut references = vec![0, 0, 0, 0, 0, 0, 0, 1];
    append_box(&mut references, b"url ", &[0, 0, 0, 1]);
    let mut data_information = Vec::new();
    append_box(&mut data_information, b"dref", &references);
    let mut media_information = Vec::new();
    append_box(&mut media_information, b"dinf", &data_information);
    append_box(&mut media_information, b"stbl", &sample_table);
    let mut media = Vec::new();
    append_box(&mut media, b"minf", &media_information);
    let mut track = Vec::new();
    let mut header = [0_u8; 84];
    header[12..16].copy_from_slice(&id.to_be_bytes());
    append_box(&mut track, b"tkhd", &header);
    append_box(&mut track, b"mdia", &media);
    track
}

fn words(values: impl IntoIterator<Item = u32>) -> Vec<u8> {
    values.into_iter().flat_map(u32::to_be_bytes).collect()
}

fn directory(rows: &[(u16, u16, u32, [u8; 4])]) -> Vec<u8> {
    let mut bytes = b"II*\0\x08\0\0\0".to_vec();
    bytes.extend_from_slice(&(rows.len() as u16).to_le_bytes());
    for (tag, kind, count, value) in rows {
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(value);
    }
    bytes.extend_from_slice(&[0; 4]);
    bytes
}

fn append_box(output: &mut Vec<u8>, kind: &[u8; 4], payload: &[u8]) {
    output.extend_from_slice(&((payload.len() + 8) as u32).to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(payload);
}
