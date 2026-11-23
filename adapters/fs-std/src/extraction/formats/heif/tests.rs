use super::super::{Format, compression::XMP_BROTLI};
use super::*;
use gnunet_fs::metadata::Deflater;
use gnunet_fs_codec::Compressor;

const TIFF: &[u8] = b"II*\0\x08\0\0\0\x02\0\x0f\x01\x02\0\x04\0\0\0Cam\0\
    \x12\x01\x03\0\x01\0\0\0\x03\0\0\0\0\0\0\0";
const XMP: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Paris"/></r:RDF>"#;
const FILE_TYPE: &[u8] = b"\0\0\0\x14ftypmif1\0\0\0\0avif";

#[test]
fn heif_reads_only_bounded_items_describing_the_primary_image() -> Result<(), &'static str> {
    let exif = [b"\0\0\0\x06Exif\0\0".as_slice(), TIFF].concat();
    let exif_at = FILE_TYPE.len() + 8;
    let pixels_at = exif_at + exif.len();
    let meta_at = pixels_at + 16_384;
    let prefix = [
        FILE_TYPE,
        &((meta_at - FILE_TYPE.len()) as u32).to_be_bytes(),
        b"mdat",
        &exif,
    ]
    .concat();
    let mut compressed = [0; 256];
    let progress = Compressor::new()
        .deflate(XMP, &mut compressed)
        .map_err(|_| "compress fixture")?;
    let zlib = &compressed[..progress.produced];
    let raw = &zlib[2..zlib.len() - 4];
    let trailing = [zlib, &[0]].concat();
    for (target, corrupt_extent, encoding, encoded, expect_xmp) in [
        (1, false, b"".as_slice(), XMP, true),
        (1, false, b"identity", XMP, true),
        (2, false, b"", XMP, false),
        (1, true, b"", XMP, false),
        (1, false, b"compress_zlib", zlib, true),
        (1, false, b"deflate", raw, true),
        (1, false, b"br", XMP_BROTLI, true),
        (1, false, b"compress_zlib", &trailing, false),
    ] {
        let meta = metadata_box(
            exif_at as u32,
            exif.len() as u32,
            XmpItem {
                target,
                corrupt_extent,
                encoding,
                bytes: encoded,
            },
        );
        let base = &prefix[..FILE_TYPE.len()];
        let format = Format::detect(base).ok_or("identify AVIF")?;
        if format.mime() != b"image/avif" {
            return Err("wrong AVIF media type");
        }
        let mut scratch = [0; 1024];
        let input = Input::new(
            base,
            (meta_at + meta.len()) as u64,
            &mut scratch,
            |at, output: &mut [u8]| {
                let at = at as usize;
                let bytes = if at >= meta_at {
                    let start = at - meta_at;
                    meta.get(start..start + output.len())
                } else {
                    prefix.get(at..at + output.len())
                };
                output.copy_from_slice(bytes.ok_or("read crossed a metadata extent")?);
                Ok(())
            },
        );
        let mut fields = Vec::new();
        format.visit_text(input, 32, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        })?;
        let mut expected = vec![
            (1, b"image/avif".to_vec()),
            (112, b"6000x4000".to_vec()),
            (110, b"left, bottom".to_vec()),
            (95, b"Cam".to_vec()),
        ];
        if expect_xmp {
            expected.push((41, b"Paris".to_vec()));
        }
        if fields != expected {
            return Err("wrong primary-image metadata");
        }
    }
    Ok(())
}

#[test]
fn avif_sequence_reads_display_geometry_and_track_local_items() -> Result<(), String> {
    let exif = [b"\0\0\0\x06Exif\0\0".as_slice(), TIFF].concat();
    for (major, mapping, movie_scope) in [
        (b"avis", None, false),
        (b"mif1", None, false),
        (b"avis", Some(b"sbgp"), false),
        (b"avis", Some(b"sbgp"), true),
        (b"avis", Some(b"csgp"), true),
    ] {
        let mut file = Vec::new();
        append_box(
            &mut file,
            b"ftyp",
            &[major.as_slice(), b"\0\0\0\0avis"].concat(),
        );
        let prefix_size = file.len();
        let exif_at = (prefix_size + 8) as u32;
        let xmp_at = exif_at + exif.len() as u32;
        let sample_at = xmp_at + XMP.len() as u32;
        append_box(&mut file, b"mdat", &[exif.as_slice(), XMP, &[0]].concat());

        let mut meta = vec![0; 4];
        append_box(&mut meta, b"hdlr", &picture_handler_body());
        let mut locations = b"\0\0\0\0\x44\0\0\x02".to_vec();
        for (id, offset, size) in [(2u16, exif_at, exif.len()), (3, xmp_at, XMP.len())] {
            locations.extend_from_slice(&id.to_be_bytes());
            locations.extend_from_slice(b"\0\0\0\x01");
            locations.extend_from_slice(&offset.to_be_bytes());
            locations.extend_from_slice(&(size as u32).to_be_bytes());
        }
        append_box(&mut meta, b"iloc", &locations);
        append_box(&mut meta, b"iinf", &metadata_info(b""));
        if major == b"mif1" {
            // A file-level metadata box without a primary image cannot describe the sequence.
            append_box(&mut file, b"meta", &meta);
        }

        let mut movie = Vec::new();
        if movie_scope {
            let mut container = Vec::new();
            append_box(&mut container, b"meta", &meta);
            append_box(&mut movie, b"meco", &container);
        }
        append_box(
            &mut movie,
            b"trak",
            &image_track(1, Some(b"auxl"), Some(&meta), None, sample_at),
        );
        append_box(
            &mut movie,
            b"trak",
            &image_track(2, Some(b"thmb"), None, None, sample_at),
        );
        append_box(
            &mut movie,
            b"trak",
            &image_track(3, None, (!movie_scope).then_some(&meta), mapping, sample_at),
        );
        append_box(&mut file, b"moov", &movie);

        let prefix = &file[..prefix_size];
        let format = Format::detect(prefix).ok_or("identify AVIF sequence")?;
        let mut scratch = [0; 4096];
        let input = Input::new(
            prefix,
            file.len() as u64,
            &mut scratch,
            |at, output: &mut [u8]| {
                let at = at as usize;
                output.copy_from_slice(file.get(at..at + output.len()).ok_or("out of bounds")?);
                Ok::<(), &'static str>(())
            },
        );
        let mut fields = Vec::new();
        format.visit_text(input, 32, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        })?;
        let mut expected = vec![
            (1, b"image/avif".to_vec()),
            (112, b"640x480".to_vec()),
            (110, b"right, top".to_vec()),
        ];
        if mapping.is_some() {
            expected.push((41, b"Paris".to_vec()));
        } else {
            expected.extend([(95, b"Cam".to_vec()), (41, b"Paris".to_vec())]);
        }
        if fields != expected {
            return Err(format!(
                "mapping {mapping:?}, movie scope {movie_scope}: fields {fields:?}, expected {expected:?}"
            ));
        }
    }
    Ok(())
}

fn image_track(
    id: u32,
    relation: Option<&[u8; 4]>,
    metadata: Option<&[u8]>,
    mapping: Option<&[u8; 4]>,
    sample_at: u32,
) -> Vec<u8> {
    let mut header = [0; 84];
    header[3] = 3;
    header[12..16].copy_from_slice(&id.to_be_bytes());
    let matrix: [i32; 9] = [0, 1 << 16, 0, -(1 << 16), 0, 0, 480 << 16, 0, 1 << 30];
    for (target, value) in header[40..76].as_chunks_mut::<4>().0.iter_mut().zip(matrix) {
        *target = value.to_be_bytes();
    }
    let (width, height): (u16, u16) = if relation.is_some() {
        (64, 48)
    } else {
        (640, 480)
    };
    header[76..78].copy_from_slice(&width.to_be_bytes());
    header[80..82].copy_from_slice(&height.to_be_bytes());

    let mut entry = [0; 78];
    entry[7] = 1;
    entry[24..28].copy_from_slice(b"\0\x80\0\x40");
    let mut descriptions = b"\0\0\0\0\0\0\0\x01".to_vec();
    append_box(&mut descriptions, b"av01", &entry);
    let mut table = Vec::new();
    append_box(&mut table, b"stsd", &descriptions);
    let chunk_offsets = [b"\0\0\0\0\0\0\0\x01".as_slice(), &sample_at.to_be_bytes()].concat();
    append_box(&mut table, b"stco", &chunk_offsets);
    if let Some(mapping) = mapping {
        append_box(&mut table, b"stsc", &words(&[0, 1, 1, 1, 1]));
        append_box(&mut table, b"stsz", &words(&[0, 1, 1]));
        append_box(
            &mut table,
            b"sgpd",
            b"\x01\0\0\0stmi\0\0\0\x0c\0\0\0\x01pict\0\0\0\x01\0\0\0\x03",
        );
        let body: &[u8] = if mapping == b"csgp" {
            b"\0\0\0\0stmi\0\0\0\x01\x11\x10"
        } else {
            b"\0\0\0\0stmi\0\0\0\x01\0\0\0\x01\0\0\0\x01"
        };
        append_box(&mut table, mapping, body);
    }
    let mut information = Vec::new();
    if mapping.is_some() {
        let mut refs = words(&[0, 1]);
        append_box(&mut refs, b"url ", &1_u32.to_be_bytes());
        let mut directory = Vec::new();
        append_box(&mut directory, b"dref", &refs);
        append_box(&mut information, b"dinf", &directory);
    }
    append_box(&mut information, b"stbl", &table);
    let mut media = Vec::new();
    append_box(&mut media, b"hdlr", &picture_handler_body());
    append_box(&mut media, b"minf", &information);

    let mut track = Vec::new();
    append_box(&mut track, b"tkhd", &header);
    if let Some(relation) = relation {
        let mut references = Vec::new();
        append_box(&mut references, relation, &3u32.to_be_bytes());
        append_box(&mut track, b"tref", &references);
    }
    if let Some(metadata) = metadata {
        append_box(&mut track, b"meta", metadata);
    }
    append_box(&mut track, b"mdia", &media);
    track
}

struct XmpItem<'a> {
    target: u16,
    corrupt_extent: bool,
    encoding: &'a [u8],
    bytes: &'a [u8],
}

fn metadata_box(exif_at: u32, exif_len: u32, xmp: XmpItem<'_>) -> Vec<u8> {
    let mut meta = vec![0; 4];
    append_box(&mut meta, b"hdlr", &picture_handler_body());
    append_box(&mut meta, b"pitm", b"\0\0\0\0\0\x01");
    let mut definitions = Vec::new();
    append_box(&mut definitions, b"ispe", b"\0\0\0\0\0\0\0\x40\0\0\0\x30");
    append_box(
        &mut definitions,
        b"ispe",
        b"\0\0\0\0\0\0\x17\x70\0\0\x0f\xa0",
    );
    append_box(&mut definitions, b"irot", &[1]);
    let mut properties = Vec::new();
    append_box(&mut properties, b"ipco", &definitions);
    append_box(
        &mut properties,
        b"ipma",
        b"\0\0\0\0\0\0\0\x02\0\x01\x02\x82\x83\0\x02\x01\x81",
    );
    append_box(&mut meta, b"iprp", &properties);

    append_box(&mut meta, b"iinf", &metadata_info(xmp.encoding));

    let mut references = vec![0; 4];
    append_box(&mut references, b"cdsc", b"\0\x02\0\x01\0\x01");
    let mut reference = b"\0\x03\0\x01".to_vec();
    reference.extend_from_slice(&xmp.target.to_be_bytes());
    append_box(&mut references, b"cdsc", &reference);
    append_box(&mut meta, b"iref", &references);

    let mut locations = b"\x01\0\0\0\x44\0\0\x02\0\x02\0\0\0\0\0\x01".to_vec();
    locations.extend_from_slice(&exif_at.to_be_bytes());
    locations.extend_from_slice(&exif_len.to_be_bytes());
    locations.extend_from_slice(b"\0\x03\0\x01\0\0\0\x02");
    let (first, second) = xmp.bytes.split_at(xmp.bytes.len() / 2);
    let second_offset = if xmp.corrupt_extent { u32::MAX } else { 0 };
    let extents = [(second.len() as u32 + 3, first), (second_offset, second)];
    for (offset, bytes) in extents {
        locations.extend_from_slice(&offset.to_be_bytes());
        locations.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    }
    append_box(&mut meta, b"iloc", &locations);
    append_box(&mut meta, b"idat", &[second, b"pad", first].concat());

    let mut file = Vec::new();
    append_box(&mut file, b"meta", &meta);
    file
}

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().copied().flat_map(u32::to_be_bytes).collect()
}

fn append_box(output: &mut Vec<u8>, kind: &[u8; 4], bytes: &[u8]) {
    output.extend_from_slice(&((bytes.len() + 8) as u32).to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(bytes);
}

fn picture_handler_body() -> [u8; 25] {
    let mut handler = [0; 25];
    handler[8..12].copy_from_slice(b"pict");
    handler
}

fn metadata_info(xmp_encoding: &[u8]) -> Vec<u8> {
    let mut info = b"\0\0\0\0\0\x02".to_vec();
    append_box(&mut info, b"infe", b"\x02\0\0\x01\0\x02\0\0Exif\0");
    let mut mime = b"\x02\0\0\x01\0\x03\0\0mime\0application/rdf+xml\0".to_vec();
    mime.extend_from_slice(xmp_encoding);
    mime.push(0);
    append_box(&mut info, b"infe", &mime);
    info
}
