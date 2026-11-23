use super::super::MovieIndex;
use super::*;
use crate::extraction::formats::boxes::samples::DecodingTime;
use gnunet_crypto::crc32_n;
use gnunet_fs::metadata::Deflater;
use gnunet_fs_codec::Compressor;

const XMP: &[u8] = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Paris"/></r:RDF></x:xmpmeta>"#;

#[test]
fn selects_linked_sync_exif_and_preceding_xmp() -> Result<(), &'static str> {
    let delta = exif(b"Tag");
    let sync = exif(b"Cam");
    let mut file = boxed(b"mdat", &[delta.as_slice(), sync.as_slice(), XMP].concat());
    let exif_at = 8;
    let xmp_at = exif_at + delta.len() as u32 + sync.len() as u32;
    let lengths = [delta.len() as u32, sync.len() as u32];
    let mut movie = Vec::new();
    for (header, target, samples) in [
        (
            Header { id: 2, group: 0 },
            8,
            Samples {
                kind: b"Exif",
                suffix: b"",
                offset: exif_at,
                lengths: &lengths,
                sync: &[],
            },
        ),
        (
            Header { id: 3, group: 1 },
            1,
            Samples {
                kind: b"Exif",
                suffix: b"",
                offset: exif_at,
                lengths: &lengths,
                sync: &[2],
            },
        ),
        (
            Header { id: 4, group: 1 },
            1,
            Samples {
                kind: b"Exif",
                suffix: b"",
                offset: exif_at,
                lengths: &lengths,
                sync: &[],
            },
        ),
        (
            Header { id: 5, group: 0 },
            1,
            Samples {
                kind: b"metx",
                suffix: b"\0urn:other\0\0",
                offset: xmp_at,
                lengths: &[XMP.len() as u32],
                sync: &[],
            },
        ),
        (
            Header { id: 6, group: 0 },
            1,
            Samples {
                kind: b"metx",
                suffix: b"\0adobe:ns:meta/\0\0",
                offset: xmp_at,
                lengths: &[XMP.len() as u32],
                sync: &[],
            },
        ),
    ] {
        movie.extend_from_slice(&track(header, target, samples));
    }
    let movie_at = file.len() as u64;
    file.extend_from_slice(&boxed(b"moov", &movie));
    let extent = file.len() as u64;

    for prefix in [&file[..8], file.as_slice()] {
        let mut scratch = [0; 2048];
        let mut input = Input::new(prefix, extent, &mut scratch, |offset, out: &mut [u8]| {
            let start = offset as usize;
            out.copy_from_slice(file.get(start..start + out.len()).ok_or("out of bounds")?);
            Ok(())
        });
        let movie = BoxSpan::read(&mut input, movie_at, extent)?.ok_or("missing movie")?;
        let mut metadata = classic_metadata(movie, 1)?;
        let mut exif = tiff::ExifOverlay::new(file.len());
        let mut fields = Vec::new();
        let mut emit = |kind, value: &[u8]| {
            fields.push((kind, value.to_vec()));
            Ok(())
        };
        visit(
            &mut input,
            &mut metadata,
            32,
            &mut Decompression::for_probe(file.len()),
            &mut exif,
            &mut emit,
        )?;
        exif.visit(32, &mut emit)?;
        if fields != [(41, b"Paris".to_vec()), (95, b"Cam".to_vec())] {
            return Err("wrong linked metadata sample");
        }
    }
    Ok(())
}

#[test]
fn exif_delta_uses_original_tiff_sources_and_the_nearest_sync() -> Result<(), &'static str> {
    let base = exif_ascii(0x0110, b"Baseline\0", false);
    let base_make = exif(b"Old");
    let blocks = [
        exif_ascii(0x010e, b"Old interval\0", true),
        exif_ascii(0x0131, b"Camera software\0", false),
        exif_ascii(0x0110, b"Unselected delta\0", false),
        exif_ascii(0x010f, b"New camera\0", true),
    ];
    let lengths = blocks.each_ref().map(|block| block.len() as u32);
    let mut file = boxed(b"mdat", &blocks.concat());
    let movie_at = file.len() as u64;
    let timed_track = track(
        Header { id: 2, group: 0 },
        1,
        Samples {
            kind: b"Exif",
            suffix: b"",
            offset: 8,
            lengths: &lengths,
            sync: &[1, 2],
        },
    );
    let track_baseline = exif_ascii(0x013b, b"Track artist\0", false);
    let track = [
        timed_track.get(8..).ok_or("missing track")?,
        &untimed_exif(&track_baseline),
    ]
    .concat();
    file.extend_from_slice(&boxed(b"moov", &boxed(b"trak", &track)));
    let extent = file.len() as u64;
    let mut scratch = [0; 4096];
    let mut input = Input::new(
        &file[..8],
        extent,
        &mut scratch,
        |offset, out: &mut [u8]| {
            let offset = offset as usize;
            out.copy_from_slice(
                file.get(offset..offset + out.len())
                    .ok_or("out of bounds")?,
            );
            Ok::<(), &'static str>(())
        },
    );
    let movie = BoxSpan::read(&mut input, movie_at, extent)?.ok_or("missing movie")?;
    let mut metadata = classic_metadata(movie, 3)?;
    let mut exif = tiff::ExifOverlay::new(file.len() + base.len() + base_make.len());
    if !exif.add_block(&base) || !exif.add_block(&base_make) {
        return Err("baseline rejected");
    }
    let mut fields = Vec::new();
    let mut emit = |kind, value: &[u8]| {
        fields.push((kind, value.to_vec()));
        Ok(())
    };
    visit(
        &mut input,
        &mut metadata,
        32,
        &mut Decompression::for_probe(file.len()),
        &mut exif,
        &mut emit,
    )?;
    exif.visit(32, &mut emit)?;
    fields.sort_unstable();
    if fields
        != [
            (95, b"New camera".to_vec()),
            (96, b"Baseline".to_vec()),
            (113, b"Camera software".to_vec()),
            (130, b"Track artist".to_vec()),
        ]
    {
        return Err("wrong effective EXIF layer or TIFF byte order");
    }
    Ok(())
}

fn untimed_exif(block: &[u8]) -> Vec<u8> {
    let mut handler = [0; 25];
    handler[8..12].copy_from_slice(b"meta");
    let info = boxed(b"infe", b"\x02\0\0\0\0\x01\0\0Exif\0");
    let info = [b"\0\0\0\0\0\x01".as_slice(), &info].concat();
    let mut locations = b"\x01\0\0\0\x44\0\0\x01\0\x01\0\x01\0\0\0\x01".to_vec();
    locations.extend_from_slice(&words(&[0, block.len() as u32]));
    let mut meta = vec![0; 4];
    for (kind, data) in [
        (b"hdlr", handler.as_slice()),
        (b"iinf", &info),
        (b"iloc", &locations),
        (b"idat", block),
    ] {
        meta.extend_from_slice(&boxed(kind, data));
    }
    boxed(b"meta", &meta)
}

#[test]
fn timed_xmp_coding_obeys_the_sample_entry_and_shared_budget() -> Result<(), &'static str> {
    use crate::extraction::formats::compression::XMP_BROTLI;

    let zlib = zlib_fixture(XMP)?;
    let gzip = [gzip_member(&XMP[..50])?, gzip_member(&XMP[50..])?].concat();
    let mut bad_gzip = gzip.clone();
    let last = bad_gzip.last_mut().ok_or("expected gzip data")?;
    *last ^= 1;

    for (suffix, payload, allowance, should_emit) in [
        (
            b"deflate\0adobe:ns:meta/\0\0".as_slice(),
            zlib.as_slice(),
            XMP.len(),
            true,
        ),
        (
            b"application/zlib\0adobe:ns:meta/\0",
            zlib.as_slice(),
            XMP.len(),
            true,
        ),
        (b"br\0urn:other adobe:ns:meta/\0\0", XMP_BROTLI, 256, true),
        (
            b"gzip\0adobe:ns:meta/\0\0",
            gzip.as_slice(),
            XMP.len(),
            true,
        ),
        (
            b"application/gzip\0adobe:ns:meta/\0\0",
            gzip.as_slice(),
            XMP.len(),
            true,
        ),
        (b"gzip\0adobe:ns:meta/\0\0", bad_gzip.as_slice(), 256, false),
        (
            b"gzip\0adobe:ns:meta/\0\0",
            gzip.as_slice(),
            XMP.len() - 1,
            false,
        ),
        (b"unknown\0adobe:ns:meta/\0\0", XMP, 256, false),
        (b"adobe:ns:meta/\0urn:schema\0", XMP, 256, false),
    ] {
        let fields = timed_xmp_fields(suffix, payload, &[payload.len() as u32], 0, allowance)?;
        if fields.len() != usize::from(should_emit)
            || fields
                .first()
                .is_some_and(|field| *field != (41, b"Paris".to_vec()))
        {
            return Err("timed XMP coding or allowance accepted the wrong sample");
        }
    }
    Ok(())
}

#[test]
fn incomplete_metadata_timeline_does_not_publish_the_preceding_packet() -> Result<(), &'static str>
{
    let fields = timed_xmp_fields(
        b"\0adobe:ns:meta/\0\0",
        XMP,
        &[XMP.len() as u32, 1],
        1,
        XMP.len(),
    )?;
    if !fields.is_empty() {
        return Err("an invalid second sample must not select the first packet");
    }
    Ok(())
}

fn timed_xmp_fields(
    suffix: &[u8],
    payload: &[u8],
    lengths: &[u32],
    anchor_tick: u64,
    allowance: usize,
) -> Result<Vec<(u32, Vec<u8>)>, &'static str> {
    // Both describing tracks share the single sample and expansion allowance.
    let moov: Vec<_> = (2..=3)
        .flat_map(|id| {
            track(
                Header { id, group: 0 },
                1,
                Samples {
                    kind: b"metx",
                    suffix,
                    offset: 8,
                    lengths,
                    sync: &[],
                },
            )
        })
        .collect();
    let mut file = boxed(b"mdat", payload);
    let movie_at = file.len() as u64;
    file.extend_from_slice(&boxed(b"moov", &moov));
    let extent = file.len() as u64;
    let mut input = Input::new(&file, extent, &mut [], |_, _: &mut [u8]| {
        Err("unexpected read outside cached file")
    });
    let movie = BoxSpan::read(&mut input, movie_at, extent)?.ok_or("missing movie")?;
    let mut metadata = classic_metadata(movie, anchor_tick)?;
    let mut fields = Vec::new();
    visit(
        &mut input,
        &mut metadata,
        32,
        &mut Decompression::new(allowance),
        &mut tiff::ExifOverlay::new(file.len()),
        &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        },
    )?;
    Ok(fields)
}

fn classic_metadata(movie: BoxSpan, tick: u64) -> Result<TimedMetadata, &'static str> {
    Ok(TimedMetadata {
        id: NonZeroU32::MIN,
        movie: MovieIndex {
            span: movie,
            fragments: Default::default(),
            fragmented: false,
            media: None,
        },
        anchor: DecodingTime::new(tick, NonZeroU32::new(1000).ok_or("invalid time scale")?),
    })
}

fn zlib_fixture(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut compressed = [0; 256];
    let progress = Compressor::new()
        .deflate(bytes, &mut compressed)
        .map_err(|_| "cannot compress XMP fixture")?;
    Ok(compressed[..progress.produced].to_vec())
}

fn gzip_member(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    let zlib = zlib_fixture(bytes)?;
    // Header exercises extra data, original filename, comment and header CRC.
    let mut gzip = b"\x1f\x8b\x08\x1e\0\0\0\0\0\xff\x04\0TE\0\0file\0note\0".to_vec();
    let header_crc = crc32_n(&gzip) as u16;
    gzip.extend_from_slice(&header_crc.to_le_bytes());
    gzip.extend_from_slice(&zlib[2..zlib.len() - 4]);
    gzip.extend_from_slice(&crc32_n(bytes).to_le_bytes());
    gzip.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    Ok(gzip)
}

#[test]
fn fragmented_sequence_requires_a_visual_sample_and_uses_linked_timed_metadata()
-> Result<(), String> {
    let non_sync = exif(b"Bad");
    let sync = exif(b"Cam");
    let mut movie = Vec::new();
    // This visual track has a sample table and trex but appears in no fragment.
    movie.extend_from_slice(&fragmented_picture(1, 720, 540));
    movie.extend_from_slice(&fragmented_picture(2, 640, 480));
    for (id, kind, suffix) in [
        (3, b"Exif", b"".as_slice()),
        (4, b"metx", b"\0adobe:ns:meta/\0\0".as_slice()),
    ] {
        movie.extend_from_slice(&track(
            Header { id, group: 0 },
            2,
            Samples {
                kind,
                suffix,
                offset: 0,
                lengths: &[],
                sync: &[],
            },
        ));
    }
    let defaults: Vec<u8> = (1..=4)
        .flat_map(|id| boxed(b"trex", &words(&[0, id, 1, 1, 0, 0])))
        .collect();
    movie.extend_from_slice(&boxed(b"mvex", &defaults));
    let xmp = std::str::from_utf8(XMP).map_err(|_| "invalid XMP fixture")?;
    movie.extend_from_slice(&grouped_metadata(xmp));

    let file_type = boxed(b"ftyp", b"avis\0\0\0\0avis");
    let mut file = file_type.clone();
    file.extend_from_slice(&boxed(b"moov", &movie));
    let earlier_xmp = xmp.replace("Paris", "Madrid");
    let metadata = [
        non_sync.as_slice(),
        sync.as_slice(),
        earlier_xmp.as_bytes(),
        XMP,
    ]
    .concat();
    let fragment = |offset: u32, valid_picture| {
        let mut moof = boxed(b"mfhd", &words(&[0, 1]));
        if valid_picture {
            // The first sample is empty. Metadata must follow the second sample's group.
            moof.extend_from_slice(&sample_run(2, offset, &[(0, 0), (1, 0)], &local_groups()));
        }
        moof.extend_from_slice(&sample_run(
            3,
            offset + 1,
            &[(non_sync.len() as u32, 0x0001_0000), (sync.len() as u32, 0)],
            &[],
        ));
        moof.extend_from_slice(&sample_run(
            4,
            offset + 1 + non_sync.len() as u32 + sync.len() as u32,
            &[(earlier_xmp.len() as u32, 0), (XMP.len() as u32, 0)],
            &[],
        ));
        boxed(b"moof", &moof)
    };
    for valid_picture in [true, false] {
        let mut data = file.clone();
        let offset = fragment(0, valid_picture).len() as u32 + 8;
        data.extend_from_slice(&fragment(offset, valid_picture));
        data.extend_from_slice(&boxed(b"mdat", &[&[0], metadata.as_slice()].concat()));
        let format =
            crate::extraction::formats::Format::detect(&file_type).ok_or("missing AVIF")?;
        let mut scratch = [0; 8192];
        let input = Input::new(
            &file_type,
            data.len() as u64,
            &mut scratch,
            |offset, out: &mut [u8]| {
                let start = offset as usize;
                out.copy_from_slice(data.get(start..start + out.len()).ok_or("out of bounds")?);
                Ok::<(), &'static str>(())
            },
        );
        let mut fields = Vec::new();
        format.visit_text(input, 32, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        })?;
        let mut expected = vec![(1, b"image/avif".to_vec())];
        if valid_picture {
            expected.extend([
                (112, b"640x480".to_vec()),
                (41, b"Lyon".to_vec()),
                (41, b"Paris".to_vec()),
                (95, b"Cam".to_vec()),
            ]);
        }
        if fields != expected {
            return Err(format!(
                "fragmented fields {fields:?}, expected {expected:?}"
            ));
        }
    }
    Ok(())
}

#[test]
fn classic_sequence_seeks_a_late_exif_delta_across_chunks_and_timescales() -> Result<(), String> {
    const FIRST_CHUNK_SAMPLES: u32 = 128;
    let old_sync = exif_ascii(0x010e, b"Old interval\0", false);
    let skipped = exif_ascii(0x0110, b"Skipped model\0", false);
    let tail = late_exif_samples();

    let mut file = boxed(b"ftyp", b"avis\0\0\0\0avis");
    let picture_at = file.len() as u32 + 8;
    let first_chunk_at = picture_at + 1;
    let mut media_data = vec![0];
    let mut sizes = vec![old_sync.len() as u32];
    media_data.extend_from_slice(&old_sync);
    for _ in 1..FIRST_CHUNK_SAMPLES {
        sizes.push(skipped.len() as u32);
        media_data.extend_from_slice(&skipped);
    }
    // A gap makes the late sample's byte offset depend on the second chunk.
    media_data.extend_from_slice(b"gap");
    let second_chunk_at = picture_at + media_data.len() as u32;
    for sample in &tail {
        sizes.push(sample.len() as u32);
        media_data.extend_from_slice(sample);
    }
    file.extend_from_slice(&boxed(b"mdat", &media_data));

    let exif = sample_description(b"Exif", b"\0\0\0\0\0\0\0\x01");
    let mut table = boxed(b"stsd", &exif);
    table.extend_from_slice(&boxed(
        b"stts",
        &words(&[0, 2, FIRST_CHUNK_SAMPLES, 1, 4, 3]),
    ));
    table.extend_from_slice(&boxed(
        b"stsc",
        &words(&[0, 2, 1, FIRST_CHUNK_SAMPLES, 1, 2, 4, 1]),
    ));
    table.extend_from_slice(&boxed(
        b"stco",
        &words(&[0, 2, first_chunk_at, second_chunk_at]),
    ));
    let mut size_table = words(&[0, 0, sizes.len() as u32]);
    size_table.extend_from_slice(&words(&sizes));
    table.extend_from_slice(&boxed(b"stsz", &size_table));
    table.extend_from_slice(&boxed(
        b"stss",
        &words(&[0, 3, 1, FIRST_CHUNK_SAMPLES + 1, FIRST_CHUNK_SAMPLES + 4]),
    ));

    // At 2 kHz the representative image falls half a 1 kHz metadata tick
    // after the late delta, with a future sync still in the current chunk.
    let picture_tick = 2 * (FIRST_CHUNK_SAMPLES + 6) + 1;
    let mut picture = boxed(b"stsd", &picture_description());
    picture.extend_from_slice(&boxed(b"stts", &words(&[0, 2, 1, picture_tick, 1, 1])));
    picture.extend_from_slice(&boxed(b"stsc", &words(&[0, 1, 1, 2, 1])));
    picture.extend_from_slice(&boxed(b"stco", &words(&[0, 1, picture_at])));
    picture.extend_from_slice(&boxed(b"stsz", &words(&[0, 0, 2, 0, 1])));
    let mut movie = picture_track(1, 640, 480, &picture, 2000);
    movie.extend_from_slice(&describing_track(Header { id: 2, group: 0 }, 1, &table));
    file.extend_from_slice(&boxed(b"moov", &movie));
    assert_late_exif(&file)
}

#[test]
fn fragmented_sequence_seeks_past_a_symbolic_default_run() -> Result<(), String> {
    const DEFAULT_COUNT: u32 = 1 << 20;
    const DEFAULT_DURATION: u32 = 70_000;
    const NON_SYNC: u32 = 0x0001_0000;

    let mut file = boxed(b"ftyp", b"avis\0\0\0\0avis");
    let mut movie = picture_track(
        1,
        640,
        480,
        &empty_sample_table(&picture_description()),
        2000,
    );
    movie.extend_from_slice(&track(
        Header { id: 2, group: 0 },
        1,
        Samples {
            kind: b"Exif",
            suffix: b"",
            offset: 0,
            lengths: &[],
            sync: &[],
        },
    ));
    let mut defaults = boxed(b"trex", &words(&[0, 1, 1, 1, 1, 0]));
    defaults.extend_from_slice(&boxed(
        b"trex",
        &words(&[0, 2, 1, DEFAULT_DURATION, 0, NON_SYNC]),
    ));
    movie.extend_from_slice(&boxed(b"mvex", &defaults));
    file.extend_from_slice(&boxed(b"moov", &movie));

    let old_sync = exif_ascii(0x010e, b"Old interval\0", false);
    let first = |offset| {
        let mut runs = boxed(
            b"trun",
            &words(&[0x0000_0601, 1, offset, old_sync.len() as u32, 0]),
        );
        // No row bytes. All samples inherit duration, zero size, and non-sync flags.
        runs.extend_from_slice(&boxed(b"trun", &words(&[0, DEFAULT_COUNT])));
        movie_fragment(1, &timed_fragment_track(2, 0, &runs))
    };
    let offset = first(0).len() as u32 + 8;
    file.extend_from_slice(&first(offset));
    file.extend_from_slice(&boxed(b"mdat", &[old_sync.as_slice(), &[0]].concat()));

    let tail_tick = (u64::from(DEFAULT_COUNT) + 1) * u64::from(DEFAULT_DURATION);
    let picture_tick = 2 * (tail_tick + 8) + 1;
    let tail = late_exif_samples();
    let second = |offset| {
        let picture = boxed(b"trun", &words(&[1, 1, offset]));
        let mut tracks = timed_fragment_track(1, picture_tick, &picture);
        let mut rows = words(&[0x0000_0701, 4, offset + 1]);
        for ((sample, duration), flags) in tail
            .iter()
            .zip([3, 5, 7, 11])
            .zip([0, NON_SYNC, NON_SYNC, 0])
        {
            rows.extend_from_slice(&words(&[duration, sample.len() as u32, flags]));
        }
        tracks.extend_from_slice(&timed_fragment_track(2, tail_tick, &boxed(b"trun", &rows)));
        movie_fragment(2, &tracks)
    };
    let offset = second(0).len() as u32 + 8;
    file.extend_from_slice(&second(offset));
    file.extend_from_slice(&boxed(b"mdat", &[&[0], tail.concat().as_slice()].concat()));
    assert_late_exif(&file)
}

#[test]
fn fragmented_exif_delta_inherits_the_classic_sync() -> Result<(), String> {
    assert_late_exif(&classic_sync_with_fragmented_delta(0))
}

#[test]
fn visual_anchor_follows_more_than_sixty_four_empty_samples() -> Result<(), String> {
    assert_late_exif(&classic_sync_with_fragmented_delta(96))
}

#[test]
fn compressed_movie_and_fragment_resolve_against_the_reconstructed_file() -> Result<(), String> {
    let ordinary = classic_sync_with_fragmented_delta(96);
    let brand = boxed(b"ftyp", b"comp\0\0\0\0comp");
    assert_late_exif(&compressed_sequence(&ordinary, &brand, false)?)?;
    if !avif_fields(&compressed_sequence(&ordinary, &brand, true)?)?.is_empty() {
        return Err("accepted a compressed fragment with trailing stream bytes".into());
    }

    let mut payload = b"avis\0\0\0\0".to_vec();
    for minor in 0..16u32 {
        payload.extend_from_slice(&(u32::from_be_bytes(*b"zz00") + minor).to_be_bytes());
    }
    payload.extend_from_slice(b"comp");
    let mut extended_brand = b"\0\0\0\x01ftyp".to_vec();
    extended_brand.extend_from_slice(&((16 + payload.len()) as u64).to_be_bytes());
    extended_brand.extend_from_slice(&payload);
    assert_late_exif(&compressed_sequence(&ordinary, &extended_brand, false)?)?;
    Ok(())
}

fn compressed_sequence(
    ordinary: &[u8],
    brand: &[u8],
    invalid: bool,
) -> Result<Vec<u8>, &'static str> {
    let mut file = brand.to_vec();
    let extent = ordinary.len() as u64;
    let mut input = Input::new(ordinary, extent, &mut [], |_, _: &mut [u8]| {
        Err("unexpected read outside cached fixture")
    });
    let mut at = 0;
    while at < extent {
        let span = BoxSpan::read(&mut input, at, extent)?.ok_or("invalid fixture box")?;
        let whole = &ordinary[at as usize..span.end as usize];
        if span.kind == *b"ftyp" {
            file.extend_from_slice(&boxed(b"otyp", whole));
        } else if matches!(&span.kind, b"moov" | b"moof") {
            let payload = &ordinary[span.data as usize..span.end as usize];
            let mut buffer = vec![0; payload.len() + 256];
            let progress = Compressor::new()
                .deflate(payload, &mut buffer)
                .map_err(|_| "cannot compress fixture box")?;
            let mut raw = buffer[2..progress.produced - 4].to_vec();
            let kind = if span.kind == *b"moov" {
                b"!mov"
            } else {
                b"!mof"
            };
            if invalid && kind == b"!mof" {
                raw.push(0);
            }
            file.extend_from_slice(&boxed(kind, &raw));
        } else {
            file.extend_from_slice(whole);
        }
        at = span.end;
    }
    Ok(file)
}

fn classic_sync_with_fragmented_delta(leading_empty: u32) -> Vec<u8> {
    const NON_SYNC: u32 = 0x0001_0000;
    let [sync, _, delta, _] = late_exif_samples();
    let mut file = boxed(b"ftyp", b"avis\0\0\0\0avis");
    let classic_sync_at = file.len() as u32 + 8;
    file.extend_from_slice(&boxed(b"mdat", &sync));

    let mut movie = picture_track(
        1,
        640,
        480,
        &empty_sample_table(&picture_description()),
        2000,
    );
    movie.extend_from_slice(&track(
        Header { id: 2, group: 0 },
        1,
        Samples {
            kind: b"Exif",
            suffix: b"",
            offset: classic_sync_at,
            lengths: &[sync.len() as u32],
            sync: &[1],
        },
    ));
    let mut defaults = boxed(b"trex", &words(&[0, 1, 1, 2, 0, 0]));
    defaults.extend_from_slice(&boxed(b"trex", &words(&[0, 2, 1, 1, 0, NON_SYNC])));
    movie.extend_from_slice(&boxed(b"mvex", &defaults));
    file.extend_from_slice(&boxed(b"moov", &movie));

    let delta_tick = u64::from(leading_empty) + 1;
    let fragment = |offset| {
        let mut runs = Vec::new();
        if leading_empty != 0 {
            // This timeline-only run starts at moof, before any media storage.
            runs = boxed(b"trun", &words(&[0, leading_empty]));
        }
        runs.extend_from_slice(&boxed(b"trun", &words(&[0x0000_0201, 1, offset, 1])));
        // The first nonempty image begins half a metadata tick after the delta.
        let mut tracks = timed_fragment_track(1, 3, &runs);
        let delta_run = boxed(
            b"trun",
            &words(&[0x0000_0201, 1, offset + 1, delta.len() as u32]),
        );
        tracks.extend_from_slice(&timed_fragment_track(2, delta_tick, &delta_run));
        movie_fragment(1, &tracks)
    };
    let offset = fragment(0).len() as u32 + 8;
    file.extend_from_slice(&fragment(offset));
    file.extend_from_slice(&boxed(b"mdat", &[&[0], delta.as_slice()].concat()));
    file
}

fn late_exif_samples() -> [Vec<u8>; 4] {
    [
        exif_ascii(0x0131, b"Nearest software\0", false),
        exif_ascii(0x0110, b"Skipped model\0", false),
        exif_ascii(0x010f, b"Late camera\0", true),
        exif(b"New"),
    ]
}

fn assert_late_exif(file: &[u8]) -> Result<(), String> {
    let mut fields = avif_fields(file)?;
    fields.sort_unstable();
    let expected = [
        (1, b"image/avif".to_vec()),
        (95, b"Late camera".to_vec()),
        (112, b"640x480".to_vec()),
        (113, b"Nearest software".to_vec()),
    ];
    if fields != expected {
        return Err(format!(
            "late EXIF fields {fields:?}, expected {expected:?}"
        ));
    }
    Ok(())
}

fn avif_fields(file: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, String> {
    let prefix = file.get(..8).ok_or("missing file type")?;
    let mut scratch = [0; 8192];
    let mut cache = [0; 256];
    let mut input = Input::new(
        prefix,
        file.len() as u64,
        &mut scratch,
        |offset, output: &mut [u8]| {
            let at = offset as usize;
            output.copy_from_slice(
                file.get(at..at + output.len())
                    .ok_or("unavailable source bytes")?,
            );
            Ok::<(), &'static str>(())
        },
    );
    let format = input.probe(&mut cache)?.ok_or("missing AVIF")?;
    let mut fields = Vec::new();
    format.visit_text(input, 32, &mut |kind, value| {
        fields.push((kind, value.to_vec()));
        Ok(())
    })?;
    Ok(fields)
}

fn movie_fragment(sequence: u32, tracks: &[u8]) -> Vec<u8> {
    let mut fragment = boxed(b"mfhd", &words(&[0, sequence]));
    fragment.extend_from_slice(tracks);
    boxed(b"moof", &fragment)
}

fn timed_fragment_track(id: u32, tick: u64, runs: &[u8]) -> Vec<u8> {
    let mut track = boxed(b"tfhd", &words(&[0x0002_0000, id]));
    let mut time = words(&[0x0100_0000]);
    time.extend_from_slice(&tick.to_be_bytes());
    track.extend_from_slice(&boxed(b"tfdt", &time));
    track.extend_from_slice(runs);
    boxed(b"traf", &track)
}

fn fragmented_picture(id: u32, width: u32, height: u32) -> Vec<u8> {
    picture_track(
        id,
        width,
        height,
        &empty_sample_table(&picture_description()),
        1000,
    )
}

fn picture_description() -> Vec<u8> {
    let mut av1 = [0; 78];
    av1[7] = 1;
    av1[24..28].copy_from_slice(b"\0\x80\0\x40");
    sample_description(b"av01", &av1)
}

fn picture_track(id: u32, width: u32, height: u32, table: &[u8], timescale: u32) -> Vec<u8> {
    let mut header = [0; 84];
    header[12..16].copy_from_slice(&id.to_be_bytes());
    header[76..80].copy_from_slice(&(width << 16).to_be_bytes());
    header[80..84].copy_from_slice(&(height << 16).to_be_bytes());
    let minf = media_information(table);
    let mut track = boxed(b"tkhd", &header);
    track.extend_from_slice(&boxed(b"mdia", &media(b"pict", &minf, timescale)));
    boxed(b"trak", &track)
}

fn sample_run(id: u32, offset: u32, samples: &[(u32, u32)], groups: &[u8]) -> Vec<u8> {
    let mut track = boxed(b"tfhd", &words(&[0x0002_0000, id]));
    track.extend_from_slice(&boxed(b"tfdt", &words(&[0, 100])));
    let mut run = words(&[0x0000_0601, samples.len() as u32, offset]);
    for &(length, flags) in samples {
        run.extend_from_slice(&words(&[length, flags]));
    }
    track.extend_from_slice(&boxed(b"trun", &run));
    track.extend_from_slice(groups);
    boxed(b"traf", &track)
}

fn local_groups() -> Vec<u8> {
    let stmi = u32::from_be_bytes(*b"stmi");
    let pict = u32::from_be_bytes(*b"pict");
    let mut groups = boxed(
        b"sgpd",
        &words(&[0x0100_0000, stmi, 12, 2, pict, 1, 1, pict, 1, 2]),
    );
    groups.extend_from_slice(&boxed(
        b"sbgp",
        &words(&[0, stmi, 2, 1, 0x1_0001, 1, 0x1_0002]),
    ));
    groups
}

fn grouped_metadata(xmp: &str) -> Vec<u8> {
    let mut handler = [0; 25];
    handler[8..12].copy_from_slice(b"pict");
    let mut payload = vec![0; 4];
    payload.extend_from_slice(&boxed(b"hdlr", &handler));

    let mut data = Vec::new();
    let mut locations = b"\x01\0\0\0\x44\0\0\x02".to_vec();
    let mut info = b"\0\0\0\0\0\x02".to_vec();
    for (id, city) in [(1_u16, "Rome"), (2, "Lyon")] {
        let packet = xmp.replace("Paris", city);
        locations.extend_from_slice(&id.to_be_bytes());
        locations.extend_from_slice(b"\0\x01\0\0\0\x01");
        locations.extend_from_slice(&words(&[data.len() as u32, packet.len() as u32]));
        data.extend_from_slice(packet.as_bytes());

        let mut entry = words(&[0x0200_0001]);
        entry.extend_from_slice(&id.to_be_bytes());
        entry.extend_from_slice(b"\0\0mime\0application/rdf+xml\0\0");
        info.extend_from_slice(&boxed(b"infe", &entry));
    }
    for (kind, bytes) in [(b"iinf", info), (b"iloc", locations), (b"idat", data)] {
        payload.extend_from_slice(&boxed(kind, &bytes));
    }
    boxed(b"meta", &payload)
}

fn exif(make: &[u8; 3]) -> Vec<u8> {
    [
        b"\0\0\0\x06Exif\0\0II*\0\x08\0\0\0\x01\0\x0f\x01\x02\0\x04\0\0\0".as_slice(),
        make,
        b"\0\0\0\0\0",
    ]
    .concat()
}

fn exif_ascii(tag: u16, value: &[u8], big_endian: bool) -> Vec<u8> {
    let word = |value: u32| {
        if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        }
    };
    let half = |value: u16| {
        if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        }
    };
    let mut bytes = vec![0; 4];
    bytes.extend_from_slice(if big_endian { b"MM" } else { b"II" });
    bytes.extend_from_slice(&half(42));
    bytes.extend_from_slice(&word(8));
    bytes.extend_from_slice(&half(1));
    bytes.extend_from_slice(&half(tag));
    bytes.extend_from_slice(&half(2));
    bytes.extend_from_slice(&word(value.len() as u32));
    bytes.extend_from_slice(&word(26));
    bytes.extend_from_slice(&word(0));
    bytes.extend_from_slice(value);
    bytes
}

struct Header {
    id: u32,
    group: u16,
}

struct Samples<'a> {
    kind: &'a [u8; 4],
    suffix: &'a [u8],
    offset: u32,
    lengths: &'a [u32],
    sync: &'a [u32],
}

fn track(header: Header, target: u32, samples: Samples<'_>) -> Vec<u8> {
    let entry = [b"\0\0\0\0\0\0\0\x01".as_slice(), samples.suffix].concat();
    let stsd = sample_description(samples.kind, &entry);
    let table = if samples.lengths.is_empty() {
        empty_sample_table(&stsd)
    } else {
        classic_sample_table(&stsd, samples)
    };
    describing_track(header, target, &table)
}

fn sample_description(kind: &[u8; 4], entry: &[u8]) -> Vec<u8> {
    let mut stsd = words(&[0, 1]);
    stsd.extend_from_slice(&boxed(kind, entry));
    stsd
}

fn describing_track(header: Header, target: u32, table: &[u8]) -> Vec<u8> {
    let mut tkhd = [0; 84];
    tkhd[12..16].copy_from_slice(&header.id.to_be_bytes());
    tkhd[34..36].copy_from_slice(&header.group.to_be_bytes());
    let mut track = boxed(b"tkhd", &tkhd);
    track.extend_from_slice(&boxed(b"tref", &boxed(b"cdsc", &target.to_be_bytes())));
    let minf = media_information(table);
    track.extend_from_slice(&boxed(b"mdia", &media(b"meta", &minf, 1000)));
    boxed(b"trak", &track)
}

fn classic_sample_table(stsd: &[u8], samples: Samples<'_>) -> Vec<u8> {
    let count = samples.lengths.len() as u32;
    let mut sizes = words(&[0, 0, count]);
    sizes.extend_from_slice(&words(samples.lengths));
    let mut table = boxed(b"stsd", stsd);
    table.extend_from_slice(&boxed(b"stts", &words(&[0, 1, count, 1])));
    table.extend_from_slice(&boxed(b"stsc", &words(&[0, 1, 1, count, 1])));
    table.extend_from_slice(&boxed(b"stco", &words(&[0, 1, samples.offset])));
    table.extend_from_slice(&boxed(b"stsz", &sizes));
    if !samples.sync.is_empty() {
        let mut sync = words(&[0, samples.sync.len() as u32]);
        sync.extend_from_slice(&words(samples.sync));
        table.extend_from_slice(&boxed(b"stss", &sync));
    }

    table
}

fn empty_sample_table(stsd: &[u8]) -> Vec<u8> {
    let mut table = boxed(b"stsd", stsd);
    table.extend_from_slice(&boxed(b"stts", &words(&[0, 0])));
    table.extend_from_slice(&boxed(b"stsc", &words(&[0, 0])));
    table.extend_from_slice(&boxed(b"stco", &words(&[0, 0])));
    table.extend_from_slice(&boxed(b"stsz", &words(&[0, 0, 0])));
    table
}

fn media_information(table: &[u8]) -> Vec<u8> {
    let mut dref = words(&[0, 1]);
    dref.extend_from_slice(&boxed(b"url ", &words(&[1])));
    let mut minf = boxed(b"dinf", &boxed(b"dref", &dref));
    minf.extend_from_slice(&boxed(b"stbl", table));
    minf
}

fn media(kind: &[u8; 4], minf: &[u8], timescale: u32) -> Vec<u8> {
    let mut handler = [0; 25];
    handler[8..12].copy_from_slice(kind);
    let mut media = boxed(b"hdlr", &handler);
    media.extend_from_slice(&boxed(b"mdhd", &words(&[0, 0, 0, timescale, 0, 0])));
    media.extend_from_slice(&boxed(b"minf", minf));
    media
}

fn boxed(kind: &[u8; 4], bytes: &[u8]) -> Vec<u8> {
    let mut output = words(&[(bytes.len() + 8) as u32]);
    output.extend_from_slice(kind);
    output.extend_from_slice(bytes);
    output
}

fn words(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}
