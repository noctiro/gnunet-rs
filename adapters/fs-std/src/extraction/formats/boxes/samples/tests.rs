use super::{BoxSpan, Input, MediaData, MovieFragments, SampleTable};
use std::num::NonZeroU32;

type Observed = ([u8; 4], bool, u64, u64);

const EXPECTED: [Observed; 3] = [
    (*b"Exif", true, 8, 2),
    (*b"Exif", false, 10, 3),
    (*b"metx", true, 13, 4),
];

#[test]
fn compact_sizes_and_chunk_runs_resolve_only_local_media_payloads() {
    assert_eq!(read_samples(&fixture(13, true)), Ok(EXPECTED.to_vec()));
    // The same second run cannot point at the following mdia box or its bytes.
    assert_eq!(read_samples(&fixture(17, true)), Ok(EXPECTED[..2].to_vec()));
    // An external run cannot hide later local samples or shift their sync numbers.
    assert_eq!(
        read_samples(&fixture(13, false)),
        Ok(EXPECTED[2..].to_vec())
    );
}

#[test]
fn fragments_inherit_local_track_and_run_ends() {
    assert_eq!(
        fragment_samples(true),
        Ok(vec![(*b"metx", false, 11, 2), (*b"metx", true, 13, 4)])
    );
    assert_eq!(fragment_samples(false), Ok(Vec::new()));
}

fn fragment_samples(first_local: bool) -> Result<Vec<Observed>, &'static str> {
    let mut bytes = Vec::new();
    append_box(&mut bytes, b"mdat", &[0; 9]);
    let mut movie = Vec::new();
    for (id, local) in [(1_u32, first_local), (2, true)] {
        let mut header = [0; 84];
        header[12..16].copy_from_slice(&id.to_be_bytes());
        let mut track = Vec::new();
        append_box(&mut track, b"tkhd", &header);
        append_box(&mut track, b"mdia", &media(13, local, false));
        append_box(&mut movie, b"trak", &track);
    }
    let mut defaults = Vec::new();
    append_box(&mut defaults, b"trex", &words(&[0, 1, 1, 1, 3, 0]));
    append_box(&mut defaults, b"trex", &words(&[0, 2, 2, 1, 4, 0]));
    append_box(&mut movie, b"mvex", &defaults);
    append_box(&mut bytes, b"moov", &movie);

    let mut fragment = Vec::new();
    append_box(&mut fragment, b"mfhd", &words(&[0, 1]));
    let mut first = Vec::new();
    // Explicit base at byte 10 and signed data offset -2.
    append_box(&mut first, b"tfhd", &words(&[1, 1, 0, 10]));
    append_box(&mut first, b"trun", &words(&[1, 1, (-2_i32) as u32]));
    append_box(&mut fragment, b"traf", &first);
    let mut second = Vec::new();
    append_box(&mut second, b"tfhd", &words(&[0, 2]));
    append_box(&mut second, b"trun", &words(&[0x600, 1, 2, 0x10000]));
    append_box(&mut second, b"trun", &words(&[0, 1]));
    append_box(&mut fragment, b"traf", &second);
    append_box(&mut bytes, b"moof", &fragment);

    let mut input = Input::new(&bytes, bytes.len() as u64, &mut [], |_, _: &mut [u8]| {
        Err("unexpected read outside the cached file")
    });
    let data = MediaData::read(&mut input)?;
    let movie = BoxSpan::read(&mut input, 17, bytes.len() as u64)?.ok_or("missing moov")?;
    let init = MovieFragments::read(&mut input, &movie)?;
    let first = BoxSpan::read(&mut input, movie.data, movie.end)?.ok_or("missing first track")?;
    let target = BoxSpan::read(&mut input, first.end, movie.end)?.ok_or("missing target track")?;
    let tkhd = BoxSpan::read(&mut input, target.data, target.end)?.ok_or("missing tkhd")?;
    let media = BoxSpan::read(&mut input, tkhd.end, target.end)?.ok_or("missing mdia")?;
    let table = SampleTable::read(&mut input, &media)?.ok_or("invalid sample table")?;
    let mut cursor = table.samples_with_fragments(&data, &init, NonZeroU32::new(2));
    let mut samples = Vec::new();
    while let Some(span) = cursor.next(&mut input)? {
        samples.push((span.description.kind, span.sync, span.start, span.length));
    }
    Ok(samples)
}

fn read_samples(bytes: &[u8]) -> Result<Vec<Observed>, &'static str> {
    let mut input = Input::new(bytes, bytes.len() as u64, &mut [], |_, _: &mut [u8]| {
        Err("unexpected read outside the cached file")
    });
    let data = MediaData::read(&mut input)?;
    let media = BoxSpan::read(&mut input, 17, bytes.len() as u64)?.ok_or("missing mdia")?;
    let table = SampleTable::read(&mut input, &media)?.ok_or("invalid sample table")?;
    let mut cursor = table.samples(&data);
    let mut samples = Vec::new();
    while let Some(span) = cursor.next(&mut input)? {
        samples.push((span.description.kind, span.sync, span.start, span.length));
    }
    Ok(samples)
}

fn fixture(second_chunk: u64, first_local: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_box(&mut bytes, b"mdat", &[0; 9]);
    append_box(&mut bytes, b"mdia", &media(second_chunk, first_local, true));
    bytes
}

fn media(second_chunk: u64, first_local: bool, classic: bool) -> Vec<u8> {
    let mut descriptions = words(&[0, 2]);
    for (kind, reference) in [(b"Exif", if first_local { 1_u64 } else { 2 }), (b"metx", 1)] {
        append_box(&mut descriptions, kind, &reference.to_be_bytes());
    }
    let mut table = Vec::new();
    append_box(&mut table, b"stsd", &descriptions);
    if classic {
        append_box(&mut table, b"stsc", &words(&[0, 2, 1, 2, 1, 2, 1, 2]));
        append_box(
            &mut table,
            b"stz2",
            &[0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 3, 0x23, 0x40],
        );
        let mut chunks = words(&[0, 2]);
        chunks.extend_from_slice(&8_u64.to_be_bytes());
        chunks.extend_from_slice(&second_chunk.to_be_bytes());
        append_box(&mut table, b"co64", &chunks);
        append_box(&mut table, b"stss", &words(&[0, 2, 1, 3]));
    } else {
        append_box(&mut table, b"stsc", &words(&[0, 0]));
        append_box(&mut table, b"stsz", &words(&[0, 0, 0]));
        append_box(&mut table, b"stco", &words(&[0, 0]));
    }

    let mut references = words(&[0, 2]);
    append_box(&mut references, b"url ", &1_u32.to_be_bytes());
    append_box(&mut references, b"url ", b"\0\0\0\0external\0");
    let mut dinf = Vec::new();
    append_box(&mut dinf, b"dref", &references);
    let mut information = Vec::new();
    append_box(&mut information, b"dinf", &dinf);
    append_box(&mut information, b"stbl", &table);
    let mut media = Vec::new();
    append_box(&mut media, b"minf", &information);
    media
}

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().copied().flat_map(u32::to_be_bytes).collect()
}

fn append_box(bytes: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    bytes.extend_from_slice(&(data.len() as u32 + 8).to_be_bytes());
    bytes.extend_from_slice(kind);
    bytes.extend_from_slice(data);
}
