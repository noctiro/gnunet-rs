use crate::extraction::formats::{Format, Input};

const EXIF: &[u8] = b"\0\0\0\0II*\0\x08\0\0\0\x01\0\x0f\x01\x02\0\x04\0\0\0Cam\0\0\0\0\0";
const XMP: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Paris"/></r:RDF>"#;

#[test]
fn whole_track_items_require_an_ungrouped_complete_fragment_index() -> Result<(), &'static str> {
    let mut file = boxed(b"ftyp", b"avis\0\0\0\0avis");
    let mut movie = picture_track(1);
    movie.extend(picture_track(2));
    let defaults: Vec<_> = [1, 2]
        .into_iter()
        .flat_map(|id| boxed(b"trex", &words(&[0, id, 1, 1, 1, 0])))
        .collect();
    movie.extend(boxed(b"mvex", &defaults));
    file.extend(boxed(b"moov", &movie));
    file.extend(fragment(1, 1, false));

    let format = Format::detect(&file).ok_or("missing AVIF format")?;
    for (later, expect_whole) in [
        (fragment(2, 2, true), true),
        (fragment(2, 1, true), false),
        (vec![0], false),
    ] {
        let bytes = [file.as_slice(), &later].concat();
        let input = Input::new(&bytes, bytes.len() as u64, &mut [], |_, _: &mut [u8]| {
            Err("read outside the cached file")
        });
        let mut fields = Vec::new();
        format.visit_text(input, 32, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        })?;
        if !fields.contains(&(112, b"640x480".to_vec()))
            || fields.contains(&(95, b"Cam".to_vec())) != expect_whole
            || fields.contains(&(41, b"Paris".to_vec())) != expect_whole
        {
            return Err("wrong metadata for the scope of the verified fragment index");
        }
    }
    Ok(())
}

fn picture_track(id: u32) -> Vec<u8> {
    let mut track_header = [0; 84];
    track_header[12..16].copy_from_slice(&id.to_be_bytes());
    track_header[76..80].copy_from_slice(&(640u32 << 16).to_be_bytes());
    track_header[80..84].copy_from_slice(&(480u32 << 16).to_be_bytes());
    let mut track = boxed(b"tkhd", &track_header);
    track.extend(whole_metadata());

    let mut entry = [0; 78];
    entry[7] = 1;
    entry[24..28].copy_from_slice(&[0x02, 0x80, 0x01, 0xe0]);
    let mut entries = words(&[0, 1]);
    entries.extend(boxed(b"av01", &entry));
    let mut table = boxed(b"stsd", &entries);
    for kind in [b"stts", b"stsc", b"stco"] {
        table.extend(boxed(kind, &words(&[0, 0])));
    }
    table.extend(boxed(b"stsz", &words(&[0, 1, 0])));
    let mut references = words(&[0, 1]);
    references.extend(boxed(b"url ", &1u32.to_be_bytes()));
    let mut information = boxed(b"dinf", &boxed(b"dref", &references));
    information.extend(boxed(b"stbl", &table));
    let mut media = boxed(b"hdlr", &picture_handler());
    let mut media_header = [0; 24];
    media_header[12..16].copy_from_slice(&1u32.to_be_bytes());
    media.extend(boxed(b"mdhd", &media_header));
    media.extend(boxed(b"minf", &information));
    track.extend(boxed(b"mdia", &media));
    boxed(b"trak", &track)
}

fn whole_metadata() -> Vec<u8> {
    let mut metadata = words(&[0]);
    metadata.extend(boxed(b"hdlr", &picture_handler()));
    let mut locations = b"\x01\0\0\0\x44\0\0\x02".to_vec();
    let mut info = b"\0\0\0\0\0\x02".to_vec();
    for (id, kind, offset, len) in [
        (1u16, b"Exif\0".as_slice(), 0, EXIF.len()),
        (2, b"mime\0application/rdf+xml\0\0", EXIF.len(), XMP.len()),
    ] {
        locations.extend(id.to_be_bytes());
        locations.extend(b"\0\x01\0\0\0\x01");
        locations.extend(words(&[offset as u32, len as u32]));
        let mut item = words(&[0x0200_0000]);
        item.extend(id.to_be_bytes());
        item.extend([0, 0]);
        item.extend(kind);
        info.extend(boxed(b"infe", &item));
    }
    metadata.extend(boxed(b"iinf", &info));
    metadata.extend(boxed(b"iloc", &locations));
    metadata.extend(boxed(b"idat", &[EXIF, XMP].concat()));
    boxed(b"meta", &metadata)
}

fn fragment(sequence: u32, track: u32, grouped: bool) -> Vec<u8> {
    let mut movie = boxed(b"mfhd", &words(&[0, sequence]));
    let mut track = boxed(b"tfhd", &words(&[0x0002_0000, track]));
    if grouped {
        let stmi = u32::from_be_bytes(*b"stmi");
        let pict = u32::from_be_bytes(*b"pict");
        track.extend(boxed(
            b"sgpd",
            &words(&[0x0100_0000, stmi, 12, 1, pict, 1, 1]),
        ));
        track.extend(boxed(b"sbgp", &words(&[0, stmi, 1, 1, 0x1_0001])));
    }
    // moof + traf + trun + mdat headers plus the trun's three words.
    let offset = movie.len() + track.len() + 44;
    track.extend(boxed(b"trun", &words(&[1, 1, offset as u32])));
    movie.extend(boxed(b"traf", &track));
    let mut result = boxed(b"moof", &movie);
    result.extend(boxed(b"mdat", &[0]));
    result
}

fn picture_handler() -> [u8; 25] {
    let mut handler = [0; 25];
    handler[8..12].copy_from_slice(b"pict");
    handler
}

fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from(((payload.len() + 8) as u32).to_be_bytes());
    bytes.extend(kind);
    bytes.extend(payload);
    bytes
}

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().copied().flat_map(u32::to_be_bytes).collect()
}
