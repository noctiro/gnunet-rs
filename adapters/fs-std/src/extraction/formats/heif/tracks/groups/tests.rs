use super::*;

#[test]
fn an_explicit_unmapped_sample_does_not_take_the_uncovered_tail_default() -> Result<(), &'static str>
{
    let desc = description(2, 0, 12, 2, &[&[7], &[11]]);
    let runs = mapping(1, &[(1, 1), (1, 0)]);
    let groups = parse(b"stbl", &[(*b"sgpd", &desc), (*b"sbgp", &runs)])?
        .ok_or("invalid track sample grouping")?;
    if !items(groups.select(0, 3, None), b"pict", &[7])
        || !matches!(groups.select(1, 3, None), Some(Selection::Unmapped))
        || !items(groups.select(2, 3, None), b"pict", &[11])
        || groups.select(0, 1, None).is_some()
        || groups.select(3, 3, None).is_some()
    {
        return Err("sample mapping or tail default does not match its ordinal");
    }
    Ok(())
}

#[test]
fn fragment_entries_and_defaults_keep_their_own_index_space() -> Result<(), &'static str> {
    let track = description(2, 0, 0, 1, &[&[7, 9]]);
    let track =
        parse(b"stbl", &[(*b"sgpd", &track)])?.ok_or("invalid initialization sample grouping")?;
    let fragment = description(2, 0, 0, 0x1_0001, &[&[11]]);
    let runs = mapping(0, &[(1, 1), (1, 0x1_0001), (1, 0)]);
    let local = parse(b"traf", &[(*b"sgpd", &fragment), (*b"sbgp", &runs)])?
        .ok_or("invalid fragment sample grouping")?;
    let local_default =
        parse(b"traf", &[(*b"sgpd", &fragment)])?.ok_or("invalid fragment default")?;
    let empty = parse(b"traf", &[])?.ok_or("invalid empty fragment")?;
    if !items(local.select(0, 3, Some(&track)), b"pict", &[7, 9])
        || !items(local.select(1, 3, Some(&track)), b"pict", &[11])
        || !matches!(local.select(2, 3, Some(&track)), Some(Selection::Unmapped))
        || local.select(0, 4, Some(&track)).is_some()
        || !items(local_default.select(0, 1, Some(&track)), b"pict", &[11])
        || !items(empty.select(0, 1, Some(&track)), b"pict", &[7, 9])
    {
        return Err("a fragment index was applied to the wrong description table");
    }

    let shadow = description(2, 0, 0, 0, &[&[12]]);
    let shadow = parse(b"traf", &[(*b"sgpd", &shadow)])?.ok_or("invalid shadow default")?;
    if !matches!(shadow.select(0, 1, Some(&track)), Some(Selection::Unmapped)) {
        return Err("a fragment without a default used the overridden track default");
    }
    Ok(())
}

#[test]
fn rejects_overlong_group_tables_and_conflicting_static_flags() -> Result<(), &'static str> {
    let desc = description(1, 0, 0, 0, &[&[3]]);
    let mut surplus = desc.clone();
    surplus.push(0);
    let mut truncated = mapping(0, &[(1, 1)]);
    let _ = truncated.pop();
    for (kind, bytes) in [(*b"sgpd", surplus), (*b"sbgp", truncated)] {
        if parse(b"stbl", &[(kind, &bytes)])?.is_some() {
            return Err("accepted an inexact group extent");
        }
    }

    let static_track = description(2, STATIC_DESCRIPTIONS | STATIC_MAPPING, 12, 1, &[&[7]]);
    let static_track =
        parse(b"stbl", &[(*b"sgpd", &static_track)])?.ok_or("invalid initialization flags")?;
    let local = parse(b"traf", &[(*b"sgpd", &desc)])?.ok_or("invalid local group")?;
    if local.select(0, 1, Some(&static_track)).is_some() {
        return Err("accepted a fragment-local description under a static track");
    }
    Ok(())
}

#[test]
fn compact_patterns_repeat_by_sample_and_preserve_uncovered_defaults() -> Result<(), &'static str> {
    let desc = description(2, 0, 12, 3, &[&[7], &[11], &[13]]);
    // Two four-bit fields per row and three indices with one padding nibble.
    let body = b"\0\0\0\x40stmi\0\0\0\0\0\0\0\x02\x25\x13\x10\x20";
    let read = |body| parse(b"stbl", &[(*b"sgpd", &desc), (*b"csgp", body)]);
    let groups = read(body)?.ok_or("valid compact table rejected")?;
    if !items(groups.select(4, 9, None), b"pict", &[7])
        || !matches!(groups.select(3, 9, None), Some(Selection::Unmapped))
        || !items(groups.select(5, 9, None), b"pict", &[11])
        || !items(groups.select(7, 9, None), b"pict", &[11])
        || !items(groups.select(8, 9, None), b"pict", &[13])
        || groups.select(0, 7, None).is_some()
    {
        return Err("compact pattern or uncovered default selected the wrong group");
    }

    let mut nonzero_padding = *body;
    nonzero_padding[19] |= 1;
    let ordinary = mapping(0, &[(1, 1)]);
    if read(&nonzero_padding)?.is_some()
        || read(&body[..19])?.is_some()
        || parse(b"stbl", &[(*b"sbgp", &ordinary), (*b"csgp", body)])?.is_some()
    {
        return Err("invalid compact encoding or competing mappings accepted");
    }
    Ok(())
}

#[test]
fn compact_fragment_keeps_local_indices_typed_and_uses_a_default_for_its_tail()
-> Result<(), &'static str> {
    let track_desc = description(2, 0, 12, 1, &[&[7]]);
    let track = parse(b"stbl", &[(*b"sgpd", &track_desc)])?.ok_or("invalid track groups")?;
    let fragment_desc = description(2, 0, 12, 0x1_0001, &[&[11]]);
    let local = b"\0\0\0\x95stmi\0\0\0\x01\x02\x03\x01\x81";
    let numbered = b"\0\0\0\x27stmi\0\0\0\x01\0\x01\x02\0\x01\0\x01";
    let bad_local = b"\0\0\0\x80stmi\0\0\0\x01\x11\x80";
    let read = |body| parse(b"traf", &[(*b"sgpd", &fragment_desc), (*b"csgp", body)]);
    let direct = read(local)?.ok_or("invalid fragment selector encoding")?;
    let numbered = read(numbered)?.ok_or("invalid ordinary fragment index encoding")?;
    let bad = read(bad_local)?.ok_or("index validity must be checked at selection")?;
    if !items(direct.select(0, 4, Some(&track)), b"pict", &[7])
        || !items(direct.select(1, 4, Some(&track)), b"pict", &[11])
        || !items(direct.select(3, 4, Some(&track)), b"pict", &[11])
        || !items(numbered.select(1, 2, Some(&track)), b"pict", &[11])
        || bad.select(0, 2, Some(&track)).is_some()
        || parse(b"stbl", &[(*b"csgp", local)])?.is_some()
    {
        return Err("compacted fragment selected the wrong index space");
    }
    Ok(())
}

fn items(selection: Option<Selection<'_>>, handler: &[u8; 4], values: &[u32]) -> bool {
    matches!(selection, Some(Selection::Items(group))
        if &group.handler == handler && group.items.iter().map(|id| id.get()).eq(values.iter().copied()))
}

fn description(version: u8, flags: u8, length: u32, default: u32, groups: &[&[u32]]) -> Vec<u8> {
    let mut bytes = vec![version, 0, 0, flags];
    bytes.extend_from_slice(b"stmi");
    if version >= 1 {
        bytes.extend_from_slice(&length.to_be_bytes());
    }
    if version >= 2 {
        bytes.extend_from_slice(&default.to_be_bytes());
    }
    bytes.extend_from_slice(&(groups.len() as u32).to_be_bytes());
    for ids in groups {
        if version >= 1 && length == 0 {
            bytes.extend_from_slice(&(8 + ids.len() as u32 * 4).to_be_bytes());
        }
        bytes.extend_from_slice(b"pict");
        bytes.extend_from_slice(&(ids.len() as u32).to_be_bytes());
        bytes.extend(ids.iter().flat_map(|id| id.to_be_bytes()));
    }
    bytes
}

fn mapping(version: u8, ranges: &[(u32, u32)]) -> Vec<u8> {
    let mut bytes = vec![version, 0, 0, 0];
    bytes.extend_from_slice(b"stmi");
    if version == 1 {
        bytes.extend_from_slice(&[0; 4]);
    }
    bytes.extend_from_slice(&(ranges.len() as u32).to_be_bytes());
    for (count, index) in ranges {
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&index.to_be_bytes());
    }
    bytes
}

fn parse(kind: &[u8; 4], children: &[([u8; 4], &[u8])]) -> Result<Option<Groups>, &'static str> {
    let mut data = Vec::new();
    for (child, payload) in children {
        data.extend_from_slice(&(payload.len() as u32 + 8).to_be_bytes());
        data.extend_from_slice(child);
        data.extend_from_slice(payload);
    }
    let span = BoxSpan {
        kind: *kind,
        data: 0,
        end: data.len() as u64,
    };
    let mut input = Input::new(&data, span.end, &mut [], |_, _: &mut [u8]| {
        Err("unexpected read outside the cached group")
    });
    Groups::read(&mut input, &span)
}
