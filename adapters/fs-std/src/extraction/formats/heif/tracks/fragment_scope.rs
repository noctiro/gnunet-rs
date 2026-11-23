//! Track-wide absence of explicit metadata grouping in movie fragments.

use super::{BoxSpan, Input, MediaData, groups};
use std::num::NonZeroU32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Coverage {
    Absent,
    Present,
    Incomplete,
}

impl Coverage {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        target: NonZeroU32,
    ) -> Result<Self, E> {
        let Some(fragments) = media.fragment_spans() else {
            return Ok(Self::Incomplete);
        };
        for fragment in fragments {
            let coverage = movie_fragment(input, &fragment, target)?;
            if coverage != Self::Absent {
                return Ok(coverage);
            }
        }
        Ok(Self::Absent)
    }
}

fn movie_fragment<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    fragment: &BoxSpan,
    target: NonZeroU32,
) -> Result<Coverage, E> {
    let Some(header) = BoxSpan::read(input, fragment.data, fragment.end)? else {
        return Ok(Coverage::Incomplete);
    };
    if header.kind != *b"mfhd" || header.len() != 8 || input.range(header.data, 4)? != Some(&[0; 4])
    {
        return Ok(Coverage::Incomplete);
    }
    let mut at = header.end;
    while at < fragment.end {
        let Some(span) = BoxSpan::read(input, at, fragment.end)? else {
            return Ok(Coverage::Incomplete);
        };
        at = span.end;
        match &span.kind {
            b"mfhd" => return Ok(Coverage::Incomplete),
            b"traf" => {
                let coverage = track_fragment(input, &span, target)?;
                if coverage != Coverage::Absent {
                    return Ok(coverage);
                }
            }
            _ => {}
        }
    }
    Ok(Coverage::Absent)
}

fn track_fragment<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    fragment: &BoxSpan,
    target: NonZeroU32,
) -> Result<Coverage, E> {
    let Some(header) = BoxSpan::read(input, fragment.data, fragment.end)? else {
        return Ok(Coverage::Incomplete);
    };
    if header.kind != *b"tfhd" || !(8..=32).contains(&header.len()) {
        return Ok(Coverage::Incomplete);
    }
    let Some(&[0, _, _, _, a, b, c, d]) = input.range(header.data, 8)? else {
        return Ok(Coverage::Incomplete);
    };
    let Some(id) = NonZeroU32::new(u32::from_be_bytes([a, b, c, d])) else {
        return Ok(Coverage::Incomplete);
    };
    let mut at = header.end;
    while at < fragment.end {
        let Some(span) = BoxSpan::read(input, at, fragment.end)? else {
            return Ok(Coverage::Incomplete);
        };
        at = span.end;
        if span.kind == *b"tfhd" {
            return Ok(Coverage::Incomplete);
        }
        if id == target && groups::is_group_box(&span.kind) {
            match groups::is_metadata_group(input, &span)? {
                Some(true) => return Ok(Coverage::Present),
                Some(false) => {}
                None => return Ok(Coverage::Incomplete),
            }
        }
    }
    Ok(Coverage::Absent)
}
