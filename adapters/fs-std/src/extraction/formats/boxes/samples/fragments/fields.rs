//! Bounded fragment headers and positioned sample fields from ISO BMFF.

use super::super::{BoxSpan, Input};
use std::num::NonZeroU32;

const NON_SYNC: u32 = 0x0001_0000;

#[derive(Clone, Copy)]
pub(super) struct SampleDefaults {
    pub(super) description: NonZeroU32,
    pub(super) duration: u32,
    pub(super) size: u32,
    flags: u32,
}

pub(super) struct TrackDefaults {
    pub(super) track_id: NonZeroU32,
    pub(super) defaults: SampleDefaults,
}

impl TrackDefaults {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        if span.kind != *b"trex" || span.len() != 24 {
            return Ok(None);
        }
        let Some(words) = input.range(span.data, 24)? else {
            return Ok(None);
        };
        let ([[0, 0, 0, 0], id, description, duration, size, flags], []) = words.as_chunks::<4>()
        else {
            return Ok(None);
        };
        let (Some(track_id), Some(description)) = (
            NonZeroU32::new(u32::from_be_bytes(*id)),
            NonZeroU32::new(u32::from_be_bytes(*description)),
        ) else {
            return Ok(None);
        };
        Ok(Some(Self {
            track_id,
            defaults: SampleDefaults {
                description,
                duration: u32::from_be_bytes(*duration),
                size: u32::from_be_bytes(*size),
                flags: u32::from_be_bytes(*flags),
            },
        }))
    }
}

#[derive(Clone, Copy)]
pub(super) enum Base {
    Explicit(u64),
    Moof,
    Implicit,
}

pub(super) struct TrackHeader {
    pub(super) track_id: NonZeroU32,
    pub(super) base: Base,
    pub(super) is_empty: bool,
    description: Option<NonZeroU32>,
    duration: Option<u32>,
    size: Option<u32>,
    flags: Option<u32>,
}

impl TrackHeader {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        if span.kind != *b"tfhd" || !(8..=32).contains(&span.len()) {
            return Ok(None);
        }
        Ok(input
            .range(span.data, span.len() as usize)?
            .and_then(Self::parse))
    }

    fn parse(mut bytes: &[u8]) -> Option<Self> {
        const EXPLICIT: u32 = 0x000001;
        const DESCRIPTION: u32 = 0x000002;
        const DURATION: u32 = 0x000008;
        const SIZE: u32 = 0x000010;
        const FLAGS: u32 = 0x000020;
        const EMPTY: u32 = 0x010000;
        const MOOF: u32 = 0x020000;
        let flags = take(&mut bytes)?;
        if flags & !(EXPLICIT | DESCRIPTION | DURATION | SIZE | FLAGS | EMPTY | MOOF) != 0 {
            return None;
        }
        let track_id = NonZeroU32::new(take(&mut bytes)?)?;
        let base = if flags & EXPLICIT != 0 {
            let (offset, tail) = bytes.split_first_chunk()?;
            bytes = tail;
            Base::Explicit(u64::from_be_bytes(*offset))
        } else if flags & MOOF != 0 {
            Base::Moof
        } else {
            Base::Implicit
        };
        let description = if flags & DESCRIPTION != 0 {
            Some(NonZeroU32::new(take(&mut bytes)?)?)
        } else {
            None
        };
        let duration = optional_word(&mut bytes, flags & DURATION != 0)?;
        let size = optional_word(&mut bytes, flags & SIZE != 0)?;
        let sample_flags = optional_word(&mut bytes, flags & FLAGS != 0)?;
        if !bytes.is_empty() {
            return None;
        }
        Some(Self {
            track_id,
            base,
            is_empty: flags & EMPTY != 0,
            description,
            duration,
            size,
            flags: sample_flags,
        })
    }

    pub(super) fn defaults(&self, inherited: SampleDefaults) -> SampleDefaults {
        SampleDefaults {
            description: self.description.unwrap_or(inherited.description),
            duration: self.duration.unwrap_or(inherited.duration),
            size: self.size.unwrap_or(inherited.size),
            flags: self.flags.unwrap_or(inherited.flags),
        }
    }
}

/// Reads the first decode timestamp of a fragment in track media ticks.
pub(super) fn fragment_decode_time<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
) -> Result<Option<u64>, E> {
    if span.kind != *b"tfdt" || !matches!(span.len(), 8 | 12) {
        return Ok(None);
    }
    let Some(bytes) = input.range(span.data, span.len() as usize)? else {
        return Ok(None);
    };
    Ok(match *bytes {
        [0, 0, 0, 0, a, b, c, d] => Some(u64::from(u32::from_be_bytes([a, b, c, d]))),
        [1, 0, 0, 0, a, b, c, d, e, f, g, h] => Some(u64::from_be_bytes([a, b, c, d, e, f, g, h])),
        _ => None,
    })
}

pub(super) struct Run {
    pub(super) data_offset: Option<i32>,
    pub(super) count: u32,
    first_flags: Option<u32>,
    rows: u64,
    stride: u8,
    layout: RowLayout,
}

struct RowLayout {
    duration: bool,
    size: bool,
    flags: bool,
}

#[derive(Clone, Copy)]
pub(super) enum SampleRead {
    Storage,
    Timed,
}

pub(super) struct RunSample {
    pub(super) duration: Option<u32>,
    pub(super) size: u32,
    pub(super) sync: bool,
}

pub(super) struct UniformRun {
    pub(super) duration: u32,
    pub(super) size: u32,
    first_sync: bool,
    rest_sync: bool,
}

impl UniformRun {
    pub(super) fn sync_at(&self, index: u32) -> bool {
        if index == 0 {
            self.first_sync
        } else {
            self.rest_sync
        }
    }

    /// Returns the last sync index in the half-open interval.
    pub(super) fn prior_sync(&self, first: u32, end: u32) -> Option<u32> {
        if first >= end {
            None
        } else if end > 1 && self.rest_sync {
            Some(end - 1)
        } else if first == 0 && self.first_sync {
            Some(0)
        } else {
            None
        }
    }
}

impl Run {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        const OFFSET: u8 = 0x01;
        const FIRST: u8 = 0x04;
        const DURATION: u8 = 0x01;
        const SIZE: u8 = 0x02;
        const FLAGS: u8 = 0x04;

        if span.kind != *b"trun" || span.len() < 8 {
            return Ok(None);
        }
        let Some(&[0 | 1, 0, row_flags, run_flags, a, b, c, d]) = input.range(span.data, 8)? else {
            return Ok(None);
        };
        if run_flags & FIRST != 0 && row_flags & FLAGS != 0 {
            return Ok(None);
        }
        let count = u32::from_be_bytes([a, b, c, d]);
        // Optional extension words follow the defined fields in both regions.
        let head = 8 + u64::from(run_flags.count_ones()) * 4;
        let stride = row_flags.count_ones() as u8 * 4;
        if span.len() != head + u64::from(stride) * u64::from(count) {
            return Ok(None);
        }
        let extra = (run_flags & (OFFSET | FIRST)).count_ones() as usize * 4;
        let (data_offset, first_flags) = if extra == 0 {
            (None, None)
        } else {
            let Some(mut bytes) = input.range(span.data + 8, extra)? else {
                return Ok(None);
            };
            let offset = if run_flags & OFFSET != 0 {
                let Some((raw, tail)) = bytes.split_first_chunk() else {
                    return Ok(None);
                };
                bytes = tail;
                Some(i32::from_be_bytes(*raw))
            } else {
                None
            };
            let Some(first) = optional_word(&mut bytes, run_flags & FIRST != 0) else {
                return Ok(None);
            };
            (offset, first)
        };
        Ok(Some(Self {
            data_offset,
            count,
            first_flags,
            rows: span.data + head,
            stride,
            layout: RowLayout {
                duration: row_flags & DURATION != 0,
                size: row_flags & SIZE != 0,
                flags: row_flags & FLAGS != 0,
            },
        }))
    }

    pub(super) fn byte_length<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        defaults: SampleDefaults,
    ) -> Result<Option<u64>, E> {
        if !self.layout.size {
            return Ok(Some(u64::from(self.count) * u64::from(defaults.size)));
        }
        let offset = u8::from(self.layout.duration) * 4;
        let mut total = 0;
        for index in 0..self.count {
            let Some(size) = word(input, self.row(index, offset))? else {
                return Ok(None);
            };
            total += u64::from(size);
        }
        Ok(Some(total))
    }

    pub(super) fn uniform(&self, defaults: SampleDefaults) -> Option<UniformRun> {
        if self.variable_extent() || self.layout.flags {
            return None;
        }
        Some(UniformRun {
            duration: defaults.duration,
            size: defaults.size,
            first_sync: self.first_flags.unwrap_or(defaults.flags) & NON_SYNC == 0,
            rest_sync: defaults.flags & NON_SYNC == 0,
        })
    }

    pub(super) fn variable_extent(&self) -> bool {
        self.layout.duration || self.layout.size
    }

    pub(super) fn sample<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        index: u32,
        defaults: SampleDefaults,
        read: SampleRead,
    ) -> Result<Option<RunSample>, E> {
        if index >= self.count {
            return Ok(None);
        }
        let default_flags = if index == 0 {
            self.first_flags.unwrap_or(defaults.flags)
        } else {
            defaults.flags
        };
        let timed = matches!(read, SampleRead::Timed);
        let duration_present = timed && self.layout.duration;
        let word_count = usize::from(duration_present)
            + usize::from(self.layout.size)
            + usize::from(self.layout.flags);
        let mut bytes: &[u8] = if word_count == 0 {
            &[]
        } else {
            let offset = u8::from(!timed && self.layout.duration) * 4;
            let Some(bytes) = input.range(self.row(index, offset), word_count * 4)? else {
                return Ok(None);
            };
            bytes
        };
        let (Some(duration), Some(size), Some(flags)) = (
            optional_word(&mut bytes, duration_present),
            optional_word(&mut bytes, self.layout.size),
            optional_word(&mut bytes, self.layout.flags),
        ) else {
            return Ok(None);
        };
        Ok(Some(RunSample {
            duration: timed.then_some(duration.unwrap_or(defaults.duration)),
            size: size.unwrap_or(defaults.size),
            sync: flags.unwrap_or(default_flags) & NON_SYNC == 0,
        }))
    }

    fn row(&self, index: u32, offset: u8) -> u64 {
        self.rows + u64::from(index) * u64::from(self.stride) + u64::from(offset)
    }
}

fn take(bytes: &mut &[u8]) -> Option<u32> {
    let (word, rest) = bytes.split_first_chunk()?;
    *bytes = rest;
    Some(u32::from_be_bytes(*word))
}

fn optional_word(bytes: &mut &[u8], present: bool) -> Option<Option<u32>> {
    if present {
        take(bytes).map(Some)
    } else {
        Some(None)
    }
}

fn word<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    at: u64,
) -> Result<Option<u32>, E> {
    Ok(input
        .range(at, 4)?
        .and_then(|bytes| bytes.first_chunk().copied())
        .map(u32::from_be_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_inherited_defaults_before_resolving_zero_width_run() -> Result<(), &'static str> {
        let trex = words(&[0, 7, 3, 1_000, 80, 0]);
        let mut bytes = cached(&trex);
        let track = TrackDefaults::read(&mut bytes, &span(b"trex", &trex))?
            .ok_or("missed valid defaults")?;

        let tfhd = words(&[0x0003_003b, 7, 1, 500, 2, 20, 16, 0x0001_0000]);
        let mut bytes = cached(&tfhd);
        let header = TrackHeader::read(&mut bytes, &span(b"tfhd", &tfhd))?
            .ok_or("missed valid fragment header")?;
        let defaults = header.defaults(track.defaults);
        if track.track_id != header.track_id
            || !matches!(header.base, Base::Explicit(0x1_0000_01f4))
            || !header.is_empty
            || defaults.description.get() != 2
            || track.defaults.duration != 1_000
            || defaults.duration != 20
        {
            return Err("lost a fragment header field");
        }

        let trun = words(&[
            0x0000_0005,
            2,
            u32::from_be_bytes((-40_i32).to_be_bytes()),
            0,
        ]);
        let mut bytes = cached(&trun);
        let run = Run::read(&mut bytes, &span(b"trun", &trun))?.ok_or("missed valid run")?;
        let first = run
            .sample(&mut bytes, 0, defaults, SampleRead::Timed)?
            .ok_or("missing first sample")?;
        let second = run
            .sample(&mut bytes, 1, defaults, SampleRead::Timed)?
            .ok_or("missing second sample")?;
        if run.data_offset != Some(-40)
            || run.byte_length(&mut bytes, defaults)? != Some(32)
            || first.duration != Some(20)
            || second.duration != Some(20)
            || first.size != 16
            || second.size != 16
            || !first.sync
            || second.sync
            || run
                .sample(&mut bytes, 2, defaults, SampleRead::Timed)?
                .is_some()
        {
            return Err("incorrect default or first-sample override");
        }
        Ok(())
    }

    #[test]
    fn positions_size_and_flag_words_among_other_fields() -> Result<(), &'static str> {
        let defaults = SampleDefaults {
            description: NonZeroU32::MIN,
            duration: 111,
            size: 4,
            flags: 0x0001_0000,
        };
        let trun = words(&[
            0x0100_1f03,
            2,
            15,
            123,
            100,
            3,
            0,
            u32::MAX,
            123,
            200,
            6,
            0x0001_0000,
            u32::MAX,
            123,
        ]);
        let mut bytes = cached(&trun);
        let run = Run::read(&mut bytes, &span(b"trun", &trun))?.ok_or("missed valid run")?;
        let first = run
            .sample(&mut bytes, 0, defaults, SampleRead::Storage)?
            .ok_or("missing first sample")?;
        let second = run
            .sample(&mut bytes, 1, defaults, SampleRead::Timed)?
            .ok_or("missing second sample")?;
        if run.data_offset != Some(15)
            || run.byte_length(&mut bytes, defaults)? != Some(9)
            || first.duration.is_some()
            || second.duration != Some(200)
            || first.size != 3
            || second.size != 6
            || !first.sync
            || second.sync
        {
            return Err("misaligned fields in variable-width samples");
        }

        for bad in [&trun[..trun.len() - 1], &words(&[0x0000_0404, 1, 0, 0])] {
            if Run::read(&mut cached(bad), &span(b"trun", bad))?.is_some() {
                return Err("admitted inconsistent run geometry or flags");
            }
        }
        Ok(())
    }

    #[test]
    fn fragment_decode_time_requires_exact_version_and_length() -> Result<(), &'static str> {
        let tfdt32 = words(&[0, u32::MAX]);
        let tfdt64 = words(&[0x0100_0000, 1, 17]);
        let malformed = words(&[0, 1, 17]);
        for (bytes, expected) in [
            (tfdt32, Some(u64::from(u32::MAX))),
            (tfdt64, Some(0x1_0000_0011)),
            (malformed, None),
        ] {
            if fragment_decode_time(&mut cached(&bytes), &span(b"tfdt", &bytes))? != expected {
                return Err("wrong decode time for the tfdt version and size");
            }
        }
        Ok(())
    }

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().copied().flat_map(u32::to_be_bytes).collect()
    }

    fn span(kind: &[u8; 4], payload: &[u8]) -> BoxSpan {
        BoxSpan {
            kind: *kind,
            data: 0,
            end: payload.len() as u64,
        }
    }

    fn cached(payload: &[u8]) -> Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), &'static str>> {
        Input::new(payload, payload.len() as u64, &mut [], |_, _: &mut [u8]| {
            Err("unexpected read outside the cached payload")
        })
    }
}
