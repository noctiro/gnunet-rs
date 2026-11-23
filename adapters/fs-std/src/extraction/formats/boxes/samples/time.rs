//! Decode timestamps in each track's media timebase.

use std::{cmp::Ordering, num::NonZeroU32};

use super::{BoxSpan, Input, table::children};

/// A decode timestamp comparable across tracks with different timebases.
#[derive(Clone, Copy, Debug)]
pub(in crate::extraction::formats) struct DecodingTime {
    ticks: u64,
    timescale: NonZeroU32,
}

impl DecodingTime {
    pub(in crate::extraction::formats) const fn new(ticks: u64, timescale: NonZeroU32) -> Self {
        Self { ticks, timescale }
    }

    pub(super) fn floor_in(self, timescale: NonZeroU32) -> u64 {
        let ticks =
            u128::from(self.ticks) * u128::from(timescale.get()) / u128::from(self.timescale.get());
        u64::try_from(ticks).unwrap_or(u64::MAX)
    }
}

impl PartialEq for DecodingTime {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for DecodingTime {}

impl PartialOrd for DecodingTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DecodingTime {
    fn cmp(&self, other: &Self) -> Ordering {
        // The products fit in 96 bits and retain fractional ticks exactly.
        let left = u128::from(self.ticks) * u128::from(other.timescale.get());
        let right = u128::from(other.ticks) * u128::from(self.timescale.get());
        left.cmp(&right)
    }
}

#[derive(Debug)]
pub(in crate::extraction::formats) struct TrackClock {
    timescale: NonZeroU32,
    classic: ClassicTimeline,
}

#[derive(Debug)]
struct ClassicTimeline {
    count: u32,
    duration: u64,
    runs: Vec<Run>,
}

#[derive(Debug)]
struct Run {
    first_tick: u64,
    first_sample: u32,
    delta: u32,
}

impl TrackClock {
    /// Reads a timebase from `mdia` and verifies that `stbl/stts` covers every classic sample.
    pub(in crate::extraction::formats) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &BoxSpan,
        table: &BoxSpan,
        count: u64,
    ) -> Result<Option<Self>, E> {
        let Ok(count) = u32::try_from(count) else {
            return Ok(None);
        };
        let Some([Some(header)]) = children(input, media, |kind| (kind == b"mdhd").then_some(0))?
        else {
            return Ok(None);
        };
        let Some(timescale) = media_timescale(input, &header)? else {
            return Ok(None);
        };
        let Some([Some(timing)]) = children(input, table, |kind| (kind == b"stts").then_some(0))?
        else {
            return Ok(None);
        };
        let Some(classic) = read_classic(input, &timing, count)? else {
            return Ok(None);
        };
        Ok(Some(Self { timescale, classic }))
    }

    /// Returns the decode timestamp of a zero-based classic sample ordinal.
    pub(in crate::extraction::formats) fn classic(&self, ordinal: u64) -> Option<DecodingTime> {
        let ordinal = u32::try_from(ordinal)
            .ok()
            .filter(|&n| n < self.classic.count)?;
        let runs = &self.classic.runs;
        let index = runs.partition_point(|run| run.first_sample <= ordinal);
        let run = runs.get(index.checked_sub(1)?)?;
        // The table validates the end of each run before exposing its timestamps.
        let ticks = run.first_tick + u64::from(ordinal - run.first_sample) * u64::from(run.delta);
        Some(DecodingTime::new(ticks, self.timescale))
    }

    pub(super) fn classic_at_or_before(&self, time: DecodingTime) -> Option<u32> {
        let ticks = time.floor_in(self.timescale);
        let timeline = &self.classic;
        let end = timeline.runs.partition_point(|run| run.first_tick <= ticks);
        let run = timeline.runs.get(end.checked_sub(1)?)?;
        let end_sample = timeline
            .runs
            .get(end)
            .map_or(timeline.count, |next| next.first_sample);
        let last_offset = u64::from(end_sample - run.first_sample - 1);
        let offset = (ticks - run.first_tick)
            .checked_div(u64::from(run.delta))
            .unwrap_or(last_offset)
            .min(last_offset);
        Some(run.first_sample + u32::try_from(offset).ok()?)
    }

    pub(super) fn last_classic_time(&self) -> Option<DecodingTime> {
        self.classic(u64::from(self.classic.count.checked_sub(1)?))
    }

    pub(in crate::extraction::formats) const fn timescale(&self) -> NonZeroU32 {
        self.timescale
    }

    /// End of the classic timeline in track ticks, used to continue into fragments.
    pub(in crate::extraction::formats) const fn classic_duration(&self) -> u64 {
        self.classic.duration
    }

    pub(super) fn last_classic_tick(&self) -> Option<u64> {
        self.last_classic_time().map(|time| time.ticks)
    }
}

fn media_timescale<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
) -> Result<Option<NonZeroU32>, E> {
    let (length, version, timescale_at) = match span.len() {
        24 => (24, 0, 12),
        36 => (36, 1, 20),
        _ => return Ok(None),
    };
    let Some(bytes) = input.range(span.data, length)? else {
        return Ok(None);
    };
    if bytes[..4] != [version, 0, 0, 0] {
        return Ok(None);
    }
    Ok(bytes[timescale_at..]
        .first_chunk()
        .and_then(|value| NonZeroU32::new(u32::from_be_bytes(*value))))
}

fn read_classic<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
    count: u32,
) -> Result<Option<ClassicTimeline>, E> {
    if span.len() < 8 {
        return Ok(None);
    }
    let Some(&[0, 0, 0, 0, a, b, c, d]) = input.range(span.data, 8)? else {
        return Ok(None);
    };
    let entries = u32::from_be_bytes([a, b, c, d]);
    if entries > count || span.len() != 8 + 8 * u64::from(entries) {
        return Ok(None);
    }
    if entries == 0 {
        return Ok((count == 0).then_some(ClassicTimeline {
            count,
            duration: 0,
            runs: Vec::new(),
        }));
    }
    let Ok(length) = usize::try_from(span.len() - 8) else {
        return Ok(None);
    };
    let Some(bytes) = input.range(span.data + 8, length)? else {
        return Ok(None);
    };
    let (rows, _) = bytes.as_chunks::<8>();
    let mut runs = Vec::new();
    if runs.try_reserve_exact(rows.len()).is_err() {
        return Ok(None);
    }
    let (mut first_sample, mut first_tick) = (0u32, 0u64);
    for (index, &[a, b, c, d, e, f, g, h]) in rows.iter().enumerate() {
        let samples = u32::from_be_bytes([a, b, c, d]);
        let delta = u32::from_be_bytes([e, f, g, h]);
        if samples == 0 || (delta == 0 && (samples != 1 || index + 1 != rows.len())) {
            return Ok(None);
        }
        let Some(next_sample) = first_sample.checked_add(samples).filter(|&n| n <= count) else {
            return Ok(None);
        };
        let Some(next_tick) = first_tick.checked_add(u64::from(samples) * u64::from(delta)) else {
            return Ok(None);
        };
        runs.push(Run {
            first_tick,
            first_sample,
            delta,
        });
        first_sample = next_sample;
        first_tick = next_tick;
    }
    Ok((first_sample == count).then_some(ClassicTimeline {
        count,
        duration: first_tick,
        runs,
    }))
}

#[cfg(test)]
mod tests {
    use super::{BoxSpan, DecodingTime, Input, TrackClock};
    use std::num::NonZeroU32;

    #[test]
    fn classic_timestamps_preserve_run_boundaries_and_track_units() -> Result<(), &'static str> {
        let bytes: Vec<_> = [
            32u32,
            u32::from_be_bytes(*b"mdhd"),
            0,
            0,
            0,
            600,
            0,
            0,
            40,
            u32::from_be_bytes(*b"stts"),
            0,
            3,
            2,
            200,
            1,
            50,
            1,
            0,
        ]
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect();
        let mut input = Input::new(&bytes, bytes.len() as u64, &mut [], |_, _: &mut [u8]| {
            Err("unexpected read outside the cached file")
        });
        let media = BoxSpan {
            kind: *b"mdia",
            data: 0,
            end: 32,
        };
        let table = BoxSpan {
            kind: *b"stbl",
            data: 32,
            end: 72,
        };
        let clock = TrackClock::read(&mut input, &media, &table, 4)?.ok_or("invalid timing")?;
        let quarter = NonZeroU32::new(4).ok_or("invalid timescale")?;
        if clock.timescale().get() != 600
            || clock.classic(3) != Some(DecodingTime::new(3, quarter))
            || clock.classic(2) != Some(DecodingTime::new(400, clock.timescale()))
            || clock.classic_duration() != 450
            || clock.classic(4).is_some()
        {
            return Err("wrong decode time across runs and track timebases");
        }
        if TrackClock::read(&mut input, &media, &table, 3)?.is_some() {
            return Err("accepted a timing table with the wrong sample count");
        }
        let rate = NonZeroU32::new(1200).ok_or("invalid timescale")?;
        for (ticks, ordinal) in [
            (399, 0),
            (400, 1),
            (799, 1),
            (800, 2),
            (899, 2),
            (900, 3),
            (u64::MAX, 3),
        ] {
            if clock.classic_at_or_before(DecodingTime::new(ticks, rate)) != Some(ordinal) {
                return Err("ordinal lookup lost a sample across a decode-time run boundary");
            }
        }
        Ok(())
    }
}
