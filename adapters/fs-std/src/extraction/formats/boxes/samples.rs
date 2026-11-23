//! Checked BMFF sample ranges. Track consumers interpret their own payloads.

mod classic_seek;
mod fragments;
mod table;
#[cfg(test)]
mod tests;
mod time;

use super::{BoxSpan, Input};
use classic_seek::{ClassicSeek, ClassicSync};
use fragments::{FragmentSamples, FragmentSeek};
pub(in crate::extraction::formats) use fragments::{
    MovieFragments, fragment_sample_count, track_id,
};
use std::num::NonZeroU32;
use std::ops::Range;
use table::{ChunkRun, Sizes, Values};
pub(in crate::extraction::formats) use time::{DecodingTime, TrackClock};

pub(in crate::extraction::formats) struct MediaData {
    ranges: Vec<Range<u64>>,
    fragments: Vec<MovieFragment>,
    extent: u64,
    complete: bool,
}

#[derive(Clone, Copy)]
struct MovieFragment {
    start: u64,
    body: BoxSpan,
}

impl MediaData {
    pub(in crate::extraction::formats) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    ) -> Result<Self, E> {
        let mut ranges = Vec::new();
        let mut fragments = Vec::new();
        let mut at = 0;
        let extent = input.extent;
        while let Some(span) = BoxSpan::read(input, at, extent)? {
            match &span.kind {
                b"mdat" if span.data < span.end => {
                    if ranges.try_reserve(1).is_err() {
                        break;
                    }
                    ranges.push(span.data..span.end);
                }
                b"moof" => {
                    if fragments.try_reserve(1).is_err() {
                        break;
                    }
                    fragments.push(MovieFragment {
                        start: at,
                        body: span,
                    });
                }
                _ => {}
            }
            at = span.end;
        }
        Ok(Self {
            ranges,
            fragments,
            extent,
            complete: at == extent,
        })
    }

    /// Iterates fragment boxes only when the file's top-level framing was read completely.
    pub(in crate::extraction::formats) fn fragment_spans(
        &self,
    ) -> Option<impl Iterator<Item = BoxSpan> + '_> {
        self.complete
            .then(|| self.fragments.iter().map(|fragment| fragment.body))
    }

    fn contains(&self, start: u64, end: u64) -> bool {
        if start == end {
            // A zero-byte sample advances its timeline without reading storage.
            return start <= self.extent;
        }
        let candidate = self.ranges.partition_point(|span| span.start <= start);
        candidate != 0 && end <= self.ranges[candidate - 1].end
    }
}

struct Description {
    span: BoxSpan,
    local: bool,
}

pub(in crate::extraction::formats) struct SampleTable {
    descriptions: Vec<Description>,
    runs: Vec<ChunkRun>,
    chunks: Values,
    sizes: Sizes,
    sync: Option<Values>,
    clock: Option<TrackClock>,
}

impl SampleTable {
    pub(in crate::extraction::formats) fn descriptions(&self) -> impl Iterator<Item = &BoxSpan> {
        self.descriptions
            .iter()
            .filter(|entry| entry.local)
            .map(|entry| &entry.span)
    }

    pub(in crate::extraction::formats) fn classic_sample_count(&self) -> u64 {
        u64::from(self.sizes.count())
    }

    fn samples(self, media: &MediaData) -> SampleSpans<'_> {
        SampleSpans {
            table: self,
            media,
            cursor: Some(Cursor::default()),
        }
    }

    pub(in crate::extraction::formats) fn samples_with_fragments<'a>(
        self,
        media: &'a MediaData,
        init: &'a MovieFragments,
        track: Option<NonZeroU32>,
    ) -> TrackSamples<'a> {
        let fragments = track
            .filter(|&id| init.has_track(id))
            .map(|id| FragmentSamples::new(init, id, self.clock.as_ref()));
        TrackSamples {
            classic: self.samples(media),
            fragments,
        }
    }

    pub(in crate::extraction::formats) fn seek_time<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        init: &MovieFragments,
        track: NonZeroU32,
        anchor: DecodingTime,
        sync_kind: [u8; 4],
    ) -> Result<Option<TimedSelection>, E> {
        let Some(clock) = &self.clock else {
            return Ok(None);
        };
        if init.has_track(track) && clock.last_classic_time().is_none_or(|time| time < anchor) {
            let mut fragments = FragmentSamples::new(init, track, Some(clock));
            match fragments.seek(input, media, &self.descriptions, anchor, sync_kind)? {
                FragmentSeek::Found {
                    sample,
                    mut prior_sync,
                } => {
                    if !sample.sync && sample.description.kind == sync_kind && prior_sync.is_none()
                    {
                        prior_sync = match self.sync_before_classic(
                            input,
                            media,
                            self.sizes.count(),
                            sync_kind,
                        )? {
                            ClassicSync::Found(sync) => Some(sync),
                            ClassicSync::Absent => None,
                            ClassicSync::Unavailable => return Ok(None),
                        };
                    }
                    return Ok(Some(TimedSelection { sample, prior_sync }));
                }
                FragmentSeek::Unavailable => return Ok(None),
                FragmentSeek::Before => {}
            }
        }
        let Some(ordinal) = clock.classic_at_or_before(anchor) else {
            return Ok(None);
        };
        Ok(self
            .seek_classic(input, media, ordinal, sync_kind)?
            .map(|ClassicSeek { sample, prior_sync }| TimedSelection { sample, prior_sync }))
    }
}

pub(in crate::extraction::formats) struct TrackSamples<'a> {
    classic: SampleSpans<'a>,
    fragments: Option<FragmentSamples<'a>>,
}

impl TrackSamples<'_> {
    pub(in crate::extraction::formats) fn next<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    ) -> Result<Option<SampleSpan>, E> {
        if let Some(span) = self.classic.next(input)? {
            return Ok(Some(span));
        }
        if let Some(cursor) = &mut self.fragments {
            return cursor.next(input, self.classic.media, &self.classic.table.descriptions);
        }
        Ok(None)
    }

    pub(in crate::extraction::formats) fn next_visual<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        eligible: &impl Fn(&BoxSpan) -> bool,
    ) -> Result<Option<SampleSpan>, E> {
        while let Some(sample) = self.classic.next_matching(input, Some(eligible))? {
            if sample.length != 0 {
                return Ok(Some(sample));
            }
        }
        if let Some(cursor) = &mut self.fragments {
            return cursor.next_visual(
                input,
                self.classic.media,
                &self.classic.table.descriptions,
                eligible,
            );
        }
        Ok(None)
    }
}

pub(in crate::extraction::formats) struct TimedSelection {
    pub(in crate::extraction::formats) sample: SampleSpan,
    pub(in crate::extraction::formats) prior_sync: Option<SampleExtent>,
}

#[derive(Clone, Copy)]
pub(in crate::extraction::formats) struct SampleExtent {
    pub(in crate::extraction::formats) start: u64,
    pub(in crate::extraction::formats) length: u64,
}

#[derive(Clone, Copy)]
pub(in crate::extraction::formats) enum SampleLocation {
    Classic(u64),
    Fragment { track: BoxSpan, ordinal: u64 },
}

pub(in crate::extraction::formats) struct SampleSpan {
    pub(in crate::extraction::formats) description: BoxSpan,
    pub(in crate::extraction::formats) sync: bool,
    pub(in crate::extraction::formats) start: u64,
    pub(in crate::extraction::formats) length: u64,
    pub(in crate::extraction::formats) location: SampleLocation,
    pub(in crate::extraction::formats) decoded_at: Option<DecodingTime>,
}

impl SampleSpan {
    pub(in crate::extraction::formats) const fn extent(&self) -> SampleExtent {
        SampleExtent {
            start: self.start,
            length: self.length,
        }
    }
}

pub(in crate::extraction::formats) struct SampleSpans<'a> {
    table: SampleTable,
    media: &'a MediaData,
    cursor: Option<Cursor>,
}

#[derive(Default)]
struct Cursor {
    sample: u32,
    chunk: u32,
    run: usize,
    within_chunk: u32,
    offset: u64,
    sync_read: u32,
    next_sync: Option<u32>,
}

impl SampleSpans<'_> {
    pub(in crate::extraction::formats) fn next<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    ) -> Result<Option<SampleSpan>, E> {
        self.next_matching(input, None)
    }

    fn next_matching<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        eligible: Option<&dyn Fn(&BoxSpan) -> bool>,
    ) -> Result<Option<SampleSpan>, E> {
        let Some(mut at) = self.cursor.take() else {
            return Ok(None);
        };
        let sample = self.read_sample(input, &mut at, eligible)?;
        if sample.is_some() {
            self.cursor = Some(at);
        }
        Ok(sample)
    }

    fn read_sample<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        at: &mut Cursor,
        eligible: Option<&dyn Fn(&BoxSpan) -> bool>,
    ) -> Result<Option<SampleSpan>, E> {
        let (run, entry) = loop {
            if at.sample == self.table.sizes.count() {
                return Ok(None);
            }
            if self
                .table
                .runs
                .get(at.run + 1)
                .is_some_and(|run| run.first_chunk == at.chunk)
            {
                at.run += 1;
            }
            let run = &self.table.runs[at.run];
            let entry = &self.table.descriptions[run.description];
            if entry.local && eligible.is_none_or(|eligible| eligible(&entry.span)) {
                break (run, entry);
            }
            // The mapping already proves each run fits the total sample count.
            let end = self
                .table
                .runs
                .get(at.run + 1)
                .map_or(self.table.chunks.count, |next| next.first_chunk);
            at.sample += (end - at.chunk) * run.samples - at.within_chunk;
            at.chunk = end;
            at.within_chunk = 0;
        };
        let start = if at.within_chunk == 0 {
            let Some(offset) = self.table.chunks.get(input, at.chunk)? else {
                return Ok(None);
            };
            offset
        } else {
            at.offset
        };
        let Some(length) = self.table.sizes.get(input, at.sample)? else {
            return Ok(None);
        };
        let Some(end) = start
            .checked_add(length)
            .filter(|&end| self.media.contains(start, end))
        else {
            return Ok(None);
        };
        let number = at.sample + 1;
        let sync = if let Some(sync) = self.table.sync {
            while at.next_sync.is_none_or(|next| next < number) && at.sync_read < sync.count {
                let Some(next) = sync
                    .get(input, at.sync_read)?
                    .and_then(|n| u32::try_from(n).ok())
                else {
                    return Ok(None);
                };
                if next <= at.next_sync.unwrap_or(0) || next > self.table.sizes.count() {
                    return Ok(None);
                }
                at.sync_read += 1;
                at.next_sync = Some(next);
            }
            at.next_sync == Some(number)
        } else {
            true
        };
        at.sample = number;
        at.within_chunk += 1;
        if at.within_chunk == run.samples {
            at.chunk += 1;
            at.within_chunk = 0;
        }
        at.offset = end;
        Ok(Some(SampleSpan {
            description: entry.span,
            sync,
            start,
            length,
            location: SampleLocation::Classic(u64::from(number - 1)),
            decoded_at: self
                .table
                .clock
                .as_ref()
                .and_then(|clock| clock.classic(u64::from(number - 1))),
        }))
    }
}
