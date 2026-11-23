//! Resolves ordinary movie fragments in file, track-fragment and run order.

mod fields;

use super::{
    BoxSpan, DecodingTime, Description, Input, MediaData, SampleExtent, SampleLocation, SampleSpan,
    TrackClock, table,
};
use fields::{
    Base, Run, SampleDefaults, SampleRead, TrackDefaults, TrackHeader, UniformRun,
    fragment_decode_time,
};
use std::num::NonZeroU32;

#[derive(Default)]
pub(in crate::extraction::formats) struct MovieFragments {
    tracks: Vec<(NonZeroU32, BoxSpan)>,
    defaults: Vec<TrackDefaults>,
}

impl MovieFragments {
    pub(in crate::extraction::formats) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        movie: &BoxSpan,
    ) -> Result<Self, E> {
        let mut result = Self::default();
        let mut tracks = Vec::new();
        let mut extensions = None;
        let mut at = movie.data;
        while at < movie.end {
            let Some(span) = BoxSpan::read(input, at, movie.end)? else {
                return Ok(Self::default());
            };
            at = span.end;
            match &span.kind {
                b"mvex" if extensions.replace(span).is_some() => return Ok(Self::default()),
                b"trak" => {
                    if tracks.try_reserve(1).is_err() {
                        return Ok(Self::default());
                    }
                    tracks.push(span);
                }
                _ => {}
            }
        }
        let Some(extensions) = extensions else {
            return Ok(Self::default());
        };
        let mut at = extensions.data;
        while at < extensions.end {
            let Some(span) = BoxSpan::read(input, at, extensions.end)? else {
                return Ok(Self::default());
            };
            at = span.end;
            if span.kind != *b"trex" {
                continue;
            }
            let Some(defaults) = TrackDefaults::read(input, &span)? else {
                return Ok(Self::default());
            };
            if result.defaults.try_reserve(1).is_err() {
                return Ok(Self::default());
            }
            result.defaults.push(defaults);
        }
        result.defaults.sort_unstable_by_key(|track| track.track_id);
        if result
            .defaults
            .windows(2)
            .any(|tracks| tracks[0].track_id == tracks[1].track_id)
        {
            return Ok(Self::default());
        }
        if result.defaults.is_empty() || result.tracks.try_reserve_exact(tracks.len()).is_err() {
            return Ok(Self::default());
        }
        for track in tracks {
            if let Some(id) = track_id(input, &track)? {
                result.tracks.push((id, track));
            }
        }
        result.tracks.sort_unstable_by_key(|(id, _)| *id);
        if result
            .tracks
            .windows(2)
            .any(|tracks| tracks[0].0 == tracks[1].0)
        {
            return Ok(Self::default());
        }
        Ok(result)
    }

    pub(in crate::extraction::formats) fn is_empty(&self) -> bool {
        self.defaults.is_empty()
    }

    pub(in crate::extraction::formats) fn has_track(&self, id: NonZeroU32) -> bool {
        self.track(id).is_some() && self.defaults(id).is_some()
    }

    fn track(&self, id: NonZeroU32) -> Option<&BoxSpan> {
        let index = self.tracks.binary_search_by_key(&id, |(id, _)| *id).ok()?;
        Some(&self.tracks[index].1)
    }

    fn defaults(&self, id: NonZeroU32) -> Option<SampleDefaults> {
        let index = self
            .defaults
            .binary_search_by_key(&id, |track| track.track_id)
            .ok()?;
        Some(self.defaults[index].defaults)
    }
}

pub(in crate::extraction::formats) fn track_id<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    track: &BoxSpan,
) -> Result<Option<NonZeroU32>, E> {
    let Some([Some(header)]) =
        table::children(input, track, |kind| (kind == b"tkhd").then_some(0))?
    else {
        return Ok(None);
    };
    let offset = match header.len() {
        84 => 12,
        96 => 20,
        _ => return Ok(None),
    };
    if input.range(header.data, 1)? != Some(&[u8::from(offset == 20)]) {
        return Ok(None);
    }
    Ok(input
        .range(header.data + offset, 4)?
        .and_then(|bytes| NonZeroU32::new(u32::from_be_bytes(*bytes.first_chunk()?))))
}

pub(super) struct FragmentSamples<'a> {
    init: &'a MovieFragments,
    target: NonZeroU32,
    timeline: Option<Timeline>,
    next_movie: usize,
    movie: Option<MovieCursor>,
    track: Option<TrackCursor>,
    run: Option<RunCursor>,
    // Unrelated descriptors are loaded only when needed and reused across moofs.
    descriptions: Vec<(NonZeroU32, Option<Vec<Description>>)>,
}

pub(super) enum FragmentSeek {
    /// No fragment sample falls on or before the anchor.
    Before,
    Unavailable,
    Found {
        sample: SampleSpan,
        prior_sync: Option<SampleExtent>,
    },
}

struct FragmentMatch {
    sample: SampleSpan,
    prior_sync: Option<SampleExtent>,
}

impl FragmentMatch {
    fn preceding_sync(self, kind: [u8; 4]) -> Option<SampleExtent> {
        if self.sample.sync && self.sample.description.kind == kind {
            Some(self.sample.extent())
        } else {
            self.prior_sync
        }
    }

    fn finish(found: Option<Self>) -> FragmentSeek {
        match found {
            Some(Self { sample, prior_sync }) => FragmentSeek::Found { sample, prior_sync },
            None => FragmentSeek::Before,
        }
    }
}

struct RunMatch {
    sample: SampleSpan,
    prior_sync: Option<SampleExtent>,
    has_later_sample: bool,
}

#[derive(Clone, Copy)]
enum Sampling<'a> {
    All,
    Visual(&'a dyn Fn(&BoxSpan) -> bool),
}

struct Timeline {
    timescale: NonZeroU32,
    next: Option<u64>,
    last: Option<u64>,
    gap: bool,
}

impl Timeline {
    fn reset(&mut self, ticks: Option<u64>) {
        self.next = ticks.filter(|&ticks| {
            self.next.is_none_or(|next| ticks >= next) && self.last.is_none_or(|last| ticks > last)
        });
        self.gap |= self.next.is_none();
    }

    fn advance(&mut self, duration: Option<u32>) -> Option<DecodingTime> {
        let ticks = self.next?;
        if self.last.is_some_and(|last| ticks <= last) {
            self.reset(None);
            return None;
        }
        self.last = Some(ticks);
        self.next = duration.and_then(|duration| ticks.checked_add(u64::from(duration)));
        self.gap |= self.next.is_none();
        Some(DecodingTime::new(ticks, self.timescale))
    }

    fn advance_uniform(&mut self, count: u32, duration: u32) -> Option<()> {
        let first = self.next?;
        if self.last.is_some_and(|last| first <= last) || (duration == 0 && count > 1) {
            return None;
        }
        let previous = count.checked_sub(1)?;
        let duration = u64::from(duration);
        let last = first.checked_add(u64::from(previous) * duration)?;
        let next = first.checked_add(u64::from(count) * duration)?;
        self.last = Some(last);
        self.next = Some(next);
        Some(())
    }
}

struct MovieCursor {
    start: u64,
    at: u64,
    end: u64,
    previous_end: Option<u64>,
}

struct TrackCursor {
    span: BoxSpan,
    at: u64,
    end: u64,
    base: u64,
    data_end: u64,
    description: BoxSpan,
    defaults: SampleDefaults,
    target: bool,
    empty: bool,
    ordinal: u64,
    seen_decode_time: bool,
    seen_run: bool,
}

impl TrackCursor {
    fn sample(
        &self,
        ordinal: u64,
        start: u64,
        length: u64,
        sync: bool,
        decoded_at: Option<DecodingTime>,
    ) -> SampleSpan {
        SampleSpan {
            description: self.description,
            sync,
            start,
            length,
            location: SampleLocation::Fragment {
                track: self.span,
                ordinal,
            },
            decoded_at,
        }
    }
}

struct RunCursor {
    run: Run,
    index: u32,
    at: u64,
}

impl<'a> FragmentSamples<'a> {
    pub(super) fn new(
        init: &'a MovieFragments,
        target: NonZeroU32,
        clock: Option<&TrackClock>,
    ) -> Self {
        Self {
            init,
            target,
            timeline: clock.map(|clock| Timeline {
                timescale: clock.timescale(),
                next: Some(clock.classic_duration()),
                last: clock.last_classic_tick(),
                gap: false,
            }),
            next_movie: 0,
            movie: None,
            track: None,
            run: None,
            descriptions: Vec::new(),
        }
    }

    pub(super) fn has_gap(&self) -> bool {
        self.timeline.as_ref().is_none_or(|timeline| timeline.gap)
    }

    fn mark_gap(&mut self) {
        if let Some(timeline) = &mut self.timeline {
            timeline.reset(None);
        }
    }

    pub(super) fn next<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        descriptions: &[Description],
    ) -> Result<Option<SampleSpan>, E> {
        self.next_with(input, media, descriptions, Sampling::All)
    }

    /// Returns the first nonempty sample with an eligible description.
    pub(super) fn next_visual<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        descriptions: &[Description],
        eligible: &impl Fn(&BoxSpan) -> bool,
    ) -> Result<Option<SampleSpan>, E> {
        self.next_with(input, media, descriptions, Sampling::Visual(eligible))
    }

    fn next_with<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        descriptions: &[Description],
        sampling: Sampling<'_>,
    ) -> Result<Option<SampleSpan>, E> {
        while self.prepare_run(input, media, descriptions)? {
            let visual = match sampling {
                Sampling::All => None,
                Sampling::Visual(eligible) => {
                    let Some((track, cursor)) = self.track.as_ref().zip(self.run.as_ref()) else {
                        return Ok(None);
                    };
                    let eligible = eligible(&track.description);
                    if !cursor.run.variable_extent() && (!eligible || track.defaults.size == 0) {
                        if self.skip_uniform(media).is_none() {
                            self.discard_current_run();
                        }
                        continue;
                    }
                    Some(eligible)
                }
            };
            if let Some(sample) = self.read_current_sample(input, media)? {
                if visual.is_none_or(|eligible| eligible && sample.length != 0) {
                    return Ok(Some(sample));
                }
            } else {
                self.discard_current_run();
            }
        }
        Ok(None)
    }

    /// Searches from a fresh fragment cursor, retaining the closest preceding sync sample.
    pub(super) fn seek<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        descriptions: &[Description],
        anchor: DecodingTime,
        sync_kind: [u8; 4],
    ) -> Result<FragmentSeek, E> {
        if self.has_gap() {
            return Ok(FragmentSeek::Unavailable);
        }
        let mut found: Option<FragmentMatch> = None;
        while self.prepare_run(input, media, descriptions)? {
            let Some(timeline) = self.timeline.as_ref().filter(|clock| !clock.gap) else {
                return Ok(FragmentSeek::Unavailable);
            };
            let Some(ticks) = timeline
                .next
                .filter(|&ticks| timeline.last.is_none_or(|last| ticks > last))
            else {
                return Ok(FragmentSeek::Unavailable);
            };
            if DecodingTime::new(ticks, timeline.timescale) > anchor {
                return Ok(FragmentMatch::finish(found));
            }
            let uniform = self
                .run
                .as_ref()
                .zip(self.track.as_ref())
                .and_then(|(cursor, track)| cursor.run.uniform(track.defaults));
            let prefix = if let Some(uniform) = uniform {
                let Some(prefix) = self.seek_uniform(media, uniform, anchor, sync_kind) else {
                    return Ok(FragmentSeek::Unavailable);
                };
                prefix
            } else {
                let Some(sample) = self.read_current_sample(input, media)? else {
                    return Ok(FragmentSeek::Unavailable);
                };
                if self.has_gap() {
                    return Ok(FragmentSeek::Unavailable);
                }
                RunMatch {
                    sample,
                    prior_sync: None,
                    has_later_sample: false,
                }
            };
            let RunMatch {
                sample,
                prior_sync,
                has_later_sample,
            } = prefix;
            let exact = sample.decoded_at == Some(anchor);
            let prior_sync =
                prior_sync.or_else(|| found.and_then(|prior| prior.preceding_sync(sync_kind)));
            found = Some(FragmentMatch { sample, prior_sync });
            if exact || has_later_sample {
                return Ok(FragmentMatch::finish(found));
            }
        }
        if self.has_gap() || !media.complete {
            return Ok(FragmentSeek::Unavailable);
        }
        Ok(FragmentMatch::finish(found))
    }

    fn prepare_run<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        descriptions: &[Description],
    ) -> Result<bool, E> {
        while self.run.is_none() {
            if let Some(mut track) = self.track.take() {
                match self.read_track_run(input, media, &mut track)? {
                    TrackProgress::Run(run) => {
                        self.track = Some(track);
                        self.run = Some(run);
                        return Ok(true);
                    }
                    TrackProgress::Finished => {
                        if let Some(movie) = &mut self.movie {
                            movie.previous_end = Some(track.data_end);
                        }
                    }
                    TrackProgress::Invalid => {
                        self.reject_run(track.target);
                    }
                }
            }
            if let Some(span) = self.next_track(input, media)? {
                self.open_track(input, span, descriptions)?;
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn reject_run(&mut self, target: bool) {
        if target {
            self.mark_gap();
        }
        self.run = None;
        if let Some(movie) = &mut self.movie {
            movie.previous_end = None;
        }
    }

    fn discard_current_run(&mut self) {
        let target = self.track.take().is_some_and(|track| track.target);
        self.reject_run(target);
    }

    fn skip_uniform(&mut self, media: &MediaData) -> Option<()> {
        let track = self.track.as_ref()?;
        let cursor = self.run.as_ref()?;
        let count = cursor.run.count.checked_sub(cursor.index)?;
        let end = cursor
            .at
            .checked_add(u64::from(count) * u64::from(track.defaults.size))?;
        if !media.contains(cursor.at, end) {
            return None;
        }
        if let Some(timeline) = &mut self.timeline
            && timeline
                .advance_uniform(count, track.defaults.duration)
                .is_none()
        {
            timeline.reset(None);
        }
        self.advance_run(count, end)
    }

    fn read_current_sample<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
    ) -> Result<Option<SampleSpan>, E> {
        let Some((track, cursor)) = self.track.as_ref().zip(self.run.as_ref()) else {
            return Ok(None);
        };
        let mode = if self.timeline.is_some() {
            SampleRead::Timed
        } else {
            SampleRead::Storage
        };
        let Some(sample) = cursor
            .run
            .sample(input, cursor.index, track.defaults, mode)?
        else {
            return Ok(None);
        };
        let length = u64::from(sample.size);
        let Some(end) = cursor
            .at
            .checked_add(length)
            .filter(|&end| media.contains(cursor.at, end))
        else {
            return Ok(None);
        };
        let decoded_at = self.timeline.as_mut().and_then(|timeline| {
            if sample.duration == Some(0) && cursor.index + 1 < cursor.run.count {
                timeline.reset(None);
                return None;
            }
            timeline.advance(sample.duration)
        });
        let span = track.sample(track.ordinal, cursor.at, length, sample.sync, decoded_at);
        Ok(self.advance_run(1, end).map(|()| span))
    }

    fn seek_uniform(
        &mut self,
        media: &MediaData,
        uniform: UniformRun,
        anchor: DecodingTime,
        sync_kind: [u8; 4],
    ) -> Option<RunMatch> {
        let track = self.track.as_ref()?;
        let cursor = self.run.as_ref()?;
        let timeline = self.timeline.as_mut()?;
        let first_tick = timeline.next?;
        let count = cursor.run.count.checked_sub(cursor.index)?;
        let duration = u64::from(uniform.duration);
        let size = u64::from(uniform.size);

        // Integer decode ticks are at or before the anchor exactly when they
        // are at or below the anchor floored to this track's timescale.
        let last = count.checked_sub(1)?;
        let elapsed = anchor
            .floor_in(timeline.timescale)
            .checked_sub(first_tick)?;
        let last_offset = match elapsed.checked_div(duration) {
            Some(offset) => u32::try_from(offset.min(u64::from(last))).ok()?,
            None if last == 0 => 0,
            None => return None,
        };
        let read = last_offset + 1;
        let end = cursor.at.checked_add(u64::from(read) * size)?;
        if !media.contains(cursor.at, end) {
            return None;
        }
        let last_index = cursor.index + last_offset;
        let ticks = first_tick.checked_add(u64::from(last_offset) * duration)?;
        let sample = track.sample(
            track.ordinal.checked_add(u64::from(last_offset))?,
            end - size,
            size,
            uniform.sync_at(last_index),
            Some(DecodingTime::new(ticks, timeline.timescale)),
        );
        let prior_sync = if track.description.kind == sync_kind {
            if let Some(index) = uniform.prior_sync(cursor.index, last_index) {
                let offset = index - cursor.index;
                Some(SampleExtent {
                    start: cursor.at.checked_add(u64::from(offset) * size)?,
                    length: size,
                })
            } else {
                None
            }
        } else {
            None
        };
        timeline.advance_uniform(read, uniform.duration)?;
        self.advance_run(read, end)?;
        Some(RunMatch {
            sample,
            prior_sync,
            has_later_sample: read < count,
        })
    }

    fn advance_run(&mut self, count: u32, end: u64) -> Option<()> {
        let track = self.track.as_mut()?;
        let cursor = self.run.as_mut()?;
        track.ordinal = track.ordinal.checked_add(u64::from(count))?;
        cursor.index = cursor.index.checked_add(count)?;
        cursor.at = end;
        if cursor.index == cursor.run.count {
            track.data_end = end;
            self.run = None;
        }
        Some(())
    }

    fn next_track<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
    ) -> Result<Option<BoxSpan>, E> {
        loop {
            if let Some(mut movie) = self.movie.take() {
                while movie.at < movie.end {
                    let Some(span) = BoxSpan::read(input, movie.at, movie.end)? else {
                        self.mark_gap();
                        break;
                    };
                    movie.at = span.end;
                    match &span.kind {
                        b"traf" => {
                            self.movie = Some(movie);
                            return Ok(Some(span));
                        }
                        b"mfhd" => {
                            self.mark_gap();
                            break;
                        }
                        _ => {}
                    }
                }
            }
            let Some(fragment) = media.fragments.get(self.next_movie) else {
                return Ok(None);
            };
            self.next_movie += 1;
            let Some(header) = BoxSpan::read(input, fragment.body.data, fragment.body.end)? else {
                self.mark_gap();
                continue;
            };
            if header.kind != *b"mfhd"
                || header.len() != 8
                || input.range(header.data, 4)? != Some(&[0; 4])
            {
                self.mark_gap();
                continue;
            }
            self.movie = Some(MovieCursor {
                start: fragment.start,
                at: header.end,
                end: fragment.body.end,
                previous_end: Some(fragment.start),
            });
        }
    }

    fn open_track<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: BoxSpan,
        descriptions: &[Description],
    ) -> Result<(), E> {
        let Some(movie) = &mut self.movie else {
            return Ok(());
        };
        // A malformed or external preceding track cannot authorize inheritance.
        let implicit = movie.previous_end.take();
        let Some(header_span) = BoxSpan::read(input, span.data, span.end)? else {
            self.mark_gap();
            return Ok(());
        };
        if header_span.kind != *b"tfhd" {
            self.mark_gap();
            return Ok(());
        }
        let Some(header) = TrackHeader::read(input, &header_span)? else {
            self.mark_gap();
            return Ok(());
        };
        let target = header.track_id == self.target;
        let base = match header.base {
            Base::Explicit(offset) => offset,
            Base::Moof => movie.start,
            Base::Implicit => {
                let Some(base) = implicit else {
                    if target {
                        self.mark_gap();
                    }
                    return Ok(());
                };
                base
            }
        };
        let Some(defaults) = self
            .init
            .defaults(header.track_id)
            .map(|defaults| header.defaults(defaults))
        else {
            if target {
                self.mark_gap();
            }
            return Ok(());
        };
        let index = (defaults.description.get() - 1) as usize;
        let description = if target {
            descriptions
                .get(index)
                .filter(|item| item.local)
                .map(|item| item.span)
        } else {
            self.other_description(input, header.track_id, index)?
        };
        if let Some(description) = description {
            self.track = Some(TrackCursor {
                span,
                at: header_span.end,
                end: span.end,
                base,
                data_end: base,
                description,
                defaults,
                target,
                empty: header.is_empty,
                ordinal: 0,
                seen_decode_time: false,
                seen_run: false,
            });
        } else if target {
            self.mark_gap();
        }
        Ok(())
    }

    fn other_description<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        id: NonZeroU32,
        index: usize,
    ) -> Result<Option<BoxSpan>, E> {
        let descriptions = match self.descriptions.binary_search_by_key(&id, |entry| entry.0) {
            Ok(found) => &self.descriptions[found].1,
            Err(position) => {
                let descriptions = if let Some(track) = self.init.track(id) {
                    table::track_descriptions(input, track)?
                } else {
                    None
                };
                if self.descriptions.try_reserve(1).is_err() {
                    return Ok(None);
                }
                self.descriptions.insert(position, (id, descriptions));
                &self.descriptions[position].1
            }
        };
        Ok(descriptions
            .as_ref()
            .and_then(|list| list.get(index))
            .filter(|item| item.local)
            .map(|item| item.span))
    }

    fn read_track_run<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        track: &mut TrackCursor,
    ) -> Result<TrackProgress, E> {
        loop {
            if track.at == track.end {
                if track.empty
                    && track.target
                    && let Some(timeline) = &mut self.timeline
                {
                    timeline.next = timeline
                        .next
                        .and_then(|ticks| ticks.checked_add(u64::from(track.defaults.duration)));
                    timeline.gap |= timeline.next.is_none();
                }
                return Ok(TrackProgress::Finished);
            }
            let Some(span) = BoxSpan::read(input, track.at, track.end)? else {
                return Ok(TrackProgress::Invalid);
            };
            track.at = span.end;
            match &span.kind {
                b"tfhd" => return Ok(TrackProgress::Invalid),
                b"tfdt" if track.target && self.timeline.is_some() => {
                    let ticks = if track.seen_run || track.seen_decode_time {
                        None
                    } else {
                        fragment_decode_time(input, &span)?
                    };
                    track.seen_decode_time = true;
                    if let Some(timeline) = &mut self.timeline {
                        timeline.reset(ticks);
                    }
                    continue;
                }
                b"trun" if !track.empty => track.seen_run = true,
                b"trun" | b"ctrn" => return Ok(TrackProgress::Invalid),
                _ => continue,
            }
            let Some(run) = Run::read(input, &span)? else {
                return Ok(TrackProgress::Invalid);
            };
            let start = match run.data_offset {
                Some(distance) => track.base.checked_add_signed(i64::from(distance)),
                None => Some(track.data_end),
            };
            let Some(start) = start else {
                return Ok(TrackProgress::Invalid);
            };
            if run.count == 0 {
                track.data_end = start;
            } else if track.target {
                return Ok(TrackProgress::Run(RunCursor {
                    run,
                    index: 0,
                    at: start,
                }));
            } else {
                let Some(end) = run
                    .byte_length(input, track.defaults)?
                    .and_then(|length| start.checked_add(length))
                    .filter(|&end| media.contains(start, end))
                else {
                    return Ok(TrackProgress::Invalid);
                };
                track.data_end = end;
            }
        }
    }
}

enum TrackProgress {
    Run(RunCursor),
    Finished,
    Invalid,
}

// Count samples across all runs before applying a fragment-local group map.
pub(in crate::extraction::formats) fn fragment_sample_count<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    track: &BoxSpan,
) -> Result<Option<u64>, E> {
    let mut at = track.data;
    let mut count = 0u64;
    while at < track.end {
        let Some(span) = BoxSpan::read(input, at, track.end)? else {
            return Ok(None);
        };
        at = span.end;
        match &span.kind {
            b"trun" => {
                let Some(run) = Run::read(input, &span)? else {
                    return Ok(None);
                };
                let Some(total) = count.checked_add(u64::from(run.count)) else {
                    return Ok(None);
                };
                count = total;
            }
            b"ctrn" => return Ok(None),
            _ => {}
        }
    }
    Ok(Some(count))
}
