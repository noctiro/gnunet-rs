//! Selects an image sequence and reads its display geometry and track metadata scope.

mod fragment_scope;
mod groups;
mod scope;
mod timed;
mod visual;
#[cfg(test)]
mod whole_tests;

use super::{
    super::{
        Dimensions,
        boxes::samples::{
            DecodingTime, MediaData, MovieFragments, SampleLocation, SampleTable, TimedSelection,
            TrackSamples, fragment_sample_count,
        },
        compression::Decompression,
        tiff,
    },
    BoxSpan, Input, picture_handler, read_body,
};
use groups::{Groups, Selection};
use std::num::NonZeroU32;
use visual::{VisualSamples, entry_dimensions};

#[derive(Clone, Copy)]
pub(super) enum Codec {
    Av1,
    Hevc,
    Generic,
}

impl Codec {
    pub(super) fn for_brand(brand: &[u8; 4]) -> Self {
        match brand {
            b"avif" | b"avis" => Self::Av1,
            b"heic" | b"heix" | b"heim" | b"heis" | b"hevc" | b"hevx" | b"hevm" | b"hevs" => {
                Self::Hevc
            }
            _ => Self::Generic,
        }
    }

    fn accepts(self, sample_entry: &[u8; 4]) -> bool {
        match self {
            Self::Av1 => sample_entry == b"av01",
            Self::Hevc => matches!(sample_entry, b"hvc1" | b"hvc2" | b"lhv1"),
            Self::Generic => true,
        }
    }
}

pub(super) struct VisualTrack {
    timed: Option<TimedMetadata>,
    pub(super) dimensions: Dimensions,
    pub(super) orientation: Option<u8>,
    metadata: TrackMetadata,
}

struct TimedMetadata {
    id: NonZeroU32,
    movie: MovieIndex,
    anchor: DecodingTime,
}

enum TrackMetadata {
    None,
    Whole(BoxSpan),
    Sample {
        track: BoxSpan,
        movie: BoxSpan,
        group: groups::Group,
    },
}

struct MovieIndex {
    span: BoxSpan,
    fragments: MovieFragments,
    fragmented: bool,
    media: Option<MediaData>,
}

impl MovieIndex {
    fn samples<'a, E>(
        &'a mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        table: SampleTable,
        id: NonZeroU32,
    ) -> Result<TrackSamples<'a>, E> {
        let media = cached_media(input, &mut self.media)?;
        Ok(table.samples_with_fragments(media, &self.fragments, Some(id)))
    }

    fn seek_metadata<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        table: &SampleTable,
        id: NonZeroU32,
        anchor: DecodingTime,
    ) -> Result<Option<TimedSelection>, E> {
        if self.fragmented && !self.fragments.has_track(id) {
            return Ok(None);
        }
        let media = cached_media(input, &mut self.media)?;
        table.seek_time(input, media, &self.fragments, id, anchor, *b"Exif")
    }
}

fn cached_media<'a, E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    media: &'a mut Option<MediaData>,
) -> Result<&'a MediaData, E> {
    if let Some(ref media) = *media {
        return Ok(media);
    }
    Ok(media.insert(MediaData::read(input)?))
}

struct Candidate {
    id: NonZeroU32,
    media: BoxSpan,
    track: BoxSpan,
    table: BoxSpan,
    metadata: Option<BoxSpan>,
    geometry: TrackGeometry,
}

struct SelectedSample {
    dimensions: Dimensions,
    metadata: TrackMetadata,
    time: Option<DecodingTime>,
}

impl Candidate {
    fn sample<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        movie: &mut MovieIndex,
        codec: Codec,
    ) -> Result<Option<SelectedSample>, E> {
        let Some(table) = SampleTable::read_timed(input, &self.media)? else {
            return Ok(None);
        };
        let mut eligible = Vec::new();
        for entry in table.descriptions() {
            if let Some(dimensions) = entry_dimensions(input, entry, codec)? {
                if eligible.try_reserve(1).is_err() {
                    return Ok(None);
                }
                eligible.push((entry.data, dimensions));
            }
        }
        if eligible.is_empty() {
            return Ok(None);
        }
        let count = table.classic_sample_count();
        let mut samples = movie.samples(input, table, self.id)?;
        let Some(sample) = samples.next_visual(input, &|description| {
            eligible
                .binary_search_by_key(&description.data, |entry| entry.0)
                .is_ok()
        })?
        else {
            return Ok(None);
        };
        let Ok(index) = eligible.binary_search_by_key(&sample.description.data, |entry| entry.0)
        else {
            return Ok(None);
        };
        let (_, dimensions) = eligible.swap_remove(index);
        let metadata = self.sample_metadata(input, movie, sample.location, count)?;
        Ok(Some(SelectedSample {
            dimensions,
            metadata,
            time: sample.decoded_at,
        }))
    }

    fn sample_metadata<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        movie: &mut MovieIndex,
        location: SampleLocation,
        classic_count: u64,
    ) -> Result<TrackMetadata, E> {
        let Some(init) = Groups::read(input, &self.table)? else {
            return Ok(TrackMetadata::None);
        };
        let fragment = match location {
            SampleLocation::Classic(_) => None,
            SampleLocation::Fragment { track, .. } => {
                let Some(groups) = Groups::read(input, &track)? else {
                    return Ok(TrackMetadata::None);
                };
                Some(groups)
            }
        };
        let selection = match location {
            SampleLocation::Classic(ordinal) => init.select(ordinal, classic_count, None),
            SampleLocation::Fragment { track, ordinal } => {
                let count = fragment_sample_count(input, &track)?;
                fragment
                    .as_ref()
                    .zip(count)
                    .and_then(|(group, count)| group.select(ordinal, count, Some(&init)))
            }
        };
        match selection {
            Some(Selection::Items(group)) => {
                // Only the selected description outlives the input box scan.
                Ok(group.copy_selected().map_or(TrackMetadata::None, |group| {
                    TrackMetadata::Sample {
                        track: self.track,
                        movie: movie.span,
                        group,
                    }
                }))
            }
            Some(Selection::Unspecified) => self.whole_metadata(input, movie),
            _ => Ok(TrackMetadata::None),
        }
    }

    fn whole_metadata<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        movie: &mut MovieIndex,
    ) -> Result<TrackMetadata, E> {
        let Some(meta) = self.metadata else {
            return Ok(TrackMetadata::None);
        };
        if movie.fragmented {
            let media = cached_media(input, &mut movie.media)?;
            if fragment_scope::Coverage::read(input, media, self.id)?
                != fragment_scope::Coverage::Absent
            {
                return Ok(TrackMetadata::None);
            }
        }
        Ok(TrackMetadata::Whole(meta))
    }

    fn select(self, sample: SelectedSample, movie: Option<MovieIndex>) -> VisualTrack {
        VisualTrack {
            timed: sample.time.zip(movie).map(|(anchor, movie)| TimedMetadata {
                id: self.id,
                movie,
                anchor,
            }),
            dimensions: self.geometry.dimensions.unwrap_or(sample.dimensions),
            orientation: self.geometry.orientation,
            metadata: sample.metadata,
        }
    }
}

impl VisualTrack {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        movie: &BoxSpan,
        codec: Codec,
    ) -> Result<Option<Self>, E> {
        let mut selected = None;
        let mut unindexed = Vec::new();
        let mut fragmented = false;
        let mut track_count = 0u8;
        let mut cursor = movie.data;
        while cursor < movie.end {
            let Some(child) = BoxSpan::read(input, cursor, movie.end)? else {
                return Ok(None);
            };
            cursor = child.end;
            match &child.kind {
                b"trak" => {
                    track_count = track_count.saturating_add(1);
                    if selected.is_none()
                        && let Some(choice) = Self::read_track(input, &child, codec)?
                    {
                        match choice {
                            TrackChoice::Classic(candidate, dimensions, grouped) => {
                                selected = Some((candidate, dimensions, grouped))
                            }
                            TrackChoice::Fragmented(candidate) => {
                                if unindexed.try_reserve(1).is_err() {
                                    return Ok(None);
                                }
                                unindexed.push(candidate);
                            }
                        }
                    }
                }
                b"mvex" => fragmented = true,
                _ => {}
            }
        }
        let mut index = MovieIndex {
            span: *movie,
            fragmented,
            fragments: if fragmented {
                MovieFragments::read(input, movie)?
            } else {
                MovieFragments::default()
            },
            media: None,
        };
        let mut track = None;
        for candidate in unindexed {
            if index.fragments.has_track(candidate.id)
                && let Some(sample) = candidate.sample(input, &mut index, codec)?
            {
                track = Some((candidate, sample));
                break;
            }
        }
        if track.is_none()
            && let Some((candidate, dimensions, grouped)) = selected
        {
            let sample = if grouped || track_count > 1 {
                candidate.sample(input, &mut index, codec)?
            } else {
                None
            };
            let sample = match sample {
                Some(sample) => sample,
                None => SelectedSample {
                    dimensions,
                    metadata: if grouped {
                        TrackMetadata::None
                    } else {
                        candidate.whole_metadata(input, &mut index)?
                    },
                    time: None,
                },
            };
            track = Some((candidate, sample));
        }
        Ok(track.map(|(candidate, sample)| {
            candidate.select(sample, (track_count > 1).then_some(index))
        }))
    }

    pub(super) fn visit_metadata<E>(
        self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        decompression: &mut Decompression,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let Some(mut timed) = self.timed else {
            return scope::visit(input, self.metadata, limit, decompression, None, emit);
        };
        let mut exif =
            tiff::ExifOverlay::new(input.prefix.len().saturating_add(input.unread_bytes()));
        scope::visit(
            input,
            self.metadata,
            limit,
            decompression,
            Some(&mut exif),
            emit,
        )?;
        timed::visit(input, &mut timed, limit, decompression, &mut exif, emit)?;
        exif.visit(limit, emit)
    }

    fn read_track<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        track: &BoxSpan,
        codec: Codec,
    ) -> Result<Option<TrackChoice>, E> {
        let (mut header, mut media, mut metadata, mut references) = (None, None, None, None);
        let mut cursor = track.data;
        while cursor < track.end {
            let Some(child) = BoxSpan::read(input, cursor, track.end)? else {
                return Ok(None);
            };
            cursor = child.end;
            let slot = match &child.kind {
                b"tkhd" => &mut header,
                b"mdia" => &mut media,
                b"meta" => &mut metadata,
                b"tref" => &mut references,
                _ => continue,
            };
            if slot.replace(child).is_some() {
                return Ok(None);
            }
        }
        if let Some(references) = references {
            let mut cursor = references.data;
            while cursor < references.end {
                let Some(reference) = BoxSpan::read(input, cursor, references.end)? else {
                    return Ok(None);
                };
                cursor = reference.end;
                if matches!(&reference.kind, b"auxl" | b"thmb") {
                    return Ok(None);
                }
            }
        }
        let (Some(header), Some(media)) = (header, media) else {
            return Ok(None);
        };
        if !matches!(header.len(), 84 | 96) {
            return Ok(None);
        }
        let Some(bytes) = read_body(input, &header)? else {
            return Ok(None);
        };
        let (Some(identity), Some(header)) =
            (TrackIdentity::parse(bytes), TrackGeometry::parse(bytes))
        else {
            return Ok(None);
        };
        let Some(samples) = VisualSamples::read(input, &media, codec)? else {
            return Ok(None);
        };
        let table = match &samples {
            VisualSamples::Classic { table, .. } | VisualSamples::Fragmented(table) => table,
        };
        let candidate = Candidate {
            id: identity.id,
            media,
            track: *track,
            table: *table,
            metadata,
            geometry: header,
        };
        Ok(Some(match samples {
            VisualSamples::Classic {
                dimensions,
                metadata_groups,
                ..
            } => TrackChoice::Classic(candidate, dimensions, metadata_groups),
            VisualSamples::Fragmented(_) => TrackChoice::Fragmented(candidate),
        }))
    }
}

struct TrackIdentity {
    id: NonZeroU32,
    alternate_group: u16,
}

impl TrackIdentity {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let (id, group) = match (bytes.first()?, bytes.len()) {
            (0, 84) => (12, 34),
            (1, 96) => (20, 46),
            _ => return None,
        };
        let id = NonZeroU32::new(u32::from_be_bytes(*bytes.get(id..)?.first_chunk()?))?;
        let alternate_group = u16::from_be_bytes(*bytes.get(group..)?.first_chunk()?);
        Some(Self {
            id,
            alternate_group,
        })
    }
}

struct TrackGeometry {
    dimensions: Option<Dimensions>,
    orientation: Option<u8>,
}

impl TrackGeometry {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let matrix_at = match (bytes.first()?, bytes.len()) {
            (0, 84) => 40,
            (1, 96) => 52,
            _ => return None,
        };
        let [a, b, u, c, d, v, _, _, w, width, height] = bytes.get(matrix_at..)?.as_chunks::<4>().0
        else {
            return None;
        };
        let orientation = match (
            u32::from_be_bytes(*u),
            u32::from_be_bytes(*v),
            u32::from_be_bytes(*w),
        ) {
            (0, 0, 0x4000_0000) => matrix_orientation([*a, *b, *c, *d].map(i32::from_be_bytes)),
            _ => None,
        };
        let dimensions = Dimensions::new(
            u32::from_be_bytes(*width) >> 16,
            u32::from_be_bytes(*height) >> 16,
        );
        Some(Self {
            dimensions,
            orientation,
        })
    }
}

fn matrix_orientation(matrix: [i32; 4]) -> Option<u8> {
    const ONE: i32 = 1 << 16;
    const NEGATIVE_ONE: i32 = -ONE;
    // The matrix maps the horizontal basis to (a, b) and the vertical basis to (c, d).
    Some(match matrix {
        [NEGATIVE_ONE, 0, 0, ONE] => 2,
        [NEGATIVE_ONE, 0, 0, NEGATIVE_ONE] => 3,
        [ONE, 0, 0, NEGATIVE_ONE] => 4,
        [0, ONE, ONE, 0] => 5,
        [0, ONE, NEGATIVE_ONE, 0] => 6,
        [0, NEGATIVE_ONE, NEGATIVE_ONE, 0] => 7,
        [0, NEGATIVE_ONE, ONE, 0] => 8,
        _ => return None,
    })
}

enum TrackChoice {
    Classic(Candidate, Dimensions, bool),
    Fragmented(Candidate),
}
