//! Positioned lookup of classic BMFF samples and their preceding sync samples.

use super::table::ChunkRun;
use super::{Input, MediaData, SampleExtent, SampleLocation, SampleSpan, SampleTable};

pub(super) struct ClassicSeek {
    pub(super) sample: SampleSpan,
    pub(super) prior_sync: Option<SampleExtent>,
}

pub(super) enum ClassicSync {
    Found(SampleExtent),
    Absent,
    Unavailable,
}

enum SyncSamples<'a> {
    Every,
    Listed(&'a [[u8; 4]]),
}

impl SampleTable {
    pub(super) fn seek_classic<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        ordinal: u32,
        sync_kind: [u8; 4],
    ) -> Result<Option<ClassicSeek>, E> {
        let Some(run) = self.classic_run(ordinal) else {
            return Ok(None);
        };
        let Some(sync) = self.classic_sync_samples(input)? else {
            return Ok(None);
        };
        let is_sync = sync.contains(ordinal + 1);
        let prior = if !is_sync && self.descriptions[run.description].span.kind == sync_kind {
            self.prior_sync_sample(&sync, ordinal, sync_kind)
        } else {
            None
        };
        let Some(sample) = self.classic_sample_at(input, media, run, ordinal, is_sync)? else {
            return Ok(None);
        };
        let prior_sync = if let Some((run, ordinal)) = prior {
            let Some(span) = self.classic_sample_at(input, media, run, ordinal, true)? else {
                return Ok(None);
            };
            Some(span.extent())
        } else {
            None
        };
        Ok(Some(ClassicSeek { sample, prior_sync }))
    }

    pub(super) fn sync_before_classic<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        exclusive_ordinal: u32,
        sync_kind: [u8; 4],
    ) -> Result<ClassicSync, E> {
        if exclusive_ordinal > self.sizes.count() {
            return Ok(ClassicSync::Unavailable);
        }
        if exclusive_ordinal == 0 {
            return Ok(ClassicSync::Absent);
        }
        let Some(sync) = self.classic_sync_samples(input)? else {
            return Ok(ClassicSync::Unavailable);
        };
        let Some((run, ordinal)) = self.prior_sync_sample(&sync, exclusive_ordinal, sync_kind)
        else {
            return Ok(ClassicSync::Absent);
        };
        Ok(self
            .classic_sample_at(input, media, run, ordinal, true)?
            .map_or(ClassicSync::Unavailable, |span| {
                ClassicSync::Found(span.extent())
            }))
    }

    fn classic_run(&self, ordinal: u32) -> Option<&ChunkRun> {
        if ordinal >= self.sizes.count() {
            return None;
        }
        let index = self.runs.partition_point(|run| run.first_sample <= ordinal);
        self.runs.get(index.checked_sub(1)?)
    }

    fn classic_sample_at<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &MediaData,
        run: &ChunkRun,
        ordinal: u32,
        sync: bool,
    ) -> Result<Option<SampleSpan>, E> {
        let Some(description) = self
            .descriptions
            .get(run.description)
            .filter(|entry| entry.local)
            .map(|entry| entry.span)
        else {
            return Ok(None);
        };
        let relative = ordinal - run.first_sample;
        let chunk = run.first_chunk + relative / run.samples;
        let first = ordinal - relative % run.samples;
        let Some(chunk_start) = self.chunks.get(input, chunk)? else {
            return Ok(None);
        };
        let Some((offset, length)) = self.sizes.chunk_position(input, first, ordinal)? else {
            return Ok(None);
        };
        let Some(start) = chunk_start.checked_add(offset) else {
            return Ok(None);
        };
        if !start
            .checked_add(length)
            .is_some_and(|end| media.contains(chunk_start, end))
        {
            return Ok(None);
        }
        let ordinal = u64::from(ordinal);
        Ok(Some(SampleSpan {
            description,
            sync,
            start,
            length,
            location: SampleLocation::Classic(ordinal),
            decoded_at: self.clock.as_ref().and_then(|clock| clock.classic(ordinal)),
        }))
    }

    fn classic_sync_samples<'a, E>(
        &self,
        input: &'a mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    ) -> Result<Option<SyncSamples<'a>>, E> {
        let Some(table) = self.sync else {
            return Ok(Some(SyncSamples::Every));
        };
        let Some(bytes) = table.slice(input, 0, table.count)? else {
            return Ok(None);
        };
        let (entries, padding) = bytes.as_chunks::<4>();
        if !padding.is_empty()
            || entries.first() == Some(&[0; 4])
            || entries
                .last()
                .is_some_and(|&entry| u32::from_be_bytes(entry) > self.sizes.count())
            || entries.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Ok(None);
        }
        Ok(Some(SyncSamples::Listed(entries)))
    }

    fn prior_sync_sample(
        &self,
        sync: &SyncSamples<'_>,
        exclusive_ordinal: u32,
        kind: [u8; 4],
    ) -> Option<(&ChunkRun, u32)> {
        let until = self
            .runs
            .partition_point(|run| run.first_sample < exclusive_ordinal);
        let mut end = exclusive_ordinal;
        for run in self.runs[..until].iter().rev() {
            if self.descriptions[run.description].span.kind == kind
                && let Some(number) = sync.last_through(end)
                && number > run.first_sample
            {
                return Some((run, number - 1));
            }
            end = run.first_sample;
        }
        None
    }
}

impl SyncSamples<'_> {
    fn contains(&self, number: u32) -> bool {
        match self {
            Self::Every => true,
            Self::Listed(entries) => entries.binary_search(&number.to_be_bytes()).is_ok(),
        }
    }

    fn last_through(&self, number: u32) -> Option<u32> {
        match self {
            Self::Every => Some(number),
            Self::Listed(entries) => {
                let upper = number.to_be_bytes();
                let index = entries.partition_point(|entry| *entry <= upper);
                entries
                    .get(index.checked_sub(1)?)
                    .copied()
                    .map(u32::from_be_bytes)
            }
        }
    }
}
