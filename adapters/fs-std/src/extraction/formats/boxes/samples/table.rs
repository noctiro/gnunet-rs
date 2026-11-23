//! Admission of sample tables before the positioned sample cursor can use them.

use super::{BoxSpan, Description, Input, SampleTable, TrackClock};

impl SampleTable {
    pub(in crate::extraction::formats) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        Self::read_with_clock(input, media, false)
    }

    pub(in crate::extraction::formats) fn read_timed<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        Self::read_with_clock(input, media, true)
    }

    fn read_with_clock<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &BoxSpan,
        time: bool,
    ) -> Result<Option<Self>, E> {
        let Some([Some(information)]) =
            children(input, media, |kind| (kind == b"minf").then_some(0))?
        else {
            return Ok(None);
        };
        let Some([Some(references), Some(table)]) =
            children(input, &information, |kind| match kind {
                b"dinf" => Some(0),
                b"stbl" => Some(1),
                _ => None,
            })?
        else {
            return Ok(None);
        };
        let Some([Some(dref)]) =
            children(input, &references, |kind| (kind == b"dref").then_some(0))?
        else {
            return Ok(None);
        };
        let Some([Some(stsd), Some(stsc), Some(sizes), Some(chunks), sync]) =
            children(input, &table, |kind| match kind {
                b"stsd" => Some(0),
                b"stsc" => Some(1),
                b"stsz" | b"stz2" => Some(2),
                b"stco" | b"co64" => Some(3),
                b"stss" => Some(4),
                _ => None,
            })?
        else {
            return Ok(None);
        };
        let Some(locals) = local_references(input, &dref)? else {
            return Ok(None);
        };
        let Some(descriptions) = descriptions(input, &stsd, &locals)? else {
            return Ok(None);
        };
        let width = if chunks.kind == *b"stco" { 4 } else { 8 };
        let Some(chunks) = Values::read(input, &chunks, width)? else {
            return Ok(None);
        };
        let Some(sizes) = Sizes::read(input, &sizes)? else {
            return Ok(None);
        };
        let sync = if let Some(span) = sync {
            let Some(sync) = Values::read(input, &span, 4)?.filter(|n| n.count <= sizes.count())
            else {
                return Ok(None);
            };
            Some(sync)
        } else {
            None
        };
        let Some(runs) = ChunkRun::read_all(
            input,
            &stsc,
            chunks.count,
            sizes.count(),
            descriptions.len(),
        )?
        else {
            return Ok(None);
        };
        let clock = if time {
            TrackClock::read(input, media, &table, u64::from(sizes.count()))?
        } else {
            None
        };
        Ok(Some(Self {
            descriptions,
            runs,
            chunks,
            sizes,
            sync,
            clock,
        }))
    }
}

// An unrelated fragment can establish the implicit data anchor without
// requiring its classic sample-run tables or reading its media payload.
pub(super) fn track_descriptions<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    track: &BoxSpan,
) -> Result<Option<Vec<Description>>, E> {
    let Some([Some(media)]) = children(input, track, |kind| (kind == b"mdia").then_some(0))? else {
        return Ok(None);
    };
    let Some([Some(information)]) = children(input, &media, |kind| (kind == b"minf").then_some(0))?
    else {
        return Ok(None);
    };
    let Some([Some(references), Some(table)]) = children(input, &information, |kind| match kind {
        b"dinf" => Some(0),
        b"stbl" => Some(1),
        _ => None,
    })?
    else {
        return Ok(None);
    };
    let Some([Some(dref)]) = children(input, &references, |kind| (kind == b"dref").then_some(0))?
    else {
        return Ok(None);
    };
    let Some([Some(stsd)]) = children(input, &table, |kind| (kind == b"stsd").then_some(0))? else {
        return Ok(None);
    };
    let Some(locals) = local_references(input, &dref)? else {
        return Ok(None);
    };
    descriptions(input, &stsd, &locals)
}

pub(super) fn children<const N: usize, E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    parent: &BoxSpan,
    index: impl Fn(&[u8; 4]) -> Option<usize>,
) -> Result<Option<[Option<BoxSpan>; N]>, E> {
    let mut children = [None; N];
    let mut at = parent.data;
    while at < parent.end {
        let Some(span) = BoxSpan::read(input, at, parent.end)? else {
            return Ok(None);
        };
        at = span.end;
        if let Some(index) = index(&span.kind)
            && children[index].replace(span).is_some()
        {
            return Ok(None);
        }
    }
    Ok(Some(children))
}

fn local_references<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
) -> Result<Option<Vec<bool>>, E> {
    let Some(count) = entry_count(input, span)? else {
        return Ok(None);
    };
    let mut locals = Vec::new();
    let mut at = span.data + 8;
    for _ in 0..count {
        let Some(entry) = BoxSpan::read(input, at, span.end)? else {
            return Ok(None);
        };
        at = entry.end;
        if entry.len() < 4 || locals.try_reserve(1).is_err() {
            return Ok(None);
        }
        let Some(flags) = input.range(entry.data, 4)? else {
            return Ok(None);
        };
        locals.push(entry.kind == *b"url " && entry.len() == 4 && flags == b"\0\0\0\x01");
    }
    Ok((at == span.end).then_some(locals))
}

fn descriptions<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
    locals: &[bool],
) -> Result<Option<Vec<Description>>, E> {
    let Some(count) = entry_count(input, span)? else {
        return Ok(None);
    };
    let mut entries = Vec::new();
    let mut at = span.data + 8;
    for _ in 0..count {
        let Some(entry) = BoxSpan::read(input, at, span.end)? else {
            return Ok(None);
        };
        at = entry.end;
        if entry.len() < 8 || entries.try_reserve(1).is_err() {
            return Ok(None);
        }
        let Some(&[0, 0, 0, 0, 0, 0, high, low]) = input.range(entry.data, 8)? else {
            return Ok(None);
        };
        let index = usize::from(u16::from_be_bytes([high, low]));
        let Some(&local) = index.checked_sub(1).and_then(|index| locals.get(index)) else {
            return Ok(None);
        };
        entries.push(Description { span: entry, local });
    }
    Ok((at == span.end).then_some(entries))
}

fn entry_count<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
) -> Result<Option<u32>, E> {
    if span.len() < 8 {
        return Ok(None);
    }
    let Some(&[0, 0, 0, 0, a, b, c, d]) = input.range(span.data, 8)? else {
        return Ok(None);
    };
    Ok(Some(u32::from_be_bytes([a, b, c, d])))
}

#[derive(Clone, Copy)]
pub(super) struct Values {
    start: u64,
    pub(super) count: u32,
    width: u8,
}

impl Values {
    const fn new(start: u64, count: u32, width: u8) -> Self {
        Self {
            start,
            count,
            width,
        }
    }

    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
        width: u8,
    ) -> Result<Option<Self>, E> {
        let Some(count) = entry_count(input, span)? else {
            return Ok(None);
        };
        Ok((span.len() == 8 + u64::from(width) * u64::from(count))
            .then(|| Self::new(span.data + 8, count, width)))
    }

    pub(super) fn get<E>(
        self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        index: u32,
    ) -> Result<Option<u64>, E> {
        if index >= self.count {
            return Ok(None);
        }
        let start = self.start + u64::from(index) * u64::from(self.width);
        let Some(bytes) = input.range(start, self.width.into())? else {
            return Ok(None);
        };
        Ok(Some(
            bytes
                .iter()
                .fold(0, |value, &byte| (value << 8) | u64::from(byte)),
        ))
    }

    pub(super) fn slice<'a, E>(
        self,
        input: &'a mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        first: u32,
        end: u32,
    ) -> Result<Option<&'a [u8]>, E> {
        if first > end || end > self.count {
            return Ok(None);
        }
        let width = u64::from(self.width);
        let Ok(length) = usize::try_from(u64::from(end - first) * width) else {
            return Ok(None);
        };
        input.range(self.start + u64::from(first) * width, length)
    }
}

pub(super) enum Sizes {
    Constant { count: u32, size: u32 },
    Table(Values),
    Nibbles { start: u64, count: u32 },
}

impl Sizes {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        if span.len() < 12 {
            return Ok(None);
        }
        let Some(&[0, 0, 0, 0, a, b, c, d, w, x, y, z]) = input.range(span.data, 12)? else {
            return Ok(None);
        };
        let count = u32::from_be_bytes([w, x, y, z]);
        let data_len = span.len() - 12;
        let start = span.data + 12;
        Ok(match span.kind {
            [b's', b't', b's', b'z'] => match u32::from_be_bytes([a, b, c, d]) {
                0 if data_len == 4 * u64::from(count) => {
                    Some(Self::Table(Values::new(start, count, 4)))
                }
                size if size != 0 && data_len == 0 => Some(Self::Constant { count, size }),
                _ => None,
            },
            _ if [a, b, c] == [0; 3] => match d {
                4 if data_len == u64::from(count.div_ceil(2)) => {
                    Some(Self::Nibbles { start, count })
                }
                8 | 16 if data_len == u64::from(d / 8) * u64::from(count) => {
                    Some(Self::Table(Values::new(start, count, d / 8)))
                }
                _ => None,
            },
            _ => None,
        })
    }

    pub(super) fn count(&self) -> u32 {
        match self {
            Self::Constant { count, .. } | Self::Nibbles { count, .. } => *count,
            Self::Table(values) => values.count,
        }
    }

    pub(super) fn get<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        index: u32,
    ) -> Result<Option<u64>, E> {
        match self {
            Self::Constant { size, count } => Ok((index < *count).then_some(u64::from(*size))),
            Self::Table(table) => table.get(input, index),
            Self::Nibbles { start, count } if index < *count => Ok(input
                .range(start + u64::from(index / 2), 1)?
                .and_then(|bytes| bytes.first().copied())
                .map(|byte| {
                    u64::from(if index.is_multiple_of(2) {
                        byte >> 4
                    } else {
                        byte & 0x0f
                    })
                })),
            Self::Nibbles { .. } => Ok(None),
        }
    }

    /// Returns the byte offset within a chunk and the selected sample size.
    pub(super) fn chunk_position<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        first: u32,
        ordinal: u32,
    ) -> Result<Option<(u64, u64)>, E> {
        if first > ordinal || ordinal >= self.count() {
            return Ok(None);
        }
        let end = ordinal + 1;
        match self {
            Self::Constant { size, .. } => {
                let size = u64::from(*size);
                Ok(Some((u64::from(ordinal - first) * size, size)))
            }
            Self::Table(table) => {
                let Some(bytes) = table.slice(input, first, end)? else {
                    return Ok(None);
                };
                let sizes = bytes.chunks_exact(usize::from(table.width)).map(|bytes| {
                    bytes
                        .iter()
                        .fold(0, |value, &byte| (value << 8) | u64::from(byte))
                });
                Ok(prefix_and_size(sizes))
            }
            Self::Nibbles { start, .. } => {
                let first_byte = first / 2;
                let Ok(length) = usize::try_from(end.div_ceil(2) - first_byte) else {
                    return Ok(None);
                };
                let Some(bytes) = input.range(start + u64::from(first_byte), length)? else {
                    return Ok(None);
                };
                let Ok(samples) = usize::try_from(end - first) else {
                    return Ok(None);
                };
                let sizes = bytes
                    .iter()
                    .flat_map(|&byte| [byte >> 4, byte & 0x0f])
                    .skip((first % 2) as usize)
                    .take(samples)
                    .map(u64::from);
                Ok(prefix_and_size(sizes))
            }
        }
    }
}

fn prefix_and_size(mut sizes: impl Iterator<Item = u64>) -> Option<(u64, u64)> {
    let mut size = sizes.next()?;
    let mut prefix = 0;
    for next in sizes {
        prefix += size;
        size = next;
    }
    Some((prefix, size))
}

pub(super) struct ChunkRun {
    pub(super) first_chunk: u32,
    pub(super) first_sample: u32,
    pub(super) samples: u32,
    pub(super) description: usize,
}

impl ChunkRun {
    fn read_all<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
        chunks: u32,
        samples: u32,
        descriptions: usize,
    ) -> Result<Option<Vec<Self>>, E> {
        let Some(count) = entry_count(input, span)? else {
            return Ok(None);
        };
        if count > chunks || span.len() != 8 + 12 * u64::from(count) {
            return Ok(None);
        }
        if count == 0 {
            return Ok((chunks == 0 && samples == 0).then(Vec::new));
        }
        let mut runs: Vec<Self> = Vec::new();
        let mut total = 0;
        let mut at = span.data + 8;
        for _ in 0..count {
            let Some(bytes) = input.range(at, 12)? else {
                return Ok(None);
            };
            at += 12;
            let ([first, length, reference], _) = bytes.as_chunks::<4>() else {
                return Ok(None);
            };
            let first = u32::from_be_bytes(*first);
            let length = u32::from_be_bytes(*length);
            let reference = u32::from_be_bytes(*reference) as usize;
            if first == 0
                || first > chunks
                || length == 0
                || reference == 0
                || reference > descriptions
            {
                return Ok(None);
            }
            let first_chunk = first - 1;
            if let Some(last) = runs.last() {
                if first_chunk <= last.first_chunk {
                    return Ok(None);
                }
                total += u64::from(first_chunk - last.first_chunk) * u64::from(last.samples);
            } else if first_chunk != 0 {
                return Ok(None);
            }
            let Ok(first_sample) = u32::try_from(total) else {
                return Ok(None);
            };
            if first_sample > samples || runs.try_reserve(1).is_err() {
                return Ok(None);
            }
            runs.push(Self {
                first_chunk,
                first_sample,
                samples: length,
                description: reference - 1,
            });
        }
        let Some(last) = runs.last() else {
            return Ok(None);
        };
        total += u64::from(chunks - last.first_chunk) * u64::from(last.samples);
        Ok((total == u64::from(samples)).then_some(runs))
    }
}
