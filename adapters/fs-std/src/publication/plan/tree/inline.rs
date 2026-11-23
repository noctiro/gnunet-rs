//! Optional, authenticated FULL_DATA for one original directory member.
use super::Error;
use crate::Buffers;
use gnunet_fs::{
    Content, Uri,
    content::{BLOCK_BYTES, Layout},
    directory as dir, metadata as md,
};
use std::{
    fs::File,
    io::{Read, Seek},
};

const MAX_INLINE_BYTES: usize = 65536;

pub(super) enum Source<'a, 'p> {
    File(&'a mut File),
    Directory(&'a dir::BuildPlan<'p>),
}

#[derive(Default)]
pub(super) struct Scratch {
    data: Vec<u8>,
    order: Vec<usize>,
}

impl Scratch {
    pub(super) fn metadata(
        &mut self,
        source: Source<'_, '_>,
        content: Content,
        uri: Uri<'_>,
        base: &[u8],
        output_limit: usize,
        buffers: &mut Buffers,
    ) -> Result<Option<Vec<u8>>, Error> {
        let Ok(size @ 1..=MAX_INLINE_BYTES) = usize::try_from(content.size) else {
            return Ok(None);
        };
        let prefix = uri.encoded_len()?.checked_add(5).ok_or(Error::Limit)?;
        let old_extent = prefix.checked_add(base.len()).ok_or(Error::Limit)?;
        let max_wire = old_extent
            .checked_next_multiple_of(BLOCK_BYTES)
            .ok_or(Error::Limit)?
            .checked_sub(prefix)
            .ok_or(Error::Limit)?
            .min(output_limit);
        let minimum = base
            .len()
            .checked_add(size)
            .and_then(|n| n.checked_add(md::ENTRY_BYTES))
            .ok_or(Error::Limit)?;
        if minimum > max_wire {
            return Ok(None);
        }

        let limits = md::Limits {
            max_coded_bytes: max_wire,
            max_plain_bytes: max_wire - md::HEADER_BYTES,
            max_entries: max_wire / md::ENTRY_BYTES,
        };
        let md::Decoded::Present(decoded) =
            md::decode_uncompressed(base, limits, md::Mode::Strict)?
        else {
            return Err(Error::Binding);
        };
        if dir::hints(decoded.items()).next().is_some() {
            return Ok(None);
        }
        crate::resize(&mut self.data, size, 0)?;
        match source {
            Source::File(file) => {
                // This owned descriptor has completed encoding. A failed
                // optional read leaves the already prepared CHK available.
                if file
                    .rewind()
                    .and_then(|()| file.read_exact(&mut self.data))
                    .is_err()
                {
                    return Ok(None);
                }
            }
            Source::Directory(plan) => {
                if plan.write(&mut self.data).map_err(crate::Error::from)? != size {
                    return Err(Error::Binding);
                }
            }
        }
        let layout = Layout::new(content.size);
        crate::resize(
            &mut buffers.keys,
            layout.required_keys(),
            Default::default(),
        )?;
        let match_result = dir::verify_inline(
            dir::InlineHint {
                index: 0,
                item: md::Item {
                    kind: 174,
                    format: md::Format::Binary,
                    data: &self.data,
                    plugin: None,
                    mime: None,
                },
            },
            uri,
            dir::InlineBuffers {
                keys: &mut buffers.keys,
                index: &mut buffers.index,
                encoded: &mut buffers.encoded,
            },
            layout.encoded_tree_bytes(),
        );
        let verified = match match_result {
            Ok(verified) => verified,
            Err(dir::Error::Authentication) => return Ok(None),
            Err(error) => return Err(crate::Error::from(error).into()),
        };
        let item = verified.item();
        let wire_bytes = minimum
            .checked_add(item.plugin.map_or(0, <[u8]>::len))
            .ok_or(Error::Limit)?;
        if wire_bytes > max_wire {
            return Ok(None);
        }
        let mut items = Vec::new();
        items
            .try_reserve_exact(decoded.accepted_entries() + 1)
            .map_err(|_| Error::Limit)?;
        items.extend(decoded.items());
        items.push(item);
        crate::resize(&mut self.order, items.len(), 0)?;
        crate::resize(
            &mut buffers.metadata_plain,
            wire_bytes - md::HEADER_BYTES,
            0,
        )?;
        let plan = md::plan_uncompressed(
            &items,
            &mut self.order,
            &mut buffers.metadata_plain,
            limits,
            md::Options {
                max_output_bytes: max_wire,
                ..Default::default()
            },
        )?;
        let size = plan.report().wire_bytes;
        if !dir::automatic_inline_fits(uri, verified, base.len(), size)
            .map_err(crate::Error::from)?
        {
            return Ok(None);
        }
        let mut metadata = Vec::new();
        crate::resize(&mut metadata, size, 0)?;
        plan.write(&mut metadata)?;
        Ok(Some(metadata))
    }
}
