//! Actual authenticated blocks from one bounded optional inline hint.
use crate::{BlockSink, BlockSource, Buffers, Control, Error, Insert, Result};
use gnunet_fs::{
    Content,
    content::{EncodedNode, Layout, NodeRef},
};
use std::io;
/// One bounded optional hint, encoded into actual blocks before a FileReader
/// can consume it. A wrong claimed CHK is ignored rather than published as data.
#[derive(Default)]
pub(crate) struct InlineBlocks(Vec<([u8; 64], Vec<u8>)>);
impl BlockSink for InlineBlocks {
    fn insert_block(&mut self, node: EncodedNode<'_>) -> Result<Insert> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(node.block().bytes().len())
            .map_err(|_| Error::Limit)?;
        bytes.extend_from_slice(node.block().bytes());
        self.0.try_reserve(1).map_err(|_| Error::Limit)?;
        self.0.push((node.block().key().query, bytes));
        Ok(Insert::Created)
    }
}
impl BlockSource for InlineBlocks {
    fn read_block(&mut self, node: NodeRef, out: &mut [u8]) -> Result<usize> {
        let (_, bytes) = self
            .0
            .iter()
            .find(|(key, _)| key == &node.key().query)
            .ok_or(Error::Corrupt)?;
        out.get_mut(..bytes.len())
            .ok_or(Error::Limit)?
            .copy_from_slice(bytes);
        Ok(bytes.len())
    }
}
pub(crate) fn inline_blocks(
    buffers: &mut Buffers,
    content: Content,
    bytes: Option<Vec<u8>>,
    limits: crate::Limits,
    mut control: impl FnMut(crate::Progress) -> Control,
) -> Result<Option<InlineBlocks>> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    if bytes.len() as u128 != u128::from(content.size)
        || Layout::new(content.size).encoded_tree_bytes() > limits.max_encoded_bytes
    {
        return Ok(None);
    }
    let mut blocks = InlineBlocks::default();
    let encoded = buffers.publish(
        &mut io::Cursor::new(bytes),
        content.size,
        &mut blocks,
        limits,
        &mut control,
    )?;
    Ok((encoded.content == content).then_some(blocks))
}
