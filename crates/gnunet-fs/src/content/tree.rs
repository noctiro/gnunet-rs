//! Plaintext encoding over the separate bounded reference frontier.
use super::{
    BlockKey, Content, Encoded, Layout, Node, ReferenceFrontier, encode_data, encode_index,
};
use gnunet_types::Error;

/// One actually encoded block and its canonical file position. Its bytes borrow
/// the caller's output and must be retained externally if later needed.
#[derive(Clone, Copy, Debug)]
pub struct EncodedNode<'a> {
    node: Node,
    block: Encoded<'a>,
}
impl<'a> EncodedNode<'a> {
    /// Canonical level, ordinal and covered file range.
    #[must_use]
    pub const fn node(self) -> Node {
        self.node
    }
    /// Complete official encrypted block artifact.
    #[must_use]
    pub const fn block(self) -> Encoded<'a> {
        self.block
    }
}

/// File encoder over every u64 length. Only actually sealed data/index keys can
/// enter its private frontier. It emits one block per successful operation;
/// capacity refusal leaves progress unchanged and admits an exact retry.
pub struct FileEncoder<'a> {
    frontier: ReferenceFrontier<'a>,
}
impl<'a> FileEncoder<'a> {
    /// Borrow Layout::required_keys slots; no allocator or host is selected.
    pub fn new(size: u64, keys: &'a mut [BlockKey]) -> Result<Self, Error> {
        ReferenceFrontier::new(size, keys).map(|frontier| Self { frontier })
    }
    /// Complete canonical file geometry.
    #[must_use]
    pub const fn layout(&self) -> Layout {
        self.frontier.layout()
    }
    /// Next data or index descriptor, or None after the root was sealed.
    #[must_use]
    pub fn next(&self) -> Option<Node> {
        self.frontier.next()
    }
    /// Completed root CHK and exact file size; no durable storage or availability
    /// claim is implied by finishing these local artifacts.
    #[must_use]
    pub fn content(&self) -> Option<Content> {
        self.frontier.content()
    }
    /// Seal exactly the next data leaf. A pending index returns WouldBlock.
    pub fn push_data<'b>(
        &mut self,
        plaintext: &[u8],
        output: &'b mut [u8],
    ) -> Result<EncodedNode<'b>, Error> {
        let node = self.next().ok_or(Error::Closed)?;
        if node.level() != 0 {
            return Err(Error::WouldBlock);
        }
        if plaintext.len() != node.plaintext_bytes() {
            return Err(Error::InvalidInput);
        }
        let block = encode_data(plaintext, output)?;
        self.frontier.accept_reference(node, block.key())?;
        Ok(EncodedNode { node, block })
    }
    /// Seal the pending index from its exact ordered references. More data is
    /// requested with WouldBlock; insufficient scratch/output changes no progress.
    pub fn emit_index<'b>(
        &mut self,
        scratch: &mut [u8],
        output: &'b mut [u8],
    ) -> Result<EncodedNode<'b>, Error> {
        let pending = self
            .frontier
            .pending_index()
            .ok_or(if self.content().is_some() {
                Error::Closed
            } else {
                Error::WouldBlock
            })?;
        let node = pending.node;
        let block = encode_index(pending.children, scratch, output)?;
        self.frontier.record_index(block.key())?;
        Ok(EncodedNode { node, block })
    }
}
