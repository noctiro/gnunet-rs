//! Streaming file preparation and root-bound verification of every planned node.
use super::{Artifact, Error, Limits, Payload, Plan, Position, Put};
use crate::{BlockSink, BlockSource, Buffers, Control, Insert, Progress, ReadFile, Repository};
use gnunet_fs::{
    Content,
    content::{EncodedNode, Layout, NodeRef, TAG_BYTES},
};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Seek},
    mem::size_of,
    os::unix::fs::MetadataExt,
};
#[derive(Clone, Copy, Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    bytes: u64,
    modified: i64,
    modified_nanos: i64,
    changed: i64,
    changed_nanos: i64,
}
impl Stamp {
    fn file(file: &File) -> Result<Self, Error> {
        let m = file.metadata()?;
        if !m.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication source must be a regular file",
            )
            .into());
        }
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            modified: m.mtime(),
            modified_nanos: m.mtime_nsec(),
            changed: m.ctime(),
            changed_nanos: m.ctime_nsec(),
        })
    }
}
fn count(layout: Layout) -> Result<usize, Error> {
    let total = (0..layout.levels()).try_fold(0u64, |total, level| {
        total
            .checked_add(layout.node_count(level)?)
            .ok_or(gnunet_types::Error::Overflow)
    })?;
    usize::try_from(total).map_err(|_| Error::Limit)
}
fn preflight(layout: Layout, limits: Limits) -> Result<usize, Error> {
    let n = count(layout)?;
    if n > limits.max_puts
        || layout.size() > limits.file.max_file_bytes
        || layout.encoded_tree_bytes() > limits.file.max_encoded_bytes
        || layout.encoded_tree_bytes() > limits.max_stored_bytes
        || size_of::<Plan>()
            .checked_add(n.checked_mul(size_of::<Put>()).ok_or(Error::Limit)?)
            .is_none_or(|n| n > limits.max_plan_bytes)
    {
        return Err(Error::Limit);
    }
    for level in 0..layout.levels() {
        let bytes = layout.node(level, 0)?.plaintext_bytes() + TAG_BYTES;
        if bytes > limits.max_payload_bytes
            || bytes > gnunet_wire::official::datastore::MAX_VALUE_BYTES
        {
            return Err(Error::Limit);
        }
    }
    Ok(n)
}
/// Check theoretical file geometry and local budgets before creating a task
/// directory or reading source bytes. This is not processed or verified credit.
pub fn file_budget(size: u64, limits: Limits) -> Result<(usize, u128), Error> {
    let layout = Layout::new(size);
    preflight(layout, limits).map(|count| (count, layout.encoded_tree_bytes()))
}
pub(super) struct Sink<'a> {
    pub(super) repo: &'a mut Repository,
    pub(super) rows: Vec<Put>,
}
impl BlockSink for Sink<'_> {
    fn insert_block(&mut self, encoded: EncodedNode<'_>) -> crate::Result<Insert> {
        let node = encoded.node();
        let block = encoded.block();
        let (hash, insert) = self.repo.insert_payload(block.bytes())?;
        if hash != block.key().query {
            return Err(crate::Error::Corrupt);
        }
        self.rows.push(Put {
            kind: if node.level() == 0 { 1 } else { 2 },
            key: block.key().query,
            payload: Payload {
                hash,
                bytes: block.bytes().len(),
            },
            position: Some(Position {
                level: node.level(),
                index: node.ordinal(),
            }),
        });
        Ok(insert)
    }
}
/// Prepare every real full D/I block without collecting the file plaintext or
/// ciphertext. Original source FD stamps and exact EOF must remain consistent.
/// Native publication is not performed; useful immutable objects may survive failure.
pub fn prepare_file(
    repo: &mut Repository,
    input: &mut File,
    buffers: &mut Buffers,
    limits: Limits,
    control: impl FnMut(Progress) -> Control,
) -> Result<Plan, Error> {
    let original = Stamp::file(input)?;
    let nodes = preflight(Layout::new(original.bytes), limits)?;
    input.rewind()?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(nodes).map_err(|_| Error::Limit)?;
    let mut sink = Sink { repo, rows };
    let published = buffers.publish(input, original.bytes, &mut sink, limits.file, control)?;
    if Stamp::file(input)? != original {
        return Err(crate::Error::SourceChanged.into());
    }
    let plan = Plan {
        artifact: Artifact::File(published.content),
        puts: sink.rows,
    };
    plan.validate(limits)?;
    Ok(plan)
}
fn positions(
    puts: &[Put],
    content: Content,
    limits: Limits,
) -> Result<HashMap<Position, usize>, Error> {
    let layout = Layout::new(content.size);
    let nodes = preflight(layout, limits)?;
    if puts.len() != nodes {
        return Err(Error::Binding);
    }
    let mut map = HashMap::new();
    map.try_reserve(nodes).map_err(|_| Error::Limit)?;
    for (index, put) in puts.iter().enumerate() {
        let position = put.position.ok_or(Error::Binding)?;
        let node = layout.node(position.level, position.index)?;
        if put.kind != (if position.level == 0 { 1 } else { 2 })
            || put.payload.bytes != node.plaintext_bytes() + TAG_BYTES
            || put.payload.hash != put.key
            || map.insert(position, index).is_some()
        {
            return Err(Error::Binding);
        }
        // Parents are submitted only after every actual child position. A
        // declared geometry alone cannot add an unrelated final root.
        for child in 0..node.child_count() {
            let child = node.child(child)?;
            let key = Position {
                level: child.level(),
                index: child.ordinal(),
            };
            if !map.contains_key(&key) {
                return Err(Error::Binding);
            }
        }
    }
    let root = layout.root();
    let last = puts.last().ok_or(Error::Binding)?;
    if last.position
        != Some(Position {
            level: root.level(),
            index: 0,
        })
        || last.key != content.query
    {
        return Err(Error::Binding);
    }
    Ok(map)
}
pub(super) fn validate(plan: &Plan, content: Content, limits: Limits) -> Result<(), Error> {
    validate_puts(&plan.puts, content, limits)
}
struct Source<'a> {
    repo: &'a mut Repository,
    puts: &'a [Put],
    map: HashMap<Position, usize>,
    seen: Vec<bool>,
    failure: Option<Error>,
}
impl BlockSource for Source<'_> {
    fn read_block(&mut self, request: NodeRef, output: &mut [u8]) -> crate::Result<usize> {
        let position = Position {
            level: request.node().level(),
            index: request.node().ordinal(),
        };
        let Some(&index) = self.map.get(&position) else {
            self.failure = Some(Error::Binding);
            return Err(crate::Error::Corrupt);
        };
        let put = self.puts.get(index).ok_or(crate::Error::Corrupt)?;
        if put.key != request.key().query
            || put.payload.hash != put.key
            || put.payload.bytes != request.node().plaintext_bytes() + TAG_BYTES
        {
            self.failure = Some(Error::Binding);
            return Err(crate::Error::Corrupt);
        }
        let length = self.repo.read_payload(&put.payload.hash, output)?;
        if length != put.payload.bytes {
            self.failure = Some(Error::Binding);
            return Err(crate::Error::Corrupt);
        }
        *self.seen.get_mut(index).ok_or(crate::Error::Corrupt)? = true;
        Ok(length)
    }
}
pub(super) fn verify(
    plan: &Plan,
    content: Content,
    repo: &mut Repository,
    buffers: &mut Buffers,
    limits: Limits,
    control: &mut impl FnMut(Progress) -> Control,
) -> Result<ReadFile, Error> {
    verify_puts(&plan.puts, content, repo, buffers, limits, control)
}
pub(super) fn validate_puts(puts: &[Put], content: Content, limits: Limits) -> Result<(), Error> {
    positions(puts, content, limits).map(|_| ())
}
pub(super) fn verify_puts(
    puts: &[Put],
    content: Content,
    repo: &mut Repository,
    buffers: &mut Buffers,
    limits: Limits,
    control: &mut impl FnMut(Progress) -> Control,
) -> Result<ReadFile, Error> {
    let map = positions(puts, content, limits)?;
    let mut seen = Vec::new();
    seen.try_reserve_exact(puts.len())
        .map_err(|_| Error::Limit)?;
    seen.resize(puts.len(), false);
    let mut source = Source {
        repo,
        puts,
        map,
        seen,
        failure: None,
    };
    let read = buffers.copy_to(&mut source, content, &mut io::sink(), limits.file, control);
    if let Some(error) = source.failure {
        return Err(error);
    }
    let read = read?;
    if source.seen.iter().any(|seen| !*seen) {
        return Err(Error::Binding);
    }
    Ok(read)
}
