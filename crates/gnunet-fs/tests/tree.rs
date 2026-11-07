//! General geometry, local encoding and authenticated traversal. Synthetic key
//! cases validate geometry only; they do not represent actual enormous files.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare geometry and artifact ownership boundaries"
)]
use gnunet_fs::{
    Content, Limits, Uri,
    content::{
        self, BLOCK_BYTES, BlockKey, CHK_BYTES, FileEncoder, Layout, MAX_FRONTIER_KEYS,
        MAX_TREE_LEVELS, Node, NodeRef, RangeTraversal, ReferenceFrontier, TAG_BYTES,
    },
};
use gnunet_types::Error;
use std::ops::Range;

fn fake(n: u8) -> BlockKey {
    BlockKey {
        key: [n; 64],
        query: [n.wrapping_add(7); 64],
    }
}
fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i % 251) as u8).collect()
}
struct Stored {
    node: Node,
    key: BlockKey,
    bytes: Vec<u8>,
}
fn encode_file(input: &[u8]) -> Result<(Content, Vec<Stored>), Error> {
    let layout = Layout::new(input.len() as u64);
    let mut keys = vec![BlockKey::default(); layout.required_keys()];
    let mut encoder = FileEncoder::new(layout.size(), &mut keys)?;
    let mut scratch = vec![0; BLOCK_BYTES];
    let mut output = vec![0; BLOCK_BYTES + TAG_BYTES];
    let mut stored = Vec::new();
    while let Some(node) = encoder.next() {
        let produced = if node.level() == 0 {
            let range = node.range();
            encoder.push_data(
                &input[range.start as usize..range.end as usize],
                &mut output,
            )?
        } else {
            encoder.emit_index(&mut scratch, &mut output)?
        };
        assert_eq!(produced.node(), node);
        stored.push(Stored {
            node,
            key: produced.block().key(),
            bytes: produced.block().bytes().to_vec(),
        });
    }
    Ok((encoder.content().ok_or(Error::NotReady)?, stored))
}
fn stored(nodes: &[Stored], reference: NodeRef) -> Result<&[u8], Error> {
    nodes
        .iter()
        .find(|s| s.node == reference.node() && s.key == reference.key())
        .map(|s| s.bytes.as_slice())
        .ok_or(Error::NotFound)
}
fn walk(
    content: Content,
    nodes: &[Stored],
    range: Range<u64>,
) -> Result<(Vec<u8>, Vec<Node>), Error> {
    let layout = Layout::new(content.size);
    let mut keys = vec![BlockKey::default(); layout.required_keys()];
    let mut traversal = RangeTraversal::new(content, range.clone(), &mut keys)?;
    let mut scratch = vec![0; BLOCK_BYTES];
    let mut bytes = Vec::new();
    let mut requested = Vec::new();
    let mut position = range.start;
    while let Some(reference) = traversal.next() {
        requested.push(reference.node());
        let opened = reference.open(stored(nodes, reference)?, &mut scratch)?;
        if let Some(selected) = traversal.accept(opened)? {
            assert_eq!(selected.range.start, position);
            position = selected.range.end;
            bytes.extend_from_slice(selected.bytes);
        }
    }
    assert_eq!(position, range.end);
    Ok((bytes, requested))
}

#[test]
fn all_u64_geometry_levels_and_wide_endpoints_are_explicit() -> Result<(), Error> {
    assert_eq!(MAX_TREE_LEVELS, 8);
    for level in 0..7 {
        let size = 1_u64 << (15 + 8 * level);
        assert_eq!(Layout::new(size - 1).root_level(), level);
        assert_eq!(Layout::new(size).root_level(), level);
        assert_eq!(Layout::new(size + 1).root_level(), level + 1);
        let tail = Layout::new(size + 1).root().child(1)?;
        assert_eq!(tail.range(), size..size + 1);
        assert_eq!(tail.level(), level);
    }
    let empty = Layout::new(0);
    assert_eq!(empty.leaf_count(), 1);
    assert_eq!(empty.root().range(), 0..0);
    assert_eq!(empty.root().plaintext_bytes(), 0);
    assert_eq!(empty.required_keys(), 0);
    assert_eq!(empty.encoded_tree_bytes(), 16);
    let max = Layout::new(u64::MAX);
    assert_eq!(max.levels(), 8);
    assert_eq!(max.leaf_count(), 562_949_953_421_312);
    assert_eq!(max.root().span(), 1_u128 << 71);
    assert_eq!(max.root().range(), 0..u64::MAX);
    assert_eq!(max.root().child_count(), 2);
    assert_eq!(max.root().plaintext_bytes(), 256);
    assert_eq!(max.required_keys(), MAX_FRONTIER_KEYS);
    assert_eq!(MAX_FRONTIER_KEYS * CHK_BYTES, 196_864);
    assert!(max.encoded_tree_bytes() > u128::from(u64::MAX));
    let last = max.leaf(max.leaf_count() - 1)?;
    assert_eq!(last.range(), (u64::MAX - 32767)..u64::MAX);
    assert_eq!(last.plaintext_bytes(), 32767);
    assert_eq!(max.node(7, u64::MAX), Err(Error::InvalidInput));
    assert_eq!(max.node(255, u64::MAX), Err(Error::InvalidInput));
    assert_eq!(max.node_count(8), Err(Error::InvalidInput));
    assert_eq!(last.child(0), Err(Error::InvalidInput));
    let mut node = max.root();
    for (level, index) in (0..7).rev().zip([1, 255, 255, 255, 255, 255, 255]) {
        node = node.child(index)?;
        assert_eq!(node.level(), level);
    }
    assert_eq!(node, last);
    for (size, leaves, keys, last_bytes) in [
        (0, 1, 0, 0),
        (1, 1, 0, 1),
        (32768, 1, 0, 32768),
        (32769, 2, 2, 1),
        (8 * 1024 * 1024 - 1, 256, 256, 32767),
        (8 * 1024 * 1024, 256, 256, 32768),
    ] {
        let layout = Layout::new(size);
        assert_eq!(layout.size(), size);
        assert_eq!(layout.leaf_count(), leaves);
        assert_eq!(layout.required_keys(), keys);
        assert_eq!(layout.leaf(0)?.range().start, 0);
        let range = layout.leaf(leaves - 1)?.range();
        assert_eq!(range.end, size);
        assert_eq!(range.end - range.start, last_bytes);
        assert_eq!(layout.leaf(leaves), Err(Error::InvalidInput));
    }
    Ok(())
}

#[test]
fn sampled_nodes_partition_their_ranges_at_every_u64_boundary() -> Result<(), Error> {
    let mut sizes = vec![0, 1, u64::MAX - 1, u64::MAX];
    for shift in (15..=63).step_by(8) {
        let size = 1_u64 << shift;
        sizes.extend([size - 1, size, size + 1]);
    }
    for size in sizes {
        let layout = Layout::new(size);
        for level in 0..=layout.root_level() {
            let count = layout.node_count(level)?;
            assert_eq!(layout.node(level, count), Err(Error::InvalidInput));
            for ordinal in [0, count / 2, count - 1] {
                let node = layout.node(level, ordinal)?;
                let range = node.range();
                assert!(range.start <= range.end && range.end <= size);
                assert!(node.plaintext_bytes() <= BLOCK_BYTES);
                if level == 0 {
                    assert_eq!(node.plaintext_bytes() as u64, range.end - range.start);
                } else {
                    assert!((1..=256).contains(&node.child_count()));
                    let mut cursor = range.start;
                    let mut leaves = 0;
                    for index in 0..node.child_count() {
                        let child = node.child(index)?;
                        assert_eq!(child.parent(), Some(node));
                        assert_eq!(child.range().start, cursor);
                        cursor = child.range().end;
                        leaves += child.leaf_count();
                    }
                    assert_eq!(cursor, range.end);
                    assert_eq!(leaves, node.leaf_count());
                    assert_eq!(node.child(node.child_count()), Err(Error::InvalidInput));
                }
            }
        }
        assert!(layout.required_keys() <= MAX_FRONTIER_KEYS);
    }
    Ok(())
}

#[test]
fn synthetic_frontier_keeps_every_tail_level_without_claiming_real_file_bytes() -> Result<(), Error>
{
    // Only references are supplied here: no large file, hashes or C oracle.
    for root_level in 1..8 {
        let boundary = 1_u64 << (15 + 8 * (root_level - 1));
        let layout = Layout::new(boundary + 1);
        let sentinel = fake(91);
        let mut slots = vec![sentinel; layout.required_keys() + 1];
        let mut frontier = ReferenceFrontier::new(layout.size(), &mut slots)?;
        let left = layout.root().child(0)?;
        frontier.accept_reference(left, fake(1))?;
        let progress = frontier.next_leaf();
        assert_eq!(
            frontier.accept_reference(left, fake(2)),
            Err(Error::InvalidInput)
        );
        assert_eq!(frontier.next_leaf(), progress);
        let last = layout.leaf(layout.leaf_count() - 1)?;
        frontier.accept_reference(last, fake(3))?;
        assert_eq!(frontier.next_leaf(), layout.leaf_count());
        for level in 1..=root_level {
            let pending = frontier.pending_index().ok_or(Error::NotReady)?;
            assert_eq!(pending.node.level(), level);
            assert_eq!(
                pending.children.len(),
                if level == root_level { 2 } else { 1 }
            );
            assert_eq!(
                frontier.accept_reference(last, fake(4)),
                Err(Error::WouldBlock)
            );
            frontier.record_index(fake(level + 10))?;
            assert_eq!(frontier.next_leaf(), layout.leaf_count());
        }
        assert!(frontier.next().is_none());
        assert_eq!(
            frontier.content().ok_or(Error::NotReady)?.size,
            layout.size()
        );
        assert_eq!(frontier.record_index(fake(99)), Err(Error::Closed));
        assert_eq!(slots[layout.required_keys()], sentinel);
    }
    let max = Layout::new(u64::MAX);
    let mut slots = vec![fake(0); max.required_keys()];
    let mut frontier = ReferenceFrontier::new(u64::MAX, &mut slots)?;
    frontier.accept_reference(max.root().child(0)?, fake(1))?;
    frontier.accept_reference(max.root().child(1)?, fake(2))?;
    assert_eq!(frontier.next_leaf(), 1_u64 << 49);
    assert_eq!(
        frontier.pending_index().ok_or(Error::NotReady)?.children,
        &[fake(1), fake(2)]
    );
    frontier.record_index(fake(3))?;
    assert_eq!(frontier.content(), Some(fake(3).content(u64::MAX)));
    Ok(())
}

#[test]
fn synthetic_full256_carry_and_reference_admission_are_transactional() -> Result<(), Error> {
    let layout = Layout::new(8 * 1024 * 1024 + 1);
    let mut short = vec![fake(9); layout.required_keys() - 1];
    assert!(matches!(
        ReferenceFrontier::new(layout.size(), &mut short),
        Err(Error::Capacity)
    ));
    assert!(short.iter().all(|key| *key == fake(9)));
    let mut slots = vec![fake(9); layout.required_keys()];
    let mut frontier = ReferenceFrontier::new(layout.size(), &mut slots)?;
    let wrong = Layout::new(layout.size() + 1).leaf(0)?;
    assert_eq!(
        frontier.accept_reference(wrong, fake(1)),
        Err(Error::InvalidInput)
    );
    assert_eq!(frontier.next_leaf(), 0);
    for ordinal in 0..256 {
        frontier.accept_reference(layout.leaf(ordinal)?, fake(ordinal as u8))?;
    }
    let pending = frontier.pending_index().ok_or(Error::NotReady)?;
    assert_eq!(pending.node, layout.node(1, 0)?);
    assert_eq!(pending.children.len(), 256);
    assert_eq!(
        frontier.accept_reference(layout.leaf(256)?, fake(5)),
        Err(Error::WouldBlock)
    );
    frontier.record_index(fake(6))?;
    assert_eq!(frontier.next(), Some(layout.leaf(256)?));
    frontier.accept_reference(layout.leaf(256)?, fake(7))?;
    assert_eq!(
        frontier.pending_index().ok_or(Error::NotReady)?.children,
        &[fake(7)]
    );
    frontier.record_index(fake(8))?;
    assert_eq!(
        frontier.pending_index().ok_or(Error::NotReady)?.children,
        &[fake(6), fake(8)]
    );
    frontier.record_index(fake(10))?;
    assert_eq!(frontier.content(), Some(fake(10).content(layout.size())));
    Ok(())
}

#[test]
fn synthetic_full256_carry_works_in_each_upper_bucket() -> Result<(), Error> {
    // Precomputed references stand in for whole subtrees. This exercises upper
    // bucket carries without materializing, hashing or claiming those files.
    for root_level in 2..8 {
        let boundary = 1_u64 << (15 + 8 * (root_level - 1));
        let layout = Layout::new(boundary + 1);
        let mut slots = vec![fake(9); layout.required_keys()];
        let mut frontier = ReferenceFrontier::new(layout.size(), &mut slots)?;
        for ordinal in 0..256 {
            frontier
                .accept_reference(layout.node(root_level - 2, ordinal)?, fake(ordinal as u8))?;
        }
        let pending = frontier.pending_index().ok_or(Error::NotReady)?;
        assert_eq!(pending.node, layout.node(root_level - 1, 0)?);
        assert_eq!(pending.children.len(), 256);
        for (index, child) in pending.children.iter().enumerate() {
            assert_eq!(*child, fake(index as u8));
        }
        frontier.record_index(fake(17))?;
        let tail = layout.leaf(layout.leaf_count() - 1)?;
        assert_eq!(frontier.next(), Some(tail));
        frontier.accept_reference(tail, fake(18))?;
        for level in 1..root_level {
            let pending = frontier.pending_index().ok_or(Error::NotReady)?;
            assert_eq!(pending.node.level(), level);
            assert_eq!(pending.children.len(), 1);
            frontier.record_index(fake(19))?;
        }
        assert_eq!(
            frontier.pending_index().ok_or(Error::NotReady)?.children,
            &[fake(17), fake(19)]
        );
        frontier.record_index(fake(20))?;
        assert_eq!(frontier.content(), Some(fake(20).content(layout.size())));
    }
    Ok(())
}

#[test]
fn real_encoder_capacity_refusal_never_advances_a_node() -> Result<(), Error> {
    let mut keys = [fake(9); 3];
    let mut encoder = FileEncoder::new(32769, &mut keys)?;
    let first = encoder.next().ok_or(Error::NotReady)?;
    let mut tiny = [0x55; 16];
    assert!(matches!(
        encoder.push_data(b"bad", &mut tiny),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        encoder.push_data(&vec![0; BLOCK_BYTES], &mut tiny),
        Err(Error::Capacity)
    ));
    assert_eq!(encoder.next(), Some(first));
    assert!(tiny.iter().all(|b| *b == 0x55));
    assert!(matches!(
        encoder.emit_index(&mut [], &mut tiny),
        Err(Error::WouldBlock)
    ));
    let mut output = vec![0; BLOCK_BYTES + TAG_BYTES];
    encoder.push_data(&vec![0; BLOCK_BYTES], &mut output)?;
    encoder.push_data(b"x", &mut output)?;
    let index = encoder.next().ok_or(Error::NotReady)?;
    assert_eq!(index.level(), 1);
    assert!(matches!(
        encoder.push_data(b"x", &mut tiny),
        Err(Error::WouldBlock)
    ));
    let mut scratch = [0x55; 256];
    let mut root = [0x55; 272];
    assert!(matches!(
        encoder.emit_index(&mut scratch[..255], &mut root),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        encoder.emit_index(&mut scratch, &mut root[..271]),
        Err(Error::Capacity)
    ));
    assert_eq!(encoder.next(), Some(index));
    assert!(scratch.iter().chain(&root).all(|b| *b == 0x55));
    encoder.emit_index(&mut scratch, &mut root)?;
    assert_eq!(encoder.next(), None);
    assert!(matches!(
        encoder.emit_index(&mut [], &mut []),
        Err(Error::Closed)
    ));
    assert!(matches!(
        encoder.push_data(b"x", &mut output),
        Err(Error::Closed)
    ));
    assert_eq!(keys[2], fake(9));
    let mut unused = [fake(9)];
    let mut empty = FileEncoder::new(0, &mut unused)?;
    empty.push_data(&[], &mut [0; TAG_BYTES])?;
    assert!(empty.content().is_some());
    assert_eq!(unused, [fake(9)]);
    Ok(())
}

#[test]
fn real_multilevel_files_recover_bytes_and_keep_the_existing_chk_format() -> Result<(), Error> {
    for length in [
        0,
        1,
        BLOCK_BYTES - 1,
        BLOCK_BYTES,
        BLOCK_BYTES + 1,
        2 * BLOCK_BYTES + 17,
        8 * 1024 * 1024,
        8 * 1024 * 1024 + 1,
    ] {
        let input = pattern(length);
        let (content, nodes) = encode_file(&input)?;
        let layout = Layout::new(content.size);
        for level in 0..=layout.root_level() {
            assert_eq!(
                nodes
                    .iter()
                    .filter(|node| node.node.level() == level)
                    .count() as u64,
                layout.node_count(level)?
            );
        }
        let (decoded, _) = walk(content, &nodes, 0..content.size)?;
        assert_eq!(decoded, input);
        let mut scratch = vec![0; BLOCK_BYTES];
        let root = NodeRef::root(content);
        let opened = root.open(stored(&nodes, root)?, &mut scratch)?;
        if length == 0 {
            assert_eq!(opened.data(), Some([].as_slice()));
        }
        if length == 8 * 1024 * 1024 + 1 {
            let tail = opened.child(1)?;
            assert_eq!(tail.node().level(), 1);
            assert_eq!(tail.node().child_count(), 1);
        }
        let uri = content.uri();
        let mut bytes = vec![0; uri.encoded_len()?];
        uri.encode(&mut bytes)?;
        assert!(matches!(Uri::parse(&bytes, Limits::default())?, Uri::Content(c) if c == content));
    }
    Ok(())
}

#[test]
fn authenticated_range_walk_prunes_and_retries_without_trusting_stale_nodes() -> Result<(), Error> {
    let input = pattern(8 * 1024 * 1024 + 1);
    let (content, nodes) = encode_file(&input)?;
    let (bytes, visited) = walk(content, &nodes, 32760..32780)?;
    assert_eq!(bytes, input[32760..32780]);
    assert_eq!(visited.iter().filter(|node| node.level() == 0).count(), 2);
    let (bytes, visited) = walk(content, &nodes, (content.size - 1)..content.size)?;
    assert_eq!(bytes, input[input.len() - 1..]);
    assert_eq!(visited.len(), 3);
    let mut keys = vec![fake(8); Layout::new(content.size).required_keys()];
    let mut traversal = RangeTraversal::new(content, 0..1, &mut keys)?;
    let expected = traversal.next().ok_or(Error::NotReady)?;
    let mut short = [0x55; 1];
    assert!(matches!(
        expected.open(stored(&nodes, expected)?, &mut short),
        Err(Error::Capacity)
    ));
    assert_eq!(short, [0x55]);
    assert_eq!(traversal.next(), Some(expected));
    let mut scratch = vec![0; BLOCK_BYTES];
    let other = nodes
        .iter()
        .find(|s| s.node.level() == 0)
        .ok_or(Error::NotFound)?;
    let opened = NodeRef::new(other.node, other.key).open(&other.bytes, &mut scratch)?;
    assert!(matches!(traversal.accept(opened), Err(Error::InvalidInput)));
    assert_eq!(traversal.next(), Some(expected));
    let mut corrupt = stored(&nodes, expected)?.to_vec();
    corrupt[0] ^= 1;
    assert!(matches!(
        expected.open(&corrupt, &mut scratch),
        Err(Error::Authentication)
    ));
    assert!(
        scratch[..expected.node().plaintext_bytes()]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(traversal.next(), Some(expected));
    let opened = expected.open(stored(&nodes, expected)?, &mut scratch)?;
    traversal.accept(opened)?;
    let next = traversal.next();
    let stale = expected.open(stored(&nodes, expected)?, &mut scratch)?;
    assert!(matches!(traversal.accept(stale), Err(Error::InvalidInput)));
    assert_eq!(traversal.next(), next);
    let mut none = [];
    assert!(
        RangeTraversal::new(content, 1..1, &mut none)?
            .next()
            .is_none()
    );
    assert!(matches!(
        RangeTraversal::new(content, Range { start: 2, end: 1 }, &mut none),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        RangeTraversal::new(content, 0..content.size + 1, &mut none),
        Err(Error::InvalidInput)
    ));
    Ok(())
}

#[test]
fn file_size_binds_node_shapes_before_output_without_private_type_domains() -> Result<(), Error> {
    let mut leaf = [0; TAG_BYTES + 1];
    let leaf_key = content::encode_data(b"x", &mut leaf)?.key();
    let mut scratch = [0; CHK_BYTES * 3];
    let mut output = [0; CHK_BYTES * 3 + TAG_BYTES];
    let index = content::encode_index(&[leaf_key], &mut scratch, &mut output)?;
    let mut untouched = [0x55; BLOCK_BYTES];
    assert!(matches!(
        NodeRef::root(index.key().content(1)).open(index.bytes(), &mut untouched),
        Err(Error::Malformed)
    ));
    assert!(untouched.iter().all(|byte| *byte == 0x55));
    // No type tag/AAD: raw one-child index plaintext is also valid128-byte data.
    let root = NodeRef::root(index.key().content(128)).open(index.bytes(), &mut untouched)?;
    let data = root.data().ok_or(Error::Malformed)?;
    assert_eq!(&data[..64], &leaf_key.key);
    assert_eq!(&data[64..], &leaf_key.query);
    assert_eq!(root.children().len(), 0);
    assert_eq!(root.child(0).map(NodeRef::node), Err(Error::InvalidInput));
    untouched.fill(0x55);
    let index = content::encode_index(&[leaf_key; 3], &mut scratch, &mut output)?;
    assert!(matches!(
        NodeRef::root(index.key().content(32769)).open(index.bytes(), &mut untouched),
        Err(Error::Malformed)
    ));
    assert!(untouched.iter().all(|byte| *byte == 0x55));
    let index = content::encode_index(&[leaf_key; 2], &mut scratch, &mut output)?;
    let mut root_scratch = [0; 256];
    let root = NodeRef::root(index.key().content(32769)).open(index.bytes(), &mut root_scratch)?;
    assert!(matches!(
        root.child(0)?.open(&leaf, &mut untouched),
        Err(Error::Malformed)
    ));
    assert_eq!(
        root.child(1)?.open(&leaf, &mut untouched)?.data(),
        Some(b"x".as_slice())
    );
    assert_eq!(root.child(2).map(NodeRef::node), Err(Error::InvalidInput));
    Ok(())
}

#[test]
fn authenticated_synthetic_u64_tail_path_is_not_a_complete_large_file_claim() -> Result<(), Error> {
    // The selected path is cryptographically materialized. All unvisited sibling
    // references below are fake; this is NOT a real u64::MAX file or C comparison.
    let layout = Layout::new(u64::MAX);
    let mut path = vec![layout.root()];
    while path.last().ok_or(Error::NotReady)?.level() > 0 {
        let parent = *path.last().ok_or(Error::NotReady)?;
        path.push(parent.child(parent.child_count() - 1)?);
    }
    let mut output = vec![0; BLOCK_BYTES + TAG_BYTES];
    let mut scratch = vec![0; BLOCK_BYTES];
    let mut nodes = Vec::new();
    let leaf = *path.last().ok_or(Error::NotReady)?;
    let block = content::encode_data(&pattern(leaf.plaintext_bytes()), &mut output)?;
    let mut key = block.key();
    nodes.push(Stored {
        node: leaf,
        key,
        bytes: block.bytes().to_vec(),
    });
    for node in path[..path.len() - 1].iter().rev() {
        let mut children = vec![fake(71); node.child_count()];
        *children.last_mut().ok_or(Error::NotReady)? = key;
        let block = content::encode_index(&children, &mut scratch, &mut output)?;
        key = block.key();
        nodes.push(Stored {
            node: *node,
            key,
            bytes: block.bytes().to_vec(),
        });
    }
    let (bytes, visited) = walk(key.content(u64::MAX), &nodes, (u64::MAX - 1)..u64::MAX)?;
    assert_eq!(visited.len(), 8);
    assert_eq!(bytes, [((32767 - 1) % 251) as u8]);
    Ok(())
}
