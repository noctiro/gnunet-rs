//! Real CHK paths and directory records over reusable bounded buffers.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check authenticated source ownership"
)]
use gnunet_fs::{
    Content,
    content::{BlockKey, FileEncoder, FileReader, Layout, NodeRef},
    directory::{self as dir, SourceError, SourceParser, Status},
    metadata::{self as md, Format, Item},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
type Blocks = Vec<(NodeRef, Vec<u8>)>;

fn encode(bytes: &[u8]) -> Result<(Content, Blocks), Box<dyn std::error::Error>> {
    let mut keys = vec![BlockKey::default(); Layout::new(bytes.len() as u64).required_keys()];
    let mut encoder = FileEncoder::new(bytes.len() as u64, &mut keys)?;
    let mut index = [0; 32768];
    let mut output = [0; 32784];
    let mut blocks = Vec::new();
    while let Some(node) = encoder.next() {
        let encoded = if node.level() == 0 {
            let range = node.range();
            encoder.push_data(
                &bytes[range.start as usize..range.end as usize],
                &mut output,
            )?
        } else {
            encoder.emit_index(&mut index, &mut output)?
        };
        blocks.push((
            NodeRef::new(encoded.node(), encoded.block().key()),
            encoded.block().bytes().to_vec(),
        ));
    }
    Ok((encoder.content().ok_or("encoder incomplete")?, blocks))
}
fn metadata(items: &[Item<'_>]) -> Result<Vec<u8>, md::Error> {
    let mut order = vec![0; items.len()];
    let mut plain = vec![0; 1024 * 1024];
    let plan = md::plan_uncompressed(
        items,
        &mut order,
        &mut plain,
        md::Limits::default(),
        md::Options::default(),
    )?;
    let mut output = vec![0; plan.report().wire_bytes];
    plan.write(&mut output)?;
    Ok(output)
}
fn directory(child: Content) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let root = metadata(&[dir::MIME_ITEM])?;
    let payload = vec![17; 70000];
    let entry = metadata(&[Item {
        kind: 4,
        format: Format::Binary,
        data: &payload,
        plugin: None,
        mime: None,
    }])?;
    let root =
        dir::PreparedMetadata::validate(&root, &mut [], &mut md::NoCodec, md::Limits::default())?;
    let entry =
        dir::PreparedMetadata::validate(&entry, &mut [], &mut md::NoCodec, md::Limits::default())?;
    let mut arena = vec![0; entry.bytes().len() + 512];
    let entries = [dir::PreparedEntry::prepare(child.uri(), entry, &mut arena)?];
    let mut placements = [dir::Placement::default()];
    let plan = dir::plan(
        root,
        &entries,
        &mut placements,
        dir::BuildOptions::default(),
    )?;
    let mut bytes = vec![0; plan.report().wire_bytes as usize];
    plan.write(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn authenticated_directory_stream_follows_parent_indexes_and_long_records() -> TestResult {
    let (child, _) = encode(b"child content")?;
    let bytes = directory(child)?;
    let (source, blocks) = encode(&bytes)?;
    let mut keys = vec![BlockKey::default(); Layout::new(source.size).required_keys()];
    let mut reader = FileReader::new(source, &mut keys)?;
    let mut block = [0; 32768];
    let mut carry = vec![0; 100000];
    let mut parser = SourceParser::new(source, &mut carry, dir::Limits::default())?;
    let mut roots = 0;
    let mut entries = 0;
    let mut complete = false;
    while let Some(request) = reader.next() {
        let (_, ciphertext) = blocks
            .iter()
            .find(|(r, _)| *r == request)
            .ok_or("missing block")?;
        let Some(chunk) = reader.open_next(ciphertext, &mut block)? else {
            continue;
        };
        let mut local = 0;
        loop {
            let progress = parser.feed(&chunk, local, &mut [], &mut md::NoCodec)?;
            local += progress.consumed;
            if let Some(proof) = progress.entry() {
                assert_eq!(proof.source(), source);
                assert!(proof.entry().boundary_tracked);
                assert!(matches!(proof.entry().uri()?, gnunet_fs::Uri::Content(c) if c == child));
                assert_eq!(
                    proof
                        .entry()
                        .metadata
                        .items()
                        .next()
                        .ok_or("missing item")?
                        .data
                        .len(),
                    70000
                );
                entries += 1;
            }
            match progress.status() {
                Status::Event(dir::Event::Directory { .. }) => roots += 1,
                Status::Event(_) => {}
                Status::NeedMore { .. } => {
                    assert_eq!(local, chunk.bytes().len());
                    break;
                }
                Status::Complete(summary) => {
                    assert_eq!(summary.end, source.size);
                    complete = true;
                    break;
                }
                other => return Err(format!("unexpected progress: {other:?}").into()),
            }
        }
    }
    assert_eq!((roots, entries, complete), (1, 1, true));
    assert_eq!(
        parser
            .completion()
            .ok_or("directory proof missing")?
            .content(),
        source
    );
    assert_eq!(
        reader.completion().ok_or("file proof missing")?.content(),
        source
    );
    Ok(())
}

#[test]
fn source_mismatch_and_corrupt_block_cannot_advance_the_original_owner() -> TestResult {
    let (a, a_blocks) = encode(b"a")?;
    let (b, b_blocks) = encode(b"b")?;
    let mut a_keys = [];
    let mut b_keys = [];
    let mut reader = FileReader::new(a, &mut a_keys)?;
    let request = reader.next();
    let mut plain = [0; 32768];
    let mut corrupt = a_blocks[0].1.clone();
    corrupt[0] ^= 1;
    assert!(reader.open_next(&corrupt, &mut plain).is_err());
    assert_eq!(reader.next(), request);
    assert!(reader.completion().is_none());
    assert_eq!(
        reader
            .open_next(&a_blocks[0].1, &mut plain)?
            .ok_or("chunk missing")?
            .bytes(),
        b"a"
    );
    let mut foreign = FileReader::new(b, &mut b_keys)?;
    let foreign = foreign
        .open_next(&b_blocks[0].1, &mut plain)?
        .ok_or("foreign chunk missing")?;
    let mut carry = [0; 128];
    let mut parser = SourceParser::new(a, &mut carry, dir::Limits::default())?;
    assert!(matches!(
        parser.feed(&foreign, 0, &mut [], &mut md::NoCodec),
        Err(SourceError::Source)
    ));
    assert_eq!(parser.offset(), 0);
    Ok(())
}

#[test]
fn empty_file_proof_requires_its_real_authenticated_root() -> TestResult {
    let (source, blocks) = encode(b"")?;
    let mut keys = [];
    let mut reader = FileReader::new(source, &mut keys)?;
    assert!(reader.next().is_some());
    assert!(reader.completion().is_none());
    assert!(reader.open_next(&[], &mut []).is_err());
    let chunk = reader
        .open_next(&blocks[0].1, &mut [])?
        .ok_or("empty root missing")?;
    assert_eq!(chunk.range(), 0..0);
    assert!(chunk.bytes().is_empty());
    assert_eq!(
        reader
            .completion()
            .ok_or("empty file proof missing")?
            .content(),
        source
    );
    Ok(())
}
