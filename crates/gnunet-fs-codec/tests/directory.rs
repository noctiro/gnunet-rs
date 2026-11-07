//! Actual pure Rust zlib provider with complete directory artifacts.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify real codec composition and reset/refusal boundaries"
)]
use gnunet_fs::{
    Content,
    directory::{self as dir, Event, Parser, Policy, Segment, Status},
    metadata::{self as md, Deflater, Format, Item},
};
use gnunet_fs_codec::{Compressor, Inflate};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn encode(items: &[Item<'_>], compression: md::Compression) -> Result<Vec<u8>, md::Error> {
    let mut order = vec![0; items.len()];
    let mut plain = vec![0; 1024 * 1024];
    let mut coded = vec![0; 1024 * 1024];
    let mut compressor = Compressor::new();
    let plan = md::plan(
        items,
        &mut order,
        &mut plain,
        &mut coded,
        &mut compressor,
        md::Limits::default(),
        md::Options {
            compression,
            ..md::Options::default()
        },
    )?;
    let mut output = vec![0; plan.report().wire_bytes];
    plan.write(&mut output)?;
    Ok(output)
}
fn binary(kind: u32, data: &[u8]) -> Item<'_> {
    Item {
        kind,
        format: Format::Binary,
        data,
        plugin: None,
        mime: None,
    }
}
fn build(root: &[u8], entry: &[u8]) -> Result<Vec<u8>, dir::Error> {
    let mut inflater = Inflate::new();
    let mut plain = vec![0; 1024 * 1024];
    let root =
        dir::PreparedMetadata::validate(root, &mut plain, &mut inflater, md::Limits::default())?;
    let entry =
        dir::PreparedMetadata::validate(entry, &mut plain, &mut inflater, md::Limits::default())?;
    let mut record = vec![0; entry.bytes().len() + 512];
    let entry = dir::PreparedEntry::prepare(
        Content {
            key: [1; 64],
            query: [2; 64],
            size: 80000,
        }
        .uri(),
        entry,
        &mut record,
    )?;
    let entries = [entry];
    let mut placements = [dir::Placement::default()];
    let plan = dir::plan(
        root,
        &entries,
        &mut placements,
        dir::BuildOptions::default(),
    )?;
    let mut output = vec![0; plan.report().wire_bytes as usize];
    plan.write(&mut output)?;
    Ok(output)
}

#[test]
fn real_compressed_and_raw_root_entry_product_supports_segmented_large_hints() -> TestResult {
    let root_data = vec![b'R'; 50000];
    let entry_data: Vec<_> = (0..80000).map(|i| ((i * 197 + 11) % 251) as u8).collect();
    for root_codec in [md::Compression::Never, md::Compression::Always] {
        for entry_codec in [md::Compression::Never, md::Compression::Always] {
            let root = encode(&[dir::MIME_ITEM, binary(4, &root_data)], root_codec)?;
            let entry = encode(
                &[
                    binary(174, &entry_data),
                    Item {
                        format: Format::CString,
                        ..binary(180, b"../unsafe\\name\0")
                    },
                ],
                entry_codec,
            )?;
            let data = build(&root, &entry)?;
            for chunk in [1, 7, 32768, data.len()] {
                let mut carry = vec![0; data.len() + 1024];
                let mut plain = vec![0; 1024 * 1024];
                let mut inflater = Inflate::new();
                let mut parser = Parser::new(&mut carry, dir::Limits::default(), Policy::default());
                let mut pos = 0;
                let mut roots = 0;
                let mut entries = 0;
                loop {
                    let end = (pos + chunk).min(data.len());
                    let p = parser.feed(
                        Segment {
                            base: pos as u64,
                            bytes: &data[pos..end],
                            final_extent: Some(data.len() as u64),
                        },
                        &mut plain,
                        &mut inflater,
                    )?;
                    pos += p.consumed;
                    match p.status {
                        Status::Event(Event::Directory { raw, metadata, .. }) => {
                            roots += 1;
                            assert_eq!(raw, root);
                            assert_eq!(
                                metadata.was_compressed(),
                                root_codec == md::Compression::Always
                            );
                            assert!(metadata.items().any(|i| i.data == root_data));
                        }
                        Status::Event(Event::Entry(e)) => {
                            entries += 1;
                            assert_eq!(e.raw_metadata, entry);
                            assert_eq!(
                                e.metadata.was_compressed(),
                                entry_codec == md::Compression::Always
                            );
                            assert_eq!(
                                dir::hints(e.metadata.items()).next().map(|h| h.item.data),
                                Some(entry_data.as_slice())
                            );
                            assert_eq!(
                                dir::filename(e.metadata.items()),
                                Some(&b"../unsafe\\name"[..])
                            );
                        }
                        Status::Complete(summary) => {
                            assert_eq!(summary.entries, 1);
                            break;
                        }
                        Status::NeedMore { .. } | Status::Event(Event::Padding { .. }) => {}
                        other => return Err(format!("unexpected status {other:?}").into()),
                    }
                }
                assert_eq!((roots, entries), (1, 1));
            }
        }
    }
    Ok(())
}

#[test]
fn actual_codec_plain_capacity_retry_reset_and_checksum_failure_are_explicit() -> TestResult {
    let root = encode(
        &[dir::MIME_ITEM, binary(4, &[b'x'; 4096])],
        md::Compression::Always,
    )?;
    let entry = encode(&[], md::Compression::Always)?;
    let data = build(&root, &entry)?;
    let mut carry = vec![0; data.len()];
    let mut plain = vec![0; 8192];
    let mut inflater = Inflate::new();
    let mut parser = Parser::new(&mut carry, dir::Limits::default(), Policy::default());
    let p = parser.feed(
        Segment {
            base: 0,
            bytes: &data,
            final_extent: Some(data.len() as u64),
        },
        &mut [],
        &mut inflater,
    )?;
    let consumed = p.consumed;
    assert!(matches!(p.status,Status::NeedPlain {required} if required>4096));
    assert_eq!(parser.summary().entries, 0);
    let off = parser.offset();
    let p = parser.feed(
        Segment {
            base: off,
            bytes: &data[consumed..],
            final_extent: None,
        },
        &mut plain,
        &mut inflater,
    )?;
    assert_eq!(p.consumed, 0);
    assert!(
        matches!(p.status,Status::Event(Event::Directory {metadata,..}) if metadata.is_complete())
    );
    let mut bad = data.clone();
    bad[12 + root.len() - 1] ^= 1;
    let mut carry_bad = vec![0; bad.len()];
    let mut failed = Parser::new(&mut carry_bad, dir::Limits::default(), Policy::default());
    plain.fill(0xa7);
    assert!(matches!(
        failed.feed(
            Segment {
                base: 0,
                bytes: &bad,
                final_extent: Some(bad.len() as u64)
            },
            &mut plain,
            &mut inflater
        ),
        Err(dir::Failure {
            error: dir::Error::Metadata(md::Error::Codec(_)),
            ..
        })
    ));
    let declared = u32::from_be_bytes(root[8..12].try_into()?) as usize;
    assert!(plain[..declared].iter().all(|b| *b == 0));
    let mut carry_good = vec![0; data.len()];
    let mut retried = Parser::new(&mut carry_good, dir::Limits::default(), Policy::default());
    assert!(matches!(
        retried
            .feed(
                Segment {
                    base: 0,
                    bytes: &data,
                    final_extent: Some(data.len() as u64)
                },
                &mut plain,
                &mut inflater
            )?
            .status,
        Status::Event(Event::Directory { .. })
    ));
    Ok(())
}

#[test]
fn compressed_bad_second_record_stays_recovered_in_directory_and_never_complete() -> TestResult {
    let mut raw = encode(
        &[binary(4, b"first"), binary(5, b"other")],
        md::Compression::Never,
    )?;
    raw[36..40].copy_from_slice(&99_u32.to_be_bytes());
    let mut coded = vec![0; 1024];
    let p = Compressor::new()
        .deflate(&raw[12..], &mut coded)
        .map_err(md::Error::Codec)?;
    coded.truncate(p.produced);
    raw[..4].copy_from_slice(&(2 | md::COMPRESSED).to_be_bytes());
    raw.truncate(12);
    raw.extend_from_slice(&coded);
    let mut data = dir::MAGIC.to_vec();
    data.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    data.extend_from_slice(&raw);
    let mut inflater = Inflate::new();
    let mut plain = [0; 1024];
    let mut carry = [0; 2048];
    let mut strict = Parser::new(&mut carry, dir::Limits::default(), Policy::default());
    assert!(matches!(
        strict.feed(
            Segment {
                base: 0,
                bytes: &data,
                final_extent: Some(data.len() as u64)
            },
            &mut plain,
            &mut inflater
        ),
        Err(dir::Failure {
            error: dir::Error::Metadata(md::Error::Entry { index: 1, .. }),
            ..
        })
    ));
    let mut recovery = Parser::new(
        &mut carry,
        dir::Limits::default(),
        Policy {
            metadata: md::Mode::ReferencePrefix,
            ..Policy::default()
        },
    );
    let p = recovery.feed(
        Segment {
            base: 0,
            bytes: &data,
            final_extent: Some(data.len() as u64),
        },
        &mut plain,
        &mut inflater,
    )?;
    assert!(
        matches!(p.status,Status::Event(Event::Directory {metadata,..}) if !metadata.is_complete() && metadata.accepted_entries()==1)
    );
    let p = recovery.feed(
        Segment {
            base: data.len() as u64,
            bytes: &[],
            final_extent: None,
        },
        &mut plain,
        &mut inflater,
    )?;
    assert!(matches!(p.status,Status::Partial(summary) if summary.root_seen && summary.recovered));
    Ok(())
}
