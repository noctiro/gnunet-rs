//! Directory framing, actual inline CHKs and caller-storage refusal controls.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify directory wire and refusal contracts"
)]
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey};
use gnunet_fs::{
    Content, Namespace, Uri,
    content::{self, BlockKey},
    directory::{self as dir, Error, Event, Parser, Policy, Segment, Status},
    metadata::{self as md, Format, Item},
};
use gnunet_wire::official::AbsoluteTime;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn item(kind: u32, data: &[u8]) -> Item<'_> {
    Item {
        kind,
        format: Format::Binary,
        data,
        plugin: None,
        mime: None,
    }
}
fn raw(items: &[Item<'_>]) -> Result<Vec<u8>, Error> {
    let mut order = vec![0; items.len()];
    let mut plain = vec![0; 1024 * 1024];
    let plan = md::plan_uncompressed(
        items,
        &mut order,
        &mut plain,
        md::Limits::default(),
        md::Options::default(),
    )
    .map_err(Error::Metadata)?;
    let mut output = vec![0; plan.report().wire_bytes];
    plan.write(&mut output).map_err(Error::Metadata)?;
    Ok(output)
}
fn content(size: u64) -> Content {
    Content {
        key: [1; 64],
        query: [2; 64],
        size,
    }
}
fn build(root: &[u8], entries: &[(Uri<'_>, Vec<u8>)]) -> Result<Vec<u8>, Error> {
    let root =
        dir::PreparedMetadata::validate(root, &mut [], &mut md::NoCodec, md::Limits::default())?;
    let mut arenas: Vec<_> = entries
        .iter()
        .map(|(uri, md)| {
            Ok(vec![
                0;
                uri.encoded_len().map_err(Error::Uri)? + 5 + md.len()
            ])
        })
        .collect::<Result<_, Error>>()?;
    let mut records = Vec::new();
    for ((uri, md), arena) in entries.iter().zip(&mut arenas) {
        let metadata =
            dir::PreparedMetadata::validate(md, &mut [], &mut md::NoCodec, md::Limits::default())?;
        records.push(dir::PreparedEntry::prepare(*uri, metadata, arena)?);
    }
    let mut placements = vec![dir::Placement::default(); records.len()];
    let plan = dir::plan(
        root,
        &records,
        &mut placements,
        dir::BuildOptions::default(),
    )?;
    let mut output = vec![0; plan.report().wire_bytes as usize];
    plan.write(&mut output)?;
    Ok(output)
}
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    root: Vec<u8>,
    uris: Vec<Vec<u8>>,
    metadata: Vec<Vec<u8>>,
    offsets: Vec<(u64, u64, bool)>,
    gaps: Vec<(u64, u64, bool)>,
    complete: bool,
}
fn collect(data: &[u8], chunk: usize, policy: Policy) -> Result<Seen, dir::Failure> {
    let mut carry = vec![0; 2 * 1024 * 1024];
    let mut plain = vec![0; 1024 * 1024];
    let mut parser = Parser::new(&mut carry, dir::Limits::default(), policy);
    let mut pos = 0;
    let mut seen = Seen {
        root: Vec::new(),
        uris: Vec::new(),
        metadata: Vec::new(),
        offsets: Vec::new(),
        gaps: Vec::new(),
        complete: false,
    };
    loop {
        let end = (pos + chunk).min(data.len());
        let p = parser.feed(
            Segment {
                base: pos as u64,
                bytes: &data[pos..end],
                final_extent: Some(data.len() as u64),
            },
            &mut plain,
            &mut md::NoCodec,
        )?;
        pos += p.consumed;
        match p.status {
            Status::Event(Event::Directory { raw, .. }) => seen.root = raw.to_vec(),
            Status::Event(Event::Entry(entry)) => {
                seen.uris.push(entry.raw_uri.to_vec());
                seen.metadata.push(entry.raw_metadata.to_vec());
                seen.offsets
                    .push((entry.range.start, entry.range.end, entry.boundary_tracked));
            }
            Status::Event(Event::Padding {
                range, invalid_uri, ..
            }) => seen.gaps.push((range.start, range.end, invalid_uri)),
            Status::NeedMore { .. } => {}
            Status::Complete(summary) => {
                assert_eq!(summary.end, data.len() as u64);
                seen.complete = true;
                break;
            }
            Status::Partial(_) => break,
            _ => {
                return Err(dir::Failure {
                    consumed: 0,
                    at: pos as u64,
                    stage: dir::Stage::End,
                    error: Error::Capacity,
                });
            }
        }
    }
    Ok(seen)
}

#[test]
fn empty_directory_has_magic_and_present_metadata_and_unknown_eof_is_not_complete() -> TestResult {
    let root = raw(&[dir::MIME_ITEM])?;
    let data = build(&root, &[])?;
    assert_eq!(&data[..8], dir::MAGIC);
    assert_eq!(
        u32::from_be_bytes(data[8..12].try_into()?),
        root.len() as u32
    );
    let got = collect(&data, 1, Policy::default())?;
    assert!(got.complete);
    assert!(got.uris.is_empty());
    assert_eq!(got.root, root);
    let mut carry = vec![0; data.len()];
    let mut parser = Parser::new(&mut carry, dir::Limits::default(), Policy::default());
    let p = parser.feed(
        Segment {
            base: 0,
            bytes: &data,
            final_extent: None,
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    assert!(matches!(p.status, Status::Event(Event::Directory { .. })));
    let p = parser.feed(
        Segment {
            base: data.len() as u64,
            bytes: &[],
            final_extent: None,
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    assert!(matches!(p.status, Status::NeedMore { .. }));
    Ok(())
}

#[test]
fn all_small_chunk_sizes_preserve_root_uris_names_and_metadata() -> TestResult {
    let root = raw(&[dir::MIME_ITEM, item(999, b"root")])?;
    let metadata = raw(&[
        Item {
            format: Format::CString,
            ..item(180, b"../a\\b\0tail\0")
        },
        item(174, b"\0binary\0"),
        Item {
            plugin: Some(b"\0"),
            mime: Some(b"\0"),
            ..item(0xffff_ffff, b"")
        },
    ])?;
    let signer = EddsaPrivateKey::from_seed([17; 32]);
    let loc = gnunet_fs::Location::sign(content(8), &signer, AbsoluteTime::from_micros(0))?;
    let sks = Namespace::new(EddsaPublicKey::from_bytes([3; 32]), b"child")?;
    let data = build(
        &root,
        &[
            (content(8).uri(), metadata.clone()),
            (Uri::Location(loc), metadata.clone()),
            (Uri::Namespace(sks), metadata.clone()),
        ],
    )?;
    let whole = collect(&data, data.len(), Policy::default())?;
    for n in 1..=37 {
        assert_eq!(collect(&data, n, Policy::default())?, whole);
    }
    assert_eq!(whole.metadata, vec![metadata.clone(); 3]);
    let md = md::decode_uncompressed(&metadata, md::Limits::default(), md::Mode::Strict)?;
    if let md::Decoded::Present(md) = md {
        assert_eq!(dir::filename(md.items()), Some(&b"../a\\b"[..]));
        assert_eq!(
            dir::hints(md.items()).next().map(|h| h.item.data),
            Some(&b"\0binary\0"[..])
        );
    }
    Ok(())
}

#[test]
fn boundary_padding_and_long_records_are_real_not_synthetic_geometry() -> TestResult {
    let root = raw(&[])?;
    let uri = content(0).uri();
    let fixed = uri.encoded_len()? + 5 + 12 + 20;
    for len in [32767, 32768, 32769, 65536, 65537] {
        let payload = vec![0xa5; len - fixed];
        let metadata = raw(&[item(174, &payload)])?;
        let data = build(&root, &[(uri, metadata.clone()), (uri, raw(&[])?)])?;
        let got = collect(&data, 32768, Policy::default())?;
        assert!(got.complete);
        assert_eq!(got.offsets[0].1 - got.offsets[0].0, len as u64);
        assert_eq!(got.metadata[0], metadata);
        assert_eq!(got.offsets[0].0, 32768);
        assert!(got.gaps.iter().all(|(_, _, invalid)| !*invalid));
        assert_eq!(collect(&data, 257, Policy::default())?, got);
    }
    let payload = vec![7; 50000];
    let root = raw(&[item(4, &payload)])?;
    let data = build(&root, &[(uri, raw(&[])?)])?;
    assert_eq!(collect(&data, 4093, Policy::default())?.root, root);
    Ok(())
}

#[test]
fn known_final_truncation_identifies_header_uri_length_and_metadata_without_oob() -> TestResult {
    let root = raw(&[])?;
    let data = build(&root, &[(content(2).uri(), raw(&[item(4, b"abc")])?)])?;
    let full = collect(&data, data.len(), Policy::default())?;
    let start = full.offsets[0].0 as usize;
    let nul = data[start..]
        .iter()
        .position(|b| *b == 0)
        .ok_or(Error::Input)?
        + start;
    for cut in (0..12).chain([
        start + 1,
        nul,
        nul + 1,
        nul + 2,
        nul + 3,
        nul + 4,
        data.len() - 1,
    ]) {
        let result = collect(&data[..cut], 3, Policy::default());
        assert!(
            matches!(
                result,
                Err(dir::Failure {
                    error: Error::Truncated,
                    ..
                })
            ),
            "cut={cut} result={result:?}"
        );
    }
    let mut bad = data;
    bad[0] ^= 1;
    assert!(matches!(
        collect(&bad, 7, Policy::default()),
        Err(dir::Failure {
            error: Error::Magic,
            ..
        })
    ));
    let mut absent = dir::MAGIC.to_vec();
    absent.extend_from_slice(&0u32.to_be_bytes());
    assert!(collect(&absent, 99, Policy::default()).is_err());
    Ok(())
}

#[test]
fn record_capacity_retry_preserves_partial_uri_and_emits_once() -> TestResult {
    let root = raw(&[])?;
    let data = build(&root, &[(content(2).uri(), raw(&[item(4, b"abc")])?)])?;
    let mut tiny = [0; 12];
    let mut medium = [0; 25];
    let mut enough = vec![0; data.len()];
    let mut parser = Parser::new(&mut tiny, dir::Limits::default(), Policy::default());
    let mut pos = 0;
    let p = parser.feed(
        Segment {
            base: 0,
            bytes: &data,
            final_extent: Some(data.len() as u64),
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    pos += p.consumed;
    assert!(matches!(p.status, Status::NeedRecord { required: 24 }));
    assert_eq!(pos, 12);
    parser.replace_buffer(&mut medium)?;
    let p = parser.feed(
        Segment {
            base: pos as u64,
            bytes: &data[pos..],
            final_extent: None,
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    pos += p.consumed;
    assert!(matches!(p.status, Status::Event(Event::Directory { .. })));
    let p = parser.feed(
        Segment {
            base: pos as u64,
            bytes: &data[pos..],
            final_extent: None,
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    pos += p.consumed;
    assert!(matches!(p.status, Status::NeedRecord { .. }));
    let retained = parser.offset();
    parser.replace_buffer(&mut enough)?;
    assert_eq!(parser.offset(), retained);
    let p = parser.feed(
        Segment {
            base: pos as u64,
            bytes: &data[pos..],
            final_extent: None,
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    pos += p.consumed;
    assert!(matches!(p.status, Status::Event(Event::Entry(_))));
    let p = parser.feed(
        Segment {
            base: pos as u64,
            bytes: &[],
            final_extent: None,
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    assert!(matches!(p.status,Status::Complete(summary) if summary.entries==1));
    Ok(())
}

#[test]
fn invalid_uri_resync_is_explicit_partial_and_padding_coordinates_are_absolute() -> TestResult {
    let root = raw(&[])?;
    let mut bytes = build(&root, &[])?;
    bytes.extend_from_slice(b"invalid\0");
    bytes.resize(32768, 0x55);
    let md = raw(&[])?;
    let prepared =
        dir::PreparedMetadata::validate(&md, &mut [], &mut md::NoCodec, md::Limits::default())?;
    let mut record = vec![0; 1024];
    let entry = dir::PreparedEntry::prepare(content(0).uri(), prepared, &mut record)?;
    bytes.extend_from_slice(entry.bytes());
    assert!(collect(&bytes, 99, Policy::default()).is_err());
    let got = collect(
        &bytes,
        300,
        Policy {
            recover_uri: true,
            ..Policy::default()
        },
    )?;
    assert!(!got.complete);
    assert_eq!(got.uris.len(), 1);
    assert_eq!(got.offsets[0].0, 32768);
    assert!(!got.offsets[0].2);
    assert!(got.gaps[0].2);
    let mut carry = vec![0; 1024];
    let mut parser =
        Parser::from_block(&mut carry, 32768, dir::Limits::default(), Policy::default())?;
    let p = parser.feed(
        Segment {
            base: 32768,
            bytes: &bytes[32768..],
            final_extent: Some(bytes.len() as u64),
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    assert!(
        matches!(p.status,Status::Event(Event::Entry(e)) if e.range.start==32768 && !e.boundary_tracked)
    );
    let off = parser.offset();
    let p = parser.feed(
        Segment {
            base: off,
            bytes: &[],
            final_extent: None,
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    assert!(matches!(p.status, Status::Partial(_)));
    Ok(())
}

#[test]
fn terminal_padding_and_nonzero_opaque_padding_have_explicit_policy() -> TestResult {
    let mut data = build(&raw(&[])?, &[])?;
    data.extend_from_slice(&[0, 42, 99]);
    let got = collect(&data, 1, Policy::default())?;
    assert!(got.complete);
    assert_eq!(got.gaps.len(), 1);
    assert!(
        collect(
            &data,
            1,
            Policy {
                canonical_padding: true,
                ..Policy::default()
            }
        )
        .is_err()
    );
    let mut carry = [0; 64];
    let mut parser = Parser::new(&mut carry, dir::Limits::default(), Policy::default());
    let p = parser.feed(
        Segment {
            base: 0,
            bytes: &data,
            final_extent: None,
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    let used = p.consumed;
    let p = parser.feed(
        Segment {
            base: used as u64,
            bytes: &data[used..],
            final_extent: None,
        },
        &mut [],
        &mut md::NoCodec,
    )?;
    assert!(matches!(
        p.status,
        Status::NeedMore {
            stage: dir::Stage::Padding,
            ..
        }
    ));
    Ok(())
}

#[test]
fn builder_full_partial_metadata_omissions_and_final_output_are_atomic() -> TestResult {
    let raw = raw(&[])?;
    let root =
        dir::PreparedMetadata::validate(&raw, &mut [], &mut md::NoCodec, md::Limits::default())?;
    let mut record = [0; 512];
    let entry = dir::PreparedEntry::prepare(content(0).uri(), root, &mut record)?;
    let entries = [entry, entry];
    let mut slots = [dir::Placement::default(); 2];
    let cap = 24 + entry.bytes().len() as u64;
    assert!(matches!(
        dir::plan(
            root,
            &entries,
            &mut slots,
            dir::BuildOptions {
                max_output_bytes: cap,
                ..dir::BuildOptions::default()
            }
        ),
        Err(Error::Capacity)
    ));
    let plan = dir::plan(
        root,
        &entries,
        &mut slots,
        dir::BuildOptions {
            max_output_bytes: cap,
            inclusion: dir::Inclusion::Partial,
            ..dir::BuildOptions::default()
        },
    )?;
    assert_eq!(plan.report().omitted_entries, 1);
    assert_eq!(plan.placements()[0].source_index, 0);
    let mut short = vec![0xa7; cap as usize - 1];
    assert_eq!(plan.write(&mut short), Err(Error::Capacity));
    assert!(short.iter().all(|b| *b == 0xa7));
    let mut exact = vec![0xa7; cap as usize + 5];
    let written = plan.write(&mut exact)?;
    assert_eq!(&exact[written..], &[0xa7; 5]);
    assert_eq!(
        collect(&exact[..written], 23, Policy::default())?
            .uris
            .len(),
        1
    );
    let items = [item(4, b"long payload"), item(5, b"x")];
    let mut order = [0; 2];
    let mut plain = [0; 512];
    let selection = md::plan_uncompressed(
        &items,
        &mut order,
        &mut plain,
        md::Limits::default(),
        md::Options {
            inclusion: md::Inclusion::Partial,
            max_output_bytes: 33,
            ..md::Options::default()
        },
    )?;
    assert_ne!(selection.report().omitted_entries, 0);
    let mut md_out = [0; 64];
    let partial = dir::PreparedMetadata::materialize(&selection, &mut md_out)?;
    assert!(matches!(
        dir::plan(partial, &[], &mut [], dir::BuildOptions::default()),
        Err(Error::PartialMetadata)
    ));
    let p = dir::plan(
        partial,
        &[],
        &mut [],
        dir::BuildOptions {
            allow_partial_metadata: true,
            ..dir::BuildOptions::default()
        },
    )?;
    assert_ne!(p.report().metadata_omissions, 0);
    Ok(())
}

#[test]
fn ksk_rejects_while_size_work_and_segment_limits_are_typed() -> TestResult {
    let root = raw(&[])?;
    let metadata =
        dir::PreparedMetadata::validate(&root, &mut [], &mut md::NoCodec, md::Limits::default())?;
    let uri = Uri::parse(b"gnunet://fs/ksk/example", gnunet_fs::Limits::default())?;
    let mut output = [0xa7; 1024];
    assert!(matches!(
        dir::PreparedEntry::prepare(uri, metadata, &mut output),
        Err(Error::Keyword)
    ));
    assert!(output.iter().all(|b| *b == 0xa7));
    let mut illegal = build(&root, &[])?;
    let mut uri_text = vec![0; uri.encoded_len()?];
    uri.encode(&mut uri_text)?;
    illegal.extend_from_slice(&uri_text);
    illegal.push(0);
    illegal.extend_from_slice(&(root.len() as u32).to_be_bytes());
    illegal.extend_from_slice(&root);
    assert!(matches!(
        collect(&illegal, 2, Policy::default()),
        Err(dir::Failure {
            error: Error::Keyword,
            ..
        })
    ));
    let data = build(&root, &[])?;
    for limits in [
        dir::Limits {
            max_work: 1,
            ..dir::Limits::default()
        },
        dir::Limits {
            max_extent: 1,
            ..dir::Limits::default()
        },
        dir::Limits {
            max_record_bytes: 1,
            ..dir::Limits::default()
        },
    ] {
        let mut carry = [0; 64];
        let mut p = Parser::new(&mut carry, limits, Policy::default());
        assert!(matches!(
            p.feed(
                Segment {
                    base: 0,
                    bytes: &data,
                    final_extent: Some(data.len() as u64)
                },
                &mut [],
                &mut md::NoCodec
            ),
            Err(dir::Failure {
                error: Error::Limit,
                ..
            })
        ));
    }
    let mut carry = [0; 64];
    let mut p = Parser::new(&mut carry, dir::Limits::default(), Policy::default());
    assert!(matches!(
        p.feed(
            Segment {
                base: 1,
                bytes: &[],
                final_extent: None
            },
            &mut [],
            &mut md::NoCodec
        ),
        Err(dir::Failure {
            error: Error::Input,
            ..
        })
    ));
    assert!(
        Parser::from_block(
            &mut carry,
            u64::MAX,
            dir::Limits::default(),
            Policy::default()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn actual_inline_verification_encodes_every_node_and_never_trusts_length_alone() -> TestResult {
    for size in [0, 1, 32767, 32768, 32769, 65535, 65536, 65537] {
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let mut keys = vec![
            BlockKey {
                key: [0; 64],
                query: [0; 64]
            };
            content::Layout::new(size as u64).required_keys()
        ];
        let mut index = vec![0; 32768];
        let mut encoded = vec![0; 32784];
        let mut encoder = content::FileEncoder::new(size as u64, &mut keys)?;
        while let Some(node) = encoder.next() {
            if node.level() == 0 {
                let range = node.range();
                encoder.push_data(
                    &bytes[range.start as usize..range.end as usize],
                    &mut encoded,
                )?;
            } else {
                encoder.emit_index(&mut index, &mut encoded)?;
            }
        }
        let expected = encoder.content().ok_or(Error::Input)?;
        let hint = dir::InlineHint {
            index: 0,
            item: item(174, &bytes),
        };
        let verified = dir::verify_inline(
            hint,
            expected.uri(),
            dir::InlineBuffers {
                keys: &mut keys,
                index: &mut index,
                encoded: &mut encoded,
            },
            u128::MAX,
        )?;
        assert_eq!(verified.bytes(), bytes);
        assert_eq!(verified.content(), expected);
        assert_eq!(verified.item().kind, 174);
        assert_eq!(
            dir::automatic_inline_fits(expected.uri(), verified, 100, 101)?,
            size > 0 && size <= 65536
        );
        let mut corrupt = expected;
        corrupt.query[0] ^= 1;
        assert!(matches!(
            dir::verify_inline(
                hint,
                corrupt.uri(),
                dir::InlineBuffers {
                    keys: &mut keys,
                    index: &mut index,
                    encoded: &mut encoded
                },
                u128::MAX
            ),
            Err(Error::Authentication)
        ));
        corrupt = expected;
        corrupt.size += 1;
        assert!(matches!(
            dir::verify_inline(
                hint,
                corrupt.uri(),
                dir::InlineBuffers {
                    keys: &mut keys,
                    index: &mut index,
                    encoded: &mut encoded
                },
                u128::MAX
            ),
            Err(Error::Authentication)
        ));
        corrupt = expected;
        corrupt.key[0] ^= 1;
        assert!(matches!(
            dir::verify_inline(
                hint,
                corrupt.uri(),
                dir::InlineBuffers {
                    keys: &mut keys,
                    index: &mut index,
                    encoded: &mut encoded
                },
                u128::MAX
            ),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            dir::verify_inline(
                hint,
                expected.uri(),
                dir::InlineBuffers {
                    keys: &mut keys,
                    index: &mut index,
                    encoded: &mut encoded
                },
                0
            ),
            Err(Error::Limit)
        ));
        assert!(matches!(
            dir::verify_inline(
                hint,
                expected.uri(),
                dir::InlineBuffers {
                    keys: &mut keys,
                    index: &mut index,
                    encoded: &mut []
                },
                u128::MAX
            ),
            Err(Error::Content(gnunet_types::Error::Capacity))
        ));
        if size > 32768 {
            assert!(matches!(
                dir::verify_inline(
                    hint,
                    expected.uri(),
                    dir::InlineBuffers {
                        keys: &mut [],
                        index: &mut index,
                        encoded: &mut encoded
                    },
                    u128::MAX
                ),
                Err(Error::Content(gnunet_types::Error::Capacity))
            ));
        }
        let signer = EddsaPrivateKey::from_seed([8; 32]);
        let loc = gnunet_fs::Location::sign(expected, &signer, AbsoluteTime::from_micros(0))?;
        assert_eq!(
            dir::verify_inline(
                hint,
                Uri::Location(loc),
                dir::InlineBuffers {
                    keys: &mut keys,
                    index: &mut index,
                    encoded: &mut encoded
                },
                u128::MAX
            )?
            .content(),
            expected
        );
    }
    Ok(())
}

#[test]
fn nested_empty_directory_is_an_actual_inline_artifact_not_a_mime_proof() -> TestResult {
    let child = build(&raw(&[dir::MIME_ITEM])?, &[])?;
    let md = raw(&[dir::MIME_ITEM, item(174, &child)])?;
    let data = build(
        &raw(&[dir::MIME_ITEM])?,
        &[(content(child.len() as u64).uri(), md)],
    )?;
    let parsed = collect(&data, 17, Policy::default())?;
    assert_eq!(parsed.uris.len(), 1);
    let md = md::decode_uncompressed(&parsed.metadata[0], md::Limits::default(), md::Mode::Strict)?;
    if let md::Decoded::Present(metadata) = md {
        assert_eq!(dir::claims_directory(metadata.items()), Some(true));
        let hint = dir::hints(metadata.items()).next().ok_or(Error::Input)?;
        assert_eq!(collect(hint.item.data, 3, Policy::default())?.uris.len(), 0);
        let mut out = [0; 32784];
        assert!(matches!(
            dir::verify_inline(
                hint,
                content(child.len() as u64).uri(),
                dir::InlineBuffers {
                    keys: &mut [],
                    index: &mut [],
                    encoded: &mut out
                },
                u128::MAX
            ),
            Err(Error::Authentication)
        ));
        let expected = content::encode_data(&child, &mut out)?
            .key()
            .content(child.len() as u64);
        let verified = dir::verify_inline(
            hint,
            expected.uri(),
            dir::InlineBuffers {
                keys: &mut [],
                index: &mut [],
                encoded: &mut out,
            },
            u128::MAX,
        )?;
        assert!(collect(verified.bytes(), 3, Policy::default())?.complete);
        let unresolved = Namespace::new(EddsaPublicKey::from_bytes([5; 32]), b"name")?;
        assert!(matches!(
            dir::verify_inline(
                hint,
                Uri::Namespace(unresolved),
                dir::InlineBuffers {
                    keys: &mut [],
                    index: &mut [],
                    encoded: &mut out
                },
                u128::MAX
            ),
            Err(Error::Unresolved)
        ));
    }
    Ok(())
}
