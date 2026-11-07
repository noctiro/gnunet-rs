//! Metadata framing/selection tests; actual zlib composition is in fs-codec.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify wire boundaries and rejection ownership"
)]
use gnunet_fs::metadata::{
    self as md, CodecError, Decoded, EntryIssue, Error, Format, Inclusion, Inflater, Item, Limits,
    Mode, Options, Progress, Recovery,
};

fn value<'a>(kind: u32, format: Format, data: &'a [u8]) -> Item<'a> {
    Item {
        kind,
        format,
        data,
        plugin: None,
        mime: None,
    }
}
fn present(decoded: Decoded<'_>) -> Result<md::Metadata<'_>, Error> {
    match decoded {
        Decoded::Present(body) => Ok(body),
        Decoded::NullMarker => Err(Error::Invalid),
    }
}
fn encode(items: &[Item<'_>]) -> Result<Vec<u8>, Error> {
    let mut order = vec![0; items.len()];
    let mut plain = vec![0; 4096];
    let plan = md::plan_uncompressed(
        items,
        &mut order,
        &mut plain,
        Limits::default(),
        Options::default(),
    )?;
    let mut bytes = vec![0; plan.report().wire_bytes];
    plan.write(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn descriptor_words_and_reverse_payload_have_no_private_header() -> Result<(), Error> {
    let item = Item {
        mime: Some(b"\0"),
        ..value(4, Format::Utf8, b"abc\0")
    };
    let actual = encode(&[item])?;
    let mut expected = Vec::new();
    for word in [2_u32, 1, 25, 4, 1, 4, 0, 1] {
        expected.extend_from_slice(&word.to_be_bytes());
    }
    expected.extend_from_slice(b"\0abc\0");
    assert_eq!(actual, expected);
    let metadata = present(md::decode_uncompressed(
        &actual,
        Limits::default(),
        Mode::Strict,
    )?)?;
    assert!(metadata.is_complete());
    assert_eq!(metadata.declared_entries(), 1);
    assert_eq!(metadata.items().collect::<Vec<_>>(), [item]);
    Ok(())
}

#[test]
fn records_preserve_binary_string_labels_null_names_and_unknown_types() -> Result<(), Error> {
    let items = [
        value(u32::MAX, Format::Binary, &[]),
        value(5, Format::CString, b"\xff\0"),
        value(6, Format::Utf8, b"\xff\0"),
        Item {
            plugin: Some(b"\0"),
            mime: Some(b"application/octet-stream\0"),
            ..value(7, Format::Binary, b"a\0b")
        },
        value(8, Format::Utf8, b"\0"),
    ];
    let bytes = encode(&items)?;
    let decoded = present(md::decode_uncompressed(
        &bytes,
        Limits::default(),
        Mode::Strict,
    )?)?;
    let mut actual = decoded.items().collect::<Vec<_>>();
    actual.sort_by_key(|item| item.kind);
    let mut expected = items.to_vec();
    expected.sort_by_key(|item| item.kind);
    assert_eq!(actual, expected);
    assert!(items[1].utf8().is_err());
    assert!(items[2].utf8().is_err());
    assert_eq!(items[0].text(), None);
    assert_eq!(items[4].utf8().map_err(|_| Error::Invalid)?, Some(""));
    Ok(())
}

#[test]
fn absent_v1_and_present_empty_are_three_explicit_states() -> Result<(), Error> {
    let mut absent = [0x55; 8];
    assert_eq!(md::write_absent(&mut absent)?, 4);
    assert_eq!(absent, [0, 0, 0, 0, 0x55, 0x55, 0x55, 0x55]);
    let (decoded, used) = md::decode_length_prefixed(
        &absent,
        &mut [],
        &mut md::NoCodec,
        Limits::default(),
        Mode::Strict,
    )?;
    assert!(decoded.is_none());
    assert_eq!(used, 4);
    let mut null = [0xff; 16];
    null[..4].copy_from_slice(&(1_u32 | md::COMPRESSED).to_be_bytes());
    assert!(matches!(
        md::decode_uncompressed(&null, Limits::default(), Mode::Strict)?,
        Decoded::NullMarker
    ));
    let empty = encode(&[])?;
    assert_eq!(empty, [0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(
        present(md::decode_uncompressed(
            &empty,
            Limits::default(),
            Mode::Strict
        )?)?
        .is_complete()
    );
    for length in 0..12 {
        assert!(matches!(
            md::decode_uncompressed(&empty[..length], Limits::default(), Mode::Strict),
            Err(Error::Truncated)
        ));
    }
    let mut unsupported = empty;
    unsupported[3] = 3;
    assert!(matches!(
        md::decode_uncompressed(&unsupported, Limits::default(), Mode::Strict),
        Err(Error::Version(3))
    ));
    Ok(())
}

#[test]
fn invalid_entries_and_unused_payload_never_become_complete_containers() -> Result<(), Error> {
    let items = [
        value(10, Format::Utf8, b"a\0"),
        value(11, Format::Utf8, b"b\0"),
        value(12, Format::Utf8, b"c\0"),
    ];
    for index in 0..3 {
        let mut bytes = encode(&items)?;
        let format = md::HEADER_BYTES + index * md::ENTRY_BYTES + 4;
        bytes[format..format + 4].fill(0);
        assert!(matches!(
            md::decode_uncompressed(&bytes, Limits::default(), Mode::Strict),
            Err(Error::Entry {
                issue: EntryIssue::Format,
                ..
            })
        ));
        let recovered = present(md::decode_uncompressed(
            &bytes,
            Limits::default(),
            Mode::ReferencePrefix,
        )?)?;
        assert!(!recovered.is_complete());
        assert_eq!(recovered.accepted_entries(), index);
        assert_eq!(
            recovered.recovery(),
            Some(Recovery::Entry {
                index: index as u32,
                issue: EntryIssue::Format
            })
        );
        assert_eq!(recovered.items().collect::<Vec<_>>(), items[..index]);
    }
    let mut trailing = encode(&[])?;
    trailing[8..12].copy_from_slice(&1_u32.to_be_bytes());
    trailing.push(1);
    assert!(matches!(
        md::decode_uncompressed(&trailing, Limits::default(), Mode::Strict),
        Err(Error::Trailing(1))
    ));
    let recovered = present(md::decode_uncompressed(
        &trailing,
        Limits::default(),
        Mode::ReferencePrefix,
    )?)?;
    assert_eq!(recovered.accepted_entries(), 0);
    assert_eq!(recovered.recovery(), Some(Recovery::Trailing));
    assert_eq!(recovered.unused_payload_bytes(), 1);
    Ok(())
}

#[test]
fn every_field_refusal_and_envelope_limit_is_bounded() -> Result<(), Error> {
    let item = Item {
        plugin: Some(b"p\0"),
        mime: Some(b"m\0"),
        ..value(4, Format::Utf8, b"d\0")
    };
    let original = encode(&[item])?;
    for offset in [8, 12, 16] {
        let mut bad = original.clone();
        bad[12 + offset..16 + offset].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            md::decode_uncompressed(&bad, Limits::default(), Mode::Strict),
            Err(Error::Entry {
                issue: EntryIssue::Length,
                ..
            })
        ));
    }
    for position in [original.len() - 1, original.len() - 3, original.len() - 5] {
        let mut bad = original.clone();
        bad[position] = b'x';
        assert!(matches!(
            md::decode_uncompressed(&bad, Limits::default(), Mode::Strict),
            Err(Error::Entry {
                issue: EntryIssue::Terminator,
                ..
            })
        ));
    }
    for limits in [
        Limits {
            max_coded_bytes: original.len() - 1,
            ..Limits::default()
        },
        Limits {
            max_plain_bytes: 0,
            ..Limits::default()
        },
        Limits {
            max_entries: 0,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            md::decode_uncompressed(&original, limits, Mode::Strict),
            Err(Error::Limit)
        ));
    }
    let mut bad = original;
    bad[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        md::decode_uncompressed(
            &bad,
            Limits {
                max_entries: usize::MAX,
                ..Limits::default()
            },
            Mode::Strict
        ),
        Err(Error::Invalid | Error::Overflow)
    ));
    Ok(())
}

#[test]
fn plans_are_atomic_and_partial_reports_preserve_only_selected_values() -> Result<(), Error> {
    let items = [
        value(1, Format::Binary, &[1; 128]),
        value(2, Format::Utf8, b"small\0"),
    ];
    let mut order = [99; 2];
    let mut plain = [0x55; 256];
    let full = md::plan_uncompressed(
        &items,
        &mut order,
        &mut plain,
        Limits::default(),
        Options::default(),
    )?;
    for capacity in 0..full.report().wire_bytes {
        let mut out = vec![0x55; capacity];
        assert_eq!(full.write(&mut out), Err(Error::Capacity));
        assert!(out.iter().all(|byte| *byte == 0x55));
    }
    let options = Options {
        inclusion: Inclusion::Partial,
        max_output_bytes: 38,
        ..Options::default()
    };
    let partial =
        md::plan_uncompressed(&items, &mut order, &mut plain, Limits::default(), options)?;
    assert_eq!(partial.report().source_entries, 2);
    assert_eq!(partial.report().selected_entries, 1);
    assert_eq!(partial.report().omitted_entries, 1);
    assert_eq!(partial.selected_source_indices(), [1]);
    let mut out = [0x55; 42];
    assert_eq!(partial.write(&mut out)?, 38);
    assert_eq!(&out[38..], &[0x55; 4]);
    assert_eq!(
        present(md::decode_uncompressed(
            &out[..38],
            Limits::default(),
            Mode::Strict
        )?)?
        .items()
        .collect::<Vec<_>>(),
        [items[1]]
    );
    let empty = md::plan_uncompressed(
        &items,
        &mut order,
        &mut plain,
        Limits::default(),
        Options {
            max_output_bytes: 12,
            ..options
        },
    )?;
    assert_eq!(empty.report().selected_entries, 0);
    assert_eq!(empty.report().omitted_entries, 2);
    assert!(matches!(
        md::plan_uncompressed(
            &items,
            &mut order,
            &mut plain,
            Limits::default(),
            Options {
                max_trials: 1,
                ..options
            }
        ),
        Err(Error::Work)
    ));
    assert!(matches!(
        md::plan_uncompressed(
            &items,
            &mut order,
            &mut plain,
            Limits::default(),
            Options {
                max_output_bytes: 11,
                ..options
            }
        ),
        Err(Error::Capacity)
    ));
    Ok(())
}

struct Counter {
    called: usize,
    result: Result<Progress, CodecError>,
}
impl Inflater for Counter {
    fn inflate(&mut self, _: &[u8], output: &mut [u8]) -> Result<Progress, CodecError> {
        self.called += 1;
        output.fill(0xaa);
        self.result
    }
}
#[test]
fn codec_contract_counters_and_scratch_wipe_cannot_bypass_envelope_preflight() -> Result<(), Error>
{
    let mut bytes = encode(&[])?;
    bytes[..4].copy_from_slice(&(2_u32 | md::COMPRESSED).to_be_bytes());
    bytes[8..12].copy_from_slice(&4_u32.to_be_bytes());
    bytes.push(0);
    let mut scratch = [0x55; 8];
    let mut codec = Counter {
        called: 0,
        result: Ok(Progress {
            consumed: 1,
            produced: 3,
        }),
    };
    assert!(matches!(
        md::decode(
            &bytes,
            &mut scratch,
            &mut codec,
            Limits::default(),
            Mode::Strict
        ),
        Err(Error::Codec(CodecError::Length))
    ));
    assert_eq!(codec.called, 1);
    assert_eq!(scratch, [0, 0, 0, 0, 0x55, 0x55, 0x55, 0x55]);
    scratch.fill(0x55);
    assert!(matches!(
        md::decode(
            &bytes,
            &mut scratch[..3],
            &mut codec,
            Limits::default(),
            Mode::Strict
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(codec.called, 1);
    assert_eq!(scratch, [0x55; 8]);
    codec.result = Err(CodecError::Invalid);
    assert!(matches!(
        md::decode(
            &bytes,
            &mut scratch,
            &mut codec,
            Limits::default(),
            Mode::Strict
        ),
        Err(Error::Codec(CodecError::Invalid))
    ));
    assert_eq!(scratch, [0, 0, 0, 0, 0x55, 0x55, 0x55, 0x55]);
    Ok(())
}

#[test]
fn semantic_import_matches_duplicate_enrichment_and_bounded_filename_rules() -> Result<(), Error> {
    let first = Item {
        plugin: Some(b"first\0"),
        ..value(4, Format::CString, b"same\0")
    };
    let second = Item {
        plugin: Some(b"second\0"),
        mime: Some(b"text/plain\0"),
        ..value(4, Format::Utf8, b"same\0")
    };
    let mut slots = [None; 3];
    let mut filename = [0x55; 32];
    {
        let mut set = md::Set::new(&mut slots);
        assert_eq!(set.insert(first, &mut [])?, md::Insert::Added);
        assert_eq!(
            set.insert(second, &mut [])?,
            md::Insert::Duplicate {
                mime_enriched: true,
                format_upgraded: true
            }
        );
        assert_eq!(set.len(), 1);
        let imported = set.items().next().ok_or(Error::Invalid)?;
        assert_eq!(imported.plugin, first.plugin);
        assert_eq!(imported.mime, second.mime);
        assert_eq!(imported.format, Format::Utf8);
        let source = value(180, Format::Utf8, b"a\\b\0tail\\\0");
        set.insert(source, &mut filename)?;
        let normalized = set
            .items()
            .find(|item| item.kind == 180)
            .ok_or(Error::Invalid)?;
        assert_eq!(normalized.data, b"a/b\0tail\\\0");
    }
    assert!(filename[10..].iter().all(|byte| *byte == 0x55));
    let mut output = [0x55; 4];
    assert_eq!(
        md::normalize_filename(2, b"longer", &mut output),
        Err(Error::Capacity)
    );
    assert_eq!(output, [0x55; 4]);
    Ok(())
}

#[test]
fn filename_normalization_follows_raw_duplicate_detection_even_at_capacity() -> Result<(), Error> {
    let mut slots = [None; 2];
    let mut first = [0; 4];
    let mut second = [0; 4];
    let mut set = md::Set::new(&mut slots);
    let source = value(2, Format::CString, b"a\\b\0");
    assert_eq!(set.insert(source, &mut first)?, md::Insert::Added);
    // The first stored value is normalized, so the same raw backslash value
    // does not match it until the second insertion is normalized as well.
    assert_eq!(set.insert(source, &mut second)?, md::Insert::Added);
    assert_eq!(set.len(), 2);
    assert_eq!(
        set.insert(value(2, Format::Utf8, b"a/b\0"), &mut [])?,
        md::Insert::Duplicate {
            mime_enriched: false,
            format_upgraded: true
        }
    );
    assert_eq!(set.len(), 2);
    assert!(matches!(
        set.insert(value(4, Format::Binary, b"new"), &mut []),
        Err(Error::Capacity)
    ));
    assert!(set.items().all(|item| item.data == b"a/b\0"));
    Ok(())
}

#[test]
fn name_canonicalization_is_reported_and_invalid_source_never_writes_workspaces()
-> Result<(), Error> {
    let item = Item {
        plugin: Some(b"p\0suffix\0"),
        ..value(9, Format::Binary, b"x")
    };
    let mut order = [0];
    let mut plain = [0; 64];
    let plan = md::plan_uncompressed(
        &[item],
        &mut order,
        &mut plain,
        Limits::default(),
        Options::default(),
    )?;
    assert_eq!(plan.report().normalized_names, 1);
    let mut bytes = [0; 64];
    let n = plan.write(&mut bytes)?;
    let imported = present(md::decode_uncompressed(
        &bytes[..n],
        Limits::default(),
        Mode::Strict,
    )?)?
    .items()
    .next()
    .ok_or(Error::Invalid)?;
    assert_eq!(imported.plugin, Some(b"p\0".as_slice()));
    let mut order = [99];
    let mut plain = [0x55; 64];
    assert!(matches!(
        md::plan_uncompressed(
            &[value(1, Format::Utf8, b"unterminated")],
            &mut order,
            &mut plain,
            Limits::default(),
            Options::default()
        ),
        Err(Error::Invalid)
    ));
    assert_eq!(order, [99]);
    assert_eq!(plain, [0x55; 64]);
    Ok(())
}
