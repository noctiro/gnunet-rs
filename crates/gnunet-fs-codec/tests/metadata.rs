//! Actual pure Rust zlib/metadata composition; original C acceptance is separate.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare actual codec and metadata boundaries"
)]
use gnunet_fs::metadata::{
    self as md, CodecError, Compression, Decoded, Deflater, EntryIssue, Error, Format, Inclusion,
    Item, Limits, Mode, Options, Recovery,
};
use gnunet_fs_codec::{Compressor, Inflate};

fn item(kind: u32, format: Format, data: &[u8]) -> Item<'_> {
    Item {
        kind,
        format,
        data,
        plugin: None,
        mime: None,
    }
}
fn present(value: Decoded<'_>) -> Result<md::Metadata<'_>, Error> {
    match value {
        Decoded::Present(m) => Ok(m),
        Decoded::NullMarker => Err(Error::Invalid),
    }
}
fn encoded(
    items: &[Item<'_>],
    compressor: &mut impl Deflater,
    options: Options,
) -> Result<(Vec<u8>, md::Report), Error> {
    let mut order = vec![0; items.len()];
    let mut plain = vec![0; 128 * 1024];
    let mut coded = vec![0; 128 * 1024];
    let plan = md::plan(
        items,
        &mut order,
        &mut plain,
        &mut coded,
        compressor,
        Limits::default(),
        options,
    )?;
    let report = plan.report();
    let mut output = vec![0; report.wire_bytes];
    plan.write(&mut output)?;
    Ok((output, report))
}

#[test]
fn actual_zlib_and_raw_paths_retain_all_reverse_payload_values() -> Result<(), Error> {
    let items = [
        Item {
            plugin: Some(b"first\0"),
            mime: Some(b"text/plain\0"),
            ..item(4, Format::Utf8, "标题\0".as_bytes())
        },
        Item {
            plugin: Some(b"\0"),
            mime: Some(b"application/octet-stream\0"),
            ..item(u32::MAX, Format::Binary, b"a\0\xffb")
        },
        item(6, Format::CString, b"\xff\0"),
        item(7, Format::Binary, b""),
    ];
    let mut compressor = Compressor::new();
    let mut inflater = Inflate::new();
    for compression in [
        Compression::Never,
        Compression::Always,
        Compression::Adaptive,
    ] {
        let (bytes, report) = encoded(
            &items,
            &mut compressor,
            Options {
                compression,
                ..Options::default()
            },
        )?;
        assert_eq!(report.selected_entries, items.len());
        assert_eq!(report.omitted_entries, 0);
        if compression == Compression::Always {
            assert!(report.compressed);
        }
        if compression == Compression::Never {
            assert!(!report.compressed);
        }
        let mut scratch = vec![0; report.plain_bytes + 8];
        let parsed = present(md::decode(
            &bytes,
            &mut scratch,
            &mut inflater,
            Limits::default(),
            Mode::Strict,
        )?)?;
        assert!(parsed.is_complete());
        assert_eq!(parsed.was_compressed(), report.compressed);
        let mut actual = parsed.items().collect::<Vec<_>>();
        actual.sort_by_key(|i| i.kind);
        let mut expected = items.to_vec();
        expected.sort_by_key(|i| i.kind);
        assert_eq!(actual, expected);
    }
    Ok(())
}

#[test]
fn compression_keeps_full_values_when_uncompressed_cannot_fit() -> Result<(), Error> {
    let data = vec![b'x'; 32768];
    let values = [
        item(10, Format::Binary, &data),
        item(11, Format::Binary, &data),
    ];
    let mut compressor = Compressor::new();
    let options = Options {
        max_output_bytes: 512,
        compression: Compression::Never,
        ..Options::default()
    };
    assert!(matches!(
        encoded(&values, &mut compressor, options),
        Err(Error::Capacity)
    ));
    let (bytes, report) = encoded(
        &values,
        &mut compressor,
        Options {
            compression: Compression::Adaptive,
            ..options
        },
    )?;
    assert!(report.compressed);
    assert!(report.wire_bytes <= 512);
    assert_eq!(report.selected_entries, 2);
    let mut scratch = vec![0; report.plain_bytes];
    let parsed = present(md::decode(
        &bytes,
        &mut scratch,
        &mut Inflate::new(),
        Limits::default(),
        Mode::Strict,
    )?)?;
    assert!(parsed.items().all(|i| i.data == data));
    let (_, partial) = encoded(
        &values,
        &mut compressor,
        Options {
            inclusion: Inclusion::Partial,
            ..options
        },
    )?;
    assert_eq!(partial.selected_entries, 0);
    assert_eq!(partial.omitted_entries, 2);
    Ok(())
}

#[test]
fn real_inflate_length_checksum_truncation_and_trailing_errors_reset_for_retry() -> Result<(), Error>
{
    let data = vec![b'q'; 1024];
    let values = [item(10, Format::Binary, &data)];
    let (original, report) = encoded(
        &values,
        &mut Compressor::new(),
        Options {
            compression: Compression::Always,
            ..Options::default()
        },
    )?;
    let mut variants = Vec::new();
    let mut oversized = original.clone();
    oversized[8..12].copy_from_slice(&((report.plain_bytes + 1) as u32).to_be_bytes());
    variants.push(oversized);
    let mut undersized = original.clone();
    undersized[8..12].copy_from_slice(&((report.plain_bytes - 1) as u32).to_be_bytes());
    variants.push(undersized);
    let mut checksum = original.clone();
    let end = checksum.len() - 1;
    checksum[end] ^= 1;
    variants.push(checksum);
    variants.push(original[..original.len() - 1].to_vec());
    let mut trailing = original.clone();
    trailing.push(0x55);
    variants.push(trailing);
    let mut inflater = Inflate::new();
    for bad in variants {
        let expected = u32::from_be_bytes([bad[8], bad[9], bad[10], bad[11]]) as usize;
        let mut scratch = vec![0x55; expected + 8];
        assert!(matches!(
            md::decode(
                &bad,
                &mut scratch,
                &mut inflater,
                Limits::default(),
                Mode::Strict
            ),
            Err(Error::Codec(_))
        ));
        assert!(scratch[..expected].iter().all(|b| *b == 0));
        assert!(scratch[expected..].iter().all(|b| *b == 0x55));
        let mut scratch = vec![0; report.plain_bytes];
        assert!(
            present(md::decode(
                &original,
                &mut scratch,
                &mut inflater,
                Limits::default(),
                Mode::Strict
            )?)?
            .is_complete()
        );
    }
    Ok(())
}

#[test]
fn valid_zlib_can_contain_a_reported_invalid_entry_prefix() -> Result<(), Error> {
    let values = [
        item(10, Format::Utf8, b"a\0"),
        item(11, Format::Utf8, b"b\0"),
        item(12, Format::Utf8, b"c\0"),
    ];
    let mut compressor = Compressor::new();
    let (mut raw, _) = encoded(
        &values,
        &mut compressor,
        Options {
            compression: Compression::Never,
            ..Options::default()
        },
    )?;
    raw[12 + 20 + 4..12 + 20 + 8].fill(0);
    let mut compressed = vec![0; 1024];
    let produced = compressor
        .deflate(&raw[12..], &mut compressed)
        .map_err(Error::Codec)?;
    let mut wire = raw[..12].to_vec();
    wire[..4].copy_from_slice(&(2 | md::COMPRESSED).to_be_bytes());
    wire.extend_from_slice(&compressed[..produced.produced]);
    let mut inflater = Inflate::new();
    let mut scratch = [0; 256];
    assert!(matches!(
        md::decode(
            &wire,
            &mut scratch,
            &mut inflater,
            Limits::default(),
            Mode::Strict
        ),
        Err(Error::Entry {
            index: 1,
            issue: EntryIssue::Format
        })
    ));
    let recovered = present(md::decode(
        &wire,
        &mut scratch,
        &mut inflater,
        Limits::default(),
        Mode::ReferencePrefix,
    )?)?;
    assert_eq!(recovered.accepted_entries(), 1);
    assert!(!recovered.is_complete());
    assert_eq!(recovered.items().collect::<Vec<_>>(), values[..1]);
    assert_eq!(
        recovered.recovery(),
        Some(Recovery::Entry {
            index: 1,
            issue: EntryIssue::Format
        })
    );
    Ok(())
}

#[test]
fn compressed_header_budget_and_uncompressed_after_reuse_are_explicit() -> Result<(), Error> {
    let data = vec![42; 4096];
    let values = [item(10, Format::Binary, &data)];
    let mut compressor = Compressor::new();
    let always = Options {
        compression: Compression::Always,
        ..Options::default()
    };
    let (first, report) = encoded(&values, &mut compressor, always)?;
    assert!(matches!(
        encoded(
            &values,
            &mut compressor,
            Options {
                max_output_bytes: report.wire_bytes - 1,
                ..always
            }
        ),
        Err(Error::Capacity)
    ));
    let (second, exact) = encoded(
        &values,
        &mut compressor,
        Options {
            max_output_bytes: report.wire_bytes,
            ..always
        },
    )?;
    assert_eq!(first, second);
    assert_eq!(exact.wire_bytes, report.wire_bytes);
    let (raw, raw_report) = encoded(
        &values,
        &mut compressor,
        Options {
            compression: Compression::Never,
            ..always
        },
    )?;
    assert!(!raw_report.compressed);
    assert_eq!(&raw[..4], &2_u32.to_be_bytes());
    let mut scratch = vec![0; raw_report.plain_bytes];
    assert!(
        present(md::decode(
            &raw,
            &mut scratch,
            &mut Inflate::new(),
            Limits::default(),
            Mode::Strict
        )?)?
        .is_complete()
    );
    Ok(())
}

#[test]
fn compressed_empty_and_standard_optional_framing_keep_distinct_meanings() -> Result<(), Error> {
    let (raw, report) = encoded(
        &[],
        &mut Compressor::new(),
        Options {
            compression: Compression::Always,
            ..Options::default()
        },
    )?;
    assert!(report.compressed);
    assert_eq!(report.plain_bytes, 0);
    let mut framed = (raw.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&raw);
    framed.push(0xaa);
    let (decoded, consumed) = md::decode_length_prefixed(
        &framed,
        &mut [],
        &mut Inflate::new(),
        Limits::default(),
        Mode::Strict,
    )?;
    assert_eq!(consumed, framed.len() - 1);
    let metadata = present(decoded.ok_or(Error::Invalid)?)?;
    assert!(metadata.is_complete());
    assert_eq!(metadata.declared_entries(), 0);
    let (absent, consumed) = md::decode_length_prefixed(
        &[0, 0, 0, 0, 0xaa],
        &mut [],
        &mut Inflate::new(),
        Limits::default(),
        Mode::Strict,
    )?;
    assert!(absent.is_none());
    assert_eq!(consumed, 4);
    Ok(())
}

#[test]
fn unavailable_and_invalid_compressor_capabilities_are_not_silent_success() -> Result<(), Error> {
    let values = [item(10, Format::Binary, b"value")];
    assert!(matches!(
        encoded(&values, &mut md::NoCodec, Options::default()),
        Err(Error::Codec(CodecError::Unavailable))
    ));
    Ok(())
}
