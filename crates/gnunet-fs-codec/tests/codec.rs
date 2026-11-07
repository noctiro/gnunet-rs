//! Actual provider checks using independent stored/fixed-Huffman zlib fixtures.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify exact codec bytes, framing rejection and reset boundaries"
)]

use gnunet_fs::metadata::{CodecError, Inflater, Progress};
use gnunet_fs_codec::Inflate;

// A complete fixed-Huffman member for the five literal bytes 'hello'.
const HELLO: &[u8] = &[
    0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15,
];
const EMPTY: &[u8] = &[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01];

fn stored(input: &[u8]) -> Vec<u8> {
    // Test-only zlib framing with one final stored DEFLATE block. This is not
    // the production compressor or an external C-interoperability receipt.
    let len = input.len() as u16;
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(&(!len).to_le_bytes());
    bytes.extend_from_slice(input);
    let mut a = 1_u32;
    let mut b = 0_u32;
    for byte in input {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    bytes.extend_from_slice(&((b << 16) | a).to_be_bytes());
    bytes
}

#[test]
fn fixed_huffman_empty_and_binary_members_decode_without_alloc_feature() -> Result<(), CodecError> {
    let mut decoder = Inflate::new();
    let mut hello = [0; 5];
    assert_eq!(
        decoder.inflate(HELLO, &mut hello)?,
        Progress {
            consumed: HELLO.len(),
            produced: 5
        }
    );
    assert_eq!(&hello, b"hello");
    assert_eq!(
        decoder.inflate(EMPTY, &mut [])?,
        Progress {
            consumed: EMPTY.len(),
            produced: 0
        }
    );
    let input: Vec<_> = (0..4097).map(|i| (i % 251) as u8).collect();
    let stream = stored(&input);
    let mut output = vec![0; input.len()];
    assert_eq!(decoder.inflate(&stream, &mut output)?.produced, input.len());
    assert_eq!(output, input);
    Ok(())
}

#[test]
fn short_output_is_capacity_and_retry_starts_a_new_member() -> Result<(), CodecError> {
    let mut decoder = Inflate::new();
    let mut output = [0x55; 7];
    assert_eq!(
        decoder.inflate(HELLO, &mut output[..4]),
        Err(CodecError::Capacity)
    );
    assert_eq!(&output[4..], &[0x55; 3]);
    assert_eq!(decoder.inflate(HELLO, &mut output[..5])?.produced, 5);
    assert_eq!(&output[..5], b"hello");
    assert_eq!(&output[5..], &[0x55; 2]);
    let mut larger = [0x55; 9];
    assert_eq!(decoder.inflate(HELLO, &mut larger)?.produced, 5);
    assert_eq!(&larger[..5], b"hello");
    Ok(())
}

#[test]
fn incomplete_header_body_and_adler_never_finish_a_member() -> Result<(), CodecError> {
    let mut decoder = Inflate::new();
    for length in 0..HELLO.len() {
        let mut output = [0; 5];
        assert_eq!(
            decoder.inflate(&HELLO[..length], &mut output),
            Err(CodecError::Truncated)
        );
    }
    let mut output = [0; 5];
    assert_eq!(decoder.inflate(HELLO, &mut output)?.produced, 5);
    assert_eq!(&output, b"hello");
    Ok(())
}

#[test]
fn bad_header_checksum_dictionary_and_other_wrappers_are_refused() -> Result<(), CodecError> {
    let mut decoder = Inflate::new();
    let mut output = [0; 32];
    let mut bad = HELLO.to_vec();
    bad[1] ^= 1;
    assert_eq!(decoder.inflate(&bad, &mut output), Err(CodecError::Invalid));
    let mut bad = HELLO.to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(decoder.inflate(&bad, &mut output), Err(CodecError::Invalid));
    // Valid FCHECK with FDICT set, followed by a dictionary identifier.
    let dictionary = [0x78, 0x20, 0, 0, 0, 0, 0x03, 0, 0, 0, 0, 1];
    assert_eq!(
        decoder.inflate(&dictionary, &mut output),
        Err(CodecError::Invalid)
    );
    assert_eq!(
        decoder.inflate(&HELLO[2..9], &mut output),
        Err(CodecError::Invalid)
    );
    let gzip_header = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    assert_eq!(
        decoder.inflate(&gzip_header, &mut output),
        Err(CodecError::Invalid)
    );
    assert_eq!(decoder.inflate(HELLO, &mut output)?.produced, 5);
    Ok(())
}

#[test]
fn trailing_bytes_and_concatenated_members_are_not_silently_consumed() -> Result<(), CodecError> {
    let mut decoder = Inflate::new();
    let mut output = [0; 5];
    for suffix in [&[0x55][..], EMPTY] {
        let mut stream = HELLO.to_vec();
        stream.extend_from_slice(suffix);
        assert_eq!(
            decoder.inflate(&stream, &mut output),
            Err(CodecError::Trailing)
        );
    }
    assert_eq!(decoder.inflate(EMPTY, &mut [])?.produced, 0);
    assert_eq!(decoder.inflate(HELLO, &mut output)?.produced, 5);
    Ok(())
}

#[cfg(feature = "alloc")]
mod compression {
    use gnunet_fs::metadata::{CodecError, Deflater, Inflater};
    use gnunet_fs_codec::{Compressor, Inflate};

    #[test]
    fn real_compressor_roundtrips_empty_binary_and_repetitive_data() -> Result<(), CodecError> {
        let mut encoder = Compressor::new();
        let mut decoder = Inflate::new();
        for input in [
            vec![],
            vec![0],
            (0..4097).map(|i| (i % 251) as u8).collect(),
            vec![b'a'; 32768],
            b"UTF8 text\0 and a binary\0suffix\xff".to_vec(),
        ] {
            let mut coded = vec![0; input.len() + 128];
            let compressed = encoder.deflate(&input, &mut coded)?;
            assert_eq!(compressed.consumed, input.len());
            assert!(compressed.produced >= 6);
            assert_eq!(coded[0] & 0x0f, 8); // DEFLATE in a zlib header.
            assert_eq!((u16::from(coded[0]) * 256 + u16::from(coded[1])) % 31, 0);
            let mut output = vec![0; input.len()];
            let opened = decoder.inflate(&coded[..compressed.produced], &mut output)?;
            assert_eq!(opened.consumed, compressed.produced);
            assert_eq!(opened.produced, input.len());
            assert_eq!(output, input);
            if input.len() == 32768 {
                assert!(compressed.produced < input.len());
            }
        }
        Ok(())
    }

    #[test]
    fn exhausted_output_and_empty_output_admit_exact_deterministic_retry() -> Result<(), CodecError>
    {
        let input = vec![0x37; 8192];
        let mut encoder = Compressor::new();
        assert_eq!(encoder.deflate(&input, &mut []), Err(CodecError::Capacity));
        let mut short = [0x55; 7];
        assert_eq!(
            encoder.deflate(&input, &mut short[..5]),
            Err(CodecError::Capacity)
        );
        assert_eq!(&short[5..], &[0x55; 2]);
        let mut retry = vec![0; input.len() + 128];
        let a = encoder.deflate(&input, &mut retry)?;
        let mut fresh = vec![0; input.len() + 128];
        let b = Compressor::new().deflate(&input, &mut fresh)?;
        assert_eq!(a, b);
        assert_eq!(&retry[..a.produced], &fresh[..b.produced]);
        let mut too_short = vec![0; a.produced - 1];
        assert_eq!(
            encoder.deflate(&input, &mut too_short),
            Err(CodecError::Capacity)
        );
        let mut exact = vec![0; a.produced];
        assert_eq!(encoder.deflate(&input, &mut exact)?, a);
        assert_eq!(exact, retry[..a.produced]);
        Ok(())
    }

    #[test]
    fn consecutive_independent_members_reset_both_codec_states() -> Result<(), CodecError> {
        let mut encoder = Compressor::new();
        let mut decoder = Inflate::new();
        let mut coded = [0; 2048];
        let mut output = [0; 1024];
        for value in 0..32 {
            let input = vec![value; usize::from(value) * 17];
            let progress = encoder.deflate(&input, &mut coded)?;
            assert_eq!(
                decoder
                    .inflate(&coded[..progress.produced], &mut output)?
                    .produced,
                input.len()
            );
            assert_eq!(&output[..input.len()], input.as_slice());
            let last = progress.produced - 1;
            coded[last] ^= 1;
            assert_eq!(
                decoder.inflate(&coded[..progress.produced], &mut output),
                Err(CodecError::Invalid)
            );
        }
        let n = encoder.deflate(&[], &mut coded)?.produced;
        assert_eq!(decoder.inflate(&coded[..n], &mut [])?.produced, 0);
        Ok(())
    }
}
