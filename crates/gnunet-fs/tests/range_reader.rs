//! Actual selected content authentication; no service/network availability claim.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible source tests assert actual selected proofs and unchanged pending state"
)]
use gnunet_fs::{
    Content,
    content::{
        self, BLOCK_BYTES, BlockKey, CHK_BYTES, FileReader, Layout, MAX_CHILDREN, RangeReader,
        TAG_BYTES,
    },
};
use gnunet_types::Error;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn selected_multilevel_tail_authenticates_only_its_real_ancestors_and_clipped_leaf() -> TestResult {
    // A genuine file with 256 repeated complete leaves and one short tail. We
    // form its actual indexes from real sealed child keys, without materializing
    // the unselected 8 MiB plaintext as a fixture or authenticating it as a range.
    let tail = [0x93; 317];
    let mut wire = vec![0; BLOCK_BYTES + TAG_BYTES];
    let mut scratch = vec![0; BLOCK_BYTES];
    let first_leaf = content::encode_data(&vec![0x29; BLOCK_BYTES], &mut wire)?.key();
    let first_index =
        content::encode_index(&vec![first_leaf; MAX_CHILDREN], &mut scratch, &mut wire)?.key();
    let encoded = content::encode_data(&tail, &mut wire)?;
    let tail_key = encoded.key();
    let tail_wire = encoded.bytes().to_vec();
    let encoded = content::encode_index(&[tail_key], &mut scratch, &mut wire)?;
    let tail_index = encoded.key();
    let tail_index_wire = encoded.bytes().to_vec();
    let encoded = content::encode_index(&[first_index, tail_index], &mut scratch, &mut wire)?;
    let root_wire = encoded.bytes().to_vec();
    let size = BLOCK_BYTES as u64 * MAX_CHILDREN as u64 + tail.len() as u64;
    let source = encoded.key().content(size);
    let base = BLOCK_BYTES as u64 * MAX_CHILDREN as u64;
    let selected = base + 19..base + 147;
    let layout = Layout::new(size);
    assert_eq!(layout.root_level(), 2);
    let mut keys = vec![BlockKey::default(); layout.required_keys()];
    let mut reader = RangeReader::new(source, selected.clone(), &mut keys)?;
    let mut plain = vec![0; BLOCK_BYTES];
    let mut requested = Vec::new();
    let mut selected_bytes = Vec::new();
    assert_eq!(reader.content(), source);
    assert_eq!(reader.range(), selected);
    assert!(reader.completion().is_none());
    while let Some(request) = reader.next() {
        let position = (request.node().level(), request.node().ordinal());
        let actual = match position {
            (2, 0) => &root_wire,
            (1, 1) => &tail_index_wire,
            (0, 256) => &tail_wire,
            _ => return Err("range reader requested an unselected node".into()),
        };
        if requested.is_empty() {
            let mut wrong = actual.clone();
            wrong[0] ^= 1;
            assert!(matches!(
                reader.open_next(&wrong, &mut plain),
                Err(Error::Authentication)
            ));
            assert_eq!(reader.next(), Some(request));
            assert!(reader.completion().is_none());
            assert!(matches!(
                reader.open_next(actual, &mut [0; CHK_BYTES]),
                Err(Error::Capacity)
            ));
            assert_eq!(reader.next(), Some(request));
        }
        requested.push(position);
        if let Some(chunk) = reader.open_next(actual, &mut plain)? {
            assert_eq!(chunk.content(), source);
            assert_eq!(chunk.range(), selected);
            selected_bytes.extend_from_slice(chunk.bytes());
        }
    }
    assert_eq!(requested, [(2, 0), (1, 1), (0, 256)]);
    assert_eq!(selected_bytes, tail[19..147]);
    let proof = reader
        .completion()
        .ok_or("selected range lacks a genuine proof")?;
    assert_eq!(proof.content(), source);
    assert_eq!(proof.range(), selected);
    assert!(matches!(
        reader.open_next(&tail_wire, &mut plain),
        Err(Error::Closed)
    ));
    Ok(())
}

#[test]
fn empty_file_requires_its_actual_root_and_nonempty_zero_ranges_never_mint_proofs() -> TestResult {
    let mut ciphertext = [0; TAG_BYTES];
    let source = content::encode_data(&[], &mut ciphertext)?.key().content(0);
    let mut reader = RangeReader::new(source, 0..0, &mut [])?;
    let original = reader.next().ok_or("empty root not requested")?;
    assert!(reader.completion().is_none());
    assert!(matches!(
        reader.open_next(&ciphertext[..TAG_BYTES - 1], &mut []),
        Err(Error::Malformed)
    ));
    assert_eq!(reader.next(), Some(original));
    let mut corrupt = ciphertext;
    corrupt[0] ^= 1;
    assert!(matches!(
        reader.open_next(&corrupt, &mut []),
        Err(Error::Authentication)
    ));
    assert_eq!(reader.next(), Some(original));
    assert!(reader.completion().is_none());
    let chunk = reader
        .open_next(&ciphertext, &mut [])?
        .ok_or("missing actual empty chunk")?;
    assert!(chunk.bytes().is_empty());
    assert_eq!(chunk.range(), 0..0);
    let proof = reader
        .completion()
        .ok_or("missing actual empty root proof")?;
    assert_eq!(proof.content(), source);
    assert_eq!(proof.range(), 0..0);
    let nonempty = Content { size: 1, ..source };
    assert!(matches!(
        RangeReader::new(nonempty, 0..0, &mut []),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        RangeReader::new(nonempty, 1..1, &mut []),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        RangeReader::new(nonempty, core::ops::Range { start: 1, end: 0 }, &mut []),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        RangeReader::new(source, 0..1, &mut []),
        Err(Error::InvalidInput)
    ));
    // The original full-file API delegates to the same owner and still cannot
    // produce VerifiedFile before opening even an empty file's real root.
    let mut full = FileReader::new(source, &mut [])?;
    assert!(full.completion().is_none());
    full.open_next(&ciphertext, &mut [])?
        .ok_or("missing full empty-file chunk")?;
    assert_eq!(
        full.completion()
            .ok_or("missing real full-file proof")?
            .content(),
        source
    );
    // Wide endpoint geometry is admission only, and gives no success credit.
    let enormous = Content {
        size: u64::MAX,
        ..source
    };
    let mut keys = vec![BlockKey::default(); Layout::new(enormous.size).required_keys()];
    let wide = RangeReader::new(enormous, u64::MAX - 1..u64::MAX, &mut keys)?;
    assert_eq!(wide.range(), u64::MAX - 1..u64::MAX);
    assert_eq!(wide.next().ok_or("missing wide root")?.node().level(), 7);
    assert!(wide.completion().is_none());
    Ok(())
}
