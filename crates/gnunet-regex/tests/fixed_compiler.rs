//! Public compiler and artifact interfaces with default features.

use gnunet_block::{ReturnValue, regex::State as BlockState};
use gnunet_crypto::EddsaPrivateKey;
use gnunet_regex::{
    ArtifactMemory, BuildError, Compiler, GraphMemory, Limit, Limits, ProofMemory, RecordMemory,
    accept::{ACCEPT_BLOCK_BYTES, AcceptBlock, AcceptMaterial},
    first_key,
};

const EXPRESSION: &[u8] = b"(a|b)cdefghijklmnopqrstuvwxyz0123456789";
const INPUT: &[u8] = b"acdefghijklmnopqrstuvwxyz0123456789";

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The test asserts semantic and wire properties and propagates setup errors"
)]
fn fixed_compiler_preserves_full_artifacts_and_reuses_storage() -> Result<(), &'static str> {
    let mut graph = GraphMemory::<128, 192, 96, 48, 96, 192, 2>::new();
    let mut proof = ProofMemory::<1600, 4096, 128, 40, 8192>::new();
    let mut artifacts = ArtifactMemory::<48, 96, 96, 192>::new();
    let mut compiler = Compiler::new(graph.workspace(), proof.workspace(), artifacts.workspace());
    let mut grammar_output = RecordMemory::<32, 64, 4096>::new();
    let mut output = RecordMemory::<80, 256, 16_384>::new();
    let mut tiny_output = RecordMemory::<1, 4, 128>::new();

    // Alternative prefixes share a suffix. Square brackets are literal bytes.
    let grammar = compiler
        .compile_into(b"(ab|cb)([x])?", 0, Limits::default(), &mut grammar_output)
        .map_err(|_| "grammar did not compile")?;
    assert_eq!(grammar.is_match(b"ab"), Ok(true));
    assert_eq!(grammar.is_match(b"cb[x]"), Ok(true));
    assert_eq!(grammar.is_match(b"abx"), Ok(false));
    assert_eq!(grammar.is_match(b"ab[x"), Ok(false));

    // The matrix limit and the physical output table both fail without a view.
    assert!(matches!(
        compiler.compile_into(
            EXPRESSION,
            0,
            Limits {
                matrix_cells: 4,
                ..Limits::default()
            },
            &mut output
        ),
        Err(BuildError::Limit(Limit::MatrixCells))
    ));
    assert!(output.view().is_none());
    assert!(matches!(
        compiler.compile_into(b"ab", 0, Limits::default(), &mut tiny_output),
        Err(BuildError::Limit(Limit::DfaStates))
    ));
    assert!(tiny_output.view().is_none());

    let compiled = compiler
        .compile_into(EXPRESSION, 0, Limits::default(), &mut output)
        .map_err(|_| "workspace could not be reused")?;
    assert_eq!(grammar.is_match(b"ab[x]"), Ok(true));
    assert_eq!(compiled.is_match(INPUT), Ok(true));
    let (consumed, key) = first_key(INPUT);
    assert_eq!(consumed, 24);
    let entry = (0..compiled.initial_count())
        .filter_map(|index| compiled.initial(index))
        .find(|record| record.key == key)
        .ok_or("missing synthetic 24-byte entry")?;
    assert_eq!(entry.proof, &INPUT[..consumed]);
    let suffix = &INPUT[consumed..];
    let edge = entry
        .edges
        .into_iter()
        .find(|edge| edge.label() == suffix)
        .ok_or("missing long compressed-edge bridge")?;
    let mut block = [0; 512];
    let length = entry
        .encode(&mut block)
        .map_err(|_| "state block could not be encoded")?;
    let block = BlockState::parse_prefix(&block[..length]).map_err(|_| "invalid state block")?;
    assert_eq!(block.key(), key);
    let mut query = [0; 32];
    query[..suffix.len()].copy_from_slice(suffix);
    assert_eq!(
        block.check(Some(&key), Some(&query[..=suffix.len()])),
        Ok(ReturnValue::Yes)
    );

    let terminal = compiled
        .states()
        .into_iter()
        .map(|state| state.record())
        .find(|record| record.key == edge.destination() && record.accepting)
        .ok_or("bridge does not terminate at the accepting record")?;
    let signer = EddsaPrivateKey::from_seed([0x42; 32]);
    let bytes = AcceptMaterial::new(terminal.key, 25)
        .sign(&signer)
        .map_err(|_| "accepting block could not be signed")?;
    assert_eq!(bytes.len(), ACCEPT_BLOCK_BYTES);
    let block = AcceptBlock::decode(&bytes).map_err(|_| "invalid accepting block")?;
    let checked = block
        .verify(25, &terminal.key)
        .map_err(|_| "accepting block signature did not bind its state key")?;
    assert_eq!(&checked.peer(), signer.public_key().as_bytes());
    assert!(block.verify(26, &terminal.key).is_err());
    assert!(block.verify(25, &key).is_err());

    // Fail after minimized states and their compressed edges have been staged.
    assert!(matches!(
        compiler.compile_into(
            EXPRESSION,
            0,
            Limits {
                initial_records: 0,
                ..Limits::default()
            },
            &mut output
        ),
        Err(BuildError::Limit(Limit::InitialRecords))
    ));
    assert!(output.view().is_none());
    let replacement = compiler
        .compile_into(b"q", 1, Limits::default(), &mut output)
        .map_err(|_| "destination could not be reused after late failure")?;
    assert_eq!(replacement.is_match(b"q"), Ok(true));
    assert_eq!(replacement.is_match(INPUT), Ok(false));
    Ok(())
}
