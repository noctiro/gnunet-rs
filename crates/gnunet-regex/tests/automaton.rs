//! One comprehensive pure grammar/artifact/resource model, source only here.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Exact pure matching and official block artifacts are the single model's assertions"
)]
use gnunet_block::{ReturnValue, regex::State as BlockState};
use gnunet_regex::{Automaton, BuildError, Limit, Limits, Record, first_key, proof_key};
fn record(a: &Automaton, key: [u8; 64]) -> Option<Record<'_>> {
    for state in a.states() {
        let r = state.record();
        if r.key == key {
            return Some(r);
        }
    }
    (0..a.initial_count())
        .filter_map(|i| a.initial(i))
        .find(|r| r.key == key)
}
fn distributed_match(a: &Automaton, input: &[u8]) -> Result<bool, &'static str> {
    let (mut at, mut key) = first_key(input);
    for _ in 0..=input.len() {
        let Some(r) = record(a, key) else {
            return Ok(false);
        };
        if at == input.len() {
            return Ok(r.accepting);
        }
        let Some(edge) = r
            .edges
            .iter()
            .filter(|e| input[at..].starts_with(e.label()))
            .max_by_key(|e| e.label().len())
        else {
            return Ok(false);
        };
        if edge.label().is_empty() {
            return Err("synthetic empty edge");
        }
        at += edge.label().len();
        key = edge.destination();
    }
    Err("unbounded artifact walk")
}
#[test]
fn complete_grammar_compression_proofs_native_blocks_and_capacity() -> Result<(), String> {
    type Case<'a> = (&'a [u8], &'a [&'a [u8]], &'a [&'a [u8]]);
    let cases: &[Case<'_>] = &[
        (b"a|bc", &[b"a", b"bc"], &[b"", b"ab", b"ac"]),
        (
            b"(a|b)012345678901234567890123456789",
            &[
                b"a012345678901234567890123456789",
                b"b012345678901234567890123456789",
            ],
            &[
                b"a012345678901234567890123",
                b"c012345678901234567890123456789",
            ],
        ),
        (
            b"123456789012345678901234(ab|c)+d?",
            &[
                b"123456789012345678901234ab",
                b"123456789012345678901234c",
                b"123456789012345678901234abcabd",
                b"123456789012345678901234cd",
            ],
            &[
                b"123456789012345678901234d",
                b"123456789012345678901234a",
                b"123456789012345678901234abcdx",
            ],
        ),
        (
            b"x*y+z?",
            &[b"y", b"xxxyyyy", b"yz", b"xxxxyz"],
            &[b"", b"x", b"z"],
        ),
        (b"a()b", &[b"ab"], &[b"a", b"b", b"a()b"]),
        (b"a?*+", &[b"", b"a", b"aaaa"], &[b"b", b"ab"]),
        (
            b".[]{}\\^$-:",
            &[b".[]{}\\^$-:"],
            &[b"x[]{}\\^$-:", b".[]{}^$-:"],
        ),
        (&[0x80, 0xff], &[&[0x80, 0xff]], &[&[0x80], &[0xff]]),
    ];
    for &(expression, yes, no) in cases {
        for compression in [0, 1, 2, 8] {
            let a = Automaton::compile(expression, compression, Limits::default())
                .map_err(|e| format!("compile {expression:?}: {e:?}"))?;
            for input in yes {
                assert_eq!(a.is_match(input), Ok(true), "{expression:?} {input:?}");
            }
            for input in no {
                assert_eq!(a.is_match(input), Ok(false), "{expression:?} {input:?}");
            }
            if yes.iter().any(|input| input.is_empty()) {
                assert_eq!(distributed_match(&a, b""), Ok(true));
            }
            assert!(a.is_match(b"a\0tail").is_err());
            for state in a.states() {
                let r = state.record();
                assert_eq!(r.key, proof_key(r.proof));
                let mut out = vec![0; r.encoded_len().map_err(|e| format!("size {e:?}"))?];
                r.encode(&mut out).map_err(|e| format!("encode {e:?}"))?;
                let parsed = BlockState::parse_prefix(&out).map_err(|e| format!("block {e:?}"))?;
                assert_eq!(parsed.key(), r.key);
                assert_eq!(parsed.check(Some(&r.key), None), Ok(ReturnValue::Yes));
                for edge in r.edges {
                    assert!(!edge.label().is_empty());
                    assert!(record(&a, edge.destination()).is_some());
                    if compression == 1 {
                        assert_eq!(edge.label().len(), 1);
                    }
                }
            }
            // The independently spelled proof expression must still describe
            // the original complete language whenever it is nonempty syntax.
            if !a.language_expression().is_empty()
                && !expression.iter().any(|b| matches!(b, b'*' | b'+' | b'?'))
            {
                let b = Automaton::compile(a.language_expression(), 1, Limits::default())
                    .map_err(|e| format!("proof recompile: {e:?}"))?;
                for input in yes {
                    assert_eq!(b.is_match(input), Ok(true));
                }
                for input in no {
                    assert_eq!(b.is_match(input), Ok(false));
                }
            }
        }
    }
    let expression = b"GNUNET-VPN-VER-0001-4-(0050|01BB)-C000020(1|2)";
    for compression in [0, 1, 4] {
        let a = Automaton::compile(expression, compression, Limits::default())
            .map_err(|e| format!("VPN: {e:?}"))?;
        for input in [
            b"GNUNET-VPN-VER-0001-4-0050-C0000201".as_slice(),
            b"GNUNET-VPN-VER-0001-4-01BB-C0000202",
        ] {
            assert_eq!(a.is_match(input), Ok(true));
            assert_eq!(distributed_match(&a, input), Ok(true));
        }
        assert_eq!(
            distributed_match(&a, b"GNUNET-VPN-VER-0001-4-0035-C0000201"),
            Ok(false)
        );
        for i in 0..a.initial_count() {
            let r = a.initial(i).ok_or("initial vanished")?;
            let mut out = vec![
                0;
                r.encoded_len()
                    .map_err(|e| format!("initial size: {e:?}"))?
            ];
            r.encode(&mut out)
                .map_err(|e| format!("initial encode: {e:?}"))?;
            assert_eq!(
                BlockState::parse_prefix(&out)
                    .map_err(|e| format!("initial parse: {e:?}"))?
                    .key(),
                r.key
            );
        }
    }
    for expression in [
        b"".as_slice(),
        b"()",
        b"|a",
        b"a|",
        b"a(|b)",
        b"(a|)",
        b"*a",
        b"(a",
        b"a)",
        b"a\0b",
    ] {
        assert!(matches!(
            Automaton::compile(expression, 1, Limits::default()),
            Err(BuildError::Syntax { .. })
        ));
    }
    assert!(matches!(
        Automaton::compile(
            b"abc",
            1,
            Limits {
                nfa_states: 1,
                ..Limits::default()
            }
        ),
        Err(BuildError::Limit(Limit::NfaStates))
    ));
    assert!(matches!(
        Automaton::compile(
            b"ab",
            1,
            Limits {
                dfa_states: 1,
                ..Limits::default()
            }
        ),
        Err(BuildError::Limit(Limit::DfaStates))
    ));
    assert!(matches!(
        Automaton::compile(
            b"ab",
            1,
            Limits {
                matrix_cells: 1,
                ..Limits::default()
            }
        ),
        Err(BuildError::Limit(Limit::MatrixCells))
    ));
    assert!(matches!(
        Automaton::compile(
            b"a",
            1,
            Limits {
                work: 0,
                ..Limits::default()
            }
        ),
        Err(BuildError::Limit(Limit::Work))
    ));
    // An unnamespaced cyclic branching language has exponentially many
    // initial24-byte keys. This is a real resource refusal, not lost grammar.
    assert!(matches!(
        Automaton::compile(
            b"(ab|c)+d?",
            0,
            Limits {
                initial_records: 64,
                ..Limits::default()
            }
        ),
        Err(BuildError::Limit(Limit::InitialRecords))
    ));
    let literal_dot = Automaton::compile(b"12345678901234567890123.x", 0, Limits::default())
        .map_err(|e| format!("literal dot: {e:?}"))?;
    assert_eq!(
        distributed_match(&literal_dot, b"12345678901234567890123.x"),
        Ok(true)
    );
    assert_eq!(
        first_key(b"123456789012345678901234tail"),
        (24, proof_key(b"123456789012345678901234"))
    );
    assert_eq!(first_key(b"short"), (5, proof_key(b"short")));
    Ok(())
}
