//! Independent fixtures plus native POSIX comparison for the defined shared grammar.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Semantic fixtures compare complete results; operational failures remain fallible"
)]
use super::{CharacterClass, Comparison, CompileError, Context, Limits, Program, ResourceLimit};
use std::{cmp::Ordering, io};
struct C;
impl Context for C {
    fn classify(&self, unit: u32, class: CharacterClass) -> io::Result<bool> {
        let Some(value) = char::from_u32(unit).filter(char::is_ascii) else {
            return Ok(false);
        };
        Ok(match class {
            CharacterClass::Alnum => value.is_ascii_alphanumeric(),
            CharacterClass::Alpha => value.is_ascii_alphabetic(),
            CharacterClass::Blank => matches!(value, ' ' | '\t'),
            CharacterClass::Control => value.is_ascii_control(),
            CharacterClass::Digit => value.is_ascii_digit(),
            CharacterClass::Graph => value.is_ascii_graphic(),
            CharacterClass::Lower => value.is_ascii_lowercase(),
            CharacterClass::Print => (' '..='~').contains(&value),
            CharacterClass::Punct => value.is_ascii_punctuation(),
            CharacterClass::Space => value.is_ascii_whitespace(),
            CharacterClass::Upper => value.is_ascii_uppercase(),
            CharacterClass::Hex => value.is_ascii_hexdigit(),
        })
    }
    fn compare(&self, left: &[u32], right: &[u32], _: Comparison) -> io::Result<Ordering> {
        Ok(left.cmp(right))
    }
    fn collating_symbol(&self, value: &[u32]) -> io::Result<bool> {
        Ok(value.len() == 1)
    }
    fn element_width(&self) -> usize {
        1
    }
}
fn units(value: &str) -> Vec<u32> {
    value.chars().map(u32::from).collect()
}
fn compile_with(pattern: &str, limits: Limits) -> io::Result<Program> {
    Program::compile(&units(pattern), &C, limits).map_err(|error| match error {
        CompileError::Syntax(error) => io::Error::new(io::ErrorKind::InvalidInput, error),
        CompileError::Boundary(error) => error,
    })
}
fn compile(pattern: &str) -> io::Result<Program> {
    compile_with(pattern, Limits::default())
}
#[test]
fn captures_repetition_classes_and_literal_bre_punctuation() -> io::Result<()> {
    for (pattern, yes, no) in [
        (r"^pro\(be\)$", "probe", "pro(be)"),
        (r"^\(ab\)\{2,3\}\1$", "ababab", "abababa"),
        (r"^\(a*\)a*\1$", "aaaaaa", "aaaab"),
        (r"^\(a\|aa\)*\1$", "aaaaa", "b"),
        (r"^\(\)\1*$", "", "x"),
        (r"^[[:alpha:]_][[:alnum:]_]*$", "name_42", "9name"),
        (r"^[[:blank:]]\{2\}$", "\t ", "\n "),
        (r"^[]a-]*$", "]a-a]", "ab"),
        (r"^[^a-c]*$", "xyz\n", "xyb"),
        (r"^[[.a.]-[.c.]]*$", "abcba", "abcd"),
        (r"^[[=a=]]*$", "aaa", "aaA"),
        (r"^a+(b)?|c{}$", "a+(b)?|c{}", "ab"),
        (r"\<a\w*\>", "..alpha_9..", "..9alpha.."),
        (r"^a\+b\?$", "aaab", "b"),
        (r"^.$", "😀", "😀😀"),
        (r"^é\{2\}$", "éé", "ee"),
        (r"^.$", "\n", "\n\n"),
    ] {
        let program = compile(pattern)?;
        assert!(program.matches(&units(yes), &C)?, "{pattern:?} / {yes:?}");
        assert!(!program.matches(&units(no), &C)?, "{pattern:?} / {no:?}");
    }
    Ok(())
}
#[test]
fn malformed_patterns_remain_syntax_errors() {
    for pattern in [
        r"[",
        r"\",
        r"\(x",
        r"x\)",
        r"\1",
        r"\(a\1\)",
        r"a\{2,1\}",
        r"a\{32768\}",
        r"a\{1,2",
        r"a**",
        r"[z-a]",
        r"[[:unknown:]]",
        r"[[.ch.]]",
        r"[[:alpha:]-z]",
    ] {
        assert!(
            matches!(
                Program::compile(&units(pattern), &C, Limits::default()),
                Err(CompileError::Syntax(_))
            ),
            "{pattern}"
        );
    }
}
#[test]
fn resource_and_context_failures_are_never_negative_matches() -> io::Result<()> {
    let small = Limits {
        work: 30,
        ..Limits::default()
    };
    let program = compile_with("^a*b$", small)?;
    let error = program
        .matches(&units(&"a".repeat(64)), &C)
        .err()
        .ok_or_else(|| io::Error::other("work limit was hidden"))?;
    assert!(
        error
            .get_ref()
            .is_some_and(|error| error.is::<ResourceLimit>())
    );
    for (pattern, limits) in [
        (
            "abc",
            Limits {
                pattern: 2,
                ..Limits::default()
            },
        ),
        (
            r"a\{20\}",
            Limits {
                instructions: 8,
                ..Limits::default()
            },
        ),
        (
            r"\(\(\(a\)\)\)",
            Limits {
                nesting: 2,
                ..Limits::default()
            },
        ),
    ] {
        assert!(matches!(
            Program::compile(&units(pattern), &C, limits),
            Err(CompileError::Boundary(_))
        ));
    }
    struct Broken;
    impl Context for Broken {
        fn classify(&self, _: u32, _: CharacterClass) -> io::Result<bool> {
            Err(io::Error::other("native classifier failure"))
        }
        fn compare(&self, _: &[u32], _: &[u32], _: Comparison) -> io::Result<Ordering> {
            Err(io::Error::other("native collation failure"))
        }
        fn collating_symbol(&self, _: &[u32]) -> io::Result<bool> {
            Err(io::Error::other("native symbol failure"))
        }
        fn element_width(&self) -> usize {
            1
        }
    }
    assert!(
        compile("[[:alpha:]]")?
            .matches(&units("a"), &Broken)
            .is_err()
    );
    assert!(matches!(
        Program::compile(&units("[a-z]"), &Broken, Limits::default()),
        Err(CompileError::Boundary(_))
    ));
    Ok(())
}
#[test]
fn nullable_nested_repetition_terminates_without_capture_allocation() -> io::Result<()> {
    let program = compile(r"^\(a*\)*b$")?;
    assert!(!program.references);
    assert!(!program.matches(&units(&"a".repeat(2048)), &C)?);
    Ok(())
}
#[test]
fn boolean_search_keeps_empty_capture_histories_and_short_accepting_paths() -> io::Result<()> {
    // Darwin's native regexec rejects the one-letter fixture; this backend
    // intentionally searches all valid captures instead of reproducing that
    // native algorithm's pruning. No capture values escape this boolean API.
    let program = compile(r"^\(a*\)a*\1$")?;
    for input in ["", "a", "aa", "aaa", "aaaa"] {
        assert!(program.matches(&units(input), &C)?, "{input:?}");
    }
    let quick = compile_with(
        ".*",
        Limits {
            work: 20,
            ..Limits::default()
        },
    )?;
    assert!(quick.matches(&units(&"a".repeat(65536)), &C)?);
    Ok(())
}
#[cfg(unix)]
#[test]
fn shared_nonempty_bre_cases_agree_with_native_posix_search() -> io::Result<()> {
    use crate::native::regex::posix::{Regex, RegexCompileFailure};
    let mut inputs = vec![String::new()];
    for size in 1..=4 {
        for bits in 0..(1 << size) {
            inputs.push(
                (0..size)
                    .map(|at| if bits & (1 << at) == 0 { 'a' } else { 'b' })
                    .collect(),
            );
        }
    }
    inputs.extend(["\n", "aaa\n", "]a-", "12", "a_b", "a+b"].map(String::from));
    for pattern in [
        ".",
        "^$",
        "a",
        "^a",
        "b$",
        "a*b",
        "[ab]*",
        "[^a]",
        "[]a-]*",
        "[a-b]",
        "^[[:alpha:]]*$",
        "[[:digit:]]",
        "a+b",
        r"\(ab\)*",
        r"a\{0,3\}b",
        r"a\{2,\}",
        r"\(a*\)b\1",
        r"^\(a*\)*b$",
        "[[=a=]]",
        "[[.a.]]",
    ] {
        let program = compile(pattern)?;
        let native = Regex::new(pattern.as_bytes()).map_err(|error| match error {
            RegexCompileFailure::Boundary(error) => error,
            RegexCompileFailure::InvalidPattern => {
                io::Error::other(format!("native rejected defined fixture {pattern:?}"))
            }
        })?;
        for input in &inputs {
            assert_eq!(
                program.matches(&units(input), &C)?,
                native.matches(input.as_bytes())?,
                "{pattern:?} / {input:?}"
            );
        }
    }
    Ok(())
}

struct Contractions;
impl Context for Contractions {
    fn classify(&self, value: u32, class: CharacterClass) -> io::Result<bool> {
        C.classify(value, class)
    }
    fn compare(&self, left: &[u32], right: &[u32], kind: Comparison) -> io::Result<Ordering> {
        let contraction = |value: &[u32]| {
            if value == units("ch") {
                units("h~")
            } else {
                value.to_vec()
            }
        };
        match kind {
            Comparison::Collation => Ok(contraction(left).cmp(&contraction(right))),
            Comparison::Primary
                if left == units("ch") && right == units("x")
                    || right == units("ch") && left == units("x") =>
            {
                Ok(Ordering::Equal)
            }
            Comparison::Primary => Ok(left.cmp(right)),
        }
    }
    fn collating_symbol(&self, value: &[u32]) -> io::Result<bool> {
        Ok(value.len() == 1 || value == units("ch"))
    }
    fn element_width(&self) -> usize {
        2
    }
}
#[test]
fn locale_inventory_controls_range_equivalence_and_negative_width() -> io::Result<()> {
    for (pattern, yes, no) in [
        ("^[h-i]$", "ch", "cx"),
        ("^[[=x=]]$", "ch", "xx"),
        ("^[^x]$", "ch", "cx"),
        ("^[^[.ch.]]$", "x", "ch"),
        ("^[[.ch.]]$", "ch", "cx"),
        (r"^\([[=x=]]\)\1$", "chch", "chx"),
        (r"^[h-i]\{2\}$", "chch", "chcx"),
    ] {
        let program = Program::compile(&units(pattern), &Contractions, Limits::default()).map_err(
            |error| match error {
                CompileError::Syntax(error) => io::Error::new(io::ErrorKind::InvalidInput, error),
                CompileError::Boundary(error) => error,
            },
        )?;
        assert!(
            program.matches(&units(yes), &Contractions)?,
            "{pattern} / {yes}"
        );
        assert!(
            !program.matches(&units(no), &Contractions)?,
            "{pattern} / {no}"
        );
    }
    assert!(matches!(
        Program::compile(&units("[[.cx.]]"), &Contractions, Limits::default()),
        Err(CompileError::Syntax(_))
    ));
    Ok(())
}
