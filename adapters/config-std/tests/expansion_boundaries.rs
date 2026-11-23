//! Current configuration expansion and physical-line parser boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare independent upstream regression outcomes and explicit resource limits"
)]
use gnunet_config::{Configuration, Environment, Error, Limits};
use std::{io, path::PathBuf};

struct Env;
impl Environment for Env {
    fn variable(&self, name: &[u8]) -> Option<Vec<u8>> {
        match name {
            b"ENV_SELF" => Some(b"$ENV_SELF/e".to_vec()),
            _ => None,
        }
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        Ok(PathBuf::from("/unused"))
    }
}

#[test]
fn empty_and_finalized_recursive_terms_leave_later_expressions_expandable() -> Result<(), Error> {
    let mut cfg = Configuration::default();
    for (name, value) in [
        (b"EMPTY".as_slice(), b"".as_slice()),
        (b"B", b"/b"),
        (b"SELF", b"$SELF/x"),
        (b"D", b"${D:-dflt}/d"),
        (b"TWICE", b"${TWICE}:${TWICE}"),
    ] {
        cfg.set_value(b"PATHS", name, Some(value))?;
    }
    for (input, expected) in [
        (b"${EMPTY}$B".as_slice(), b"/b".as_slice()),
        (b"x${EMPTY}${EMPTY}y$B/z", b"xy/b/z"),
        (b"${SELF}${SELF} $B", b"$SELF/x$SELF/x /b"),
        (b"$D", b"dflt/d"),
        (b"$TWICE", b"${TWICE}:${TWICE}"),
        (b"$ENV_SELF", b"$ENV_SELF/e"),
        (b"$UNDEFINED/$B", b"$UNDEFINED//b"),
    ] {
        assert_eq!(cfg.expand_dollar(input, &Env)?, expected);
    }
    Ok(())
}

#[test]
fn recursion_tracks_exact_variable_spelling_and_keeps_resource_limits() -> Result<(), Error> {
    let mut cfg = Configuration::default();
    cfg.set_value(b"PATHS", b"A", Some(b"$a/x"))?;
    assert_eq!(cfg.expand_dollar(b"$A", &Env)?, b"$a/x/x");

    let mut cfg = Configuration::new(Limits {
        max_expansions: 1,
        ..Limits::default()
    });
    cfg.set_value(b"PATHS", b"EMPTY", Some(b""))?;
    assert!(matches!(
        cfg.expand_dollar(b"${EMPTY}${EMPTY}", &Env),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        cfg.expand_dollar(b"${MISSING:-${EMPTY}}", &Env),
        Err(Error::Capacity)
    ));
    assert_eq!(cfg.expand_dollar(b"${MISSING:-literal}", &Env)?, b"literal");
    let mut cfg = Configuration::new(Limits {
        max_expanded_bytes: 3,
        ..Limits::default()
    });
    cfg.set_value(b"PATHS", b"X", Some(b"abcd"))?;
    assert!(matches!(
        cfg.expand_dollar(b"$X", &Env),
        Err(Error::Capacity)
    ));
    Ok(())
}

#[test]
fn section_headers_use_trimmed_lines_and_nul_failure_preserves_only_prior_lines()
-> Result<(), Error> {
    let mut cfg = Configuration::default();
    cfg.deserialize(b"[a]\nX=1\n  [b] \r\nY=2\r\n", None)?;
    assert_eq!(cfg.get(b"a", b"X"), Some(b"1".as_slice()));
    assert_eq!(cfg.get(b"b", b"Y"), Some(b"2".as_slice()));
    assert!(matches!(
        cfg.deserialize(b"[a]\nX=accepted\nY=before\0after\nZ=skipped\n", None),
        Err(Error::InvalidInput)
    ));
    assert_eq!(cfg.get(b"a", b"X"), Some(b"accepted".as_slice()));
    assert_eq!(cfg.get(b"a", b"Y"), None);
    assert_eq!(cfg.get(b"a", b"Z"), None);
    Ok(())
}
