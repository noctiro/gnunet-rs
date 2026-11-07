//! Public option callbacks for the actual short-zero/long-descriptor boundary.
//! Source cases only for this handoff; no parser or program has been executed.
use super::Options;
use crate::helpers::{self, Target};
use std::{error::Error, ffi::OsString};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check public option results; fallible target reads preserve their errors"
)]
fn sorted_long_only_does_not_erase_registered_short_options() -> Result<(), Box<dyn Error>> {
    let timeout = Target::new(None);
    let config = Target::new(None);
    let level = Target::new(None);
    let ego = Target::new(None);
    let phone = Target::new(None);
    let mut options = Options::new();
    options.add(helpers::string(
        0,
        b"timeout",
        b"DURATION",
        b"whole lifetime",
        timeout.clone(),
    ));
    for (short, name, target) in [
        (b'c', b"config".as_slice(), config.clone()),
        (b'L', b"log", level.clone()),
        (b'e', b"ego", ego.clone()),
        (b'p', b"phone", phone.clone()),
    ] {
        options.add(helpers::string(
            short,
            name,
            b"VALUE",
            b"selected value",
            target,
        ));
    }
    options.sort_program();
    let result = options.run(
        b"tool",
        [
            "tool",
            "-c",
            "node.conf",
            "-L",
            "INFO",
            "-e",
            "callee",
            "-p",
            "1",
            "--timeout",
            "108 s",
        ]
        .map(OsString::from),
        false,
    );
    assert_eq!(result.code, 11);
    assert!(result.output.stderr.is_empty());
    assert_eq!(config.get()?, Some(b"node.conf".to_vec()));
    assert_eq!(level.get()?, Some(b"INFO".to_vec()));
    assert_eq!(ego.get()?, Some(b"callee".to_vec()));
    assert_eq!(phone.get()?, Some(b"1".to_vec()));
    assert_eq!(timeout.get()?, Some(b"108 s".to_vec()));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check two independent long-only callbacks and the real short callback"
)]
fn separate_long_only_names_keep_their_actual_descriptor() -> Result<(), Box<dyn Error>> {
    let first = Target::new(None);
    let second = Target::new(None);
    let alpha = Target::new(0);
    let mut options = Options::new();
    options.add(helpers::string(
        0,
        b"first",
        b"VALUE",
        b"first",
        first.clone(),
    ));
    options.add(helpers::string(
        0,
        b"second",
        b"VALUE",
        b"second",
        second.clone(),
    ));
    options.add(helpers::flag(b'a', b"alpha", b"alpha", alpha.clone()));
    options.sort_program();
    let result = options.run(
        b"tool",
        ["tool", "--second=two", "--first", "one", "-a"].map(OsString::from),
        false,
    );
    assert_eq!(result.code, 5);
    assert!(result.output.stderr.is_empty());
    assert_eq!(first.get()?, Some(b"one".to_vec()));
    assert_eq!(second.get()?, Some(b"two".to_vec()));
    assert_eq!(alpha.get()?, 1);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify both GNU W forms dispatch matched long-only callbacks"
)]
fn w_long_uses_the_matched_long_only_descriptor() -> Result<(), Box<dyn Error>> {
    let first = Target::new(None);
    let second = Target::new(None);
    let w = Target::new(0);
    let separator = Target::new(0);
    let mut options = Options::new();
    // The source GNU W; extension is expressed by these adjacent short bytes.
    options.add(helpers::flag(b'W', b"world", b"GNU long option", w.clone()));
    options.add(helpers::flag(
        b';',
        b"semicolon",
        b"extension marker",
        separator.clone(),
    ));
    options.add(helpers::string(
        0,
        b"first",
        b"VALUE",
        b"first",
        first.clone(),
    ));
    options.add(helpers::string(
        0,
        b"second",
        b"VALUE",
        b"second",
        second.clone(),
    ));
    let result = options.run(
        b"tool",
        ["tool", "-W", "second=two", "-Wfirst=one"].map(OsString::from),
        false,
    );
    assert_eq!(result.code, 4);
    assert!(result.output.stderr.is_empty());
    assert_eq!(first.get()?, Some(b"one".to_vec()));
    assert_eq!(second.get()?, Some(b"two".to_vec()));
    assert_eq!(w.get()?, 0);
    assert_eq!(separator.get()?, 0);
    Ok(())
}
