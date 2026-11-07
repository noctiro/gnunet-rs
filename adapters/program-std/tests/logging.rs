//! Independent source-derived policy, formatting and owner lifetime boundaries.
use gnunet_program_host::{
    logging::{Environment, Logger, Stamp, base32},
    policy::{CallSite, CallSiteCache, Level, Policy},
};
use std::{cell::RefCell, io, rc::Rc};
fn site<'a>(component: Option<&'a [u8]>, line: i32) -> CallSite<'a> {
    CallSite {
        component,
        file: b"owned/unit.c",
        function: b"probe",
        line,
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Source policy assertions now propagate actual native regex/locale boundary failures"
)]
fn source_levels_invalid_threshold_and_case_names_are_not_an_ordinal_enum() -> io::Result<()> {
    assert_eq!(Level::parse(None), Level::UNSPECIFIED);
    assert_eq!(Level::parse(Some(b"iNfO\0unused")), Level::INFO);
    assert_eq!(Level::parse(Some(b"nonsense")), Level::INVALID);
    assert_eq!(Level(67).name(), b"ERROR");
    assert_eq!(Level(64).name(), b"NONE");
    let mut policy = Policy::default();
    assert!(policy.setup(None, None, None)?.is_empty());
    assert!(policy.enabled(Level::MESSAGE, b"x", site(None, 1))?);
    assert!(!policy.enabled(Level::INFO, b"x", site(None, 1))?);
    assert!(policy.setup(Some(b"bad"), None, None)?.is_empty());
    assert!(policy.enabled(Level::INVALID, b"x", site(None, 1))?);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Source policy assertions now propagate actual native regex/locale boundary failures"
)]
fn forced_first_match_bre_is_parsed_once_and_ordinary_rules_yield_to_cli_threshold()
-> io::Result<()> {
    let mut p = Policy::default();
    assert!(
        p.setup(
            Some(b"ERROR"),
            Some(b"owned;unit[.]c$;probe;10-20;DEBUG/;;;;NONE"),
            Some(b";;;;DEBUG")
        )?
        .is_empty()
    );
    assert_eq!(p.definitions(), 3);
    assert!(p.enabled(Level::DEBUG, b"owned", site(None, 10))?);
    assert!(!p.enabled(Level::ERROR, b"other", site(None, 10))?);
    assert!(!p.enabled(Level::DEBUG, b"owned", site(None, 9))?);
    assert!(p.setup(None, Some(b";;;;DEBUG"), None)?.is_empty());
    assert_eq!(p.definitions(), 3);
    let mut p = Policy::default();
    p.setup(Some(b"ERROR"), None, Some(b";;;;DEBUG"))?;
    assert!(!p.enabled(Level::INFO, b"owned", site(None, 10))?);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Source policy assertions now propagate actual native regex/locale boundary failures"
)]
fn native_bre_and_malformed_prefix_rules_preserve_source_quirks() -> io::Result<()> {
    let mut p = Policy::default();
    p.setup(
        None,
        Some(b"^owned$;unit\\.c$;^pro\\(be\\)$;10junk;DEBUG/;;;;NONE"),
        None,
    )?;
    assert!(p.enabled(Level::DEBUG, b"owned", site(None, 10))?);
    assert!(!p.enabled(Level::ERROR, b"owned", site(None, 11))?);
    let mut p = Policy::default();
    p.setup(None, Some(b";;;;INFO/[;;;;DEBUG/;;;;NONE"), None)?;
    assert_eq!(p.definitions(), 1);
    assert!(p.enabled(Level::INFO, b"owned", site(None, 10))?);
    let mut p = Policy::default();
    let errors = p.setup(None, Some(b"broken/;;;;INFO"), None)?;
    assert_eq!(p.definitions(), 1);
    assert_eq!(
        errors,
        b"ERROR: Unable to parse log definition: Syntax error at `/;;;;INFO'.\n"
    );
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent test assertions report a violated source contract; fallible setup uses Result"
)]
fn macro_cache_skip_debug_cull_and_nocheck_have_distinct_authority() -> io::Result<()> {
    let stamp = Stamp::controlled_utc(1_700_000_000, 123456)?;
    let mut logger = Logger::new(b"owned", 42, false)?;
    logger.setup(
        b"owned",
        Some(b"ERROR"),
        None,
        &Environment::default(),
        &stamp,
    )?;
    let mut out = Vec::new();
    let mut disabled = CallSiteCache::new();
    logger.checked(
        &mut disabled,
        Level::INFO,
        site(None, 10),
        b"hidden",
        &stamp,
        &mut out,
    )?;
    logger.setup(
        b"owned",
        Some(b"DEBUG"),
        None,
        &Environment::default(),
        &stamp,
    )?;
    logger.checked(
        &mut disabled,
        Level::INFO,
        site(None, 10),
        b"still hidden",
        &stamp,
        &mut out,
    )?;
    assert!(logger.log_skip(1, false)?);
    logger.checked(
        &mut CallSiteCache::new(),
        Level::DEBUG,
        site(None, 10),
        b"debug culled",
        &stamp,
        &mut out,
    )?;
    assert_eq!(logger.get_log_skip(), 1);
    logger.checked(
        &mut CallSiteCache::constant(false),
        Level::INFO,
        site(None, 10),
        b"skip decrements while disabled",
        &stamp,
        &mut out,
    )?;
    assert_eq!(logger.get_log_skip(), 0);
    assert!(out.is_empty());
    logger.nocheck(Level::DEBUG, None, b"nocheck", &stamp, &mut out)?;
    assert!(stamp.date().starts_with(b"2023-11-14T22:13:20.123456"));
    let mut expected = stamp.date().to_vec();
    expected.extend_from_slice(b" owned-42 DEBUG nocheck\n");
    assert_eq!(out, expected);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent test assertions report a violated source contract; fallible setup uses Result"
)]
fn scope_journal_message_custom_order_and_stale_tokens_are_real_owner_operations() -> io::Result<()>
{
    let stamp = Stamp::controlled_utc(1_700_000_000, 1)?;
    let mut logger = Logger::new(b"owned", 42, true)?;
    let env = Environment {
        journal: true,
        ..Environment::default()
    };
    logger.setup(b"owned", None, None, &env, &stamp)?;
    let mut bytes = Vec::new();
    let old = logger.scope_enter([0; 16]);
    assert_eq!(old, None);
    assert_eq!(base32(&[0; 16]), b"00000000000000000000000000");
    logger.nocheck(Level::ERROR, None, b"scoped", &stamp, &mut bytes)?;
    logger.nocheck(Level::MESSAGE, None, b"message\n", &stamp, &mut bytes)?;
    assert_eq!(
        bytes,
        b"(00000000000000000000000000) ERROR scoped\n* message\n"
    );
    logger.scope_restore(old);
    assert_eq!(logger.scope_get(), None);
    let seen = Rc::new(RefCell::new(Vec::new()));
    let a = Rc::clone(&seen);
    let one = logger.logger_add(move |record| a.borrow_mut().push((1, record.message.to_vec())))?;
    let b = Rc::clone(&seen);
    let two = logger.logger_add(move |record| b.borrow_mut().push((2, record.message.to_vec())))?;
    bytes.clear();
    logger.nocheck(Level::WARNING, None, b"custom\0ignored", &stamp, &mut bytes)?;
    assert!(bytes.is_empty());
    assert_eq!(
        &*seen.borrow(),
        &[(2, b"custom".to_vec()), (1, b"custom".to_vec())]
    );
    logger.logger_remove(two)?;
    assert!(logger.logger_remove(two).is_err());
    let mut other = Logger::new(b"other", 42, true)?;
    assert!(other.logger_remove(one).is_err());
    logger.logger_remove(one)?;
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent test assertions report a violated source contract; fallible setup uses Result"
)]
fn bulk_threshold_is_strict_and_first_component_and_kind_survive_other_callers() -> io::Result<()> {
    let stamp = Stamp::controlled_utc(1_700_000_000, 0)?;
    let mut logger = Logger::new(b"owned", 42, true)?;
    let mut bytes = Vec::new();
    logger.nocheck(
        Level::ERROR,
        Some(b"first"),
        b"repeat\n",
        &stamp,
        &mut bytes,
    )?;
    for _ in 0..1000 {
        logger.nocheck(
            Level(64 | 2),
            Some(b"second"),
            b"repeat\n",
            &stamp,
            &mut bytes,
        )?;
    }
    assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 1);
    logger.nocheck(
        Level(64 | 2),
        Some(b"second"),
        b"repeat\n",
        &stamp,
        &mut bytes,
    )?;
    let mut expected = stamp.date().to_vec();
    expected.extend_from_slice(b" first-42 ERROR repeat\n");
    expected.extend_from_slice(stamp.date());
    expected.extend_from_slice(
        b" first-42 ERROR Message `repeat' repeated 1001 times in the last 0 ms\n",
    );
    assert_eq!(bytes, expected);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Lazy macro ports must not evaluate message arguments or clock when disabled/skipped"
)]
fn lazy_macro_admission_suppresses_argument_and_time_side_effects() -> io::Result<()> {
    use std::cell::Cell;
    let messages = Cell::new(0);
    let clocks = Cell::new(0);
    let mut logger = Logger::new(b"owned", 7, false)?;
    let stamp = Stamp::controlled_utc(1_700_000_000, 0)?;
    logger.setup(
        b"owned",
        Some(b"ERROR"),
        None,
        &Environment::default(),
        &stamp,
    )?;
    let mut out = Vec::new();
    let build = || {
        messages.set(messages.get() + 1);
        Ok(b"message".to_vec())
    };
    let time = || {
        clocks.set(clocks.get() + 1);
        Stamp::controlled_utc(1_700_000_000, 0)
    };
    logger.checked_lazy(
        &mut CallSiteCache::new(),
        Level::INFO,
        site(None, 1),
        build,
        time,
        &mut out,
    )?;
    assert_eq!((messages.get(), clocks.get()), (0, 0));
    assert!(logger.log_skip(1, false)?);
    logger.checked_lazy(
        &mut CallSiteCache::new(),
        Level::DEBUG,
        site(None, 1),
        build,
        time,
        &mut out,
    )?;
    assert_eq!(logger.get_log_skip(), 1);
    logger.checked_lazy(
        &mut CallSiteCache::new(),
        Level::ERROR,
        site(None, 1),
        build,
        time,
        &mut out,
    )?;
    assert_eq!(logger.get_log_skip(), 0);
    assert_eq!((messages.get(), clocks.get()), (0, 0));
    logger.checked_lazy(
        &mut CallSiteCache::new(),
        Level::ERROR,
        site(None, 1),
        build,
        time,
        &mut out,
    )?;
    assert_eq!((messages.get(), clocks.get()), (1, 1));
    assert!(!out.is_empty());
    Ok(())
}
