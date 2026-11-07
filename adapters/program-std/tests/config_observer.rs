//! Real synchronous CONFIG/log-owner composition. Native-NLS evidence is separate.
use gnunet_config::{Configuration, diagnostic::Diagnostic};
use gnunet_program_host::{
    config_observer,
    logging::{Environment, Logger, Stamp},
    shared_clock::SharedClock,
};
use std::{
    cell::RefCell,
    io,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert source event count, order and original persistent callback identity"
)]
fn operation_local_config_logs_once_and_preserves_persistent_route_after_return()
-> Result<(), Box<dyn std::error::Error>> {
    let mut logger = Logger::new(b"owned", 7, true)?;
    let clock = SharedClock::native(0)?;
    let mut stderr = Vec::new();
    logger.setup_routed(
        b"owned",
        Some(b"DEBUG"),
        None,
        &Environment::default(),
        &Stamp::setup_now()?,
        &mut stderr,
    )?;
    let events = Rc::new(RefCell::new(Vec::new()));
    let saved = Rc::clone(&events);
    let registration = logger.logger_add(move |record| {
        saved.borrow_mut().push((
            record.kind.0,
            record.component.to_vec(),
            record.message.to_vec(),
        ))
    })?;
    let mut cfg = Configuration::default();
    let persistent = Arc::new(AtomicUsize::new(0));
    let keep = Arc::clone(&persistent);
    drop(cfg.observe(Some(Arc::new(move |_| {
        keep.fetch_add(1, Ordering::SeqCst);
    }))));
    let result = config_observer::operation(&mut logger, &clock, &mut stderr, |observer| {
        cfg.deserialize_observed(b"[own]\nkey=accepted\n@BAD@ value\n", None, Some(observer))
    })?;
    assert!(result.is_err());
    assert_eq!(cfg.get(b"own", b"key"), Some(b"accepted".as_slice()));
    assert_eq!(persistent.load(Ordering::SeqCst), 0);
    assert_eq!(events.borrow().len(), 1);
    assert_eq!(events.borrow()[0].0, 2);
    assert_eq!(events.borrow()[0].1, b"util-7");
    assert_eq!(
        events.borrow()[0].2,
        b"Unknown or malformed directive 'BAD' in line 3\n"
    );
    assert!(cfg.deserialize(b"broken\n", None).is_err());
    assert_eq!(persistent.load(Ordering::SeqCst), 1);
    assert_eq!(events.borrow().len(), 1);
    logger.logger_remove(registration)?;
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Internal static source cache must survive config operations and later logger setup"
)]
fn config_source_first_call_cache_and_skip_use_the_actual_shared_logger_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let mut logger = Logger::new(b"owned", 7, true)?;
    let clock = SharedClock::native(0)?;
    let mut stderr = Vec::new();
    logger.setup_routed(
        b"owned",
        Some(b"DEBUG"),
        None,
        &Environment::default(),
        &Stamp::setup_now()?,
        &mut stderr,
    )?;
    let mut cfg = Configuration::default();
    assert!(logger.log_skip(1, false)?);
    assert!(
        config_observer::operation(&mut logger, &clock, &mut stderr, |observer| cfg
            .deserialize_observed(b"broken\n", None, Some(observer)))?
        .is_err()
    );
    assert!(stderr.is_empty());
    assert_eq!(logger.get_log_skip(), 0);
    logger.setup_routed(
        b"owned",
        Some(b"NONE"),
        None,
        &Environment::default(),
        &Stamp::setup_now()?,
        &mut stderr,
    )?;
    assert!(
        config_observer::operation(&mut logger, &clock, &mut stderr, |observer| cfg
            .deserialize_observed(b"broken\n", None, Some(observer)))?
        .is_err()
    );
    assert!(stderr.ends_with(b"WARNING Syntax error while deserializing in line 1\n"));
    Ok(())
}
struct Rejected;
impl gnunet_program_host::locale::Translations for Rejected {
    fn gettext(&self, _: Option<&[u8]>, _: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::other(
            "actual selected test backend rejects lookup",
        ))
    }
    fn ngettext(&self, _: Option<&[u8]>, _: &[u8], _: &[u8], _: u64) -> io::Result<Vec<u8>> {
        Err(io::Error::other(
            "actual selected test backend rejects plural lookup",
        ))
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "A failed selected backend or output cannot masquerade as successful config/log composition"
)]
fn rejected_translation_is_not_english_success_and_untranslated_sites_stay_untranslated()
-> Result<(), Box<dyn std::error::Error>> {
    let mut logger = Logger::new(b"owned", 7, true)?;
    let clock = SharedClock::native(0)?;
    let mut stderr = Vec::new();
    logger.setup_routed(
        b"owned",
        Some(b"DEBUG"),
        None,
        &Environment::default(),
        &Stamp::setup_now()?,
        &mut stderr,
    )?;
    logger.set_translations(Rc::new(Rejected));
    let events = Rc::new(RefCell::new(Vec::new()));
    let keep = Rc::clone(&events);
    let token = logger.logger_add(move |record| keep.borrow_mut().push(record.message.to_vec()))?;
    let mut cfg = Configuration::default();
    assert!(
        config_observer::operation(&mut logger, &clock, &mut stderr, |observer| cfg
            .deserialize_observed(b"broken\n", None, Some(observer)))?
        .is_err()
    );
    assert_eq!(events.borrow().len(), 1);
    let callback = |event: Diagnostic<'_>| {
        assert!(event.domain.is_some());
    };
    let sink: gnunet_config::diagnostic::BorrowedObserver<'_> = &callback;
    let outcome = config_observer::operation(&mut logger, &clock, &mut stderr, |observer| {
        let event = Diagnostic {
            level: gnunet_config::diagnostic::Level::ERROR,
            component: None,
            site: gnunet_config::diagnostic::Site {
                id: "owned-test-translated",
                file: b"configuration.c",
                function: b"owned",
                line: 1,
            },
            domain: Some(b"gnunet"),
            template: b"translated required",
            arguments: &[],
        };
        observer(event);
        sink(event);
        Ok::<(), gnunet_config::Error>(())
    });
    assert!(outcome.is_err());
    assert_eq!(events.borrow().len(), 1);
    logger.logger_remove(token)?;
    Ok(())
}
