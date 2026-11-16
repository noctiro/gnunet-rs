//! Catalog ownership, safe argument reordering and permanent output failure.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare observable translated output and original failure ownership"
)]
use gnunet_arm_cli::{
    diagnostics::Selection,
    locale::Locale,
    options::{self, Options},
    state::{Kind, State},
};
use gnunet_arm_core::wire::{RequestStatus, ResultCode};
use gnunet_config::{CaseContext, ProjectData};
use gnunet_program_host::{
    locale::Translations,
    logging::Environment,
    policy::Level,
    program::{Failure as ProgramFailure, LocaleSetup},
    shared_clock::SharedClock,
};
use std::{
    cell::{Cell, RefCell},
    ffi::OsString,
    io,
    rc::Rc,
};

type Failure = Box<dyn std::error::Error>;

#[derive(Clone, Copy)]
enum Mode {
    Messages,
    Refuse,
    InvalidFormat,
}
struct Catalog {
    mode: Mode,
    calls: Rc<Cell<usize>>,
}
impl Translations for Catalog {
    fn gettext(&self, _: Option<&[u8]>, message: &[u8]) -> io::Result<Vec<u8>> {
        self.calls.set(self.calls.get() + 1);
        if matches!(self.mode, Mode::Refuse) {
            return Err(io::Error::from_raw_os_error(5));
        }
        if matches!(self.mode, Mode::InvalidFormat) {
            return Ok(b"%n\n".to_vec());
        }
        Ok(match message {
            b"Control services and the Automated Restart Manager (ARM)" => b"Gerer ARM".as_slice(),
            b"print this help" => b"afficher l'aide",
            b"You must pass relative time to the `%s' option.\n" => b"duree invalide: %s\n",
            b"service failed to start" => b"echec",
            b"Failed to start the `%s' service: %s\n" => b"%2$s :: %1$s\n",
            b"Unknown status %u for service %s.\n" => b"%2$s : %1$u (etat)\n",
            b"Failed to send a request to kill the `%s' service: %%s\n" => b"%%s / arret %s\n",
            _ => message,
        }
        .to_vec())
    }
    fn ngettext(
        &self,
        _: Option<&[u8]>,
        singular: &[u8],
        plural: &[u8],
        count: u64,
    ) -> io::Result<Vec<u8>> {
        Ok(if count == 1 { singular } else { plural }.to_vec())
    }
}
struct Setup(Rc<dyn Translations>);
impl LocaleSetup for Setup {
    fn configure(&mut self, project: &ProjectData) -> Result<(), ProgramFailure> {
        if project.gettext_domain.as_deref() != Some(b"gnunet") {
            return Err(io::Error::other("wrong ARM catalog domain").into());
        }
        Ok(())
    }
    fn translations(&self) -> Rc<dyn Translations> {
        Rc::clone(&self.0)
    }
    fn case_context(&self) -> Option<CaseContext> {
        Some(CaseContext::c())
    }
}
fn locale(mode: Mode) -> Result<(Locale, Rc<Cell<usize>>), Failure> {
    let calls = Rc::new(Cell::new(0));
    let mut setup = Setup(Rc::new(Catalog {
        mode,
        calls: Rc::clone(&calls),
    }));
    Ok((
        Locale::configure(&mut setup, &ProjectData::default())?,
        calls,
    ))
}
#[test]
fn shared_help_and_time_helper_use_the_selected_catalog() -> Result<(), Failure> {
    let (locale, _) = locale(Mode::Messages)?;
    let help = options::parse_localized(
        [OsString::from("gnunet-arm"), OsString::from("--help")],
        None,
        false,
        b"0.29.1",
        &locale,
    );
    assert_eq!(help.exit, Some(0));
    assert!(help.failure.is_none());
    assert!(
        help.stdout
            .windows(b"Gerer ARM".len())
            .any(|part| part == b"Gerer ARM")
    );
    assert!(
        help.stdout
            .windows(b"afficher l'aide".len())
            .any(|part| part == b"afficher l'aide")
    );
    let bad = options::parse_localized(
        [
            OsString::from("gnunet-arm"),
            OsString::from("--timeout=bad"),
        ],
        None,
        false,
        b"0.29.1",
        &locale,
    );
    assert_eq!(bad.exit, Some(255));
    assert_eq!(bad.stderr, b"duree invalide: timeout\n");
    Ok(())
}
#[test]
fn result_and_monitor_reorder_typed_arguments_without_reinterpreting_native_names()
-> Result<(), Failure> {
    let (locale, _) = locale(Mode::Messages)?;
    let mut state = State::with_locale(
        Options {
            init: Some(b"svc%n\xff".to_vec()),
            ..Default::default()
        },
        locale.clone(),
    );
    state.result(Kind::Init, RequestStatus::SentOk, Some(ResultCode(8)));
    assert_eq!(state.stdout, b"echec :: svc%n\xff\n");
    assert!(!state.output_failed());
    let mut kill = State::with_locale(
        Options {
            term: Some(b"svc%p".to_vec()),
            ..Default::default()
        },
        locale.clone(),
    );
    kill.result(Kind::Term, RequestStatus::Disconnected, None);
    assert_eq!(
        kill.stdout,
        b"We disconnected from ARM before we could send a request / arret svc%p\n"
    );
    let mut monitor = State::with_locale(Options::default(), locale);
    monitor.monitor(b"svc%n", 27);
    assert_eq!(monitor.stderr, b"svc%n : 27 (etat)\n");
    Ok(())
}
#[test]
fn invalid_catalog_format_retires_output_after_its_original_cause_is_taken() -> Result<(), Failure>
{
    let (locale, calls) = locale(Mode::InvalidFormat)?;
    let mut state = State::with_locale(Options::default(), locale);
    state.monitor(b"first", 1);
    assert!(state.output_failed());
    assert!(state.done);
    assert_eq!(
        state.take_output_error().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    state.monitor(b"second", 1);
    state.list_disconnected();
    assert!(state.next(|| true).is_none());
    assert!(state.output_failed());
    assert!(state.take_output_error().is_none());
    assert!(state.stdout.is_empty() && state.stderr.is_empty());
    assert_eq!(calls.get(), 1);
    Ok(())
}
#[test]
fn refused_catalog_stops_getopt_and_admitted_logging_without_english_fallback()
-> Result<(), Failure> {
    let (locale, calls) = locale(Mode::Refuse)?;
    let parsed = options::parse_localized(
        [OsString::from("gnunet-arm"), OsString::from("--help")],
        None,
        false,
        b"0.29.1",
        &locale,
    );
    assert_eq!(parsed.exit, Some(255));
    assert_eq!(
        parsed.failure.and_then(|error| error.raw_os_error()),
        Some(5)
    );
    calls.set(0);
    let selection = Selection::with_locale(
        &Options::default(),
        SharedClock::native(4)?,
        &Environment::default(),
        &mut Vec::new(),
        locale,
    )?;
    let reporter = selection.reporter();
    reporter.message_translated(
        Level::DEBUG,
        "arm.test.hidden",
        Some(b"gnunet"),
        b"hidden",
        &[],
    );
    assert_eq!(calls.get(), 0);
    assert!(!reporter.failed());
    reporter.message_translated(
        Level::ERROR,
        "arm.test.original",
        Some(b"gnunet"),
        b"original",
        &[],
    );
    assert!(reporter.failed());
    assert_eq!(
        reporter.take_error().and_then(|error| error.raw_os_error()),
        Some(5)
    );
    reporter.message_translated(
        Level::ERROR,
        "arm.test.retired",
        Some(b"gnunet"),
        b"later",
        &[],
    );
    assert_eq!(calls.get(), 1);
    Ok(())
}

struct Reentrant(Rc<RefCell<Option<gnunet_program_host::reporting::Reporter>>>);
impl Translations for Reentrant {
    fn gettext(&self, _: Option<&[u8]>, _: &[u8]) -> io::Result<Vec<u8>> {
        if let Some(reporter) = self.0.borrow().as_ref() {
            reporter.message_bytes(Level::ERROR, "arm.test.nested", b"nested\n");
        }
        Err(io::ErrorKind::PermissionDenied.into())
    }
    fn ngettext(&self, _: Option<&[u8]>, _: &[u8], _: &[u8], _: u64) -> io::Result<Vec<u8>> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
#[test]
fn reentrant_catalog_preserves_the_first_reporter_failure() -> Result<(), Failure> {
    let route = Rc::new(RefCell::new(None));
    let mut setup = Setup(Rc::new(Reentrant(Rc::clone(&route))));
    let locale = Locale::configure(&mut setup, &ProjectData::default())?;
    let selection = Selection::with_locale(
        &Options::default(),
        SharedClock::native(4)?,
        &Environment::default(),
        &mut Vec::new(),
        locale,
    )?;
    *route.borrow_mut() = Some(selection.reporter().clone());
    selection.reporter().message_translated(
        Level::ERROR,
        "arm.test.outer",
        Some(b"gnunet"),
        b"outer",
        &[],
    );
    // Break the test's intentional callback cycle before inspecting its result.
    route.borrow_mut().take();
    let first = selection
        .reporter()
        .take_error()
        .ok_or_else(|| io::Error::other("original nested failure disappeared"))?;
    assert_eq!(first.kind(), io::ErrorKind::Other);
    assert!(first.to_string().contains("already borrowed"));
    assert!(selection.reporter().failed());
    Ok(())
}
