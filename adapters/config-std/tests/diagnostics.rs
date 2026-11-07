//! Observer lifetime, routing and source progress, using only owned tmp fixtures.
#![expect(
    clippy::unwrap_used,
    reason = "Test assertions unwrap only owned, deterministic fixture setup"
)]
use gnunet_config::{
    Configuration, ProcessEnvironment,
    diagnostic::{Diagnostic, Observer},
};
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::{Arc, Mutex},
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "owned-config-observer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
#[test]
fn local_nonsend_observer_overrides_persistent_through_nested_secret_and_is_not_retained() {
    let fixture = Fixture::new();
    let main = fixture.0.join("main.conf");
    let child = fixture.0.join("child.conf");
    std::fs::write(&main, b"@INLINE-SECRET@ secret child.conf\n").unwrap();
    std::fs::write(&child, b"@INLINE@ forbidden.conf\n").unwrap();
    let mut cfg = Configuration::default();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&calls);
    let callback: Observer = Arc::new(move |event| keep.lock().unwrap().push(event.site.id));
    drop(cfg.observe(Some(callback)));
    let local = Rc::new(RefCell::new(Vec::new()));
    let callback = |event: Diagnostic<'_>| local.borrow_mut().push(event.site.id);
    assert!(
        cfg.load_explicit_observed(None, Some(&main), Some(&callback))
            .is_err()
    );
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(
        local
            .borrow()
            .iter()
            .filter(|id| **id == "config.deserialize.restricted")
            .count(),
        1
    );
    assert_eq!(
        local
            .borrow()
            .iter()
            .filter(|id| **id == "config.parse.failed")
            .count(),
        2
    );
    assert_eq!(
        local.borrow().last().copied(),
        Some("config.load.main-failed")
    );
    let original = local.borrow().len();
    assert!(cfg.deserialize(b"bad\n", None).is_err());
    assert_eq!(local.borrow().len(), original);
    assert_eq!(*calls.lock().unwrap(), vec!["config.deserialize.syntax"]);
}
#[test]
fn duplicate_and_secret_fresh_keep_same_persistent_observer_identity() {
    let fixture = Fixture::new();
    let main = fixture.0.join("main.conf");
    std::fs::write(&main, b"@INLINE-SECRET@ secret child.conf\n").unwrap();
    std::fs::write(fixture.0.join("child.conf"), b"[other]\na=value\n").unwrap();
    let mut cfg = Configuration::default();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&calls);
    let callback: Observer = Arc::new(move |event| keep.lock().unwrap().push(event.site.id));
    drop(cfg.observe(Some(Arc::clone(&callback))));
    cfg.parse(&main).unwrap();
    assert!(
        calls
            .lock()
            .unwrap()
            .contains(&"config.inline.secret-absent")
    );
    let mut copy = cfg.duplicate().unwrap();
    let actual = copy.observe(None).unwrap();
    assert!(Arc::ptr_eq(&actual, &callback));
    assert!(cfg.observe(None).is_some());
}
#[test]
fn synchronous_observer_copies_borrowed_operands_and_preserves_pre_error_assignment() {
    let mut cfg = Configuration::default();
    let owned = RefCell::new(Vec::new());
    let sink = |event: Diagnostic<'_>| {
        owned.borrow_mut().push((
            event.site.id,
            event.template.to_vec(),
            event
                .arguments
                .iter()
                .filter_map(|a| match a {
                    gnunet_config::diagnostic::Argument::Bytes(v) => Some(v.to_vec()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
        ));
    };
    assert!(
        cfg.deserialize_observed(b"[own]\nkey=accepted\nbroken\n", None, Some(&sink))
            .is_err()
    );
    assert_eq!(cfg.get(b"own", b"key"), Some(b"accepted".as_slice()));
    assert_eq!(owned.borrow().len(), 1);
    assert_eq!(owned.borrow()[0].0, "config.deserialize.syntax");
}
#[test]
fn retired_persistent_observer_drops_captures_once_and_config_stays_send_sync() {
    fn require<T: Send + Sync>() {}
    require::<Configuration>();
    let captured = Arc::new(());
    let held = Arc::clone(&captured);
    let callback: Observer = Arc::new(move |_| {
        let _reference = &held;
    });
    let mut cfg = Configuration::default();
    drop(cfg.observe(Some(callback)));
    assert_eq!(Arc::strong_count(&captured), 2);
    let old = cfg.observe(None).unwrap();
    assert_eq!(Arc::strong_count(&captured), 2);
    drop(old);
    assert_eq!(Arc::strong_count(&captured), 1);
    cfg.deserialize(b"[own]\nkey=value\n", None).unwrap();
    assert_eq!(Arc::strong_count(&captured), 1);
}
#[test]
fn cleanup_read_failure_and_missing_provenance_report_distinct_source_sites() {
    let fixture = Fixture::new();
    let path = fixture.0.join("main.conf");
    std::fs::write(&path, b"[own]\nkey=value\n").unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&calls);
    let mut cfg = Configuration::default();
    cfg.enable_diagnostics();
    drop(cfg.observe(Some(Arc::new(move |event| {
        captured.lock().unwrap().push(event.site.id)
    }))));
    assert!(matches!(
        cfg.clean_file(&path),
        Err(gnunet_config::Error::Missing)
    ));
    assert_eq!(
        calls.lock().unwrap().last().copied(),
        Some("config.clean.not-parsed")
    );
    cfg.parse_observed(&path, &ProcessEnvironment, None)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        cfg.clean_file(&path),
        Err(gnunet_config::Error::Changed)
    ));
    assert_eq!(
        calls.lock().unwrap().last().copied(),
        Some("config.clean.read-changed")
    );
}

#[test]
fn native_load_marks_attempt_and_main_before_default_discovery_failure() {
    // No native installation is inferred by Configuration::default(); avoid any
    // process environment mutation or native library/OS discovery in this case.
    let project = std::sync::Arc::new(gnunet_config::ProjectData {
        base_config_varname: None,
        ..Default::default()
    });
    let mut cfg = Configuration::with_installation(
        project,
        gnunet_config::Installation::empty(),
        Default::default(),
    )
    .unwrap();
    let events = RefCell::new(Vec::new());
    let observer = |event: Diagnostic<'_>| events.borrow_mut().push(event.site.id);
    let first = std::path::Path::new("/owned/no-io/first");
    assert!(matches!(
        cfg.load_observed(Some(first), Some(&observer)),
        Err(gnunet_config::Error::Missing)
    ));
    assert!(
        cfg.serialize_diagnostics()
            .unwrap()
            .windows(b"# Entry point: /owned/no-io/first\n".len())
            .any(|v| v == b"# Entry point: /owned/no-io/first\n")
    );
    assert_eq!(*events.borrow(), ["config.load.installation-missing"]);
    assert!(matches!(
        cfg.load_observed(None, Some(&observer)),
        Err(gnunet_config::Error::Missing)
    ));
    assert!(
        cfg.serialize_diagnostics()
            .unwrap()
            .windows(b"# Entry point: <none>\n".len())
            .any(|v| v == b"# Entry point: <none>\n")
    );
    assert_eq!(
        *events.borrow(),
        [
            "config.load.installation-missing",
            "config.load.repeated",
            "config.load.installation-missing"
        ]
    );
}

#[test]
fn local_route_remains_one_identity_through_typed_expansion_iterator_write_and_clean() {
    let fixture = Fixture::new();
    let path = fixture.0.join("main.conf");
    std::fs::write(
        &path,
        b"@INLINE-SECRET@ hidden absent.conf\n[own]\nkey=value\n",
    )
    .unwrap();
    let mut cfg = Configuration::default();
    cfg.enable_diagnostics();
    let persistent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let keep = Arc::clone(&persistent);
    drop(cfg.observe(Some(Arc::new(move |_| {
        keep.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }))));
    let events = RefCell::new(Vec::new());
    let observer = |event: Diagnostic<'_>| events.borrow_mut().push(event.site.id);
    cfg.parse_observed(&path, &ProcessEnvironment, Some(&observer))
        .unwrap();
    assert!(matches!(
        cfg.get_number_observed(b"hidden", b"absent", Some(&observer)),
        Err(gnunet_config::Error::Missing)
    ));
    assert_eq!(
        cfg.section_values_observed(b"hidden", Some(&observer))
            .count(),
        0
    );
    cfg.set_value(b"own", b"choice", Some(b"wrong")).unwrap();
    assert!(
        cfg.get_choice_observed(b"own", b"choice", &[b"YES", b"NO"], Some(&observer))
            .is_err()
    );
    assert_eq!(
        cfg.expand_dollar_observed(
            b"${OWNED_CONFIG_NEVER_SET_7BB:-fallback}",
            &ProcessEnvironment,
            Some(&observer)
        )
        .unwrap(),
        b"fallback"
    );
    let blocked = fixture.0.join("blocked");
    std::fs::write(&blocked, b"owned ordinary file").unwrap();
    assert!(
        cfg.write_observed(blocked.join("result.conf"), Some(&observer))
            .is_err()
    );
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        cfg.clean_file_observed(&path, Some(&observer)),
        Err(gnunet_config::Error::Changed)
    ));
    for expected in [
        "config.find-entry.inaccessible",
        "config.iterate.inaccessible",
        "config.choice.invalid",
        "config.dollar.asked",
        "config.disk.directory-create-failed",
        "config.disk.lstat",
        "config.clean.read-changed",
    ] {
        assert!(events.borrow().contains(&expected), "missing {expected}");
    }
    assert_eq!(persistent.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(cfg.get_choice(b"own", b"choice", &[b"YES", b"NO"]).is_err());
    assert_eq!(persistent.load(std::sync::atomic::Ordering::SeqCst), 1);
}
