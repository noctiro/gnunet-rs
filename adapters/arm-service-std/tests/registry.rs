//! Source-shaped configuration snapshots; no listener or process is created.
#![expect(
    clippy::expect_used,
    reason = "Finite explicit configuration mutations and registry preparation are expected setup"
)]
use gnunet_arm_service_host::registry::{Error, Limits, Recipe, Registry};
use gnunet_config::{BinaryPathCache, Configuration, Environment, ProjectData};
use std::{io, path::PathBuf};
struct Env;
impl Environment for Env {
    fn variable(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        Ok(std::env::temp_dir())
    }
}
fn put(c: &mut Configuration, s: &[u8], k: &[u8], v: &[u8]) {
    c.set_value(s, k, Some(v)).expect("config value");
}
fn build(c: &Configuration) -> Result<Registry, Error> {
    Registry::from_config(
        c,
        &Env,
        &ProjectData::default(),
        &mut BinaryPathCache::new(),
        Limits::default(),
    )
}
fn service(c: &mut Configuration, name: &[u8]) {
    put(c, name, b"BINARY", b"/owned/example");
    put(c, name, b"TYPE", b"SIMPLE");
}
#[test]
fn all_services_remain_registered_and_head_insertion_order_is_preserved() {
    let mut c = Configuration::default();
    service(&mut c, b"first");
    service(&mut c, b"second");
    let registry = build(&c).expect("registry");
    assert_eq!(
        registry
            .services()
            .iter()
            .map(|s| s.name.as_slice())
            .collect::<Vec<_>>(),
        vec![b"first".as_slice(), b"second".as_slice()]
    );
    assert!(registry.services().iter().all(|s| !s.immediate && !s.bind));
    assert_eq!(registry.specs().len(), 2);
}
#[test]
fn category_absence_yes_no_and_invalid_follow_source_selection() {
    let mut c = Configuration::default();
    service(&mut c, b"system");
    service(&mut c, b"user");
    put(&mut c, b"user", b"RUN_PER_USER", b"YES");
    assert_eq!(
        build(&c)
            .expect("missing both enables both")
            .services()
            .len(),
        2
    );
    put(&mut c, b"arm", b"START_SYSTEM_SERVICES", b"YES");
    assert_eq!(
        build(&c)
            .expect("only system explicitly selected")
            .services()[0]
            .name,
        b"system"
    );
    put(&mut c, b"arm", b"START_SYSTEM_SERVICES", b"NO");
    assert!(matches!(build(&c), Err(Error::Categories)));
    put(&mut c, b"arm", b"START_USER_SERVICES", b"YES");
    assert_eq!(
        build(&c).expect("user selected").services()[0].name,
        b"user"
    );
    put(&mut c, b"arm", b"START_USER_SERVICES", b"maybe");
    assert!(matches!(build(&c), Err(Error::Categories)));
}
#[test]
fn immediate_noarmbind_and_ondemand_branching_retains_nonlisteners() {
    let mut c = Configuration::default();
    service(&mut c, b"s");
    put(&mut c, b"s", b"NOARMBIND", b"YES");
    put(&mut c, b"s", b"START_ON_DEMAND", b"YES");
    assert!(
        build(&c)
            .expect("NOARMBIND ignored outside immediate")
            .services()[0]
            .bind
    );
    put(&mut c, b"s", b"IMMEDIATE_START", b"YES");
    let r = build(&c).expect("immediate no bind");
    assert!(r.services()[0].immediate);
    assert!(!r.services()[0].bind);
    put(&mut c, b"s", b"NOARMBIND", b"NO");
    assert!(build(&c).expect("immediate with bind").services()[0].bind);
}
#[test]
fn simple_filename_argv0_options_and_global_substitution_are_source_exact() {
    let mut c = Configuration::default();
    service(&mut c, b"svc");
    put(&mut c, b"arm", b"GLOBAL_PREFIX", b"/owned/wrapper");
    put(&mut c, b"arm", b"GLOBAL_POSTFIX", b"--name={}");
    put(&mut c, b"svc", b"OPTIONS", b"alpha beta");
    let r = build(&c).expect("simple plan");
    assert!(
        matches!(&r.services()[0].recipe,Recipe::Simple{filename,argv0,options} if filename=="/owned/wrapper"&&argv0=="/owned/example"&&options=="--name=svc alpha beta")
    );
    let mut c = Configuration::default();
    service(&mut c, b"s");
    put(&mut c, b"s", b"OPTIONS", b"alpha beta");
    let r = build(&c).expect("empty prefix is retained for actual later precheck");
    assert!(
        matches!(&r.services()[0].recipe,Recipe::Simple{filename,options,..} if filename.is_empty()&&options==" alpha beta")
    );
}
#[test]
fn caller_capacity_rejects_complete_registry_and_recursive_substitutions() {
    let mut c = Configuration::default();
    service(&mut c, b"s");
    let result = Registry::from_config(
        &c,
        &Env,
        &ProjectData::default(),
        &mut BinaryPathCache::new(),
        Limits {
            services: 0,
            ..Limits::default()
        },
    );
    assert!(matches!(result, Err(Error::Capacity)));
    let mut c = Configuration::default();
    service(&mut c, b"{}");
    put(&mut c, b"arm", b"GLOBAL_POSTFIX", b"{}");
    let result = Registry::from_config(
        &c,
        &Env,
        &ProjectData::default(),
        &mut BinaryPathCache::new(),
        Limits {
            substitutions: 4,
            ..Limits::default()
        },
    );
    assert!(matches!(result, Err(Error::Capacity)));
}
