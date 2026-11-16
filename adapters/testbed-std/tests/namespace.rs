//! Native publication/restart and physical-source replacement behavior, without peers.
use gnunet_native::{filesystem::Directory, os_bytes};
use gnunet_testbed_host::{Options, Replace, System, core};
use std::{
    error::Error,
    ffi::OsStr,
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
type Failure = Box<dyn Error>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self, Failure> {
        let parent_path = std::env::temp_dir();
        let parent = Directory::open(&parent_path)?;
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("tb-{}-{serial}", std::process::id());
        let _original = parent.create_private_directory(OsStr::new(&name))?;
        Ok(Self {
            path: parent_path.join(name),
        })
    }
    fn options(&self) -> Options {
        Options {
            prefix: Some(self.path.join("owned")),
            ..Options::default()
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.path);
    }
}
fn check(condition: bool, message: &'static str) -> Result<(), Failure> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}
#[test]
fn restart_keeps_native_paths_and_explicit_cleanup_does_not_follow_links() -> Result<(), Failure> {
    let fixture = Fixture::new()?;
    let instance = core::Instance::new();
    let mut slots = [core::PortSlot::empty()];
    let mut system = System::create(&instance, &mut slots, fixture.options())?;
    let template = gnunet_config::Configuration::default();
    let generated = system.configuration_create(&template)?;
    let first = generated.home().to_owned();
    let canonical = generated.default_config();
    let receipt = system.write_configuration(&generated, &canonical, Replace::NewOnly)?;
    check(
        receipt.bytes() == std::fs::metadata(&canonical)?.len() as usize,
        "publication byte receipt differs from original file",
    )?;
    let configured = generated
        .configuration()
        .get(b"PATHS", b"GNUNET_HOME")
        .ok_or("generated home missing")?;
    let configured_path = os_bytes::decode(configured)?;
    check(
        &*configured_path == first.as_os_str(),
        "native generated path did not round trip",
    )?;
    system.destroy(false)?;
    let mut slots = [core::PortSlot::empty()];
    let mut reopened = System::create(&instance, &mut slots, fixture.options())?;
    let next = reopened.configuration_create(&template)?;
    check(next.home() != first, "restarted root reused an issued home")?;
    #[cfg(unix)]
    {
        let outside = fixture.path.join("outside");
        std::fs::create_dir(&outside)?;
        std::fs::write(outside.join("keep"), b"original outside bytes")?;
        std::os::unix::fs::symlink(&outside, next.home().join("external-link"))?;
    }
    drop(next);
    drop(generated);
    reopened.destroy(true)?;
    check(
        !fixture.path.join("owned").try_exists()?,
        "explicit cleanup retained the original root",
    )?;
    #[cfg(unix)]
    check(
        std::fs::read(fixture.path.join("outside/keep"))? == b"original outside bytes",
        "cleanup traversed an external symlink",
    )?;
    Ok(())
}
#[test]
fn replaced_home_and_root_cannot_redirect_a_canonical_publication() -> Result<(), Failure> {
    let fixture = Fixture::new()?;
    let instance = core::Instance::new();
    let mut slots = [core::PortSlot::empty()];
    let mut system = System::create(&instance, &mut slots, fixture.options())?;
    let generated = system.configuration_create(&gnunet_config::Configuration::default())?;
    let home = generated.home();
    let moved = fixture.path.join("original-home");
    std::fs::rename(home, &moved)?;
    let root = Directory::open(system.directory())?;
    let _replacement =
        root.create_private_directory(home.file_name().ok_or("home has no leaf")?)?;
    std::fs::write(home.join("keep"), b"replacement home")?;
    check(
        system
            .write_configuration(&generated, &generated.default_config(), Replace::NewOnly)
            .is_err(),
        "replacement home accepted original canonical publication",
    )?;
    check(
        !home.join("config").try_exists()?,
        "replacement home received canonical bytes",
    )?;
    check(
        std::fs::read(home.join("keep"))? == b"replacement home",
        "replacement home was altered",
    )?;
    let selected_root = fixture.path.join("owned");
    std::fs::rename(&selected_root, fixture.path.join("original-root"))?;
    let parent = Directory::open(&fixture.path)?;
    let _replacement = parent.create_private_directory(OsStr::new("owned"))?;
    check(
        system
            .configuration_create(&gnunet_config::Configuration::default())
            .is_err(),
        "replacement root accepted another allocation",
    )?;
    check(
        std::fs::read_dir(&selected_root)?.next().is_none(),
        "replacement root was changed",
    )?;
    system.destroy(false)?;
    check(
        moved.try_exists()?,
        "original home disappeared during refused publication",
    )
}
