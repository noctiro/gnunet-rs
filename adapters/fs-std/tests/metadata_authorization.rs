//! Configuration restoration cannot recreate native execution authority.
#![cfg(all(any(unix, windows), feature = "extraction"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native regressions compare restored authority, exact selections and real loader refusals"
)]
use gnunet_fs_host::{
    Control,
    extraction::{self, MetadataSettings, NativeMetadataAuthorization},
};
use gnunet_native::filesystem::Directory;
use std::{
    cell::Cell,
    ffi::OsStr,
    fs,
    io::{self, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Scratch(PathBuf);
impl Scratch {
    fn create() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let temporary = std::env::temp_dir();
        let name = format!(
            "gnunet-metadata-authority-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let parent = Directory::open(&temporary)?;
        let root = parent.create_private_directory(OsStr::new(&name))?;
        let mut file = root.create_private_file(OsStr::new("source.txt"))?;
        file.write_all(b"original source")?;
        Ok(Self(temporary.join(name)))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn inspect(
    scratch: &Scratch,
    metadata: MetadataSettings,
) -> Result<Box<extraction::InspectionFailure>> {
    let emitted = Cell::new(false);
    let outcome = extraction::inspect_with_metadata(
        &scratch.0.join("source.txt"),
        extraction::Limits::default(),
        extraction::Policy::default(),
        metadata,
        |_| Control::Continue,
        |_| {
            emitted.set(true);
            Ok(())
        },
    );
    assert!(!emitted.get());
    outcome
        .err()
        .ok_or_else(|| "native selection incorrectly became a successful builtin inspection".into())
}
#[test]
#[expect(
    unsafe_code,
    reason = "The only authorized library path is absent inside this test's private directory; no native initializer can execute during these negative loader checks"
)]
fn snapshots_preserve_configuration_but_require_matching_current_execution_authority() -> Result {
    let scratch = Scratch::create()?;
    let library = scratch.0.join("missing-provider.dll");
    let raw = MetadataSettings::new(false, Some(b"pdf:exact-options"), Some(library.clone()))?;
    assert!(!raw.is_native_authorized());
    // SAFETY: this private missing path remains absent for every use/clone here.
    // Loads fail before any native code can execute; no snapshot can authorize it.
    let authority = unsafe {
        NativeMetadataAuthorization::new(
            raw.native_configuration()
                .ok_or("missing native config")?
                .clone(),
        )
    };
    let approved = raw.clone().with_native_authorization(&authority)?;
    assert!(approved.is_native_authorized());
    assert_eq!(raw.snapshot()?, approved.snapshot()?);
    let restored = MetadataSettings::from_snapshot(&approved.snapshot()?)?;
    assert!(!restored.is_native_authorized());
    for settings in [raw, restored.clone()] {
        let failure = inspect(&scratch, settings)?;
        assert!(matches!(
            failure.cause,
            extraction::Error::MetadataSettings(
                gnunet_extractor_host::NativeError::AuthorizationRequired
            )
        ));
    }
    let rebound = restored.with_authorization_from(&approved)?;
    assert!(rebound.is_native_authorized());
    let failure = inspect(&scratch, rebound)?;
    assert!(
        matches!(failure.cause, extraction::Error::Extractor(ref error) if matches!(&error.cause, gnunet_extractor_host::Cause::Native(gnunet_extractor_host::NativeError::Loader { .. })))
    );
    for configured in [
        None,
        Some(b"".as_slice()),
        Some(b"pdf:different-options".as_slice()),
    ] {
        let other = MetadataSettings::new(false, configured, Some(library.clone()))?;
        assert!(matches!(
            other.with_native_authorization(&authority),
            Err(extraction::Error::MetadataSettings(
                gnunet_extractor_host::NativeError::AuthorizationMismatch
            ))
        ));
    }
    let other = MetadataSettings::new(
        false,
        Some(b"pdf:exact-options"),
        Some(scratch.0.join("other-provider.dll")),
    )?;
    assert!(matches!(
        other.with_native_authorization(&authority),
        Err(extraction::Error::MetadataSettings(
            gnunet_extractor_host::NativeError::AuthorizationMismatch
        ))
    ));
    Ok(())
}
#[cfg(all(unix, feature = "network"))]
#[test]
#[expect(
    unsafe_code,
    reason = "Only pure task creation/reopening is performed with an absent private library path; no native code is loaded"
)]
fn task_creation_retains_runtime_authority_but_reopen_requires_explicit_reattachment() -> Result {
    use gnunet_fs_host::unindex_task::{Limits, Task};
    let scratch = Scratch::create()?;
    let selected = MetadataSettings::new(false, None, Some(scratch.0.join("missing-provider.so")))?;
    // SAFETY: the test never loads this missing library; authority is checked
    // only as ephemeral in-memory state around real private task persistence.
    let authority = unsafe {
        NativeMetadataAuthorization::new(
            selected
                .native_configuration()
                .ok_or("missing native config")?
                .clone(),
        )
    };
    let approved = selected.with_native_authorization(&authority)?;
    let path = scratch.0.join("task");
    let task = Task::create(
        &path,
        scratch.0.join("source.txt"),
        &[],
        approved.clone(),
        Limits::default(),
    )?;
    assert!(task.manifest().metadata.is_native_authorized());
    let original_snapshot = task.manifest().metadata.snapshot()?;
    drop(task);
    let mut restored = Task::open(&path, Limits::default())?;
    assert!(!restored.manifest().metadata.is_native_authorized());
    restored.authorize_metadata_from(&approved)?;
    assert!(restored.manifest().metadata.is_native_authorized());
    assert_eq!(restored.manifest().metadata.snapshot()?, original_snapshot);
    Ok(())
}
