//! Path construction and cache authority only; no returned program is executed.
#![expect(
    clippy::panic_in_result_fn,
    reason = "The tests assert lazy installation/caching and native path bytes."
)]
use super::*;
use std::cell::Cell;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> std::io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "gcfg-suid-paths-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory)?;
        Ok(Self(directory))
    }
    fn installation(&self, project: &ProjectData) -> Result<Installation> {
        fs::create_dir_all(
            self.0
                .join("lib")
                .join(bytes_path(&project.project_dirname)?)
                .join("libexec"),
        )?;
        Ok(Installation::from_locations(project, &self.0, None)?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}

#[test]
fn supplied_installation_is_lazy_and_first_successful_fallback_owns_cache() -> Result<()> {
    let directory = Directory::new()?;
    let project = ProjectData {
        project_dirname: b"supplied-b".to_vec(),
        ..ProjectData::default()
    };
    let installation = directory.installation(&project)?;
    let mut cfg = Configuration::new(Limits::default());
    assert_ne!(cfg.project_data().project_dirname, project.project_dirname);
    let mut cache = BinaryPathCache::new();
    let calls = Cell::new(0);
    let first = cfg.suid_binary_path_resolve(b"helper", &mut cache, || {
        calls.set(calls.get() + 1);
        Ok(installation)
    })?;
    let mut expected = path_bytes(&directory.0)?.to_vec();
    expected.extend_from_slice(b"/lib//supplied-b/libexec/helper");
    assert_eq!(path_bytes(&first)?, expected);
    let next = cfg.suid_binary_path_resolve(b"helper", &mut cache, || {
        calls.set(calls.get() + 1);
        Err(Error::Unsupported)
    })?;
    assert_eq!(next, first);
    assert_eq!(calls.get(), 1);
    cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/raw/$LITERAL/"))?;
    assert_eq!(
        cfg.suid_binary_path_resolve(b"helper", &mut cache, || Err(Error::Unsupported))?,
        Path::new("/raw/$LITERAL/helper")
    );
    cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/changed"))?;
    assert_eq!(
        cfg.suid_binary_path_resolve(b"helper", &mut cache, || Err(Error::Unsupported))?,
        Path::new("/raw/$LITERAL/helper")
    );
    Ok(())
}

#[test]
fn absolute_and_rejected_program_do_not_discover_or_poison_cache() -> Result<()> {
    let cfg = Configuration::new(Limits::default());
    let invalid_project = ProjectData {
        project_dirname: b"invalid\0project".to_vec(),
        ..ProjectData::default()
    };
    let mut cache = BinaryPathCache::new();
    assert_eq!(
        cfg.suid_binary_path_for_project_with(&invalid_project, b"/owned/plain", &mut cache)?,
        Path::new("/owned/plain")
    );
    assert!(cache.suid.is_none() && cache.libexec.is_none());
    assert!(matches!(
        cfg.suid_binary_path_for_project_with(&invalid_project, b"helper", &mut cache),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        cfg.suid_binary_path_resolve(b"invalid\0program", &mut cache, || {
            Err(Error::Unsupported)
        }),
        Err(Error::InvalidInput)
    ));
    assert!(cache.suid.is_none() && cache.libexec.is_none());
    Ok(())
}

#[test]
fn unavailable_fallback_is_not_a_cached_negative_result() -> Result<()> {
    let cfg = Configuration::new(Limits::default());
    let mut cache = BinaryPathCache::new();
    assert_eq!(
        cfg.suid_binary_path_resolve(b"helper", &mut cache, || Ok(Installation::empty()))?,
        Path::new("helper")
    );
    assert!(cache.libexec.is_none());
    let directory = Directory::new()?;
    let project = ProjectData {
        project_dirname: b"available-next".to_vec(),
        ..ProjectData::default()
    };
    let resolved = cfg.suid_binary_path_resolve(b"helper", &mut cache, || {
        directory
            .installation(&project)
            .map_err(|_| Error::InvalidValue)
    })?;
    assert!(path_bytes(&resolved)?.ends_with(b"/available-next/libexec/helper"));
    Ok(())
}
