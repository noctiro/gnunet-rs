//! Native filename contexts are explicit and do not mutate the process cwd.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert native path identity, explicit context isolation and finite resource refusal"
)]
use gnunet_config::Environment;
use std::{
    cell::Cell,
    io,
    path::{Path, PathBuf},
};

struct Snapshot {
    cwd: PathBuf,
    home: Option<Vec<u8>>,
    cwd_queries: Cell<usize>,
}
impl Snapshot {
    #[cfg(windows)]
    fn new(cwd: &str, home: Option<&str>) -> Self {
        Self {
            cwd: cwd.into(),
            home: home.map(|p| p.as_bytes().to_vec()),
            cwd_queries: Cell::new(0),
        }
    }
}
impl Environment for Snapshot {
    fn variable(&self, key: &[u8]) -> Option<Vec<u8>> {
        (key == b"HOME").then(|| self.home.clone()).flatten()
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        self.cwd_queries.set(self.cwd_queries.get() + 1);
        Ok(self.cwd.clone())
    }
}

#[test]
fn explicit_context_resolves_relative_paths_without_changing_process_state() -> io::Result<()> {
    let original = std::env::current_dir()?;
    let root = original.join("gnunet-explicit-context");
    let environment = Snapshot {
        cwd: root.clone(),
        home: None,
        cwd_queries: Cell::new(0),
    };
    assert_eq!(
        environment.absolute_path(Path::new("child"))?,
        root.join("child")
    );
    assert_eq!(std::env::current_dir()?, original);
    assert_eq!(environment.cwd_queries.get(), 1);
    Ok(())
}

#[cfg(windows)]
mod windows {
    use super::*;
    use gnunet_config::{Configuration, Error, Limits, ProcessEnvironment};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> io::Result<Self> {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "gnunet-native-path-{}-{};space",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    #[test]
    fn denied_native_replacement_exposes_recovery_without_erasing_prepared_data()
    -> Result<(), Box<dyn std::error::Error>> {
        use gnunet_config::Dirty;
        let directory = Directory::new()?;
        let target = directory.0.join("readonly.conf");
        fs::write(&target, b"original")?;
        let writable = fs::metadata(&target)?.permissions();
        let mut readonly = writable.clone();
        readonly.set_readonly(true);
        fs::set_permissions(&target, readonly)?;
        let mut config = Configuration::default();
        config.set_value(b"test", b"value", Some(b"prepared"))?;
        let result = config.write(&target);
        fs::set_permissions(&target, writable)?;
        let Err(Error::Publication(failure)) = result else {
            return Err("read-only destination did not report a native publication failure".into());
        };
        assert_eq!(config.dirty(), Dirty::WriteFailed);
        assert!(failure.error.raw_os_error().is_some());
        assert_eq!(failure.destination, fs::canonicalize(&target)?);
        assert_eq!(fs::read(&target)?, b"original");
        assert_eq!(fs::read(&failure.prepared)?, config.serialize()?);
        assert_eq!(
            gnunet_native::identity::file_owner(&fs::File::open(&failure.prepared)?)?,
            gnunet_native::identity::process_user()?
        );
        config.write(&target)?;
        assert_eq!(config.dirty(), Dirty::Clean);
        assert_eq!(fs::read(&target)?, config.serialize()?);
        // A later success must not erase the earlier failed operation's recovery file.
        assert!(failure.prepared.is_file());
        Ok(())
    }

    #[test]
    fn native_installation_search_handles_quoted_path_and_real_directory_access()
    -> Result<(), Box<dyn std::error::Error>> {
        use gnunet_config::{Installation, InstallationOrigin, PathKind, ProjectData};
        let directory = Directory::new()?;
        let prefix = directory.0.join("installed package");
        let bin = prefix.join("bin");
        let libexec = prefix.join("lib").join("gnunet").join("libexec");
        fs::create_dir_all(&bin)?;
        fs::create_dir_all(&libexec)?;
        fs::write(
            bin.join("gnunet-arm.exe"),
            b"owned discovery marker; never executed",
        )?;
        struct Search {
            path: Vec<u8>,
            cwd: PathBuf,
        }
        impl Environment for Search {
            fn variable(&self, key: &[u8]) -> Option<Vec<u8>> {
                (key == b"PATH").then(|| self.path.clone())
            }
            fn current_dir(&self) -> io::Result<PathBuf> {
                Ok(self.cwd.clone())
            }
        }
        let paths = std::env::join_paths([directory.0.join("absent"), bin.clone()])?;
        let environment = Search {
            path: paths
                .to_str()
                .ok_or("fixture PATH is not UTF-8")?
                .as_bytes()
                .to_vec(),
            cwd: directory.0.clone(),
        };
        let installation = Installation::discover(&ProjectData::default(), &environment)?;
        assert_eq!(installation.origin(), InstallationOrigin::SearchPath);
        assert_eq!(installation.path(PathKind::Prefix), Some(prefix.as_path()));
        assert_eq!(installation.path(PathKind::Bindir), Some(bin.as_path()));
        assert_eq!(
            installation.path(PathKind::Libexecdir),
            Some(libexec.as_path())
        );
        let relative = Search {
            path: br"installed package\bin".to_vec(),
            cwd: directory.0.clone(),
        };
        assert_eq!(
            Installation::discover(&ProjectData::default(), &relative)?.path(PathKind::Prefix),
            Some(prefix.as_path())
        );
        let opened = gnunet_native::paths::open_directory(&libexec, true)?;
        assert!(opened.metadata()?.is_dir());
        let owner = gnunet_native::identity::file_owner(&opened)?;
        assert!(owner.to_string().starts_with("S-1-"));
        assert_eq!(
            gnunet_native::paths::open_directory(&bin.join("gnunet-arm.exe"), true)
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::NotADirectory)
        );
        Ok(())
    }

    #[test]
    fn native_include_glob_and_explicit_program_paths_keep_their_source_namespace()
    -> Result<(), Box<dyn std::error::Error>> {
        use gnunet_config::{BinaryPathCache, ProjectData};
        let directory = Directory::new()?;
        let main = directory.0.join("main.conf");
        let child = directory.0.join("child.conf");
        let fragments = directory.0.join("fragments+literal~parent");
        fs::create_dir(&fragments)?;
        fs::write(&child, b"[child]\nvalue=absolute\n")?;
        fs::write(fragments.join("a.conf"), b"[glob]\nvalue=first\n")?;
        fs::write(fragments.join("b.conf"), b"[glob]\nvalue=second\n")?;
        fs::write(
            &main,
            format!(
                "@INLINE@ {}\n@INLINE-MATCHING@ fragments+literal~parent\\*.conf\n",
                child.display()
            ),
        )?;
        let mut config = Configuration::default();
        config.parse(&main)?;
        assert_eq!(config.get(b"child", b"value"), Some(b"absolute".as_slice()));
        assert_eq!(config.get(b"glob", b"value"), Some(b"second".as_slice()));
        assert!(config.test_file(&main, true, &ProcessEnvironment, None)?);
        let mut diagnostic = Configuration::default();
        diagnostic.enable_diagnostics();
        let secret_main = directory.0.join("secret-main.conf");
        fs::write(&secret_main, b"@INLINE-SECRET@ child child.conf\n")?;
        diagnostic.parse(&secret_main)?;
        let text = diagnostic.serialize_diagnostics()?;
        assert!(
            text.windows(b"owner_sid=S-1-".len())
                .any(|b| b == b"owner_sid=S-1-")
        );
        config.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(br"C:\not-selected"))?;
        let mut cache = BinaryPathCache::new();
        let explicit = br"D:\native\helper.exe";
        assert_eq!(
            config.suid_binary_path_for_project_with(
                &ProjectData::default(),
                explicit,
                &mut cache
            )?,
            Path::new(r"D:\native\helper.exe")
        );
        assert_eq!(
            ProjectData::default().libexec_binary_path_with(
                explicit,
                &ProcessEnvironment,
                &mut cache
            )?,
            Path::new(r"D:\native\helper.exe")
        );
        Ok(())
    }

    #[test]
    fn absolute_drive_unc_and_verbatim_paths_keep_their_original_namespace() -> Result<(), Error> {
        let config = Configuration::default();
        let context = Snapshot::new(r"C:\captured\work", None);
        for path in [
            r"D:\data\gnunet.conf",
            r"D:/data/gnunet.conf",
            r"\\server\share\gnunet.conf",
            r"\\?\D:\data\..\literal\gnunet.conf",
            r"\\?\UNC\server\share\gnunet.conf",
        ] {
            let expanded = config.expand_filename(path.as_bytes(), &context)?;
            assert_eq!(expanded.as_os_str(), Path::new(path).as_os_str());
        }
        assert_eq!(context.cwd_queries.get(), 0);
        Ok(())
    }

    #[test]
    fn captured_current_drive_root_relative_home_and_dollar_paths_are_native() -> Result<(), Error>
    {
        let mut config = Configuration::default();
        let context = Snapshot::new(r"C:\captured\work", Some(r"D:\profiles\User λ"));
        for (input, expected) in [
            (r"child\file", r"C:\captured\work\child\file"),
            (r"\rooted\file", r"C:\rooted\file"),
            ("/rooted/file", r"C:\rooted\file"),
            (r"C:child\file", r"C:\captured\work\child\file"),
            (r"c:child\file", r"C:\captured\work\child\file"),
            (r"~\child", r"D:\profiles\User λ\child"),
            ("~/child", r"D:\profiles\User λ\child"),
            (r"~other\file", r"D:\profiles\User λ\other\file"),
        ] {
            assert_eq!(
                config.expand_filename(input.as_bytes(), &context)?,
                Path::new(expected)
            );
        }
        config.set_value(b"PATHS", b"ROOT", Some(br"D:\service"))?;
        config.set_value(b"test", b"FILE", Some(br"$ROOT\gnunet.conf"))?;
        assert_eq!(
            config.get_filename(b"test", b"FILE", &context)?,
            Path::new(r"D:\service\gnunet.conf")
        );
        Ok(())
    }

    #[test]
    fn snapshot_cannot_borrow_an_ambient_other_drive_or_home() -> Result<(), Error> {
        let config = Configuration::default();
        let context = Snapshot::new(r"C:\captured\work", None);
        assert!(
            matches!(config.expand_filename(br"D:child", &context), Err(Error::Io { error, .. }) if error.kind() == io::ErrorKind::NotFound)
        );
        assert!(matches!(
            config.expand_filename(b"~", &context),
            Err(Error::Missing)
        ));
        assert!(matches!(
            config.expand_filename(b"C:\\bad\0name", &context),
            Err(Error::InvalidInput)
        ));
        let tiny = Configuration::new(Limits {
            max_expanded_bytes: 8,
            ..Default::default()
        });
        assert!(matches!(
            tiny.expand_filename(b"child", &context),
            Err(Error::Capacity)
        ));
        Ok(())
    }

    #[test]
    fn process_context_resolves_its_real_current_drive_without_filesystem_access()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = Configuration::default();
        let cwd = std::env::current_dir()?;
        let drive = match cwd.components().next() {
            Some(std::path::Component::Prefix(p)) => match p.kind() {
                std::path::Prefix::Disk(d) | std::path::Prefix::VerbatimDisk(d) => d,
                _ => return Err("native test cwd has no drive letter".into()),
            },
            _ => return Err("native test cwd has no prefix".into()),
        };
        let drive_relative = format!("{}:gnunet-native-path-not-created", char::from(drive));
        assert_eq!(
            config.expand_filename(drive_relative.as_bytes(), &ProcessEnvironment)?,
            cwd.join("gnunet-native-path-not-created")
        );
        assert_eq!(
            config.expand_filename(b"gnunet-native-path-not-created", &ProcessEnvironment)?,
            cwd.join("gnunet-native-path-not-created")
        );
        assert_eq!(config.expand_filename(b"", &ProcessEnvironment)?, cwd);
        assert_eq!(std::env::current_dir()?, cwd);
        Ok(())
    }
}
