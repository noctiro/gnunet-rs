//! Installed/default/tool public contracts beyond the component parser oracle.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare official host boundaries and actual filesystem effects."
)]
use gnunet_config::{
    BinaryPathCache, ConfigSettings, Configuration, Dirty, Environment, Error, Installation,
    InstallationOrigin, Limits, PathKind, ProjectData,
};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "gcfg-official-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn put(&self, name: &str, data: &[u8]) -> io::Result<PathBuf> {
        let p = self.0.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&p, data)?;
        Ok(p)
    }
    fn context(&self) -> Result<(Arc<ProjectData>, Installation)> {
        let project = Arc::new(ProjectData {
            base_config_varname: None,
            ..ProjectData::default()
        });
        fs::create_dir_all(self.0.join("lib/gnunet/libexec"))?;
        let installation = Installation::from_locations(&project, &self.0, Some(&self.0))?;
        Ok((project, installation))
    }
    fn cfg(&self) -> Result<Configuration> {
        let (p, i) = self.context()?;
        Ok(Configuration::with_installation(p, i, Limits::default())?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
struct Env {
    vars: BTreeMap<Vec<u8>, Vec<u8>>,
    cwd: PathBuf,
}
impl Environment for Env {
    fn variable(&self, name: &[u8]) -> Option<Vec<u8>> {
        self.vars.get(name).cloned()
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        Ok(self.cwd.clone())
    }
}

#[test]
fn default_filename_missing_home_continues_fallback_but_keeps_capacity_errors() -> Result<()> {
    let directory = Directory::new()?;
    let marker = format!("gnunet-owned-absent-default-{}", std::process::id()).into_bytes();
    let project = ProjectData {
        config_file: marker.clone(),
        project_dirname: marker,
        ..ProjectData::default()
    };
    let mut environment = Env {
        vars: BTreeMap::new(),
        cwd: directory.0.clone(),
    };
    assert_eq!(project.default_filename(&environment)?, None);
    environment.vars.insert(
        b"XDG_CONFIG_HOME".to_vec(),
        vec![b'x'; Limits::default().max_expanded_bytes + 1],
    );
    assert!(matches!(
        project.default_filename(&environment),
        Err(Error::Capacity)
    ));
    Ok(())
}

#[test]
fn project_bootstrap_dup_diff_and_first_use_helpers_preserve_source_contract() -> Result<()> {
    let dir = Directory::new()?;
    let (project, installation) = dir.context()?;
    let mut cfg = Configuration::with_installation(
        Arc::clone(&project),
        installation.clone(),
        Limits::default(),
    )?;
    assert!(core::ptr::eq(cfg.project_data(), project.as_ref()));
    assert_eq!(cfg.dirty(), Dirty::Clean);
    let keys: Vec<_> = cfg.section_values(b"paths").map(|(_, k, _)| k).collect();
    assert_eq!(
        keys,
        [
            b"LIBEXECDIR".as_slice(),
            b"DOCDIR",
            b"ICONDIR",
            b"LOCALEDIR",
            b"PREFIX",
            b"BINDIR",
            b"LIBDIR",
            b"DATADIR"
        ]
    );
    assert!(
        cfg.get(b"PATHS", b"LIBEXECDIR")
            .ok_or(Error::Missing)?
            .ends_with(b"/lib//gnunet/libexec/")
    );
    assert_eq!(cfg.serialize()?, b"[PATHS]\n\n");
    cfg.set_value(b"PATHS", b"DATADIR", None)?;
    assert!(!cfg.have_value(b"PATHS", b"DATADIR"));
    let copy = cfg.duplicate()?;
    assert!(copy.have_value(b"PATHS", b"DATADIR"));
    assert_eq!(cfg.diff(&copy)?.serialize()?, b"[PATHS]\n\n");
    let mut cache = BinaryPathCache::new();
    cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/raw/$NOEXPANSION/"))?;
    assert_eq!(
        cfg.suid_binary_path_with(b"helper", &mut cache)?,
        Path::new("/raw/$NOEXPANSION/helper")
    );
    cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/changed"))?;
    assert_eq!(
        cfg.suid_binary_path_with(b"helper", &mut cache)?,
        Path::new("/raw/$NOEXPANSION/helper")
    );
    assert_eq!(
        cfg.suid_binary_path_with(b"/absolute", &mut cache)?,
        Path::new("/absolute")
    );
    let mut fallback = BinaryPathCache::new();
    cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b""))?;
    assert!(
        cfg.suid_binary_path_with(b"helper", &mut fallback)?
            .as_os_str()
            .as_encoded_bytes()
            .ends_with(b"/lib//gnunet/libexec/helper")
    );
    assert_eq!(
        installation
            .path(PathKind::Prefix)
            .ok_or(Error::Missing)?
            .as_os_str()
            .as_encoded_bytes()
            .last(),
        Some(&b'/')
    );
    Ok(())
}
#[test]
fn defaults_main_xdg_and_explicit_empty_override_are_distinct() -> Result<()> {
    let dir = Directory::new()?;
    dir.put("share/gnunet/config.d/10.conf", b"[s]\nx=default\n")?;
    let main = dir.put("main.conf", b"[s]\nx=main\n")?;
    let mut cfg = dir.cfg()?;
    cfg.load(None)?;
    assert_eq!(cfg.get(b"s", b"x"), Some(b"default".as_slice()));
    cfg.load(Some(&main))?;
    assert_eq!(cfg.get(b"s", b"x"), Some(b"main".as_slice()));
    assert_eq!(
        cfg.get(b"PATHS", b"DEFAULTCONFIG"),
        Some(main.as_os_str().as_encoded_bytes())
    );
    fs::create_dir(dir.0.join("empty"))?;
    dir.put("ignored/a.txt", b"ignored")?;
    assert_eq!(cfg.load_from_report(dir.0.join("empty"))?.c_status(), 0);
    let ignored = cfg.load_from_report(dir.0.join("ignored"))?;
    assert_eq!((ignored.c_status(), ignored.files_loaded), (1, 0));
    let unique = format!("gcfg-{}-default.conf", std::process::id());
    let user = dir.put("user.conf", b"[s]\nx=user\n")?;
    let xdg = dir.put(&format!("xdg/{unique}"), b"[s]\nx=xdg\n")?;
    let project = ProjectData {
        config_file: unique.into_bytes(),
        user_config_file: user.as_os_str().as_encoded_bytes().to_vec(),
        ..ProjectData::default()
    };
    let mut env = Env {
        vars: BTreeMap::new(),
        cwd: dir.0.clone(),
    };
    assert_eq!(project.default_filename(&env)?, Some(user));
    env.vars.insert(
        b"XDG_CONFIG_HOME".to_vec(),
        dir.0.join("xdg").as_os_str().as_encoded_bytes().to_vec(),
    );
    assert_eq!(project.default_filename(&env)?, Some(xdg));
    env.vars.insert(b"XDG_CONFIG_HOME".to_vec(), Vec::new());
    assert_eq!(project.default_filename(&env)?, None);
    let (project, _) = dir.context()?;
    let mut env = Env {
        vars: BTreeMap::new(),
        cwd: dir.0.clone(),
    };
    env.vars.insert(b"GNUNET_PREFIX".to_vec(), Vec::new());
    let install = Installation::discover(&project, &env)?;
    assert_eq!(install.origin(), InstallationOrigin::Environment);
    assert!(install.path(PathKind::Prefix).is_none());
    Ok(())
}
#[test]
fn diagnostics_capture_sources_nss_and_rich_clean_callbacks_only_on_commit() -> Result<()> {
    let dir = Directory::new()?;
    dir.put("secret.conf", b"[vault]\nkey=old\nKEY=current\n")?;
    let main = dir.put(
        "main.conf",
        b"@INLINE-SECRET@ vault secret.conf\n[s]\nx=same\nx=same\n",
    )?;
    let mut cfg = dir.cfg()?;
    cfg.enable_diagnostics();
    cfg.load_explicit(None, Some(&main))?;
    let normal = cfg.serialize_diagnostics()?;
    let verbose = cfg.serialize_diagnostics_verbose()?;
    assert!(
        normal
            .windows(b"# secret file stat ".len())
            .any(|v| v == b"# secret file stat ")
    );
    assert!(
        verbose
            .windows(b"duplicate definitions (highest precedence first)".len())
            .any(|v| v == b"duplicate definitions (highest precedence first)")
    );
    assert!(
        verbose
            .windows(b"(different value)".len())
            .any(|v| v == b"(different value)")
    );
    let mut removed = Vec::new();
    assert_eq!(
        cfg.clean_file_with(&main, |entry| removed.push(entry.clone()))?,
        1
    );
    assert_eq!(removed[0].section, b"s");
    assert_eq!(removed[0].option, b"x");
    assert_eq!(removed[0].line, 3);
    let mut count = 0;
    assert!(matches!(
        cfg.clean_file_with(&main, |_| count += 1),
        Err(Error::Changed)
    ));
    assert_eq!(count, 0);
    cfg.set_value(b"s", b"files", Some(b"one two three"))?;
    let mut visited = Vec::new();
    assert!(matches!(
        cfg.iterate_value_filenames(b"s", b"files", |name| {
            visited.push(name.to_vec());
            false
        }),
        Err(Error::IterationAborted)
    ));
    assert_eq!(visited, [b"one".to_vec()]);
    Ok(())
}
#[test]
fn tool_query_set_diff_full_and_errors_preserve_original_owner() -> Result<()> {
    let dir = Directory::new()?;
    dir.put("share/gnunet/config.d/base.conf", b"[s]\nx=default\n")?;
    let main = dir.put("main.conf", b"[s]\nx=before\n")?;
    let mut cfg = dir.cfg()?;
    cfg.load(Some(&main))?;
    let settings = ConfigSettings {
        section: Some(b"s".to_vec()),
        option: Some(b"x".to_vec()),
        ..ConfigSettings::default()
    };
    assert_eq!(cfg.run_tool(&settings, Some(&main))?.stdout, b"before\n");
    let changed = ConfigSettings {
        value: Some(b"after".to_vec()),
        ..settings.clone()
    };
    assert_eq!(cfg.run_tool(&changed, Some(&main))?.exit_code, 0);
    assert_eq!(cfg.get(b"s", b"x"), Some(b"before".as_slice()));
    let mut reread = dir.cfg()?;
    reread.load(Some(&main))?;
    assert_eq!(reread.get(b"s", b"x"), Some(b"after".as_slice()));
    let missing = ConfigSettings {
        option: Some(b"missing".to_vec()),
        ..settings.clone()
    };
    assert_eq!(cfg.run_tool(&missing, Some(&main))?.exit_code, 6);
    let invalid = ConfigSettings {
        value: Some(b"value".to_vec()),
        option: None,
        ..settings
    };
    assert_eq!(cfg.run_tool(&invalid, Some(&main))?.exit_code, 2);
    let full = ConfigSettings {
        full: true,
        ..ConfigSettings::default()
    };
    assert_eq!(cfg.run_tool(&full, Some(&main))?.exit_code, 0);
    assert!(
        fs::read(&main)?
            .windows(b"x = before".len())
            .any(|v| v == b"x = before")
    );
    Ok(())
}

#[test]
fn bounded_tool_output_and_profile_metadata_are_explicit() -> Result<()> {
    let mut cfg = Configuration::new(Limits {
        max_expanded_bytes: 4,
        ..Limits::default()
    });
    cfg.set_value(b"s", b"x", Some(b"larger than output budget"))?;
    let settings = ConfigSettings {
        section: Some(b"s".to_vec()),
        option: Some(b"x".to_vec()),
        ..ConfigSettings::default()
    };
    assert!(matches!(
        cfg.run_tool(&settings, None),
        Err(Error::Capacity)
    ));
    assert_eq!(
        cfg.get(b"s", b"x"),
        Some(b"larger than output budget".as_slice())
    );
    let profile = gnunet_config::OFFICIAL_BUILD_PROFILE;
    assert!(profile.experimental_macro_defined);
    assert!(!profile.experimental_macro_value);
    let result = gnunet_config::run_config_command(&["-E".into()])?;
    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.is_empty());
    Ok(())
}

#[test]
fn backend_absence_and_exclusive_queries_have_official_status() -> Result<()> {
    let absent = "config_contract_absent_20261029_f16b1b5c";
    for arguments in [
        vec!["--supported-backend", absent],
        vec!["-b", absent, "--", "ignored-positional"],
    ] {
        let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
        let output = gnunet_config::run_config_command(&arguments)?;
        assert_eq!(output.exit_code, 77);
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    for arguments in [
        vec!["--supported-backend", absent, "-s", "demo"],
        vec!["-b", absent, "-E"],
        vec!["-b", absent, "-b", absent],
    ] {
        let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
        let output = gnunet_config::run_config_command(&arguments)?;
        assert_eq!(output.exit_code, 2);
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    Ok(())
}

#[test]
fn backend_conflicts_preserve_already_emitted_version_output() -> Result<()> {
    for arguments in [
        vec!["-v", "-b", "config_contract_absent_20261029_f16b1b5c"],
        vec!["-b", "config_contract_absent_20261029_f16b1b5c", "-v"],
    ] {
        let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
        let output = gnunet_config::run_config_command_with_program(
            std::ffi::OsStr::new("fixture-config"),
            &arguments,
        )?;
        assert_eq!(output.exit_code, 2);
        assert!(output.stdout.starts_with(b"fixture-config v"));
        assert_eq!(output.stdout.iter().filter(|b| **b == b'\n').count(), 1);
        assert!(!output.stderr.is_empty());
    }
    Ok(())
}
