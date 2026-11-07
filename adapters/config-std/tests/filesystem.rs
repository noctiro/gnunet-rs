//! Real file tests for official include precedence, secret sections and rewrites.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible filesystem tests assert source provenance and actual atomic rewrite outcomes"
)]
use gnunet_config::{Configuration, Dirty, Environment, Error, Limits};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-config-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn put(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let path = self.path(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, bytes)?;
        Ok(path)
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
fn includes_are_sorted_and_use_real_source_targets() -> Result<(), Box<dyn std::error::Error>> {
    let dir = Directory::new()?;
    dir.put("fragments/b.conf", b"[s]\nx = b\n")?;
    dir.put("fragments/a.conf", b"[s]\nx = a\n")?;
    dir.put("fragments/.hidden.conf", b"[s]\nhidden = included\n")?;
    let main=dir.put("main.conf",b"@INLINE-MATCHING@ fragments/*.conf\n[s]\ny = main\n@INLINE-MATCHING@ fragments/missing*.conf\n")?;
    let mut cfg = Configuration::default();
    cfg.enable_diagnostics();
    cfg.parse(&main)?;
    assert_eq!(cfg.get(b"s", b"x"), Some(b"b".as_slice()));
    assert_eq!(cfg.get(b"s", b"hidden"), Some(b"included".as_slice()));
    assert_eq!(cfg.get(b"s", b"y"), Some(b"main".as_slice()));
    let definitions = cfg.entry(b"s", b"x").ok_or(Error::Missing)?.definitions();
    assert_eq!(definitions.len(), 2);
    assert!(definitions[0].filename.ends_with("b.conf"));
    assert!(definitions[1].filename.ends_with("a.conf"));
    assert_eq!(cfg.loaded_files().len(), 4);
    assert_eq!(cfg.loaded_files()[1].level, 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        dir.put("actual/child.conf", b"[target]\nx = actual\n")?;
        let source = dir.put("actual/parent.conf", b"@INLINE@ child.conf\n")?;
        let alias = dir.path("alias.conf");
        symlink(source, &alias)?;
        cfg.parse(alias)?;
        assert_eq!(cfg.get(b"target", b"x"), Some(b"actual".as_slice()));
    }
    Ok(())
}

#[test]
fn secret_sections_preserve_duplicate_sources_and_unreadable_state()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = Directory::new()?;
    dir.put(
        "secret.conf",
        b"[vault]\nkey = old\nKEY = current\n[other]\nleak = hidden\n",
    )?;
    let main=dir.put("main.conf",b"@INLINE-SECRET@ vault secret.conf\n@INLINE-SECRET@ absent missing.conf\n[vault]\nkey = main\n")?;
    let mut cfg = Configuration::default();
    cfg.enable_diagnostics();
    cfg.parse(main)?;
    assert_eq!(cfg.get(b"vault", b"key"), Some(b"main".as_slice()));
    assert!(cfg.get(b"other", b"leak").is_none());
    let sources = cfg
        .entry(b"vault", b"key")
        .ok_or(Error::Missing)?
        .definitions();
    assert_eq!(
        sources
            .iter()
            .map(|s| s.value.as_slice())
            .collect::<Vec<_>>(),
        [b"main".as_slice(), b"current", b"old"]
    );
    assert!(
        cfg.loaded_files()
            .iter()
            .any(|s| s.restrict_section.as_deref() == Some(b"absent".as_slice()) && s.inaccessible)
    );
    assert!(!cfg.sections().any(|s| s.name() == b"absent"));
    assert!(!String::from_utf8_lossy(&cfg.serialize()?).contains("absent"));
    fs::create_dir(dir.path("not-a-file"))?;
    let directory_secret = dir.put(
        "directory-secret.conf",
        b"@INLINE-SECRET@ unavailable not-a-file\n",
    )?;
    cfg.parse(directory_secret)?;
    assert!(
        !cfg.sections()
            .any(|section| section.name() == b"unavailable")
    );
    dir.put(
        "restricted.conf",
        b"[vault]\nkey = one\n[ignored]\n@INLINE@ nested.conf\n",
    )?;
    let bad = dir.put("bad.conf", b"@INLINE-SECRET@ vault restricted.conf\n")?;
    assert!(cfg.parse(bad).is_err());
    assert_eq!(cfg.get(b"vault", b"key"), Some(b"main".as_slice()));
    Ok(())
}

#[test]
fn cycles_and_all_declared_admission_bounds_are_real_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = Directory::new()?;
    let first = dir.put("first.conf", b"@INLINE@ second.conf\n")?;
    dir.put("second.conf", b"@INLINE@ first.conf\n")?;
    assert!(matches!(
        Configuration::default().parse(first),
        Err(Error::Cycle)
    ));
    let long = dir.put("large.conf", b"[s]\nx = too long\n")?;
    let mut cfg = Configuration::new(Limits {
        max_input_bytes: 4,
        ..Limits::default()
    });
    assert!(matches!(cfg.parse(&long), Err(Error::Capacity)));
    assert!(!cfg.have_value(b"s", b"x"));
    let mut cfg = Configuration::new(Limits {
        max_entries: 1,
        ..Limits::default()
    });
    cfg.set_value(b"s", b"x", Some(b"kept"))?;
    assert!(matches!(
        cfg.set_value(b"new", b"y", Some(b"rejected")),
        Err(Error::Capacity)
    ));
    assert_eq!(cfg.sections().count(), 1);
    assert_eq!(cfg.get(b"s", b"x"), Some(b"kept".as_slice()));
    let file = dir.put("one.conf", b"[s]\nx = 1\n")?;
    let mut cfg = Configuration::new(Limits {
        max_files: 1,
        ..Limits::default()
    });
    cfg.parse(&file)?;
    assert!(matches!(cfg.parse(&file), Err(Error::Capacity)));
    assert_eq!(cfg.loaded_files().len(), 1);
    for pattern in [
        "fragments/*.conf",
        "fragments/[ab].conf",
        "fragments/a+.conf",
        "fragments/~a.conf",
    ] {
        let content = format!("@INLINE-MATCHING@ {pattern}\n");
        let main = dir.put("glob.conf", content.as_bytes())?;
        assert!(Configuration::default().parse(main).is_err());
    }
    Ok(())
}

#[test]
fn defaults_precedence_diff_and_filename_list_operations() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = Directory::new()?;
    dir.put("defaults/10-first.conf", b"[s]\nx=first\n")?;
    dir.put("defaults/20-second.conf", b"[s]\nx=second\ny=default\n")?;
    dir.put("defaults/00-not-config.txt", b"this must be skipped\n")?;
    let main = dir.put("main.conf", b"[s]\ny=override\n")?;
    let mut defaults = Configuration::default();
    assert_eq!(defaults.load_from(dir.path("defaults"))?, 2);
    let mut cfg = Configuration::default();
    cfg.load_explicit(Some(&dir.path("defaults")), Some(&main))?;
    assert_eq!(cfg.get(b"s", b"x"), Some(b"second".as_slice()));
    assert_eq!(cfg.get(b"s", b"y"), Some(b"override".as_slice()));
    let diff = defaults.diff(&cfg)?;
    assert!(!diff.have_value(b"s", b"x"));
    assert_eq!(diff.get(b"s", b"y"), Some(b"override".as_slice()));
    assert!(!String::from_utf8_lossy(&cfg.serialize()?).contains("DEFAULTCONFIG"));
    assert!(cfg.append_filename(b"s", b"files", b"/a path")?);
    assert!(!cfg.append_filename(b"s", b"files", b"/a path")?);
    assert!(cfg.append_filename(b"s", b"files", b"c\\d")?);
    assert_eq!(
        cfg.filenames(b"s", b"files"),
        [b"/a path".to_vec(), b"c\\d".to_vec()]
    );
    assert!(cfg.remove_filename(b"s", b"files", b"/a path")?);
    assert_eq!(cfg.filenames(b"s", b"files"), [b"c\\d".to_vec()]);
    assert!(!cfg.remove_filename(b"s", b"files", b"absent")?);
    assert_eq!(cfg.dirty(), Dirty::Clean);
    assert!(cfg.remove_section(b"s"));
    assert_eq!(cfg.dirty(), Dirty::Modified);
    Ok(())
}

#[test]
fn cleanup_preserves_effective_values_and_rejects_source_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = Directory::new()?;
    let included = dir.put("included.conf", b"[s]\na = same\nb = base\n")?;
    let main = dir.put(
        "main.conf",
        b"# note\n@INLINE@ included.conf\n[s]\na = same\nb = changed\nb = changed\n# tail\n",
    )?;
    let mut cfg = Configuration::default();
    cfg.enable_diagnostics();
    cfg.parse(&main)?;
    assert_eq!(cfg.clean_file(&main)?, [4, 5]);
    assert_eq!(
        fs::read(&main)?,
        b"# note\n@INLINE@ included.conf\n[s]\nb = changed\n# tail\n"
    );
    assert_eq!(fs::read(included)?, b"[s]\na = same\nb = base\n");
    let mut reread = Configuration::default();
    reread.parse(&main)?;
    assert_eq!(reread.get(b"s", b"a"), cfg.get(b"s", b"a"));
    assert_eq!(reread.get(b"s", b"b"), cfg.get(b"s", b"b"));
    assert!(matches!(cfg.clean_file(&main), Err(Error::Changed)));
    let unchanged = fs::read(&main)?;
    assert_eq!(fs::read(&main)?, unchanged);
    Ok(())
}

#[test]
fn atomic_write_follows_existing_symlink_and_preserves_permissions()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = Directory::new()?;
    let target = dir.put("target.conf", b"old contents\n")?;
    let mut cfg = Configuration::default();
    cfg.set_value(b"s", b"value", Some(b"one\ntwo"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640))?;
        let link = dir.path("link.conf");
        symlink(&target, &link)?;
        cfg.write(&link)?;
        assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o640);
    }
    #[cfg(not(unix))]
    {
        cfg.write(&target)?;
    }
    assert_eq!(fs::read(&target)?, b"[s]\nvalue = one\\ntwo\n\n");
    assert_eq!(cfg.dirty(), Dirty::Clean);
    let bad = dir.path("directory");
    fs::create_dir(&bad)?;
    assert!(cfg.write(bad).is_err());
    assert_eq!(cfg.dirty(), Dirty::WriteFailed);
    assert!(
        !fs::read_dir(&dir.0)?
            .any(|entry| entry.is_ok_and(|e| e.file_name().to_string_lossy().ends_with(".tmp")))
    );
    Ok(())
}

struct Env;
impl Environment for Env {
    fn variable(&self, name: &[u8]) -> Option<Vec<u8>> {
        if name == b"HOME" {
            Some(b"/home/me".to_vec())
        } else {
            None
        }
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        Ok(Path::new("/working").into())
    }
}
#[test]
fn filenames_expand_with_explicit_environment_and_bounded_recursion() -> Result<(), Error> {
    let mut cfg = Configuration::default();
    cfg.set_value(b"PATHS", b"ROOT", Some(b"$HOME/project"))?;
    cfg.set_value(b"s", b"socket", Some(b"$ROOT/statistics.sock"))?;
    assert_eq!(
        cfg.get_filename(b"s", b"socket", &Env)?,
        PathBuf::from("/home/me/project/statistics.sock")
    );
    assert_eq!(
        cfg.expand_filename(b"relative", &Env)?,
        PathBuf::from("/working/relative")
    );
    assert_eq!(
        cfg.expand_filename(b"~other/file", &Env)?,
        PathBuf::from("/home/me/other/file")
    );
    assert_eq!(
        cfg.expand_dollar(b"${UNDEFINED:-$ROOT}/x", &Env)?,
        b"/home/me/project/x"
    );
    let cfg = Configuration::new(Limits {
        max_expansion_depth: 2,
        ..Limits::default()
    });
    assert!(matches!(
        cfg.expand_dollar(b"${A:-${B:-${C:-fallback}}}", &Env),
        Err(Error::Cycle)
    ));
    Ok(())
}
