//! Separate-project path resolution observer. Returned paths are never executed.
#![forbid(unsafe_code)]
use gnunet_config::{BinaryPathCache, Configuration, Limits, ProcessEnvironment, ProjectData};
use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn emit(name: &str, path: PathBuf) -> io::Result<()> {
    let mut out = io::stdout().lock();
    write!(out, "{name}|")?;
    for b in path.as_os_str().as_encoded_bytes() {
        write!(out, "{b:02x}")?;
    }
    writeln!(out)
}
fn resolve(
    cfg: &Configuration,
    pd: &ProjectData,
    program: &[u8],
    owned: bool,
    cache: &mut BinaryPathCache,
) -> Result<PathBuf> {
    Ok(if owned {
        cfg.suid_binary_path_for_project_with(pd, program, cache)?
    } else {
        cfg.suid_binary_path_for_project(pd, program)?
    })
}
fn libexec(
    project: &ProjectData,
    program: &[u8],
    owned: bool,
    cache: &mut BinaryPathCache,
) -> Result<PathBuf> {
    Ok(if owned {
        project.libexec_binary_path_with(program, &ProcessEnvironment, cache)?
    } else {
        project.libexec_binary_path(program)?
    })
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("fixture/mode/global-or-owned required".into());
    }
    let a = Arc::new(ProjectData {
        project_dirname: b"config-a".to_vec(),
        env_varname: Some(b"GCFG_SUID_A".to_vec()),
        env_varname_alt: None,
        ..ProjectData::default()
    });
    let b = ProjectData {
        project_dirname: b"supplied-b".to_vec(),
        env_varname: Some(b"GCFG_SUID_B".to_vec()),
        ..a.as_ref().clone()
    };
    let c = ProjectData {
        project_dirname: b"supplied-c".to_vec(),
        env_varname: Some(b"GCFG_SUID_C".to_vec()),
        ..a.as_ref().clone()
    };
    let mut cfg = Configuration::create(Arc::clone(&a), Limits::default())?;
    let mut cache = BinaryPathCache::new();
    let owned = args[3] == "owned";
    match args[2].as_str() {
        "libexec-b-first" => {
            cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/unused/override"))?;
            emit("first", libexec(&b, b"plain-helper", owned, &mut cache)?)?;
            emit("second", libexec(&c, b"plain-helper", owned, &mut cache)?)?;
            cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", None)?;
            emit(
                "fallback",
                resolve(&cfg, &c, b"plain-helper", owned, &mut cache)?,
            )?;
        }
        "suid-then-libexec" => {
            emit(
                "first",
                resolve(&cfg, &b, b"plain-helper", owned, &mut cache)?,
            )?;
            emit("second", libexec(&c, b"plain-helper", owned, &mut cache)?)?;
            emit(
                "absolute",
                libexec(&c, b"/ordinary/absolute-helper", owned, &mut cache)?,
            )?;
        }
        "libexec-absolute-first" => {
            emit(
                "absolute",
                libexec(&b, b"/ordinary/absolute-helper", owned, &mut cache)?,
            )?;
            emit("first", libexec(&c, b"plain-helper", owned, &mut cache)?)?;
            emit("second", libexec(&b, b"plain-helper", owned, &mut cache)?)?;
        }
        "libexec-empty" => {
            emit("empty", libexec(&b, b"", owned, &mut cache)?)?;
            emit("first", libexec(&c, b"plain-helper", owned, &mut cache)?)?;
        }
        "b-first" => {
            emit(
                "first",
                resolve(&cfg, &b, b"plain-helper", owned, &mut cache)?,
            )?;
            emit(
                "second",
                resolve(&cfg, &c, b"plain-helper", owned, &mut cache)?,
            )?;
            emit(
                "third",
                resolve(&cfg, &a, b"plain-helper", owned, &mut cache)?,
            )?;
        }
        "c-first" => {
            emit(
                "first",
                resolve(&cfg, &c, b"plain-helper", owned, &mut cache)?,
            )?;
            emit(
                "second",
                resolve(&cfg, &b, b"plain-helper", owned, &mut cache)?,
            )?;
        }
        "absolute-first" => {
            emit(
                "absolute",
                resolve(&cfg, &b, b"/ordinary/absolute-helper", owned, &mut cache)?,
            )?;
            emit(
                "first",
                resolve(&cfg, &c, b"plain-helper", owned, &mut cache)?,
            )?;
            emit(
                "second",
                resolve(&cfg, &b, b"plain-helper", owned, &mut cache)?,
            )?;
        }
        "raw-override" => {
            cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/raw/$UNEXPANDED/"))?;
            emit(
                "first",
                resolve(&cfg, &b, b"plain-helper", owned, &mut cache)?,
            )?;
            cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/changed"))?;
            emit(
                "second",
                resolve(&cfg, &c, b"plain-helper", owned, &mut cache)?,
            )?;
            emit(
                "absolute",
                resolve(&cfg, &c, b"/ordinary/absolute-helper", owned, &mut cache)?,
            )?;
        }
        "empty-then-override" => {
            cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b""))?;
            emit(
                "fallback",
                resolve(&cfg, &b, b"plain-helper", owned, &mut cache)?,
            )?;
            cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/raw/$UNEXPANDED/"))?;
            emit(
                "first",
                resolve(&cfg, &c, b"plain-helper", owned, &mut cache)?,
            )?;
            cfg.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/changed"))?;
            emit(
                "second",
                resolve(&cfg, &a, b"plain-helper", owned, &mut cache)?,
            )?;
        }
        "self-project" => {
            emit(
                "first",
                if owned {
                    cfg.suid_binary_path_with(b"plain-helper", &mut cache)?
                } else {
                    cfg.suid_binary_path(b"plain-helper")?
                },
            )?;
            emit(
                "second",
                resolve(&cfg, &b, b"plain-helper", owned, &mut cache)?,
            )?;
        }
        _ => return Err("unknown path-only fixture".into()),
    }
    Ok(())
}
