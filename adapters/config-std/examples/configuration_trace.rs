//! Independent Rust trace compared against normal unmodified C public APIs.
#![forbid(unsafe_code)]
use gnunet_config::{
    BinaryPathCache, ConfigSettings, Configuration, Dirty, Error, Limits, ProcessEnvironment,
    ProjectData,
};
use std::{
    error::Error as StdError,
    io::{self, Write},
    path::Path,
    sync::Arc,
};
type Result<T> = std::result::Result<T, Box<dyn StdError>>;
fn row(name: &str, bytes: &[u8]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    write!(out, "{name}|")?;
    for byte in bytes {
        write!(out, "{byte:02x}")?;
    }
    writeln!(out)
}
fn number(name: &str, n: i64) -> io::Result<()> {
    writeln!(io::stdout().lock(), "{name}|{n}")
}
fn dirty(value: Dirty) -> i64 {
    match value {
        Dirty::Clean => 0,
        Dirty::Modified => 1,
        Dirty::WriteFailed => -1,
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return Err("fixture root required".into());
    }
    let root = Path::new(&args[1]);
    let main = root.join("main.conf");
    let written = root.join("written.conf");
    let diff_file = root.join("diff.conf");
    let project = Arc::new(ProjectData::default());
    let mut c = Configuration::create(Arc::clone(&project), Limits::default())?;
    number(
        "project-identity",
        i64::from(core::ptr::eq(c.project_data(), project.as_ref())),
    )?;
    number("new-dirty", dirty(c.dirty()))?;
    row("new", &c.serialize()?)?;
    let default = project.default_filename(&ProcessEnvironment)?;
    let default = default
        .as_deref()
        .map(|p| p.as_os_str().as_encoded_bytes())
        .unwrap_or_default();
    row("default-file", default)?;
    number(
        "empty-directory",
        i64::from(c.load_from_report(root.join("empty"))?.c_status()),
    )?;
    number(
        "ignored-directory",
        i64::from(c.load_from_report(root.join("ignored"))?.c_status()),
    )?;
    c.enable_diagnostics();
    c.load(Some(&main))?;
    row("loaded", &c.serialize()?)?;
    row(
        "dollar",
        &c.expand_dollar(b"$DATADIR/relative", &ProcessEnvironment)?,
    )?;
    let mut memory = Configuration::create(Arc::clone(&project), Limits::default())?;
    memory.deserialize(b"[memory]\nx=raw\n", None)?;
    number("deserialize", 1)?;
    memory.parse(&main)?;
    number("parse", 1)?;
    number("memory-value", 1)?;
    row(
        "memory-value",
        memory.get(b"memory", b"x").ok_or(Error::Missing)?,
    )?;
    row("diagnostics", &c.serialize_diagnostics()?)?;
    row("verbose", &c.serialize_diagnostics_verbose()?)?;
    number("number", c.get_number(b"demo", b"number")? as i64)?;
    number(
        "float-bits",
        i64::from(c.get_float(b"demo", b"float")?.to_bits()),
    )?;
    number("size", c.get_size(b"demo", b"size")? as i64)?;
    number("time", c.get_time(b"demo", b"time")? as i64)?;
    number("yes", i64::from(c.get_yesno(b"demo", b"yes")?))?;
    row(
        "choice",
        c.get_choice(b"demo", b"choice", &[b"RED", b"GREEN"])?,
    )?;
    let mut data = [0; 2];
    c.get_data(b"demo", b"data", &mut data)?;
    row("data", &data)?;
    let mut count = 0;
    for (s, k, v) in c.section_values(b"DEMO") {
        count += 1;
        row("iter-section", s)?;
        row("iter-key", k)?;
        row("iter-value", v)?;
    }
    number("section-count", count)?;
    let mut count = 0;
    for section in c.sections() {
        count += 1;
        row("section", section.name())?;
    }
    number("sections-count", count)?;
    let mut count = 0;
    for (s, k, v) in c.entries() {
        count += 1;
        row("iter-section", s)?;
        row("iter-key", k)?;
        row("iter-value", v)?;
    }
    number("all-count", count)?;
    let mut callback_error = None;
    let count = c.iterate_value_filenames(b"demo", b"files", |name| {
        if let Err(error) = row("filename", name) {
            callback_error = Some(error);
        }
        true
    })?;
    if let Some(error) = callback_error {
        return Err(error.into());
    }
    number("filename-count", count as i64)?;
    let mut count = 0;
    let aborted = c.iterate_value_filenames(b"demo", b"files", |_| {
        count += 1;
        false
    });
    number(
        "filename-abort",
        if matches!(aborted, Err(Error::IterationAborted)) {
            -1
        } else {
            1
        },
    )?;
    number("filename-abort-calls", count)?;
    number(
        "append",
        i64::from(c.append_filename(b"demo", b"files", b"/new path")?),
    )?;
    number(
        "append-again",
        i64::from(c.append_filename(b"demo", b"files", b"/new path")?),
    )?;
    number(
        "remove",
        i64::from(c.remove_filename(b"demo", b"files", b"/new path")?),
    )?;
    row(
        "filename-expanded",
        c.get_filename(b"demo", b"path", &ProcessEnvironment)?
            .as_os_str()
            .as_encoded_bytes(),
    )?;
    c.set_number(b"scratch", b"number", u64::MAX)?;
    c.set_float(b"scratch", b"float", -1.25)?;
    number("set-float", 1)?;
    row(
        "set-float",
        c.get(b"scratch", b"float").ok_or(Error::Missing)?,
    )?;
    c.set_value(b"scratch", b"remove", Some(b"yes"))?;
    c.set_value(b"scratch", b"remove", None)?;
    number(
        "tombstone-have",
        i64::from(c.have_value(b"scratch", b"remove")),
    )?;
    number("setter-dirty", dirty(c.dirty()))?;
    c.remove_section(b"scratch");
    number("removed-dirty", dirty(c.dirty()))?;
    let mut copy = c.duplicate()?;
    row("duplicate", &copy.serialize()?)?;
    copy.set_value(b"demo", b"value", Some(b"different"))?;
    let diff = c.diff(&copy)?;
    row("diff", &diff.serialize()?)?;
    c.write_diffs(&copy, &diff_file)?;
    number("write-diff", 1)?;
    c.write(&written)?;
    number("write", 1)?;
    number("written-dirty", dirty(c.dirty()))?;
    let mut callbacks = Vec::new();
    let removed = c.clean_file_with(&main, |record| callbacks.push(record.clone()))?;
    // C invokes these before clean_file returns to the surrounding trace call.
    for removed in &callbacks {
        row("clean-section", &removed.section)?;
        row("clean-key", &removed.option)?;
        number("clean-line", removed.line as i64)?;
    }
    number("clean", 1)?;
    number("clean-count", removed as i64)?;
    number("clean-callbacks", callbacks.len() as i64)?;
    let mut count = 0;
    let status = Configuration::parse_and_run(
        Arc::clone(&project),
        Limits::default(),
        Some(&main),
        |cfg| {
            count += 1;
            if !cfg.have_value(b"demo", b"number") {
                return Err(Error::Missing);
            }
            Ok(0_i64)
        },
    )?;
    number("parse-and-run", status)?;
    number("parse-and-run-calls", count)?;
    c.set_value(
        b"PATHS",
        b"SUID_BINARY_PATH",
        Some(b"/test/raw/$UNEXPANDED/"),
    )?;
    let mut cache = BinaryPathCache::new();
    row(
        "suid",
        c.suid_binary_path_with(b"helper", &mut cache)?
            .as_os_str()
            .as_encoded_bytes(),
    )?;
    c.set_value(b"PATHS", b"SUID_BINARY_PATH", Some(b"/changed"))?;
    row(
        "suid-cached",
        c.suid_binary_path_with(b"helper", &mut cache)?
            .as_os_str()
            .as_encoded_bytes(),
    )?;
    row(
        "suid-absolute",
        c.suid_binary_path_with(b"/absolute/helper", &mut cache)?
            .as_os_str()
            .as_encoded_bytes(),
    )?;
    let mut settings = ConfigSettings {
        section: Some(b"demo".to_vec()),
        option: Some(b"value".to_vec()),
        ..ConfigSettings::default()
    };
    let output = c.run_tool(&settings, Some(&main))?;
    row("tool-query", &output.stdout)?;
    number("tool-ret", i64::from(output.exit_code))?;
    settings.clear_strings();
    number(
        "settings-freed",
        i64::from(
            settings.section.is_none() && settings.option.is_none() && settings.value.is_none(),
        ),
    )?;
    Ok(())
}
