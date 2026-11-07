//! Defined finite native locale and configuration operations.
use gnunet_program_host::{
    locale::{AbiProfile, ProcessLocale},
    program::LocaleSetup,
};
use std::{ffi::OsStr, io::Write};
fn emit_value(
    out: &mut impl Write,
    label: &str,
    cfg: &gnunet_config::Configuration,
    s: &[u8],
    k: &[u8],
) -> std::io::Result<()> {
    let v = cfg.get(s, k);
    write!(out, "{label} {} ", i32::from(v.is_some()))?;
    if let Some(v) = v {
        for b in v {
            write!(out, "{b:02x}")?;
        }
    }
    writeln!(out)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = std::env::args_os().skip(1);
    let mode = a.next().ok_or("mode")?;
    let _selection = a.next().ok_or("selection")?;
    let library = a.next().ok_or("library")?;
    let catalogs = a.next().ok_or("catalogs")?;
    let input = a.next();
    #[expect(
        unsafe_code,
        reason = "Explicit early exclusive native locale capability in this fresh observer process"
    )]
    // SAFETY: This fresh finite single-thread process has no foreign locale users;
    // runner hashes the selected standard gettext library and exact ABI profile.
    let mut locale = unsafe { ProcessLocale::load(library.into(), AbiProfile::Libintl)? };
    let mut cfg = gnunet_config::Configuration::default();
    locale.bind_case_context(cfg.case_context());
    cfg.set_value(b"own\xc9", b"k\xd6", Some(b"value"))?;
    let copy = cfg.duplicate()?;
    locale.configure(&gnunet_config::ProjectData {
        gettext_path: Some(catalogs.clone().into()),
        ..Default::default()
    })?;
    let mut out = std::io::stdout().lock();
    if mode == OsStr::new("switch") {
        emit_value(&mut out, "ORIGINAL", &cfg, b"own\xe9", b"k\xf6")?;
        emit_value(&mut out, "DUPLICATE", &copy, b"own\xe9", b"k\xf6")?;
        cfg.set_value(b"own\xe9", b"k\xf6", Some(b"replacement"))?;
        emit_value(&mut out, "UPDATED-UPPER", &cfg, b"own\xc9", b"k\xd6")?;
        emit_value(&mut out, "UPDATED-LOWER", &cfg, b"own\xe9", b"k\xf6")?;
        let _removed = cfg.remove_section(b"own\xe9");
        emit_value(&mut out, "REMOVED-UPPER", &cfg, b"own\xc9", b"k\xd6")?;
        drop(copy.case_context().replace(gnunet_config::CaseSnapshot::C));
        emit_value(&mut out, "RESET-C-UPPER", &copy, b"own\xc9", b"k\xd6")?;
        emit_value(&mut out, "RESET-C-LOWER", &copy, b"own\xe9", b"k\xf6")?;
    } else if mode == OsStr::new("float") || mode == OsStr::new("float-reset") {
        cfg.set_value(
            b"s",
            b"v",
            Some(input.ok_or("float input")?.as_encoded_bytes()),
        )?;
        let f = cfg.get_float(b"s", b"v");
        writeln!(
            out,
            "FLOAT {} {:08x}",
            if f.is_ok() { 1 } else { -1 },
            f.map(f32::to_bits).unwrap_or(0)
        )?;
        if mode == OsStr::new("float-reset") {
            #[expect(
                unsafe_code,
                reason = "Fresh single-thread observer explicitly reselects its own environment locale while all native readers are quiescent"
            )]
            // SAFETY: no task/thread/foreign environment reader exists in this actor.
            unsafe {
                std::env::set_var("LC_ALL", "C");
            }
            locale.configure(&gnunet_config::ProjectData {
                gettext_path: Some(catalogs.into()),
                ..Default::default()
            })?;
        }
        emit_value(&mut out, "AFTER-FLOAT", &cfg, b"own\xe9", b"k\xf6")?;
    } else if mode == OsStr::new("choice-paths") {
        cfg.set_value(b"s", b"v", Some(b"i"))?;
        let c = cfg.get_choice(b"s", b"v", &[b"I"]);
        writeln!(
            out,
            "CHOICE {} {}",
            if c.is_ok() { 1 } else { -1 },
            i32::from(c.is_ok())
        )?;
        cfg.set_value(b"paths", b"bindir", Some(b"owned"))?;
        write!(out, "SERIALIZED ")?;
        for b in cfg.serialize()? {
            write!(out, "{b:02x}")?;
        }
        writeln!(out)?;
    } else if mode == OsStr::new("include")
        || mode == OsStr::new("include-secret")
        || mode == OsStr::new("include-matching")
    {
        let path = input.ok_or("owned include input")?;
        let mut text = if mode == OsStr::new("include-secret") {
            b"@iNlInE-sEcReT@ own\xc9 ".to_vec()
        } else if mode == OsStr::new("include-matching") {
            b"@iNlInE-mAtChInG@ ".to_vec()
        } else {
            b"@iNlInE@ ".to_vec()
        };
        text.extend_from_slice(path.as_encoded_bytes());
        text.push(b'\n');
        let r = cfg.deserialize(&text, None);
        writeln!(out, "INCLUDE {}", if r.is_ok() { 1 } else { -1 })?;
        emit_value(&mut out, "INCLUDED-UPPER", &cfg, b"own\xc9", b"k\xd6")?;
        emit_value(&mut out, "INCLUDED-LOWER", &cfg, b"own\xe9", b"k\xf6")?;
    } else if mode == OsStr::new("dollar") {
        cfg.set_value(b"PATHS", b"OWNED_LOCALE_VAR\xc9", Some(b"value"))?;
        let value = cfg.expand_dollar(
            b"${owned_locale_var\xe9:-fallback}/leaf",
            &gnunet_config::ProcessEnvironment,
        )?;
        write!(out, "EXPANDED ")?;
        for b in value {
            write!(out, "{b:02x}")?;
        }
        writeln!(out)?;
    } else if mode == OsStr::new("byte-table") {
        let profile = cfg.case_context().snapshot();
        write!(out, "SPACES ")?;
        for i in 0..=255u8 {
            write!(out, "{}", i32::from(profile.is_space(i)))?;
        }
        write!(out, "\nCASE ")?;
        for i in 0..=255u8 {
            for j in 0..=255u8 {
                write!(out, "{}", i32::from(profile.equals(&[i], &[j])))?;
            }
        }
        writeln!(out)?;
    } else if mode == OsStr::new("parse-number") {
        let result = cfg.deserialize(b"\x0b[own\xc9]\x0c\n\tk\xd6\x0b=\x0bvalue\x0c\t\n", None);
        writeln!(out, "PARSE {}", if result.is_ok() { 1 } else { -1 })?;
        emit_value(&mut out, "PARSED", &cfg, b"own\xe9", b"k\xf6")?;
        cfg.set_value(b"s", b"n", Some(b" \x0b+12\x0c"))?;
        let n = cfg.get_number(b"s", b"n");
        writeln!(
            out,
            "NUMBER {} {}",
            if n.is_ok() { 1 } else { -1 },
            n.unwrap_or(0)
        )?;
    } else if mode == OsStr::new("thread-numeric") {
        fn require<T: Send + Sync>() {}
        require::<gnunet_config::Configuration>();
        cfg.set_value(b"s", b"v", Some(b"x"))?;
        let gnunet_config::CaseSnapshot::CurrentThread(token) = cfg.case_context().snapshot()
        else {
            return Err("native thread profile missing".into());
        };
        let (failed, other) = std::thread::scope(|scope| {
            let a = scope.spawn(|| -> Result<_, String> {
                if cfg.get_float(b"s", b"v").is_ok() {
                    return Err("native failed conversion was accepted".to_owned());
                }
                let snapshot = token.snapshot().map_err(|e| e.to_string())?;
                let n = snapshot
                    .scan_float(b"1,5")
                    .map_err(|e| e.to_string())?
                    .consumed;
                Ok((n, snapshot))
            });
            let b = scope.spawn(|| token.snapshot().and_then(|s| s.scan_float(b"1,5")));
            (
                a.join().map_err(|_| "failed worker panic"),
                b.join().map_err(|_| "normal worker panic"),
            )
        });
        let (count, retained) = failed??;
        let other = other??;
        writeln!(
            out,
            "THREAD {} {} RETAINED {}",
            count,
            other.consumed,
            retained.scan_float(b"1,5")?.consumed
        )?;
    } else if mode == OsStr::new("set-float") {
        let i = input
            .ok_or("float selector")?
            .to_str()
            .ok_or("non ASCII selector")?
            .parse::<usize>()?;
        let values = [
            0.0f32,
            -0.0,
            1.25,
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::NAN,
            -f32::NAN,
            f32::MAX,
            f32::MIN_POSITIVE,
            0.123_456_79,
        ];
        let value = values.get(i).ok_or("bad selector")?;
        cfg.set_float(b"s", b"v", *value)?;
        emit_value(&mut out, "FORMATTED", &cfg, b"s", b"v")?;
    } else {
        return Err("unknown mode".into());
    }
    Ok(())
}
