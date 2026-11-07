//! Typed synchronous observations, without a global logger or native locale.
use gnunet_config::{
    Configuration, ProcessEnvironment,
    diagnostic::{Argument, Diagnostic},
};
use std::{
    cell::RefCell,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
    sync::Arc,
};
fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        let digits = b"0123456789abcdef";
        s.push(char::from(digits[usize::from(b >> 4)]));
        s.push(char::from(digits[usize::from(b & 15)]));
    }
    s
}
fn event(event: Diagnostic<'_>, out: &RefCell<Vec<u8>>) {
    let mut out = out.borrow_mut();
    drop(write!(
        &mut *out,
        "E {} {} {} {} {} {}",
        event.level.0,
        event.component.map_or_else(|| "-".to_string(), hex),
        hex(event.site.file),
        hex(event.site.function),
        event.site.line,
        hex(event.template)
    ));
    for arg in event.arguments {
        let text = match arg {
            Argument::Bytes(b) => format!("b{}", hex(b)),
            Argument::Unsigned(n) => format!("u{n}"),
            Argument::Signed(n) => format!("i{n}"),
            Argument::Error(e) => e
                .raw_os_error()
                .map_or_else(|| "unavailable".to_string(), |n| format!("e{n}")),
            Argument::NullString => "null".to_string(),
            Argument::Translated { domain: _, message } => format!("b{}", hex(message)),
        };
        drop(write!(&mut *out, " {text}"));
    }
    drop(writeln!(&mut *out));
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("mode input option required".into());
    }
    let mode = args[1].as_bytes();
    let input = args[2].as_bytes();
    let output = RefCell::new(Vec::new());
    let observer = |ev: Diagnostic<'_>| event(ev, &output);
    let mut c = Configuration::default();
    let persistent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let keep = Arc::clone(&persistent);
    drop(c.observe(Some(Arc::new(move |ev| {
        if let Ok(mut v) = keep.lock() {
            v.push(ev.site.id);
        }
    }))));
    let result = match mode {
        b"deserialize" => c.deserialize_observed(input, None, Some(&observer)),
        b"parse" => c.parse_observed(Path::new(&args[2]), &ProcessEnvironment, Some(&observer)),
        b"load" => c.load_observed(Some(Path::new(&args[2])), Some(&observer)),
        b"load-repeat" => c
            .load_observed(Some(Path::new(&args[2])), Some(&observer))
            .and_then(|()| c.load_observed(Some(Path::new(&args[2])), Some(&observer))),
        b"diff-project" => c
            .diff_observed(&Configuration::default(), Some(&observer))
            .map(|_| ()),
        b"from" => c
            .load_from_observed(Path::new(&args[2]), Some(&observer))
            .map(|r| r.c_status())
            .map(|n| {
                drop(writeln!(&mut *output.borrow_mut(), "RESULT {n}"));
            }),
        b"choice" => {
            c.set_value(b"own", b"key", Some(input))?;
            c.get_choice_observed(b"own", b"key", &[b"YES", b"NO"], Some(&observer))
                .map(|_| ())
        }
        b"filename" => c
            .get_filename_observed(b"own", b"missing", &ProcessEnvironment, Some(&observer))
            .map(|_| ()),
        b"dollar" => c
            .expand_dollar_observed(input, &ProcessEnvironment, Some(&observer))
            .map(|value| {
                drop(writeln!(&mut *output.borrow_mut(), "VALUE {}", hex(&value)));
            }),
        b"secret-get" => {
            c.parse_observed(Path::new(&args[2]), &ProcessEnvironment, Some(&observer))?;
            c.get_observed(b"secret", b"missing", Some(&observer))
                .map(|_| ())
                .ok_or(gnunet_config::Error::Missing)
        }
        b"clean" => {
            c.enable_diagnostics();
            if args[3].as_bytes() != b"not-parsed" {
                c.parse_observed(Path::new(&args[2]), &ProcessEnvironment, Some(&observer))?;
                if args[3].as_bytes() == b"unlinked" {
                    std::fs::remove_file(&args[2])?;
                } else {
                    let mut file = std::fs::OpenOptions::new().append(true).open(&args[2])?;
                    file.write_all(b"# owned change\n")?;
                }
            }
            c.clean_file_observed(Path::new(&args[2]), Some(&observer))
                .map(|_| ())
        }
        b"write" => c.write_observed(Path::new(&args[2]), Some(&observer)),
        _ => return Err("mode".into()),
    };
    if mode != b"from" || result.is_err() {
        let status = match &result {
            Ok(()) => 1,
            Err(gnunet_config::Error::Missing) if mode != b"clean" => 0,
            Err(_) => -1,
        };
        writeln!(&mut *output.borrow_mut(), "RESULT {status}")?;
    }
    if !persistent.lock().map_err(|_| "observer lock")?.is_empty() {
        return Err("local observer duplicated persistent route".into());
    }
    io::stdout().write_all(&output.into_inner())?;
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            drop(writeln!(io::stderr(), "{e}"));
            std::process::ExitCode::FAILURE
        }
    }
}
