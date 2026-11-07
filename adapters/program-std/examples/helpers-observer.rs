//! Actual Rust helper factory/destination observer; no C FFI.
use gnunet_program_host::{
    clock::Clock,
    getopt::Options,
    helpers::{self, Filename, Target},
};
use std::{
    cell::RefCell,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    rc::Rc,
};
fn hex(value: Option<&[u8]>) -> String {
    let Some(bytes) = value else {
        return "-".to_owned();
    };
    let digits = b"0123456789abcdef";
    let mut text = String::new();
    for byte in bytes {
        text.push(char::from(digits[usize::from(byte >> 4)]));
        text.push(char::from(digits[usize::from(byte & 15)]));
    }
    text
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let project = gnunet_config::ProjectData::default();
    let flag = Target::new(7);
    let inc = Target::new(u32::MAX);
    let uint = Target::new(123);
    let small = Target::new(456);
    let big = Target::new(789);
    let string = Target::new(None);
    let file = Target::new(Filename {
        path: None,
        error: None,
    });
    let config = Target::new(Filename {
        path: None,
        error: None,
    });
    let logfile = Target::new(Filename {
        path: None,
        error: None,
    });
    let level = Target::new(None);
    let relative = Target::new(111);
    let absolute = Target::new(222);
    let timestamp = Target::new(333);
    let data = Target::new([0xaa, 0xbb, 0xcc]);
    let clock = Rc::new(RefCell::new(Clock::new()?));
    clock.borrow_mut().set_offset(444);
    let mut options = Options::new();
    let mut definition = helpers::flag(b'f', b"flag", b"flag description", flag.clone());
    if std::env::var_os("OWNED_HELPER_MODIFIERS").is_some() {
        definition = definition.mandatory();
    }
    options.add(definition);
    let mut definition = helpers::increment(b'n', b"number", b"increment description", inc.clone());
    if std::env::var_os("OWNED_HELPER_MODIFIERS").is_some() {
        definition = definition.exclusive();
    }
    options.add(definition);
    options.add(helpers::uint(
        b'u',
        b"uint",
        b"NUMBER",
        b"uint description",
        uint.clone(),
    ));
    options.add(helpers::uint16(
        b't',
        b"small",
        b"NUMBER",
        b"small description",
        small.clone(),
    ));
    options.add(helpers::ulong(
        b'g',
        b"large",
        b"NUMBER",
        b"large description",
        big.clone(),
    ));
    options.add(helpers::string(
        b's',
        b"string",
        b"TEXT",
        b"string description",
        string.clone(),
    ));
    options.add(helpers::filename(
        b'F',
        b"filename",
        b"FILENAME",
        b"filename description",
        file.clone(),
    ));
    options.add(helpers::relative_time(
        b'R',
        b"relative",
        b"TIME",
        b"relative description",
        relative.clone(),
    ));
    options.add(helpers::absolute_time(
        b'A',
        b"absolute",
        b"TIME",
        b"absolute description",
        absolute.clone(),
    ));
    options.add(helpers::timestamp(
        b'S',
        b"timestamp",
        b"TIME",
        b"timestamp description",
        timestamp.clone(),
    ));
    options.add(helpers::time_travel(b'T', b"travel", Rc::clone(&clock)));
    options.add(helpers::base32_fixed(
        b'b',
        b"bytes",
        b"BASE32",
        b"bytes description",
        data.clone(),
    ));
    options.add(helpers::verbose(inc.clone()));
    options.add(helpers::cfgfile(config.clone()));
    options.add(helpers::logfile(logfile.clone()));
    options.add(helpers::loglevel(level.clone()));
    options.add(helpers::help(&project, Some(b"Owned helpers")));
    options.add(helpers::version(b"0.29.1"));
    let diagnostics = RefCell::new(Vec::new());
    let callback_failure = RefCell::new(None);
    let observer =
        |event: gnunet_config::diagnostic::Diagnostic<'_>| match (file.get(), config.get()) {
            (Ok(file), Ok(config)) => {
                drop(writeln!(
                    diagnostics.borrow_mut(),
                    "OBS {} FILE {} CFG {} MSG {}",
                    event.level.0,
                    hex(file.path.as_ref().map(|v| v.as_os_str().as_bytes())),
                    hex(config.path.as_ref().map(|v| v.as_os_str().as_bytes())),
                    hex(Some(event.template))
                ));
            }
            (Err(error), _) | (_, Err(error)) => *callback_failure.borrow_mut() = Some(error),
        };
    let observed = std::env::var_os("OWNED_HELPER_DIAGNOSTICS").is_some();
    let result = options.run_translated_observed(
        b"owned helpers",
        std::env::args_os(),
        std::env::var_os("POSIXLY_CORRECT").is_some(),
        gnunet_program_host::locale::disabled(),
        if observed { Some(&observer) } else { None },
    );
    if let Some(error) = callback_failure.into_inner() {
        return Err(error.into());
    }
    let mut stdout = io::stdout();
    stdout.write_all(&diagnostics.into_inner())?;
    stdout.write_all(&result.output.stdout)?;
    writeln!(
        stdout,
        "RET {} VALUES {} {} {} {} {} {} {} {} {} BYTES {}",
        result.code,
        flag.get()?,
        inc.get()?,
        uint.get()?,
        small.get()?,
        big.get()?,
        relative.get()?,
        absolute.get()?,
        timestamp.get()?,
        clock.borrow().offset(),
        hex(Some(&data.get()?))
    )?;
    writeln!(
        stdout,
        "STR {} FILE {} CFG {} LOGFILE {} LEVEL {}",
        hex(string.get()?.as_deref()),
        hex(file.get()?.path.as_ref().map(|v| v.as_os_str().as_bytes())),
        hex(config
            .get()?
            .path
            .as_ref()
            .map(|v| v.as_os_str().as_bytes())),
        hex(logfile
            .get()?
            .path
            .as_ref()
            .map(|v| v.as_os_str().as_bytes())),
        hex(level.get()?.as_deref())
    )?;
    io::stderr().write_all(&result.output.stderr)?;
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            drop(writeln!(io::stderr(), "{error}"));
            std::process::ExitCode::from(1)
        }
    }
}
