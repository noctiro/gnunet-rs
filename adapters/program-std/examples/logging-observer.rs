//! Finite public Rust logger observer, no libgnunet FFI or process-global install.
use gnunet_program_host::{
    logging::{Environment, Logger, Stamp},
    policy::{CallSite, Level},
};
use std::{
    cell::RefCell,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    rc::Rc,
};
fn hex(bytes: &[u8]) -> String {
    let digits = b"0123456789abcdef";
    let mut text = String::new();
    for byte in bytes {
        text.push(char::from(digits[usize::from(byte >> 4)]));
        text.push(char::from(digits[usize::from(byte & 15)]));
    }
    text
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.len() < 4 {
        return Err("mode level extra required".into());
    }
    let mode = args[1].as_bytes();
    let level = args[2].as_bytes();
    let extra = args[3].as_bytes() != b"0";
    let minimum = if level == b"-" { None } else { Some(level) };
    let mut logger = Logger::new(b"owned-program", std::process::id(), extra)?;
    let mut stderr = io::stderr();
    let diagnostics = logger.setup(
        b"owned-program",
        minimum,
        args.get(4).map(|v| v.as_bytes()),
        &Environment::capture(),
        &Stamp::setup_now()?,
    )?;
    stderr.write_all(&diagnostics)?;
    let output = Rc::new(RefCell::new(Vec::new()));
    writeln!(
        &mut *output.borrow_mut(),
        "PID {}\nPROFILE {}",
        std::process::id(),
        i32::from(extra)
    )?;
    if mode == b"policy" {
        for (index, component) in [None, Some(b"owned-program".as_slice()), Some(b"other")]
            .into_iter()
            .enumerate()
        {
            for level in [-1, 0, 1, 2, 4, 8, 16, 32, 64, 65] {
                for line in [0, 9, 10, 11, 20, 21, i32::MAX] {
                    let site = CallSite {
                        component,
                        file: b"owned/unit.c",
                        function: b"probe",
                        line,
                    };
                    writeln!(
                        &mut *output.borrow_mut(),
                        "P {index} {level} {line} {}",
                        i32::from(logger.enabled(Level(level), site)?)
                    )?;
                }
            }
        }
    } else if mode == b"custom" {
        let mut add = |tag| {
            let output = Rc::clone(&output);
            logger.logger_add(move |record| {
                drop(writeln!(
                    &mut *output.borrow_mut(),
                    "R {tag} {} {} {} {}",
                    record.kind.0,
                    hex(record.component),
                    hex(record.date),
                    hex(record.message)
                ));
            })
        };
        let one = add(1)?;
        let two = add(2)?;
        logger.nocheck(Level::ERROR, None, b"alpha", &Stamp::now(0)?, &mut stderr)?;
        let old = logger.scope_enter([0; 16]);
        writeln!(
            &mut *output.borrow_mut(),
            "SCOPE {}",
            i32::from(logger.scope_get().is_some())
        )?;
        logger.from_nocheck(
            Level::WARNING,
            Some(b"other"),
            b"beta\n",
            &Stamp::now(0)?,
            &mut stderr,
        )?;
        logger.nocheck(Level::MESSAGE, None, b"ready", &Stamp::now(0)?, &mut stderr)?;
        logger.nocheck(Level::ERROR, None, b"", &Stamp::now(0)?, &mut stderr)?;
        logger.logger_remove(two)?;
        logger.from_nocheck(Level::DEBUG, None, b"tail", &Stamp::now(0)?, &mut stderr)?;
        logger.scope_restore(old);
        writeln!(
            &mut *output.borrow_mut(),
            "SCOPE {}",
            i32::from(logger.scope_get().is_some())
        )?;
        logger.logger_remove(one)?;
    } else if mode == b"file" {
        logger.write_diagnostic(b"diagnostic-port\n", &mut stderr)?;
        let old = logger.scope_enter([0; 16]);
        logger.nocheck(Level::ERROR, None, b"alpha", &Stamp::now(0)?, &mut stderr)?;
        logger.scope_restore(old);
        logger.nocheck(Level::MESSAGE, None, b"ready", &Stamp::now(0)?, &mut stderr)?;
        for _ in 0..1002 {
            logger.from_nocheck(
                Level(2 | 64),
                Some(b"other"),
                b"repeat\n",
                &Stamp::now(0)?,
                &mut stderr,
            )?;
        }
    } else {
        return Err("unrecognized observer mode".into());
    }
    io::stdout().write_all(&output.borrow())?;
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
