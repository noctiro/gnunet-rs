//! Actual source file-error logging observer in a unique fresh process.
use gnunet_program_host::{
    logging::{Environment, Logger, Stamp},
    process_stderr::ProcessStderr,
};
use std::{
    cell::RefCell,
    io::{self, Write},
    os::unix::{ffi::OsStrExt, fs::DirBuilderExt},
    rc::Rc,
};
fn hex(value: &[u8]) -> String {
    value.iter().map(|v| format!("{v:02x}")).collect()
}
fn main() -> io::Result<()> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.len() != 6 {
        return Err(io::Error::other(
            "mode level file parent actual-extra-profile required",
        ));
    }
    let extra: i32 = args[5]
        .to_str()
        .ok_or_else(|| io::Error::other("profile is not native decimal"))?
        .parse()
        .map_err(io::Error::other)?;
    let output = Rc::new(RefCell::new(Vec::new()));
    writeln!(
        output.borrow_mut(),
        "PID {}\nPROFILE {}",
        std::process::id(),
        extra
    )?;
    let mut logger = Logger::new(b"old", std::process::id(), extra > 0)?;
    #[expect(
        unsafe_code,
        reason = "This dedicated early single-thread exec has no other stderr owner or buffered writer"
    )]
    // SAFETY: main has created no thread or foreign callback that can use fd2.
    let capability = unsafe { ProcessStderr::claim()? };
    logger.install_process_stderr(capability)?;
    let capture = Rc::clone(&output);
    let registration = logger.logger_add(move |r| {
        drop(writeln!(
            capture.borrow_mut(),
            "R {} {} {} {}",
            r.kind.0,
            hex(r.component),
            hex(r.date),
            hex(r.message)
        ));
    })?;
    let first = logger.setup_routed(
        b"owned-errors",
        Some(args[2].as_bytes()),
        Some(args[3].as_bytes()),
        &Environment::capture(),
        &Stamp::setup_now()?,
        &mut io::stderr(),
    );
    writeln!(
        output.borrow_mut(),
        "SETUP {}",
        if first.is_ok() { 1 } else { -1 }
    )?;
    if args[1] == "cached" || args[1] == "recover" {
        std::fs::remove_file(&args[4])?;
        std::fs::DirBuilder::new().mode(0o755).create(&args[4])?;
        let mut next = args[3].as_bytes().to_vec();
        next.extend_from_slice(b".new");
        let file = if args[1] == "cached" {
            args[3].as_bytes()
        } else {
            &next
        };
        let second = logger.setup_routed(
            b"owned-errors",
            Some(args[2].as_bytes()),
            Some(file),
            &Environment::capture(),
            &Stamp::setup_now()?,
            &mut io::stderr(),
        );
        writeln!(
            output.borrow_mut(),
            "SETUP {}",
            if second.is_ok() { 1 } else { -1 }
        )?;
    }
    if args[1] == "rotate" {
        writeln!(io::stderr(), "DIRECT initial")?;
        io::stderr().flush()?;
        for index in 0..6 {
            let mut next = args[3].as_bytes().to_vec();
            next.extend_from_slice(format!(".{index}").as_bytes());
            let result = logger.setup_routed(
                b"owned-errors",
                Some(args[2].as_bytes()),
                Some(&next),
                &Environment::capture(),
                &Stamp::setup_now()?,
                &mut io::stderr(),
            );
            writeln!(
                output.borrow_mut(),
                "SETUP {}",
                if result.is_ok() { 1 } else { -1 }
            )?;
            writeln!(io::stderr(), "DIRECT {index}")?;
            io::stderr().flush()?;
        }
    }
    logger.logger_remove(registration)?;
    io::stderr().write_all(b"DIRECT after setup\n")?;
    io::stderr().flush()?;
    io::stdout().write_all(&output.borrow())?;
    Ok(())
}
