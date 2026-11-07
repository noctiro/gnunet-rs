//! Fresh-process witness for explicit global stderr installation and persistence.
use gnunet_program_host::{
    logging::{Environment, Logger, Stamp},
    policy::Level,
    process_stderr::ProcessStderr,
};
use std::{
    io::{self, Write},
    os::unix::ffi::OsStrExt,
};
fn main() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .ok_or_else(|| io::Error::other("missing owned log path"))?;
    let closed = args.next().is_some();
    // This binary has not spawned threads, installed foreign callbacks or created
    // any stderr writer/buffer. Its caller owns this dedicated exec process.
    #[expect(
        unsafe_code,
        reason = "Fresh single-thread exec exclusively installs its own stderr; no buffered writer or unrelated fd2 owner exists"
    )]
    // SAFETY: this early main is the unique fd2 replacement authority until logger Drop.
    let capability = unsafe { ProcessStderr::claim()? };
    if closed {
        #[expect(
            unsafe_code,
            reason = "This dedicated witness exclusively owns process fd2 and deliberately tests initial closed-stderr handling before creating a writer"
        )]
        // SAFETY: closing an integer descriptor is valid, and no borrowed stderr writer exists.
        let status = unsafe { libc::close(2) };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut logger = Logger::new(b"owned", std::process::id(), true)?;
    logger.install_process_stderr(capability)?;
    let stamp = Stamp::controlled_utc(1_700_000_000, 123456)?;
    logger.setup_routed(
        b"owned",
        Some(b"DEBUG"),
        Some(path.as_os_str().as_bytes()),
        &Environment::default(),
        &stamp,
        &mut io::stderr(),
    )?;
    logger.nocheck(Level::MESSAGE, None, b"logger", &stamp, &mut io::stderr())?;
    io::stderr().write_all(b"DIRECT before drop\n")?;
    io::stderr().flush()?;
    drop(logger);
    io::stderr().write_all(b"DIRECT after drop\n")?;
    io::stderr().flush()?;
    Ok(())
}
