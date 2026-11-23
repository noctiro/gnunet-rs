//! Standalone native process watchdog.
use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    process::ExitCode,
    time::Duration,
};

#[cfg(unix)]
#[path = "platform/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "platform/windows.rs"]
mod platform;

enum Outcome {
    Exited(u32),
    #[cfg(unix)]
    Signaled(i32),
    Deadline,
}

const REAP_GRACE: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let (Some(duration), Some(program)) = (arguments.next(), arguments.next()) else {
        let _diagnostic = writeln!(
            io::stderr().lock(),
            "arg 1: timeout in sec., arg 2: executable, arg<n> arguments"
        );
        return ExitCode::from(255);
    };
    let mut run = || -> io::Result<ExitCode> {
        let seconds = parse_seconds(&duration)?;
        let arguments = arguments.by_ref().collect::<Vec<OsString>>();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let outcome = runtime.block_on(platform::run(
            &program,
            &arguments,
            Duration::from_secs(u64::from(seconds)),
        ))?;
        drop(runtime);
        match outcome {
            Outcome::Exited(code) => Ok(platform::exit(code)),
            #[cfg(unix)]
            Outcome::Signaled(signal) => Ok(platform::signal_exit(signal)),
            Outcome::Deadline => {
                let _diagnostic = writeln!(
                    io::stdout().lock(),
                    "Child processes were killed after timeout of {seconds} seconds"
                );
                Ok(ExitCode::from(3))
            }
        }
    };
    match run() {
        Ok(code) => code,
        Err(error) => {
            diagnostic(error);
            ExitCode::from(255)
        }
    }
}

fn diagnostic(error: impl std::fmt::Display) {
    let _diagnostic = writeln!(io::stderr().lock(), "gnunet-timeout: {error}");
}

fn parse_seconds(argument: &OsStr) -> io::Result<u32> {
    let text = argument.as_encoded_bytes().trim_ascii_start();
    let (negative, digits) = match text {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, text),
    };
    let mut seconds = 0_i32;
    for digit in digits.iter().copied().take_while(u8::is_ascii_digit) {
        let digit = i32::from(digit - b'0');
        let digit = if negative { -digit } else { digit };
        seconds = seconds
            .checked_mul(10)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "timeout exceeds the native integer range",
                )
            })?;
    }
    Ok(if seconds == 0 { 600 } else { seconds as u32 })
}
