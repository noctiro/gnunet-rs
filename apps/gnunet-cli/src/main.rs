//! Official GNUnet IPC command-line entry point.
mod argument;
#[cfg(feature = "cadet")]
mod cadet;
#[cfg(feature = "namestore")]
mod control;
#[cfg(feature = "did")]
mod did;
#[cfg(any(feature = "statistics", feature = "transport"))]
mod foreground;
#[cfg(feature = "fs")]
mod fs;
mod help;
#[cfg(feature = "identity")]
mod identity;
#[cfg(feature = "namestore")]
mod namestore;
#[cfg(any(
    feature = "cadet",
    feature = "did",
    feature = "identity",
    feature = "namestore",
    feature = "peerstore",
    feature = "reclaim",
    feature = "regex",
    feature = "vpn"
))]
mod peer;
#[cfg(feature = "peerstore")]
mod peerstore;
#[cfg(feature = "reclaim")]
mod reclaim;
#[cfg(feature = "regex")]
mod regex;
#[cfg(feature = "revocation")]
mod revocation;
#[cfg(all(feature = "statistics", any(unix, windows)))]
mod statistics_watch;
#[cfg(all(feature = "transport", any(unix, windows)))]
mod transport;
#[cfg(feature = "vpn")]
mod vpn;
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    let mut args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match entry(&mut args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[cfg(all(feature = "statistics", any(unix, windows)))]
            if statistics_watch::selected(error.as_ref()) {
                return ExitCode::FAILURE;
            }
            #[cfg(all(feature = "transport", any(unix, windows)))]
            if transport::selected(error.as_ref()) {
                return ExitCode::FAILURE;
            }
            #[cfg(feature = "fs")]
            if fs::selected(error.as_ref()) {
                return ExitCode::FAILURE;
            }
            if writeln!(io::stderr().lock(), "gnunet-cli: {error}").is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::FAILURE
        }
    }
}
fn entry(args: &mut [OsString]) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "transport")]
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("transport"))
    {
        #[cfg(any(unix, windows))]
        {
            return transport::run(&args[1..]);
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err("native TRANSPORT observation requires a Unix or Windows runtime".into());
        }
    }
    // Native STATISTICS owns its stdout and original foreground lifecycle.
    #[cfg(feature = "statistics")]
    if args.first().is_some_and(|a| a == OsStr::new("statistics")) {
        #[cfg(any(unix, windows))]
        {
            return statistics_watch::run(&args[1..]);
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err("native STATISTICS requires a Unix or Windows runtime".into());
        }
    }
    #[cfg(feature = "fs")]
    if args.first().is_some_and(|value| value == OsStr::new("fs")) {
        return fs::native(&args[1..]);
    }
    run_os(args, &mut io::stdout().lock())
}
fn run_os(args: &mut [OsString], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "revocation")]
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("revocation"))
    {
        return revocation::run(&args[1..], out);
    }
    #[cfg(feature = "did")]
    if args.first().is_some_and(|value| value == OsStr::new("did")) {
        return did::run(&args[1..], out);
    }
    #[cfg(feature = "reclaim")]
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("reclaim"))
    {
        return reclaim::run(&args[1..], out);
    }
    #[cfg(feature = "namestore")]
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("namestore"))
    {
        return namestore::run(&args[1..], out);
    }
    #[cfg(feature = "identity")]
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("identity"))
    {
        return identity::run(&mut args[1..], out);
    }
    #[cfg(feature = "regex")]
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("regex"))
    {
        return regex::run(&args[1..], out);
    }
    #[cfg(feature = "vpn")]
    if args.first().is_some_and(|value| value == OsStr::new("vpn")) {
        return vpn::run(&args[1..], out);
    }
    #[cfg(feature = "peerstore")]
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("peerstore"))
    {
        return peerstore::run(&args[1..], out);
    }
    #[cfg(feature = "cadet")]
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("cadet"))
    {
        return cadet::run(&args[1..], out);
    }
    #[cfg(feature = "fs")]
    if args.first().is_some_and(|value| value == OsStr::new("fs")) {
        return fs::run(&args[1..], out);
    }
    let args = args
        .iter()
        .map(|arg| argument::text(arg).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    run(&args, out)
}
fn run(args: &[String], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        None | Some("--help") => help::write(out)?,
        Some("--version") => writeln!(
            out,
            "gnunet-rs {} / official GNUnet v0.29.1 (partial implementation)",
            env!("CARGO_PKG_VERSION")
        )?,
        #[cfg(feature = "fs")]
        Some("fs") => fs::run(&args[1..], out)?,
        Some("statistics") => {
            return Err("native STATISTICS must use its normal foreground entry point".into());
        }
        _ => return Err("unknown official command; see --help".into()),
    }
    Ok(())
}
