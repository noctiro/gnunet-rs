//! Official GNUnet IPC command-line entry point.
mod cadet;
mod did;
mod fs;
mod identity;
mod namestore;
mod peer;
mod peerstore;
mod reclaim;
mod regex;
mod revocation;
#[cfg(unix)]
mod statistics_watch;
#[cfg(unix)]
mod transport;
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
            #[cfg(unix)]
            if statistics_watch::selected(error.as_ref()) || transport::selected(error.as_ref()) {
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
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("transport"))
    {
        #[cfg(unix)]
        {
            return transport::run(&args[1..]);
        }
        #[cfg(not(unix))]
        {
            return Err("native TRANSPORT observation requires Unix".into());
        }
    }
    // Native STATISTICS owns its stdout and original foreground lifecycle.
    if args.first().is_some_and(|a| a == OsStr::new("statistics")) {
        #[cfg(unix)]
        {
            return statistics_watch::run(&args[1..]);
        }
        #[cfg(not(unix))]
        {
            return Err("native STATISTICS requires Unix".into());
        }
    }
    run_os(args, &mut io::stdout().lock())
}
fn run_os(args: &mut [OsString], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("revocation"))
    {
        return revocation::run(&args[1..], out);
    }
    if args.first().is_some_and(|value| value == OsStr::new("did")) {
        return did::run(&args[1..], out);
    }
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("reclaim"))
    {
        return reclaim::run(&args[1..], out);
    }
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("namestore"))
    {
        return namestore::run(&args[1..], out);
    }
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("identity"))
    {
        return identity::run(&mut args[1..], out);
    }
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("regex"))
    {
        return regex::run(&args[1..], out);
    }
    if args.first().is_some_and(|value| value == OsStr::new("vpn")) {
        return vpn::run(&args[1..], out);
    }
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("peerstore"))
    {
        return peerstore::run(&args[1..], out);
    }
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("cadet"))
    {
        return cadet::run(&args[1..], out);
    }
    if args.first().is_some_and(|value| value == OsStr::new("fs")) {
        return fs::run(&args[1..], out);
    }
    let args = args
        .iter()
        .map(|arg| {
            arg.to_str()
                .map(str::to_owned)
                .ok_or("command requires UTF-8 arguments")
        })
        .collect::<Result<Vec<_>, _>>()?;
    run(&args, out)
}
fn run(args: &[String], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        None | Some("--help") => {
            writeln!(
                out,
                "GNUnet Rust implementation (v0.29.1 compatibility, in development)"
            )?;
            writeln!(
                out,
                "statistics get [PROGRAM -c/-L/-l] <UNIXPATH|-> [subsystem [name]]"
            )?;
            writeln!(
                out,
                "statistics watch [PROGRAM -c/-L/-l] <UNIXPATH|-> <subsystem> <name>; - uses configured Unix/TCP endpoint; actual notifications until SIGINT/SIGTERM"
            )?;
            writeln!(out, "cadet peers|tunnels|paths; see cadet --help")?;
            writeln!(out, "peerstore store|iterate|monitor; see peerstore --help")?;
            writeln!(
                out,
                "transport monitor|links [PROGRAM/options] <UNIXPATH|->; see transport --help"
            )?;
            writeln!(out, "vpn internet|service; see vpn --help")?;
            writeln!(out, "regex search|announce; see regex --help")?;
            writeln!(
                out,
                "revocation query|revoke|verify|mine|prepare; see revocation --help"
            )?;
            writeln!(
                out,
                "did create|replace|remove|show|show-all|resolve; see did --help"
            )?;
            writeln!(
                out,
                "reclaim attribute-store|attribute-get|attribute-delete|attribute-list|credential-store|credential-get|credential-delete|credential-list|ticket-issue|ticket-list|ticket-revoke|ticket-consume; see reclaim --help"
            )?;
            writeln!(
                out,
                "namestore lookup|replace|import-uri|import-zonefile|delete|batch|reverse|iterate|monitor|list-orphans|purge-orphans|purge-zone|edit-begin|edit-cancel; see namestore --help"
            )?;
            writeln!(
                out,
                "identity list|monitor|lookup|lookup-suffix|export|create|rename|delete|encrypt|decrypt; see identity --help"
            )?;
            writeln!(
                out,
                "fs extract|import|pack|cat|export|ls|publish|fetch; see fs --help"
            )?;
            writeln!(
                out,
                "statistics set [PROGRAM -c/-L/-l] <UNIXPATH|-> <subsystem> <name> <value> [--relative] [--persistent]"
            )?;
            writeln!(
                out,
                "GET/SET common options precede the endpoint; - selects configured Unix/TCP. GET streams without a row aggregation cap under one 10 second deadline. WATCH stays subscribed until stopped."
            )?;
        }
        Some("--version") => writeln!(
            out,
            "gnunet-rs {} / official GNUnet v0.29.1 (partial implementation)",
            env!("CARGO_PKG_VERSION")
        )?,
        Some("fs") => fs::run(&args[1..], out)?,
        Some("statistics") => {
            return Err("native STATISTICS must use its normal foreground entry point".into());
        }
        _ => return Err("unknown official command; see --help".into()),
    }
    Ok(())
}
