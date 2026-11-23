//! Official GNUnet IPC command-line entry point.
mod argument;
#[cfg(feature = "cadet")]
mod cadet;
#[cfg(any(
    feature = "did",
    feature = "fs",
    feature = "identity",
    feature = "namestore",
    feature = "reclaim",
    feature = "regex",
    feature = "revocation",
    feature = "vpn"
))]
mod configured;
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
    all(feature = "transport", any(unix, windows)),
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
    ffi::OsString,
    io::{self, Write},
    process::ExitCode,
};

/// Run the grouped `gnunet-cli` commands with the original process arguments.
pub fn run_grouped() -> ExitCode {
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

/// Run the standalone `gnunet-fs` management command.
#[cfg(feature = "fs")]
pub fn run_fs() -> ExitCode {
    fs_exit("gnunet-fs", fs::standalone::index())
}

/// Run the standalone `gnunet-download` command.
#[cfg(feature = "fs")]
pub fn run_download() -> ExitCode {
    fs_exit("gnunet-download", fs::standalone::download())
}

/// Run the standalone `gnunet-unindex` command.
#[cfg(feature = "fs")]
pub fn run_unindex() -> ExitCode {
    fs_exit("gnunet-unindex", fs::standalone::unindex())
}

/// Run the standalone `gnunet-search` command.
#[cfg(feature = "fs")]
pub fn run_search() -> ExitCode {
    fs_exit("gnunet-search", fs::run_search())
}

/// Run the standalone `gnunet-publish` command.
#[cfg(feature = "fs")]
pub fn run_publish() -> ExitCode {
    fs_exit("gnunet-publish", fs::run_publish())
}

#[cfg(feature = "fs")]
fn fs_exit(binary: &str, result: Result<(), Box<dyn Error>>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if !fs::selected(error.as_ref()) {
                let _diagnostic = writeln!(io::stderr().lock(), "{binary}: {error}");
            }
            ExitCode::FAILURE
        }
    }
}

/// Run the standalone REGEX search and announcement command.
#[cfg(feature = "regex")]
pub fn run_regex() -> ExitCode {
    standalone_exit("gnunet-regex", regex::run_standalone())
}

/// Run the standalone RECLAIM command.
#[cfg(feature = "reclaim")]
pub fn run_reclaim() -> ExitCode {
    standalone_exit("gnunet-reclaim", reclaim::standalone::run())
}

/// Run the standalone DID command.
#[cfg(feature = "did")]
pub fn run_did() -> ExitCode {
    standalone_exit("gnunet-did", did::standalone::run())
}

/// Run the standalone VPN address allocation command.
#[cfg(feature = "vpn")]
pub fn run_vpn() -> ExitCode {
    standalone_exit("gnunet-vpn", vpn::standalone::run())
}

/// Run the standalone TRANSPORT virtual link snapshot command.
#[cfg(feature = "transport")]
pub fn run_transport() -> ExitCode {
    #[cfg(any(unix, windows))]
    match transport::run_official() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if transport::selected(error.as_ref()) => ExitCode::FAILURE,
        Err(error) => standalone_exit("gnunet-transport", Err(error)),
    }
    #[cfg(not(any(unix, windows)))]
    standalone_exit(
        "gnunet-transport",
        Err("requires a Unix or Windows runtime".into()),
    )
}

/// Run the standalone key revocation command.
#[cfg(feature = "revocation")]
pub fn run_revocation() -> ExitCode {
    standalone_exit("gnunet-revocation", revocation::run_standalone())
}

#[cfg(any(
    feature = "did",
    feature = "reclaim",
    feature = "regex",
    feature = "revocation",
    feature = "transport",
    feature = "vpn"
))]
fn standalone_exit(binary: &str, result: Result<(), Box<dyn Error>>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "{binary}: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Run the standalone `gnunet-namestore` URI import command.
#[cfg(feature = "namestore")]
pub fn run_namestore() -> ExitCode {
    match namestore::run_standalone() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-namestore: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Run the standalone `gnunet-statistics` PROGRAM.
#[cfg(feature = "statistics")]
pub fn run_statistics() -> ExitCode {
    #[cfg(any(unix, windows))]
    match statistics_watch::run_standalone() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if !statistics_watch::selected(error.as_ref()) {
                let _diagnostic = writeln!(io::stderr().lock(), "gnunet-statistics: {error}");
            }
            ExitCode::FAILURE
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _diagnostic = writeln!(
            io::stderr().lock(),
            "gnunet-statistics requires a Unix or Windows runtime"
        );
        ExitCode::FAILURE
    }
}

/// Run the standalone `gnunet-identity` PROGRAM.
#[cfg(feature = "identity")]
pub fn run_identity() -> ExitCode {
    match identity::run_standalone() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-identity: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Run the standalone `gnunet-namestore-zonefile` importer.
#[cfg(feature = "namestore")]
pub fn run_namestore_zonefile() -> ExitCode {
    match namestore::run_zonefile() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-namestore-zonefile: {error}");
            if namestore::missing_zone(error.as_ref()) {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn entry(args: &mut [OsString]) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "transport")]
    if args
        .first()
        .is_some_and(|value| value == "transport")
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
    if args.first().is_some_and(|a| a == "statistics") {
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
    if args.first().is_some_and(|value| value == "fs") {
        return fs::native(&args[1..]);
    }
    run_os(args, &mut io::stdout().lock())
}
fn run_os(args: &mut [OsString], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "revocation")]
    if args
        .first()
        .is_some_and(|value| value == "revocation")
    {
        return revocation::run(&args[1..], out);
    }
    #[cfg(feature = "did")]
    if args.first().is_some_and(|value| value == "did") {
        return did::run(&args[1..], out);
    }
    #[cfg(feature = "reclaim")]
    if args
        .first()
        .is_some_and(|value| value == "reclaim")
    {
        return reclaim::run(&args[1..], out);
    }
    #[cfg(feature = "namestore")]
    if args
        .first()
        .is_some_and(|value| value == "namestore")
    {
        return namestore::run(&args[1..], out);
    }
    #[cfg(feature = "identity")]
    if args
        .first()
        .is_some_and(|value| value == "identity")
    {
        return identity::run(&mut args[1..], out);
    }
    #[cfg(feature = "regex")]
    if args
        .first()
        .is_some_and(|value| value == "regex")
    {
        return regex::run(&args[1..], out);
    }
    #[cfg(feature = "vpn")]
    if args.first().is_some_and(|value| value == "vpn") {
        return vpn::run(&args[1..], out);
    }
    #[cfg(feature = "peerstore")]
    if args
        .first()
        .is_some_and(|value| value == "peerstore")
    {
        return peerstore::run(&args[1..], out);
    }
    #[cfg(feature = "cadet")]
    if args
        .first()
        .is_some_and(|value| value == "cadet")
    {
        return cadet::run(&args[1..], out);
    }
    #[cfg(feature = "fs")]
    if args.first().is_some_and(|value| value == "fs") {
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
