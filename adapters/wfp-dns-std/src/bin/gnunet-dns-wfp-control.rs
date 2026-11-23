//! Explicit WFP driver deployment, metadata and original retirement operations.
#[cfg(any(windows, test))]
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Policy {
    Install,
    Verify,
    Remove,
}

#[cfg(any(windows, test))]
#[derive(Debug, Eq, PartialEq)]
enum Command {
    PreparePolicy,
    Policy(Policy, [u8; 32]),
    PollDriver,
    FinalizeDriver,
    Deployment(Deployment, PathBuf),
}

#[cfg(any(windows, test))]
#[derive(Debug, Eq, PartialEq)]
enum Deployment {
    VerifyPackage,
    Install,
    Inspect,
    Start([u8; 32]),
    Stop,
    Remove,
}

#[cfg(any(windows, test))]
fn parse(mut arguments: impl Iterator<Item = std::ffi::OsString>) -> Option<Command> {
    let first = arguments.next()?;
    let command = match first.to_str()? {
        "prepare-policy" => Command::PreparePolicy,
        "poll-driver" => Command::PollDriver,
        "finalize-driver" => Command::FinalizeDriver,
        verb @ ("verify-driver-package"
        | "install-driver"
        | "inspect-driver"
        | "start-driver"
        | "stop-driver"
        | "remove-driver") => {
            let directory = PathBuf::from(arguments.next()?);
            if directory.as_os_str().is_empty() {
                return None;
            }
            let operation = match verb {
                "verify-driver-package" => Deployment::VerifyPackage,
                "install-driver" => Deployment::Install,
                "inspect-driver" => Deployment::Inspect,
                "start-driver" => Deployment::Start(parse_nonce(arguments.next()?.to_str()?)?),
                "stop-driver" => Deployment::Stop,
                "remove-driver" => Deployment::Remove,
                _ => return None,
            };
            Command::Deployment(operation, directory)
        }
        verb => {
            let policy = match verb {
                "install-policy" => Policy::Install,
                "verify-policy" => Policy::Verify,
                "remove-policy" => Policy::Remove,
                _ => return None,
            };
            let receipt = arguments.next()?;
            Command::Policy(policy, parse_nonce(receipt.to_str()?)?)
        }
    };
    arguments.next().is_none().then_some(command)
}

#[cfg(any(windows, test))]
fn parse_nonce(text: &str) -> Option<[u8; 32]> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes: &[u8; 64] = text.as_bytes().try_into().ok()?;
    let mut nonce = [0; 32];
    for (out, [high, low]) in nonce.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *out = hex(*high)? << 4 | hex(*low)?;
    }
    Some(nonce)
}

#[cfg(windows)]
fn main() -> ExitCode {
    let Some(command) = parse(std::env::args_os().skip(1)) else {
        return diagnostic(
            format_args!(
                "usage: gnunet-dns-wfp-control prepare-policy | install-policy RECEIPT | \
verify-policy RECEIPT | remove-policy RECEIPT | verify-driver-package DIR | \
install-driver DIR | inspect-driver DIR | start-driver DIR RECEIPT | stop-driver DIR | \
remove-driver DIR | poll-driver | finalize-driver"
            ),
            2,
        );
    };
    match run(command, &mut std::io::stdout().lock()) {
        Ok(status) => status,
        Err(error) => diagnostic(format_args!("{error}"), 1),
    }
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    diagnostic(format_args!("gnunet-dns-wfp-control requires Windows"), 1)
}

fn diagnostic(message: std::fmt::Arguments<'_>, code: u8) -> ExitCode {
    use std::io::Write;
    let _written = writeln!(std::io::stderr().lock(), "{message}");
    ExitCode::from(code)
}

#[cfg(windows)]
fn run(command: Command, output: &mut impl std::io::Write) -> std::io::Result<ExitCode> {
    use gnunet_wfp_dns_host::InstallationReceipt;
    match command {
        Command::PreparePolicy => {
            for byte in InstallationReceipt::generate()?.nonce() {
                write!(output, "{byte:02x}")?;
            }
            writeln!(output)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Policy(policy, nonce) => {
            update_policy(policy, InstallationReceipt::from_nonce(nonce), output)
        }
        Command::PollDriver => advance_driver(false, output),
        Command::FinalizeDriver => advance_driver(true, output),
        Command::Deployment(operation, directory) => deploy(operation, directory, output),
    }
}

#[cfg(windows)]
fn deploy(
    operation: Deployment,
    directory: PathBuf,
    output: &mut impl std::io::Write,
) -> std::io::Result<ExitCode> {
    use gnunet_wfp_dns_host::{
        InstallationReceipt,
        deployment::{InstallOutcome, RemoveOutcome, StartOutcome, StopOutcome, VerifiedPackage},
    };
    let package = VerifiedPackage::open(&directory)?;
    let status = match operation {
        Deployment::VerifyPackage => {
            writeln!(output, "verified")?;
            ExitCode::SUCCESS
        }
        Deployment::Install => match package.install()? {
            InstallOutcome::Installed(installation) => {
                write_installation(installation, output)?;
                ExitCode::SUCCESS
            }
            InstallOutcome::RestartRequired => {
                writeln!(output, "RestartRequired")?;
                ExitCode::from(3)
            }
        },
        Deployment::Inspect => {
            write_installation(package.inspect()?, output)?;
            ExitCode::SUCCESS
        }
        Deployment::Start(nonce) => {
            let outcome = package.start(InstallationReceipt::from_nonce(nonce))?;
            writeln!(output, "{outcome:?}")?;
            if outcome == StartOutcome::StartPending {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        }
        Deployment::Stop => match package.stop()? {
            StopOutcome::Stopped { win32, specific } => {
                writeln!(
                    output,
                    "Stopped Win32 {win32:#010x} service {specific:#010x}"
                )?;
                ExitCode::SUCCESS
            }
            StopOutcome::Pending(state) => {
                writeln!(output, "{state:?}")?;
                ExitCode::from(3)
            }
            StopOutcome::RundownPending(progress) => {
                writeln!(output, "{:?}", progress.phase)?;
                ExitCode::from(3)
            }
        },
        Deployment::Remove => match package.remove()? {
            RemoveOutcome::Pending(state) => {
                writeln!(output, "{state:?}")?;
                ExitCode::from(3)
            }
            RemoveOutcome::RestartRequired { published_inf } => {
                writeln!(output, "RestartRequired")?;
                writeln!(output, "{}", published_inf.display())?;
                ExitCode::from(3)
            }
            RemoveOutcome::Removed { published_inf } => {
                writeln!(output, "Removed")?;
                writeln!(output, "{}", published_inf.display())?;
                ExitCode::SUCCESS
            }
        },
    };
    Ok(status)
}

#[cfg(windows)]
fn write_installation(
    installation: gnunet_wfp_dns_host::deployment::Installation,
    output: &mut impl std::io::Write,
) -> std::io::Result<()> {
    writeln!(output, "{:?}", installation.state)?;
    writeln!(output, "{}", installation.published_inf.display())
}

#[cfg(windows)]
fn update_policy(
    policy: Policy,
    receipt: gnunet_wfp_dns_host::InstallationReceipt,
    output: &mut impl std::io::Write,
) -> std::io::Result<ExitCode> {
    use gnunet_wfp_dns_host::{ProvisionLimits, Provisioner};

    let mut engine =
        Provisioner::open(ProvisionLimits::default()).map_err(std::io::Error::other)?;
    let result = match policy {
        Policy::Install => engine.install(receipt).map(|_| "installed"),
        Policy::Verify => engine.verify(receipt).map(|_| "verified"),
        Policy::Remove => engine.remove(&receipt).map(|()| "removed"),
    };
    let close = engine.close();
    match result {
        Ok(state) => writeln!(output, "{state}")?,
        Err(error) => {
            return Err(std::io::Error::other(format!(
                "{error}; engine close {close:?}"
            )));
        }
    }
    if close.has_failure() {
        return Err(std::io::Error::other(format!(
            "closing WFP engine: {close:?}"
        )));
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(windows)]
fn advance_driver(finalize: bool, output: &mut impl std::io::Write) -> std::io::Result<ExitCode> {
    use gnunet_wfp_dns::device::maintenance::Phase;
    use gnunet_wfp_dns_host::device::Maintenance;

    let mut driver = Maintenance::open().map_err(std::io::Error::other)?;
    let progress = if finalize {
        driver.finalize()
    } else {
        driver.poll()
    }
    .map_err(std::io::Error::other)?;
    let status = match progress.phase {
        Phase::NativeRetired => {
            let released = driver.close().map_err(std::io::Error::other)?;
            writeln!(output, "{:?}", released.progress().phase)?;
            ExitCode::SUCCESS
        }
        Phase::Failed => {
            writeln!(output, "Failed {:#010x}", progress.status.cast_unsigned())?;
            ExitCode::FAILURE
        }
        phase => {
            writeln!(output, "{phase:?}")?;
            ExitCode::from(3)
        }
    };
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn command_preserves_exact_saved_receipt_across_operations() {
        let receipt = "aB".repeat(32);
        let expected = [0xab; 32];
        for (verb, operation) in [
            ("install-policy", Policy::Install),
            ("verify-policy", Policy::Verify),
            ("remove-policy", Policy::Remove),
        ] {
            let args = [verb, &receipt].into_iter().map(OsString::from);
            assert_eq!(parse(args), Some(Command::Policy(operation, expected)));
        }
    }

    #[test]
    fn command_rejects_missing_malformed_or_extra_arguments() {
        assert_eq!(
            parse(["install-policy"].into_iter().map(OsString::from)),
            None
        );
        assert_eq!(parse_nonce(&"g".repeat(64)), None);
        assert_eq!(parse_nonce(&"1".repeat(65)), None);
        assert_eq!(
            parse(["finalize-driver", "now"].into_iter().map(OsString::from)),
            None
        );
    }

    #[test]
    fn deployment_start_requires_package_and_policy_receipt() {
        let arguments = |receipt: &str| {
            ["start-driver", "node provider package", receipt]
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
                .into_iter()
        };
        assert_eq!(
            parse(arguments(&"a1".repeat(32))),
            Some(Command::Deployment(
                Deployment::Start([0xa1; 32]),
                PathBuf::from("node provider package")
            ))
        );
        assert_eq!(parse(arguments("invalid")), None);
        assert_eq!(
            parse(["install-driver", ""].into_iter().map(OsString::from)),
            None
        );
    }

    #[test]
    fn deployment_stop_and_remove_use_an_explicit_package_directory() {
        for (verb, operation) in [
            ("stop-driver", Deployment::Stop),
            ("remove-driver", Deployment::Remove),
        ] {
            assert_eq!(
                parse([verb, "signed package"].into_iter().map(OsString::from)),
                Some(Command::Deployment(
                    operation,
                    PathBuf::from("signed package")
                )),
            );
            assert_eq!(parse([verb].into_iter().map(OsString::from)), None);
            assert_eq!(
                parse(
                    [verb, "signed package", "--force"]
                        .into_iter()
                        .map(OsString::from)
                ),
                None
            );
        }
    }
}
