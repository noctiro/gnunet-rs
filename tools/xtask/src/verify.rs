//! Current official implementation matrix; external reference runs are explicit.
use std::{
    env,
    error::Error,
    ffi::OsString,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

type CheckResult<T> = Result<T, Box<dyn Error>>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Format,
    Lint,
    Tools,
    Portable,
    Runtime,
    Test,
    Embedded,
    Reference,
    DaemonReference,
}
const DEFAULT: &[Stage] = &[
    Stage::Format,
    Stage::Tools,
    Stage::Lint,
    Stage::Portable,
    Stage::Test,
    Stage::Embedded,
];
const USAGE: &str = "expected verify [all|format|lint|tools|portable|runtime|test|embedded|reference|daemon-reference]; reference groups require GNUNET_REFERENCE_SOURCE; daemon-reference also requires GNUNET_REFERENCE_BUILD";

fn stages(group: Option<&str>) -> CheckResult<Vec<Stage>> {
    Ok(match group {
        None | Some("all") => DEFAULT.to_vec(),
        Some("format") => vec![Stage::Format],
        Some("lint") => vec![Stage::Lint],
        Some("tools") => vec![Stage::Tools],
        Some("portable") => vec![Stage::Portable],
        Some("runtime") => vec![Stage::Runtime],
        Some("test") => vec![Stage::Test],
        Some("embedded") => vec![Stage::Embedded],
        Some("reference") => vec![Stage::Reference],
        Some("daemon-reference") => vec![Stage::DaemonReference],
        Some(_) => return Err(USAGE.into()),
    })
}
fn commands(stage: Stage) -> Vec<Vec<&'static str>> {
    match stage {
        Stage::Format => vec![
            vec!["cargo", "fmt", "--all", "--", "--check"],
            vec![
                "cargo",
                "fmt",
                "--manifest-path",
                "tests/embedded/noalloc/Cargo.toml",
                "--",
                "--check",
            ],
        ],
        Stage::Lint => vec![
            vec![
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
            vec![
                "cargo",
                "doc",
                "--keep-going",
                "--workspace",
                "--lib",
                "--all-features",
                "--no-deps",
                "--locked",
            ],
        ],
        Stage::Runtime => vec![
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-native",
                "--lib",
                "--all-features",
                "--locked",
            ],
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-service-runtime",
                "--all-targets",
                "--all-features",
                "--locked",
            ],
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-client-host",
                "--lib",
                "--test",
                "transport",
                "--all-features",
                "--locked",
            ],
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-resolver-broker",
                "--test",
                "tcp",
                "--all-features",
                "--locked",
            ],
        ],
        Stage::Test => vec![
            vec![
                "cargo",
                "build",
                "-p",
                "gnunet-arm-host",
                "--bin",
                "gnunet-arm-spawn-helper",
                "--locked",
            ],
            vec![
                "cargo",
                "test",
                "--workspace",
                "--all-features",
                "--locked",
                "--no-fail-fast",
            ],
        ],
        Stage::Tools => vec![vec!["python3", "-B", "tools/check_tools.py"]],
        Stage::Portable => {
            let packages: Vec<_> = crate::checks::portable_packages().collect();
            let mut commands = Vec::new();
            for feature_flag in ["--no-default-features", "--all-features"] {
                let mut command = vec!["cargo", "test", "--locked", "--no-fail-fast", feature_flag];
                for package in &packages {
                    command.extend(["-p", *package]);
                }
                // Keep native feature unification out of the facade's base API.
                if feature_flag == "--no-default-features" {
                    command.extend(["-p", "gnunet"]);
                }
                commands.push(command);
            }
            for tier in ["alloc", "std"] {
                commands.push(vec![
                    "cargo",
                    "test",
                    "-p",
                    "gnunet",
                    "--no-default-features",
                    "--features",
                    tier,
                    "--locked",
                ]);
            }
            commands
        }
        Stage::Embedded => crate::checks::EMBEDDED_TARGETS
            .iter()
            .flat_map(|target| {
                [
                    vec![
                        "cargo",
                        "check",
                        "-p",
                        "gnunet",
                        "--no-default-features",
                        "--target",
                        target,
                        "--locked",
                    ],
                    vec![
                        "cargo",
                        "check",
                        "--manifest-path",
                        "tests/embedded/noalloc/Cargo.toml",
                        "--no-default-features",
                        "--target",
                        target,
                        "--locked",
                    ],
                ]
            })
            .collect(),
        Stage::Reference => vec![vec![
            "cargo",
            "build",
            "-p",
            "gnunet-cli",
            "--bin",
            "gnunet-cli",
            "--target-dir",
            "target",
            "--locked",
        ]],
        Stage::DaemonReference => vec![vec![
            "cargo",
            "build",
            "-p",
            "gnunet-cli",
            "-p",
            "gnunet-service-statistics",
            "--target-dir",
            "target",
            "--locked",
        ]],
    }
}
fn run(program: &str, args: &[impl AsRef<std::ffi::OsStr>]) -> CheckResult<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        return Err(format!("{program} failed with {status}").into());
    }
    Ok(())
}
fn reference_source(value: Option<OsString>) -> CheckResult<PathBuf> {
    let value = value.filter(|value| !value.is_empty()).ok_or(
        "reference requires GNUNET_REFERENCE_SOURCE pointing to the clean pinned v0.29.1 checkout",
    )?;
    let path = PathBuf::from(value).canonicalize()?;
    if !path.is_dir() {
        return Err("GNUNET_REFERENCE_SOURCE must be a directory".into());
    }
    Ok(path)
}
fn reference_args(source: &Path, output: &Path) -> Vec<OsString> {
    vec![
        "tools/interop/run_reference.py".into(),
        "--source".into(),
        source.as_os_str().to_owned(),
        "--binary".into(),
        "target/debug/gnunet-cli".into(),
        "--output".into(),
        output.as_os_str().to_owned(),
    ]
}
fn daemon_reference_args(receipt: &Path, output: &Path) -> Vec<OsString> {
    vec![
        "tools/reference/statistics_daemons.py".into(),
        "--reference".into(),
        receipt.as_os_str().to_owned(),
        "--rust-client".into(),
        "target/debug/gnunet-cli".into(),
        "--rust-service".into(),
        "target/debug/gnunet-service-statistics".into(),
        "--output".into(),
        output.as_os_str().to_owned(),
    ]
}

fn check_platform(stages: &[Stage], unix: bool) -> CheckResult<()> {
    if !unix
        && stages.iter().any(|stage| {
            matches!(
                stage,
                Stage::Tools
                    | Stage::Lint
                    | Stage::Test
                    | Stage::Reference
                    | Stage::DaemonReference
            )
        })
    {
        return Err("full-workspace/reference verification and Python tool controls still require Unix; `verify runtime` runs shared native TCP/clock/framing/Resolver checks on Windows, and `verify portable` checks protocol cores".into());
    }
    Ok(())
}

pub(crate) fn verify_matrix(group: Option<&str>) -> CheckResult<()> {
    let selected = stages(group)?;
    check_platform(&selected, cfg!(unix))?;
    for stage in selected {
        writeln!(io::stdout().lock(), "verify {stage:?}")?;
        let source = if matches!(stage, Stage::Reference | Stage::DaemonReference) {
            Some(reference_source(env::var_os("GNUNET_REFERENCE_SOURCE"))?)
        } else {
            None
        };
        let reference_build = if stage == Stage::DaemonReference {
            let path = PathBuf::from(env::var_os("GNUNET_REFERENCE_BUILD").filter(|value| !value.is_empty())
                .ok_or("daemon-reference requires GNUNET_REFERENCE_BUILD pointing to build_reference.py's successful build-result.json")?).canonicalize()?;
            if !path.is_file() {
                return Err("reference build receipt must be a file".into());
            }
            Some(path)
        } else {
            None
        };
        if stage == Stage::Lint {
            crate::checks::check_deps()?;
            crate::checks::check_features()?;
            crate::checks::check_lints()?;
            crate::external_contracts::check_external_release(false)?;
        }
        if stage == Stage::Portable {
            crate::checks::check_deps()?;
        }
        for command in commands(stage) {
            let (program, args) = command.split_first().ok_or("empty matrix command")?;
            run(program, args)?;
        }
        if stage == Stage::Embedded {
            crate::checks::check_noalloc()?;
        }
        if let Some(source) = source {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let folder = if reference_build.is_some() {
                "reference-daemons"
            } else {
                "reference"
            };
            let output = PathBuf::from(format!("target/{folder}/{nanos}-{}", std::process::id()));
            if let Some(receipt) = reference_build {
                crate::external_contracts::check_external_release(false)?;
                run("python3", &daemon_reference_args(&receipt, &output))?;
            } else {
                run("python3", &reference_args(&source, &output))?;
                for (script, directory) in [
                    (
                        "adapters/config-std/tests/upstream_oracle.py",
                        "configuration",
                    ),
                    (
                        "adapters/statistics-store/tests/upstream_oracle.py",
                        "statistics-store",
                    ),
                ] {
                    run(
                        "python3",
                        &[
                            OsString::from(script),
                            OsString::from("--source"),
                            source.as_os_str().to_owned(),
                            OsString::from("--output"),
                            output.join(directory).into_os_string(),
                        ],
                    )?;
                }
            }
            writeln!(
                io::stdout().lock(),
                "reference report: {}/result.json",
                output.display()
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn non_unix_hosts_reject_native_groups_before_starting_any_commands() -> CheckResult<()> {
        check_platform(
            &[
                Stage::Portable,
                Stage::Runtime,
                Stage::Format,
                Stage::Embedded,
            ],
            false,
        )?;
        check_platform(DEFAULT, true)?;
        if check_platform(DEFAULT, false).is_ok() {
            return Err("Windows default verification could falsely certify Unix services".into());
        }
        for stage in [
            Stage::Tools,
            Stage::Lint,
            Stage::Test,
            Stage::Reference,
            Stage::DaemonReference,
        ] {
            if check_platform(&[stage], false).is_ok() {
                return Err(
                    format!("Unix-only group accepted on a non-Unix host: {stage:?}").into(),
                );
            }
        }
        Ok(())
    }
    #[test]
    fn default_matrix_covers_all_local_groups_and_never_silently_runs_reference() -> CheckResult<()>
    {
        if stages(None)? != DEFAULT || stages(Some("all"))? != DEFAULT {
            return Err("default matrix lost a required local group".into());
        }
        for (group, stage) in [
            ("format", Stage::Format),
            ("lint", Stage::Lint),
            ("tools", Stage::Tools),
            ("portable", Stage::Portable),
            ("runtime", Stage::Runtime),
            ("test", Stage::Test),
            ("embedded", Stage::Embedded),
            ("reference", Stage::Reference),
            ("daemon-reference", Stage::DaemonReference),
        ] {
            if stages(Some(group))? != [stage] || commands(stage).is_empty() {
                return Err(format!("missing matrix group {group}").into());
            }
        }
        for removed in ["host", "native", "legacy-native", "", "full"] {
            if stages(Some(removed)).is_ok() {
                return Err(format!("removed group accepted: {removed}").into());
            }
        }
        Ok(())
    }
    #[test]
    fn portable_profiles_isolate_core_features_from_native_adapters() -> CheckResult<()> {
        let commands = commands(Stage::Portable);
        for (index, command) in commands.iter().take(2).enumerate() {
            let flag = ["--no-default-features", "--all-features"][index];
            if !command.contains(&flag) || command.contains(&"--workspace") {
                return Err(
                    "portable feature profiles were unified with the native workspace".into(),
                );
            }
            let selected: Vec<_> = command
                .windows(2)
                .filter(|pair| pair[0] == "-p")
                .map(|pair| pair[1])
                .collect();
            for package in crate::checks::portable_packages() {
                if !selected.contains(&package) {
                    return Err(format!("portable core package omitted: {package}").into());
                }
            }
            if selected.contains(&"gnunet") != (index == 0) {
                return Err("facade native features entered portable CI".into());
            }
        }
        for tier in ["alloc", "std"] {
            if !commands
                .iter()
                .any(|command| command.windows(2).any(|pair| pair == ["--features", tier]))
            {
                return Err(format!("facade storage tier omitted: {tier}").into());
            }
        }
        Ok(())
    }
    #[test]
    fn embedded_matrix_checks_both_targets_and_the_independent_noalloc_fixture() -> CheckResult<()>
    {
        let commands = commands(Stage::Embedded);
        for target in crate::checks::EMBEDDED_TARGETS {
            let target_jobs: Vec<_> = commands
                .iter()
                .filter(|command| command.contains(target))
                .collect();
            if target_jobs.len() != 2
                || target_jobs.iter().any(|command| {
                    !command.contains(&"--no-default-features") || !command.contains(&"--locked")
                })
            {
                return Err(format!("missing no-default locked target coverage: {target}").into());
            }
            if !target_jobs
                .iter()
                .any(|command| command.contains(&"tests/embedded/noalloc/Cargo.toml"))
            {
                return Err("independent allocation fixture omitted".into());
            }
        }
        Ok(())
    }
    #[test]
    fn reference_requires_source_and_uses_the_actual_official_cli() -> CheckResult<()> {
        if reference_source(None).is_ok() || reference_source(Some(OsString::new())).is_ok() {
            return Err("reference ran without a reference tree".into());
        }
        let build = commands(Stage::Reference);
        if !build[0].contains(&"gnunet-cli") || !build[0].contains(&"--bin") {
            return Err("reference CLI is not built".into());
        }
        let argv = reference_args(
            Path::new("/reference checkout"),
            Path::new("target/reference/run"),
        );
        if argv.len() != 7
            || argv[2] != "/reference checkout"
            || argv[4] != "target/debug/gnunet-cli"
            || argv[6] != "target/reference/run"
        {
            return Err("reference argv did not preserve exact paths".into());
        }
        Ok(())
    }
    #[test]
    fn daemon_reference_builds_both_rust_participants_and_preserves_receipt_path() -> CheckResult<()>
    {
        let build = commands(Stage::DaemonReference);
        if !build[0].contains(&"gnunet-cli")
            || !build[0].contains(&"gnunet-service-statistics")
            || !build[0].contains(&"--locked")
        {
            return Err("daemon reference is missing a production participant".into());
        }
        let args = daemon_reference_args(
            Path::new("/reference build/result.json"),
            Path::new("target/daemon proof"),
        );
        if args.len() != 9
            || args[2] != "/reference build/result.json"
            || args[4] != "target/debug/gnunet-cli"
            || args[6] != "target/debug/gnunet-service-statistics"
            || args[8] != "target/daemon proof"
        {
            return Err("daemon reference argv changed a participant or split a path".into());
        }
        Ok(())
    }
}
