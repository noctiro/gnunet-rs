//! Current official implementation matrix; external reference runs are explicit.
use std::{
    env,
    error::Error,
    ffi::OsString,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
mod output;
use output::{Recorder, combine};

type CheckResult<T> = Result<T, Box<dyn Error>>;
const DAEMON_BUILD_TARGET: &str = "target/daemon-reference-build";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Format,
    Policy,
    Lint,
    Tools,
    Profiles,
    Portable,
    Runtime,
    Test,
    Embedded,
    Reference,
    DaemonReference,
}
const DEFAULT: &[Stage] = &[
    Stage::Format,
    Stage::Policy,
    Stage::Tools,
    Stage::Lint,
    Stage::Profiles,
    Stage::Portable,
    Stage::Test,
    Stage::Embedded,
];
const SOURCE: &[Stage] = &[Stage::Format, Stage::Policy];
const NATIVE: &[Stage] = &[Stage::Portable, Stage::Profiles, Stage::Lint, Stage::Test];
const USAGE: &str = "expected verify [all|source|native|format|lint|tools|profiles|portable|runtime|test|embedded|reference|daemon-reference] [--log-dir PATH]; reference requires GNUNET_REFERENCE_SOURCE and GNUNET_CONFIG_REFERENCE_SOURCE; daemon-reference requires GNUNET_REFERENCE_SOURCE and GNUNET_REFERENCE_BUILD";

impl Stage {
    const fn name(self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Policy => "policy",
            Self::Lint => "lint",
            Self::Tools => "tools",
            Self::Profiles => "profiles",
            Self::Portable => "portable",
            Self::Runtime => "runtime",
            Self::Test => "test",
            Self::Embedded => "embedded",
            Self::Reference => "reference",
            Self::DaemonReference => "daemon-reference",
        }
    }
}

struct Options<'a> {
    group: &'a str,
    log_dir: Option<&'a Path>,
}

fn options(args: &[String]) -> CheckResult<Options<'_>> {
    let mut group = None;
    let mut log_dir = None;
    let mut args = args.iter();
    while let Some(argument) = args.next() {
        if argument == "--log-dir" && log_dir.is_none() {
            let value = args
                .next()
                .filter(|value| !value.is_empty() && !value.starts_with('-'))
                .ok_or(USAGE)?;
            log_dir = Some(Path::new(value));
        } else if !argument.starts_with('-') && group.is_none() {
            group = Some(argument.as_str());
        } else {
            return Err(USAGE.into());
        }
    }
    Ok(Options {
        group: group.unwrap_or("all"),
        log_dir,
    })
}

fn stages(group: Option<&str>) -> CheckResult<Vec<Stage>> {
    Ok(match group {
        None | Some("all") => DEFAULT.to_vec(),
        Some("source") => SOURCE.to_vec(),
        Some("native") => NATIVE.to_vec(),
        Some("format") => vec![Stage::Format],
        Some("lint") => vec![Stage::Lint],
        Some("tools") => vec![Stage::Tools],
        Some("profiles") => vec![Stage::Profiles],
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
        Stage::Policy => Vec::new(),
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
        Stage::Profiles => crate::profiles::commands(),
        Stage::Runtime => vec![
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-namecache-client-host",
                "-p",
                "gnunet-dht-client-host",
                "-p",
                "gnunet-core-client-host",
                "-p",
                "gnunet-seti-client-host",
                "-p",
                "gnunet-setu-client-host",
                "-p",
                "gnunet-rps-client-host",
                "-p",
                "gnunet-messenger-client-host",
                "-p",
                "gnunet-set-client-host",
                "-p",
                "gnunet-scalarproduct-client-host",
                "-p",
                "gnunet-consensus-client-host",
                "-p",
                "gnunet-abd-client-host",
                "-p",
                "gnunet-secretsharing-client-host",
                "-p",
                "gnunet-conversation-client-host",
                "-p",
                "gnunet-nat-client-host",
                "-p",
                "gnunet-dns-client-host",
                "-p",
                "gnunet-nse-client-host",
                "--all-targets",
                "--all-features",
                "--locked",
            ],
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-pils-host",
                "--lib",
                "--features",
                "client",
                "--locked",
            ],
            vec![
                "cargo",
                "check",
                "-p",
                "gnunet",
                "--no-default-features",
                "--features",
                "official-namecache-client,official-pils-client,official-dht-client,official-core-client,official-seti-client,official-setu-client,official-rps-client,official-messenger-client,official-set-client,official-scalarproduct-client,official-consensus-client,official-abd-client,official-secretsharing-client,official-conversation-client,official-nat-client,official-dns-client,official-nse-client,official-fs,official-fs-extraction,official-fs-network,official-fs-auto-share,official-fs-server,official-datastore-server",
                "--locked",
            ],
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-fs-host",
                "-p",
                "gnunet-extractor-host",
                "-p",
                "gnunet-auto-share",
                "-p",
                "gnunet-datastore-host",
                "-p",
                "gnunet-service-datastore",
                "-p",
                "gnunet-service-fs",
                "-p",
                "gnunet-cadet-host",
                "-p",
                "gnunet-snapshot-host",
                "-p",
                "gnunet-identity-host",
                "-p",
                "gnunet-namestore-host",
                "-p",
                "gnunet-service-identity",
                "-p",
                "gnunet-service-namestore",
                "--features",
                "gnunet-fs-host/auto-share,gnunet-fs-host/server,gnunet-datastore-host/server",
                "--all-targets",
                "--locked",
            ],
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-extractor-host",
                "--doc",
                "--locked",
            ],
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-config",
                "-p",
                "gnunet-native",
                "--all-targets",
                "--all-features",
                "--locked",
                "--no-fail-fast",
            ],
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-service-runtime",
                "-p",
                "gnunet-service-startup",
                "-p",
                "gnunet-ipc-unix",
                "-p",
                "gnunet-statistics-store",
                "-p",
                "gnunet-service-statistics",
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
                "--test",
                "presence",
                "--all-features",
                "--locked",
            ],
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-cli",
                "--no-default-features",
                "--features",
                "cadet,did,fs,identity,namestore,peerstore,reclaim,regex,revocation,statistics,transport,vpn",
                "--all-targets",
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
            vec![
                "cargo",
                "test",
                "-p",
                "gnunet-resolver-host",
                "--test",
                "tcp",
                "--test",
                "loopback",
                "--test",
                "recovery",
                "--all-features",
                "--locked",
            ],
            vec![
                "cargo",
                "run",
                "-p",
                "gnunet-service-resolver",
                "--bin",
                "gnunet-service-resolver",
                "--all-features",
                "--locked",
                "--",
                "--help",
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
            "--bin",
            "gnunet-cli",
            "--bin",
            "gnunet-statistics",
            "--bin",
            "gnunet-service-statistics",
            "--no-default-features",
            "--features",
            "gnunet-cli/statistics",
            "--target-dir",
            DAEMON_BUILD_TARGET,
            "--locked",
        ]],
    }
}
fn reference_source(variable: &str, value: Option<OsString>) -> CheckResult<PathBuf> {
    let value = value.filter(|value| !value.is_empty()).ok_or_else(|| {
        format!("reference requires {variable} pointing to its clean pinned checkout")
    })?;
    let path = PathBuf::from(value).canonicalize()?;
    if !path.is_dir() {
        return Err(format!("{variable} must be a directory").into());
    }
    Ok(path)
}
/// Each oracle validates its own revision; retain distinct source arguments even
/// when several comparisons share the same output root and invocation group.
fn component_reference_args(
    source: &Path,
    configuration_source: &Path,
    output: &Path,
) -> Vec<Vec<OsString>> {
    let mut commands = vec![reference_args(source, output)];
    for (script, source, directory) in [
        (
            "adapters/config-std/tests/upstream_oracle.py",
            configuration_source,
            "configuration",
        ),
        (
            "adapters/statistics-store/tests/upstream_oracle.py",
            source,
            "statistics-store",
        ),
    ] {
        commands.push(vec![
            script.into(),
            "--source".into(),
            source.as_os_str().to_owned(),
            "--output".into(),
            output.join(directory).into_os_string(),
        ]);
    }
    commands
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
    let binary = |name| format!("{DAEMON_BUILD_TARGET}/debug/{name}").into();
    vec![
        "tools/reference/statistics_daemons.py".into(),
        "--reference".into(),
        receipt.as_os_str().to_owned(),
        "--rust-client".into(),
        binary("gnunet-cli"),
        "--rust-statistics".into(),
        binary("gnunet-statistics"),
        "--rust-service".into(),
        binary("gnunet-service-statistics"),
        "--output".into(),
        output.as_os_str().to_owned(),
    ]
}

fn check_platform(stages: &[Stage], unix: bool) -> CheckResult<()> {
    if !unix
        && stages.iter().any(|stage| {
            matches!(
                stage,
                Stage::Tools | Stage::Reference | Stage::DaemonReference
            )
        })
    {
        return Err("Python tool controls and official C reference groups require Unix; native Rust lint, workspace tests and focused runtime checks are available on every supported host".into());
    }
    Ok(())
}

pub(crate) fn verify_matrix(args: &[String]) -> CheckResult<()> {
    let options = options(args)?;
    let mut recorder = Recorder::new(options.group, options.log_dir)?;
    let result = (|| {
        let selected = stages(Some(options.group))?;
        check_platform(&selected, cfg!(unix))?;
        for stage in selected {
            recorder.begin_stage(stage.name())?;
            writeln!(io::stdout().lock(), "verify {stage:?}")?;
            verify_stage(stage, &mut recorder)?;
        }
        Ok(())
    })();
    let reported = recorder.finish(&result);
    combine(result, reported)
}

fn verify_stage(stage: Stage, recorder: &mut Recorder) -> CheckResult<()> {
    let source = if matches!(stage, Stage::Reference | Stage::DaemonReference) {
        Some(reference_source(
            "GNUNET_REFERENCE_SOURCE",
            env::var_os("GNUNET_REFERENCE_SOURCE"),
        )?)
    } else {
        None
    };
    let configuration_source = if stage == Stage::Reference {
        Some(reference_source(
            "GNUNET_CONFIG_REFERENCE_SOURCE",
            env::var_os("GNUNET_CONFIG_REFERENCE_SOURCE"),
        )?)
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
    if stage == Stage::Policy {
        recorder.check("dependencies", crate::checks::check_deps)?;
        recorder.check("features", crate::checks::check_features)?;
        recorder.check("lint-policy", crate::checks::check_lints)?;
        recorder.check("external-status", || {
            crate::external_contracts::check_external_release(false)
        })?;
    }
    for command in commands(stage) {
        let (program, args) = command.split_first().ok_or("empty matrix command")?;
        recorder.command(program, args)?;
    }
    if stage == Stage::Embedded {
        recorder.check("noalloc", crate::checks::check_noalloc)?;
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
            recorder.check("external-status", || {
                crate::external_contracts::check_external_release(false)
            })?;
            recorder.command("python3", &daemon_reference_args(&receipt, &output))?;
        } else {
            let configuration_source =
                configuration_source.ok_or("component reference has no configuration source")?;
            for args in component_reference_args(&source, &configuration_source, &output) {
                recorder.command("python3", &args)?;
            }
        }
        writeln!(
            io::stdout().lock(),
            "reference report: {}/result.json",
            output.display()
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_and_native_contracts_partition_global_policy_from_native_work() -> CheckResult<()> {
        let source = stages(Some("source"))?;
        let native = stages(Some("native"))?;
        if source != [Stage::Format, Stage::Policy]
            || native != [Stage::Portable, Stage::Profiles, Stage::Lint, Stage::Test]
            || native.iter().any(|stage| {
                matches!(
                    stage,
                    Stage::Format | Stage::Policy | Stage::Tools | Stage::Embedded
                )
            })
        {
            return Err("source checks and portable/native feature execution lost their independent contracts".into());
        }
        check_platform(&native, false)?;
        if stages(Some("lint"))? != [Stage::Lint] {
            return Err("native lint must not depend on source-policy tooling".into());
        }
        Ok(())
    }

    #[test]
    fn logging_arguments_are_explicit_and_never_absorb_another_option() -> CheckResult<()> {
        let arguments = ["native", "--log-dir", "target/ci/native"].map(String::from);
        let parsed = options(&arguments)?;
        if parsed.group != "native" || parsed.log_dir != Some(Path::new("target/ci/native")) {
            return Err("verification logging split the selected group or output path".into());
        }
        for invalid in [
            vec!["native", "--log-dir"],
            vec!["native", "--log-dir", "--other"],
            vec![
                "native",
                "--log-dir",
                "target/ci",
                "--log-dir",
                "target/other",
            ],
            vec!["native", "source"],
        ] {
            if options(&invalid.into_iter().map(String::from).collect::<Vec<_>>()).is_ok() {
                return Err("ambiguous verification options were accepted".into());
            }
        }
        Ok(())
    }
    #[test]
    fn native_rust_groups_are_available_on_every_host() -> CheckResult<()> {
        check_platform(
            &[
                Stage::Portable,
                Stage::Profiles,
                Stage::Runtime,
                Stage::Format,
                Stage::Embedded,
                Stage::Lint,
                Stage::Test,
            ],
            false,
        )?;
        check_platform(DEFAULT, true)?;
        if check_platform(DEFAULT, false).is_ok() {
            return Err(
                "Windows default verification must identify the Unix-only Python tool controls"
                    .into(),
            );
        }
        for stage in [Stage::Tools, Stage::Reference, Stage::DaemonReference] {
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
            ("tools", Stage::Tools),
            ("profiles", Stage::Profiles),
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
        for removed in ["host", "legacy-native", "", "full"] {
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
    fn embedded_checks_facade_and_independent_allocation_fixture() -> CheckResult<()> {
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
                .any(|command| command.windows(2).any(|pair| pair == ["-p", "gnunet"]))
                || !target_jobs
                    .iter()
                    .any(|command| command.contains(&"tests/embedded/noalloc/Cargo.toml"))
            {
                return Err(format!("missing facade or allocation fixture: {target}").into());
            }
        }
        Ok(())
    }
    #[test]
    fn reference_requires_source_and_uses_the_actual_official_cli() -> CheckResult<()> {
        for variable in ["GNUNET_REFERENCE_SOURCE", "GNUNET_CONFIG_REFERENCE_SOURCE"] {
            for value in [None, Some(OsString::new())] {
                let Err(error) = reference_source(variable, value) else {
                    return Err("reference ran without a reference tree".into());
                };
                if !error.to_string().contains(variable) {
                    return Err("missing source error lost the required input name".into());
                }
            }
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
    fn component_reference_routes_each_oracle_to_its_selected_source() -> CheckResult<()> {
        let source = Path::new("/baseline reference");
        let configuration_source = Path::new("/configuration reference");
        let output = Path::new("target/reference run");
        let commands = component_reference_args(source, configuration_source, output);
        if commands.len() != 3 || commands[0] != reference_args(source, output) {
            return Err("component reference lost its baseline protocol comparison".into());
        }
        for (args, script, source, directory) in [
            (
                &commands[1],
                "adapters/config-std/tests/upstream_oracle.py",
                configuration_source,
                "configuration",
            ),
            (
                &commands[2],
                "adapters/statistics-store/tests/upstream_oracle.py",
                source,
                "statistics-store",
            ),
        ] {
            if args.len() != 5
                || args[0] != script
                || args[1] != "--source"
                || args[2] != source.as_os_str()
                || args[3] != "--output"
                || args[4] != output.join(directory).as_os_str()
            {
                return Err("component oracle source or output path was mixed or split".into());
            }
        }
        Ok(())
    }
    #[test]
    fn daemon_reference_builds_each_rust_participant_and_preserves_receipt_path() -> CheckResult<()>
    {
        let build = commands(Stage::DaemonReference);
        let binaries: Vec<_> = build[0]
            .windows(2)
            .filter(|args| args[0] == "--bin")
            .map(|args| args[1])
            .collect();
        if binaries
            != [
                "gnunet-cli",
                "gnunet-statistics",
                "gnunet-service-statistics",
            ]
            || !build[0].contains(&"--locked")
            || !build[0].contains(&"--no-default-features")
            || !build[0]
                .windows(2)
                .any(|args| args == ["--features", "gnunet-cli/statistics"])
            || !build[0]
                .windows(2)
                .any(|args| args == ["--target-dir", DAEMON_BUILD_TARGET])
        {
            return Err("daemon reference is missing a production participant".into());
        }
        let args = daemon_reference_args(
            Path::new("/reference build/result.json"),
            Path::new("target/daemon proof"),
        );
        if !args.iter().map(OsString::as_os_str).eq([
            "tools/reference/statistics_daemons.py",
            "--reference",
            "/reference build/result.json",
            "--rust-client",
            "target/daemon-reference-build/debug/gnunet-cli",
            "--rust-statistics",
            "target/daemon-reference-build/debug/gnunet-statistics",
            "--rust-service",
            "target/daemon-reference-build/debug/gnunet-service-statistics",
            "--output",
            "target/daemon proof",
        ]
        .into_iter()
        .map(std::ffi::OsStr::new))
        {
            return Err("daemon reference argv changed a participant or split a path".into());
        }
        Ok(())
    }
}
