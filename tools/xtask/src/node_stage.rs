//! Assemble a relocatable prefix from a single native Cargo build.
use crate::dns_bundle::SignedApp;
use crate::rust_target::{OperatingSystem, RustTarget};
use std::{
    env,
    error::Error,
    ffi::{OsStr, OsString},
    io::{self, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::Command,
};

mod build;
mod catalog;
mod image;
mod prefix;
mod publication;
mod service;
mod wfp;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub(super) use image::run as run_image;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Linux,
    Macos,
    Windows,
    FreeBsd,
}

struct Target {
    triple: String,
    platform: Platform,
    gnu: bool,
}

impl Target {
    fn resolve(triple: Option<OsString>) -> Result<Self> {
        let (triple, cfg) = compiler_target(triple)?;
        Self::from_cfg(triple, &cfg)
    }

    fn from_cfg(triple: String, cfg: &str) -> Result<Self> {
        let rust_target = RustTarget::from_cfg(cfg)
            .ok_or_else(|| format!("unsupported native node target {triple}"))?;
        let platform = match rust_target.os {
            OperatingSystem::Linux => Platform::Linux,
            OperatingSystem::Macos => Platform::Macos,
            OperatingSystem::Windows => Platform::Windows,
            OperatingSystem::FreeBsd => Platform::FreeBsd,
            os @ (OperatingSystem::Android
            | OperatingSystem::Ios
            | OperatingSystem::OpenHarmony) => {
                return Err(format!(
                    "stage-node has no installed-prefix layout for {} target {triple}",
                    os.name()
                )
                .into());
            }
        };
        Ok(Self {
            triple,
            platform,
            gnu: rust_target.gnu,
        })
    }

    const fn platform(&self) -> Platform {
        self.platform
    }

    fn linux_gnu(&self) -> bool {
        self.platform == Platform::Linux && self.gnu
    }

    fn executable(&self, name: &str) -> String {
        format!("{name}{}", self.executable_suffix())
    }

    fn executable_suffix(&self) -> &'static str {
        if self.platform == Platform::Windows {
            ".exe"
        } else {
            ""
        }
    }
}

fn compiler_target(triple: Option<OsString>) -> Result<(String, String)> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let triple = if let Some(triple) = triple {
        triple
            .into_string()
            .map_err(|_| "expected a Rust target triple")?
    } else {
        let version = command_text(Command::new(&rustc).arg("-vV"), "Rust host target")?;
        version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .ok_or("rustc did not report its host target")?
            .to_owned()
    };
    if !triple
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        || !triple
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("expected a built-in Rust target triple".into());
    }
    let cfg = command_text(
        Command::new(&rustc).args(["--print", "cfg", "--target", &triple]),
        "Rust target configuration",
    )?;
    Ok((triple, cfg))
}

fn command_text(command: &mut Command, operation: &str) -> Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

struct Arguments {
    output: PathBuf,
    target: Option<OsString>,
    install_prefix: Option<OsString>,
    jobs: Option<NonZeroUsize>,
    hello_dir: Option<PathBuf>,
    locale_dir: Option<PathBuf>,
    wfp_package: Option<PathBuf>,
    macos_dns_app: Option<PathBuf>,
}

impl Arguments {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self> {
        let mut output = None;
        let mut target = None;
        let mut install_prefix = None;
        let mut jobs = None;
        let mut hello_dir = None;
        let mut locale_dir = None;
        let mut wfp_package = None;
        let mut macos_dns_app = None;
        while let Some(option) = args.next() {
            let value = args
                .next()
                .filter(|arg| !arg.is_empty() && !arg.as_encoded_bytes().starts_with(b"--"))
                .ok_or("stage-node expects an option and its nonempty value")?;
            match option.to_str() {
                Some("--output") if output.is_none() => output = Some(PathBuf::from(value)),
                Some("--target") if target.is_none() => target = Some(value),
                Some("--install-prefix") if install_prefix.is_none() => {
                    install_prefix = Some(value)
                }
                Some("--jobs") if jobs.is_none() => {
                    jobs = Some(
                        value
                            .to_str()
                            .ok_or("expected a positive job count")?
                            .parse()?,
                    );
                }
                Some("--hello-dir") if hello_dir.is_none() => {
                    hello_dir = Some(PathBuf::from(value))
                }
                Some("--locale-dir") if locale_dir.is_none() => {
                    locale_dir = Some(PathBuf::from(value))
                }
                Some("--wfp-package") if wfp_package.is_none() => {
                    wfp_package = Some(PathBuf::from(value))
                }
                Some("--macos-dns-app") if macos_dns_app.is_none() => {
                    macos_dns_app = Some(PathBuf::from(value))
                }
                _ => {
                    return Err(
                        format!("unexpected or duplicate stage-node option {option:?}").into(),
                    );
                }
            }
        }
        Ok(Self {
            output: output.ok_or("stage-node requires --output")?,
            target,
            install_prefix,
            jobs,
            hello_dir,
            locale_dir,
            wfp_package,
            macos_dns_app,
        })
    }
}

pub(super) fn run(root: &Path, args: impl Iterator<Item = OsString>) -> Result<()> {
    let arguments = Arguments::parse(args)?;
    let output = publication::Output::resolve(&arguments.output)?;
    let target = Target::resolve(arguments.target)?;
    let service = service::Assets::new(target.platform(), arguments.install_prefix.as_deref())?;
    let macos_dns = arguments
        .macos_dns_app
        .as_deref()
        .map(|path| SignedApp::open(path, &target.triple))
        .transpose()?;
    let wfp = arguments
        .wfp_package
        .as_deref()
        .map(|path| wfp::Package::open(path, &target))
        .transpose()?;
    let data = prefix::Data::load(
        arguments.hello_dir.as_deref(),
        arguments.locale_dir.as_deref(),
    )?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let plan = build::Plan::resolve(OsStr::new(&cargo), root, &target)?;
    data.validate(&target, &plan)?;
    let built = plan.build(
        &cargo,
        root,
        &target.triple,
        target.executable_suffix(),
        arguments.jobs,
    )?;
    let stage = output.begin()?;
    prefix::stage(stage.path(), &target, built, data, &service)?;
    crate::licenses::stage(
        root,
        &cargo,
        [target.triple.as_str()],
        &plan.cargo_selection(),
        &stage.path().join("share/doc/gnunet"),
    )?;
    if let Some(app) = macos_dns {
        app.stage(stage.path())?;
    }
    if let Some(package) = wfp {
        package.stage(stage.path())?;
    }
    stage.publish()?;
    writeln!(
        io::stdout().lock(),
        "Staged {} node at {}",
        target.triple,
        arguments.output.display()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operating_system_detection_is_independent_of_prefix_support() -> Result<()> {
        for (triple, cfg, os) in [
            (
                "aarch64-unknown-linux-ohos",
                "target_env=\"ohos\"\ntarget_os=\"linux\"\n",
                OperatingSystem::OpenHarmony,
            ),
            (
                "aarch64-linux-android",
                "target_env=\"\"\ntarget_os=\"android\"\n",
                OperatingSystem::Android,
            ),
            (
                "aarch64-apple-ios-sim",
                "target_env=\"sim\"\ntarget_os=\"ios\"\n",
                OperatingSystem::Ios,
            ),
        ] {
            if RustTarget::from_cfg(cfg).map(|target| target.os) != Some(os) {
                return Err(format!("expected {} for {triple}", os.name()).into());
            }
            let error = Target::from_cfg(triple.to_owned(), cfg)
                .err()
                .ok_or_else(|| format!("target unexpectedly has an installed prefix: {triple}"))?;
            if !error.to_string().contains(os.name()) {
                return Err(format!("unexpected error for {triple}: {error}").into());
            }
        }
        Ok(())
    }

    #[test]
    fn staged_node_defaults_select_real_platform_packages() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("workspace root absent")?;
        let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let data = prefix::Data::load(None, None)?;
        for triple in [
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-freebsd",
        ] {
            let target = Target::resolve(Some(triple.into()))?;
            let plan = build::Plan::resolve(&cargo, root, &target)?;
            data.validate(&target, &plan)?;
            let names: Vec<_> = catalog::packages(&target)
                .flat_map(|package| package.artifacts(&target))
                .map(|(name, _)| name)
                .collect();
            if names.contains(&"gnunet-arm-spawn-helper")
                != (target.platform() != Platform::Windows)
                || names.contains(&"gnunet-helper-vpn") != (target.platform() == Platform::Linux)
                || names.contains(&"gnunet-testing-netjail-launcher")
                    != (target.platform() == Platform::Linux)
                || plan.contains_libexec("gnunet-cmds-helper")
                    != (target.platform() == Platform::Linux)
                || names.contains(&"nss_gns") != target.linux_gnu()
                || names.contains(&"gnunet-dns-wfp-control")
                    != (target.platform() == Platform::Windows)
            {
                return Err(format!("misplaced native target in {triple}").into());
            }
        }
        Ok(())
    }
}
