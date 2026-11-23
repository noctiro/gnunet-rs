//! Compile the kernel leaf and link the WDK entry without running Windows code.
mod image;

use crate::{
    Result,
    cli::{Driver, Inputs},
    command, invalid, receipt,
    sdk::{self, Target},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub fn build(inputs: &Inputs, tools: &Driver) -> Result<()> {
    let target = inputs.target;
    let output = &inputs.output;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let wire = repo.join("crates/gnunet-wfp-dns/src");
    let platform = repo.join("platform/windows/wfp-driver");
    let driver = platform.join("src");
    let inf = platform.join("package/gnunet-wfp-driver.inf.in");
    let inf_template = fs::read_to_string(&inf)?;
    let inf_contents = render_inf(&inf_template, target)?;
    let bindings = output.join("bindings.rs");
    let wrappers = output.join("wrappers.obj");
    let libraries = target.driver_libraries(&inputs.sdk);
    let mut paths = vec![
        bindings.clone(),
        wrappers.clone(),
        output.join("receipt.json"),
        inf.clone(),
    ];
    paths.extend(libraries.iter().cloned());
    rust_sources(&wire, &mut paths)?;
    rust_sources(&driver, &mut paths)?;
    paths.sort_unstable();
    let input_files = records(&paths)?;

    command::run(
        output,
        "rustc-version",
        Command::new(&tools.rustc).arg("-vV"),
    )?;
    command::run(
        output,
        "lld-version",
        Command::new(&tools.lld).args(["-flavor", "link", "--version"]),
    )?;

    let wire_lib = output.join("libgnunet_wfp_dns.rlib");
    let driver_lib = output.join("libgnunet_wfp_driver.rlib");
    let entry_lib = output.join("gnunet-wfp-entry.lib");
    let mut compile = rustc(
        tools,
        target,
        "gnunet_wfp_dns",
        "rlib",
        &wire.join("lib.rs"),
        &wire_lib,
    );
    command::run(output, "compile-dns-wire", &mut compile)?;
    let mut compile = rustc(
        tools,
        target,
        "gnunet_wfp_driver",
        "rlib",
        &driver.join("lib.rs"),
        &driver_lib,
    );
    command::run(
        output,
        "compile-driver",
        compile
            .env("GNUNET_WDK_BINDINGS", &bindings)
            .args(["--extern", &assignment("gnunet_wfp_dns", &wire_lib)?]),
    )?;
    let mut compile = rustc(
        tools,
        target,
        "gnunet_wfp_image",
        "staticlib",
        &driver.join("image.rs"),
        &entry_lib,
    );
    command::run(
        output,
        "compile-entry",
        compile
            .args(["--extern", &assignment("gnunet_wfp_driver", &driver_lib)?])
            .args(["-L", &assignment("dependency", output)?])
            .args([
                "-C",
                "lto=fat",
                "-C",
                "codegen-units=1",
                "-C",
                "force-unwind-tables=yes",
            ]),
    )?;

    let package = output.join("package");
    fs::create_dir(&package)?;
    let image = package.join("gnunet-wfp-driver.sys");
    let package_inf = package.join("gnunet-wfp-driver.inf");
    let map = output.join("gnunet-wfp-driver.map");
    command::run(
        output,
        "link-driver",
        Command::new(&tools.lld)
            .args([
                "-flavor",
                "link",
                "/driver",
                "/subsystem:native",
                "/entry:GsDriverEntry",
                "/nodefaultlib",
                "/manifest:no",
                "/noimplib",
                "/opt:ref",
                "/dynamicbase",
                "/nxcompat",
                "/release",
                "/timestamp:0",
                "/include:_load_config_used",
            ])
            .arg(format!("/machine:{}", target.linker_machine))
            .arg(format!("/out:{}", sdk::utf8(&image)?))
            .arg(format!("/map:{}", sdk::utf8(&map)?))
            .arg(&entry_lib)
            .arg(&wrappers)
            .args(&libraries),
    )?;
    let inspected = image::inspect(target, &fs::read(&image)?, &fs::read_to_string(&map)?)?;
    if fs::read_to_string(&inf)? != inf_template || records(&paths)? != input_files {
        return Err(invalid("a WFP driver build input changed during compilation").into());
    }
    fs::write(&package_inf, inf_contents)?;
    let artifacts = records(&[wire_lib, driver_lib, entry_lib, image, package_inf, map])?;
    receipt::write(
        &output.join("driver-receipt.json"),
        &json!({
            "status": "linked-unsigned-driver", "target": target.triple,
            "sdk_profile": target.profile, "sdk_package_version": sdk::PACKAGE_VERSION,
            "input_files": input_files, "artifacts": artifacts, "inspection": inspected,
            "tools": receipt::sources(),
        }),
    )?;
    println!(
        "Staged unsigned {} WFP driver package at {}",
        target.pe_name,
        package.display()
    );
    Ok(())
}

fn rustc(
    tools: &Driver,
    target: &Target,
    name: &str,
    kind: &str,
    source: &Path,
    output: &Path,
) -> Command {
    let mut command = Command::new(&tools.rustc);
    command.args([
        "--edition",
        "2024",
        "--target",
        target.triple,
        "--crate-name",
        name,
        "--crate-type",
        kind,
        "-C",
        "panic=abort",
        "-C",
        "no-redzone=yes",
        "-C",
        "opt-level=2",
        "-D",
        "warnings",
    ]);
    if let Some(sysroot) = &tools.sysroot {
        command.arg("--sysroot").arg(sysroot);
    }
    command.arg(source).arg("-o").arg(output);
    command
}

fn render_inf(template: &str, target: &Target) -> Result<String> {
    const MARKER: &str = "@ARCH@";
    let mut sections = template
        .lines()
        .filter(|line| line.starts_with("[DefaultInstall"));
    if sections.next() != Some("[DefaultInstall.NT@ARCH@]")
        || sections.next() != Some("[DefaultInstall.NT@ARCH@.Services]")
        || sections.next().is_some()
        || template.matches(MARKER).count() != 2
    {
        return Err(
            invalid("driver INF must declare exactly one target-decorated install pair").into(),
        );
    }
    Ok(template.replace(MARKER, target.inf_arch))
}

fn assignment(name: &str, path: &Path) -> Result<String> {
    Ok(format!("{name}={}", sdk::utf8(path)?))
}

fn rust_sources(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = entry.path();
        if kind.is_dir() {
            rust_sources(&path, paths)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            if !kind.is_file() {
                return Err(invalid(format!(
                    "expected a regular Rust source: {}",
                    path.display()
                ))
                .into());
            }
            paths.push(path);
        }
    }
    Ok(())
}

fn records(paths: &[PathBuf]) -> Result<Vec<Value>> {
    paths.iter().map(|path| receipt::file(path)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn package_targets_only_the_linked_machine() -> Result<()> {
        let template =
            include_str!("../../../platform/windows/wfp-driver/package/gnunet-wfp-driver.inf.in");
        for (triple, install, foreign) in [
            ("x86_64-pc-windows-msvc", "amd64", "arm64"),
            ("aarch64-pc-windows-msvc", "arm64", "amd64"),
        ] {
            let target = Target::parse(OsStr::new(triple))?;
            let inf = render_inf(template, target)?;
            assert!(inf.contains(&format!("[DefaultInstall.NT{install}]")));
            assert!(inf.contains(&format!("[DefaultInstall.NT{install}.Services]")));
            assert!(!inf.contains(&format!("[DefaultInstall.NT{foreign}")));
        }
        Ok(())
    }
}
