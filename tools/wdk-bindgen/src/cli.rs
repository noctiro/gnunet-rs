use crate::{Result, invalid, sdk::Target};
use std::{env, ffi::OsString, fs, path::PathBuf};

pub struct Inputs {
    pub target: &'static Target,
    pub sdk: PathBuf,
    pub clang: OsString,
    pub output: PathBuf,
    pub driver: Option<Driver>,
}

pub struct Driver {
    pub rustc: OsString,
    pub lld: OsString,
    pub sysroot: Option<PathBuf>,
}

pub fn parse() -> Result<Option<Inputs>> {
    let mut arguments = env::args_os().skip(1).peekable();
    let driver = arguments
        .next_if(|argument| argument == "build-driver")
        .is_some();
    let mut sdk = None;
    let mut target = None;
    let mut clang = None;
    let mut output = None;
    let mut rustc = None;
    let mut lld = None;
    let mut sysroot = None;
    while let Some(argument) = arguments.next() {
        if argument == "--help" {
            println!(
                "gnunet-wdk-bindgen --target TRIPLE --sdk-root ROOT --clang CLANG --out-dir NEW_TARGET_DIR"
            );
            println!(
                "gnunet-wdk-bindgen build-driver --target TRIPLE --sdk-root ROOT --clang CLANG --out-dir NEW_TARGET_DIR --lld RUST_LLD [--rustc RUSTC] [--rust-sysroot SYSROOT]"
            );
            return Ok(None);
        }
        let slot = match argument.to_str() {
            Some("--target") => &mut target,
            Some("--sdk-root") => &mut sdk,
            Some("--clang") => &mut clang,
            Some("--out-dir") => &mut output,
            Some("--rustc") if driver => &mut rustc,
            Some("--lld") if driver => &mut lld,
            Some("--rust-sysroot") if driver => &mut sysroot,
            _ => return Err(invalid(format!("unknown option: {argument:?}")).into()),
        };
        if slot.is_some() {
            return Err(invalid(format!("duplicate option: {argument:?}")).into());
        }
        *slot = Some(
            arguments
                .next()
                .ok_or_else(|| invalid("option requires a value"))?,
        );
    }
    let target = Target::parse(&target.ok_or_else(|| invalid("missing --target"))?)?;
    let sdk = PathBuf::from(sdk.ok_or_else(|| invalid("missing --sdk-root"))?).canonicalize()?;
    let clang = clang.ok_or_else(|| invalid("missing --clang"))?;
    let driver = if driver {
        Some(Driver {
            rustc: rustc.unwrap_or_else(|| "rustc".into()),
            lld: lld.ok_or_else(|| invalid("missing --lld (path to rust-lld)"))?,
            sysroot: sysroot
                .map(|path| PathBuf::from(path).canonicalize())
                .transpose()?,
        })
    } else {
        None
    };
    let output = PathBuf::from(output.ok_or_else(|| invalid("missing --out-dir"))?);
    let parent = output
        .parent()
        .ok_or_else(|| invalid("output needs an existing parent under repository target"))?
        .canonicalize()?;
    let artifact_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .canonicalize()?;
    if !parent.starts_with(artifact_root) {
        return Err(
            invalid("generated output must be beneath this repository's target directory").into(),
        );
    }
    let output = parent.join(
        output
            .file_name()
            .ok_or_else(|| invalid("invalid output directory"))?,
    );
    fs::create_dir(&output)?;
    Ok(Some(Inputs {
        target,
        sdk,
        clang,
        output,
        driver,
    }))
}
