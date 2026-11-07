//! Independent native-header ABI probes. Artifacts stay under target/.
use std::{io, path::Path, process::Command};
pub(crate) fn check(source: &str, values: &[u64]) -> io::Result<()> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = manifest.join("../../target/native-abi");
    std::fs::create_dir_all(&output)?;
    let stem = Path::new(source)
        .file_stem()
        .ok_or(io::ErrorKind::InvalidInput)?;
    let binary = output.join(format!("{}-{}", stem.to_string_lossy(), std::process::id()));
    let compiler = Command::new("cc")
        .args(["-std=gnu11", "-Wall", "-Werror"])
        .arg(manifest.join("tests").join(source))
        .arg("-o")
        .arg(&binary)
        .output()?;
    std::fs::write(binary.with_extension("compiler.log"), &compiler.stderr)?;
    if !compiler.status.success() {
        return Err(io::Error::other(format!(
            "native ABI {source} compiler {}: {}",
            compiler.status,
            String::from_utf8_lossy(&compiler.stderr)
        )));
    }
    let probe = Command::new(&binary).output()?;
    if !probe.status.success() {
        return Err(io::Error::other(format!(
            "native ABI {source} probe: {}",
            probe.status
        )));
    }
    let actual = String::from_utf8(probe.stdout).map_err(io::Error::other)?;
    let expected = values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(" ")
        + "\n";
    if actual != expected {
        return Err(io::Error::other(format!(
            "native ABI {source}: expected {expected:?}, got {actual:?}"
        )));
    }
    Ok(())
}
