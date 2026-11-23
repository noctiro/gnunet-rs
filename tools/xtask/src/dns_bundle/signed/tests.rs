use super::{Result, SignedApp};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn stage_signed_app_requires_matching_slice_and_native_signature() -> Result<()> {
    let scratch = std::env::temp_dir().join(format!(
        "gnunet-dns-package-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&scratch)?;
    let scratch = Scratch(scratch);
    let input = scratch.0.join("binary");
    let output = scratch.0.join("GNUnet DNS.app");
    let mut mach_header = [0u8; 32];
    mach_header[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    mach_header[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
    mach_header[12..16].copy_from_slice(&2u32.to_le_bytes());
    fs::write(&input, mach_header)?;
    let input = input.to_str().ok_or("invalid test input path")?;
    let output_text = output.to_str().ok_or("invalid test output path")?;
    super::super::app::bundle(
        &[
            "--control-binary",
            input,
            "--provider-binary",
            input,
            "--output",
            output_text,
            "--bundle-id",
            "org.example.gnunet",
            "--provider-id",
            "org.example.gnunet.dns-proxy",
            "--app-group",
            "ABCDE12345.org.example.gnunet",
        ]
        .map(str::to_owned),
    )?;
    for (target, expected) in [
        ("x86_64-apple-darwin", "lacks the x86_64 node slice"),
        ("aarch64-apple-darwin", "read app code signature"),
    ] {
        let problem = SignedApp::open(&output, target)
            .err()
            .ok_or("an unprepared DNS app was admitted for staging")?;
        if !problem.to_string().contains(expected) {
            return Err(format!("wrong signed app refusal for {target}: {problem}").into());
        }
    }
    Ok(())
}
