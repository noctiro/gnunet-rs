//! Ordinary PROGRAM option exit through the actual native entry point.
#![cfg(any(unix, windows))]
#[test]
fn help_runs_the_native_program_without_starting_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_gnunet-auto-share"))
        .arg("--help")
        .env_remove("GNUNET_OS_CONTROL_PIPE")
        .env_remove("GNUNET_RS_DETACH_PIPE")
        .env_remove("GNUNET_RS_ACTIVATION_HANDLE")
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "native help failed: {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let text = std::str::from_utf8(&output.stdout)?;
    if !text.contains("gnunet-auto-share") || !text.contains("DIRECTORY") {
        return Err("native PROGRAM did not print its configured help".into());
    }
    Ok(())
}
