//! Harmless exec child for local ARM launch ownership tests; no service is run.
#![deny(unsafe_code)]
use gnunet_service_startup::{InheritedMode, capture_from_environment};
use std::{
    io::{Read, Write},
    os::fd::AsFd,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    time::Duration,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    let mut output = None;
    let mut hold = 0u64;
    let mut markers = false;
    let mut early = false;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--output" {
            i += 1;
            output = args.get(i).map(PathBuf::from);
        } else if args[i] == "--hold-ms" {
            i += 1;
            hold = args
                .get(i)
                .and_then(|s| s.to_str())
                .ok_or("hold")?
                .parse()?;
        } else if args[i] == "--markers" {
            markers = true;
        } else if args[i] == "--release-before-wait" {
            early = true;
        }
        i += 1;
    }
    let output = output.ok_or("owned output")?;
    let stdio = [
        nix::sys::stat::fstat(std::io::stdin().as_fd())?,
        nix::sys::stat::fstat(std::io::stdout().as_fd())?,
        nix::sys::stat::fstat(std::io::stderr().as_fd())?,
    ];
    let names = std::env::var_os("LISTEN_FDNAMES");
    let control = std::env::var_os("GNUNET_OS_CONTROL_PIPE");
    #[expect(
        unsafe_code,
        reason = "This newly exec'd controlled child exclusively owns the launcher-transferred descriptors; capture precedes every file/runtime open and happens exactly once"
    )]
    // SAFETY: no FD owner has been constructed for the foreign set; no runtime,
    // file open or thread exists; this is the only early capture entrypoint.
    let mut captured =
        Some(unsafe { capture_from_environment(InheritedMode::CloseAfterConfiguredBind) }?);
    let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let argv = args
        .iter()
        .map(|s| format!("\"{}\"", hex(s.as_bytes())))
        .collect::<Vec<_>>()
        .join(",");
    let modes = stdio
        .iter()
        .map(|s| format!("{}", s.st_mode & libc::S_IFMT))
        .collect::<Vec<_>>()
        .join(",");
    let mut file = std::fs::File::create(output)?;
    writeln!(
        file,
        "{{\"event\":\"started\",\"pid\":{},\"argv\":[{}],\"stdio_types\":[{}],\"listen\":\"{}\",\"control\":\"{}\"}}",
        std::process::id(),
        argv,
        modes,
        hex(names.as_deref().unwrap_or_default().as_bytes()),
        hex(control.as_deref().unwrap_or_default().as_bytes())
    )?;
    file.flush()?;
    if markers {
        let mut b = [0; 3];
        let n = std::io::stdin().read(&mut b)?;
        writeln!(file, "{{\"stdin\":\"{}\"}}", hex(&b[..n]))?;
        writeln!(std::io::stdout(), "CHILD_STDOUT")?;
        writeln!(std::io::stderr(), "CHILD_STDERR")?;
    }
    if early {
        drop(captured.take());
        writeln!(file, "{{\"event\":\"released\"}}")?;
        file.flush()?;
    }
    std::thread::sleep(Duration::from_millis(hold));
    drop(captured);
    writeln!(file, "{{\"event\":\"released\"}}")?;
    Ok(())
}
