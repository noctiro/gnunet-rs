//! Installed Rust peer for the official TESTING command-helper protocol.
use std::{
    io::{self, Write},
    process::ExitCode,
};

#[cfg(target_os = "linux")]
#[path = "gnunet-cmds-helper/icmp.rs"]
mod icmp;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _report = writeln!(io::stderr().lock(), "gnunet-cmds-helper: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err("the installed netjail helper requires Linux".into())
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use gnunet_testbed_host::testing::peer;
    use std::{os::fd::AsFd, time::Duration};
    use tokio::{net::unix::pipe, time::Instant};

    let mut args = std::env::args_os().skip(1);
    let identity = args.next().ok_or("expected a TESTING node ID")?;
    if args.next().is_some() {
        return Err("expected one TESTING node ID".into());
    }
    let identity = identity.to_str().ok_or("invalid TESTING node ID")?;
    let (launcher, node) = identity
        .strip_prefix("if")
        .and_then(|value| value.split_once('-'))
        .ok_or("invalid TESTING node ID")?;
    if launcher.len() != 6 || node.len() != 6 || u32::from_str_radix(launcher, 16)? == 0 {
        return Err("invalid TESTING node ID".into());
    }
    let node = usize::from_str_radix(node, 16)?;
    let input = io::stdin().as_fd().try_clone_to_owned()?;
    let output = io::stdout().as_fd().try_clone_to_owned()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let input = pipe::Receiver::from_owned_fd(input)?;
        let output = pipe::Sender::from_owned_fd(output)?;
        peer::serve(input, output, |topology| {
            let node = topology.nodes().get(node).filter(|node| node.role().is_peer())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "node ID does not identify a topology peer"))?;
            let mut program = peer::Program::new();
            match node.testbed_plugin() {
                b"libgnunet_test_testing_plugin_ping" | b"ping" => {
                    program.run(icmp::echo())?;
                }
                _ => return Err(io::Error::new(io::ErrorKind::Unsupported, "unknown installed TESTING program; supply its executable helper to the launcher")),
            }
            Ok(program)
        }, Instant::now() + Duration::from_secs(600)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
