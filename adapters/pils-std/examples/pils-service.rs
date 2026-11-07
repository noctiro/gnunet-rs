//! Controlled foreground embedding of the real Rust PILS host for C acceptance.
//! The production node owns shared configuration, listener policy and lifecycle.
use gnunet_pils::{Profile, Service};
use gnunet_pils_host::{Host, Limits, identity::load_or_create};
use std::{
    io::{self, BufRead, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let socket = PathBuf::from(args.next().ok_or("missing socket path")?);
    let key = PathBuf::from(args.next().ok_or("missing key path")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let (master, _lease) = load_or_create(&key)?;
    let hello_limits = gnunet_hello_limits();
    let service = Service::<65535>::new(master, Profile::Reference029, now()?, hello_limits)?;
    let listener = UnixListener::bind(&socket)?;
    let _path = OwnedPath(socket);
    let mut host = Host::new(
        listener,
        service,
        Limits {
            clients: 64,
            receive_bytes: 65535,
            transmit_bytes: 262140,
            accepts_per_step: 8,
            address_bytes: 65535,
        },
    )?;
    let (tx, rx) = mpsc::channel();
    let _stdin_thread = std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            if matches!(line.as_deref(), Ok("quit")) {
                let _sent = tx.send(());
                break;
            }
        }
    });
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "READY")?;
    stdout.flush()?;
    loop {
        if matches!(
            rx.try_recv(),
            Ok(()) | Err(mpsc::TryRecvError::Disconnected)
        ) {
            break;
        }
        host.poll_once(now()?)?;
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(host);
    writeln!(stdout, "STOPPED")?;
    stdout.flush()?;
    Ok(())
}
fn now() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_micros()
        .min(u64::MAX as u128) as u64)
}
fn gnunet_hello_limits() -> gnunet_pils::HelloLimits {
    gnunet_pils::HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 65535,
        maximum_addresses: 4096,
    }
}
struct OwnedPath(PathBuf);
impl Drop for OwnedPath {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}
