//! Official weak presence observations over actual caller-owned local endpoints.
#![cfg(any(unix, windows))]
#![forbid(unsafe_code)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify externally observable native presence and no-wake behavior"
)]
use gnunet_client_host::presence::{ServicePresence, test};
use gnunet_config::Configuration;
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> io::Result<Self> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "gp-{}-{stamp:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory)?;
        Ok(Self {
            path: directory.join("é.sock"),
            directory,
        })
    }
    fn configuration(&self) -> Result<Configuration, Box<dyn std::error::Error>> {
        let mut config = Configuration::default();
        let name = self
            .path
            .to_str()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        config.set_value(b"service", b"UNIXPATH", Some(name.as_bytes()))?;
        Ok(config)
    }
    fn listen(&self) -> io::Result<Socket> {
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.bind(&SockAddr::unix(&self.path)?)?;
        socket.listen(5)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _node = fs::remove_file(&self.path);
        let _directory = fs::remove_dir(&self.directory);
    }
}
#[test]
fn arm_managed_endpoint_is_not_connected_and_noarmbind_enables_actual_probe() -> Test {
    let fixture = Fixture::new()?;
    let socket = fixture.listen()?;
    let mut config = fixture.configuration()?;
    config.set_value(b"service", b"START_ON_DEMAND", Some(b"YES"))?;
    assert_eq!(test(&config, b"service")?, ServicePresence::LikelyUp);
    assert_eq!(
        socket.accept().err().map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    config.set_value(b"service", b"IMMEDIATE_START", Some(b"YES"))?;
    config.set_value(b"service", b"NOARMBIND", Some(b"YES"))?;
    assert_eq!(test(&config, b"service")?, ServicePresence::LikelyUp);
    drop(socket.accept()?);
    Ok(())
}
#[test]
fn missing_and_closed_local_nodes_are_down_without_a_tcp_alternative() -> Test {
    let fixture = Fixture::new()?;
    let config = fixture.configuration()?;
    assert_eq!(test(&config, b"service")?, ServicePresence::Down);
    let socket = fixture.listen()?;
    assert_eq!(test(&config, b"service")?, ServicePresence::LikelyUp);
    drop(socket.accept()?);
    drop(socket);
    assert_eq!(test(&config, b"service")?, ServicePresence::Down);
    Ok(())
}
#[test]
fn arm_existence_is_weak_and_invalid_tcp_configuration_is_an_error() -> Test {
    let fixture = Fixture::new()?;
    fs::write(&fixture.path, b"marker")?;
    let mut config = fixture.configuration()?;
    config.set_value(b"service", b"START_ON_DEMAND", Some(b"YES"))?;
    assert_eq!(test(&config, b"service")?, ServicePresence::LikelyUp);
    fs::remove_file(&fixture.path)?;
    config.set_number(b"service", b"PORT", 0)?;
    assert!(test(&config, b"service").is_err());
    config.set_number(b"service", b"PORT", 65536)?;
    assert!(test(&config, b"service").is_err());
    config.set_value(b"service", b"UNIXPATH", Some(b""))?;
    // Official filename expansion makes an empty configured filename the
    // current directory; ARM's existence-only observation therefore wins.
    assert_eq!(test(&config, b"service")?, ServicePresence::LikelyUp);
    Ok(())
}
