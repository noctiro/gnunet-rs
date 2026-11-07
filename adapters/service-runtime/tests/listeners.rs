//! Owned local endpoints exercise shared service-section and path lifetime rules.
#![forbid(unsafe_code)]
use gnunet_config::Configuration;
use gnunet_service_runtime::service::{Listener, ShutdownMode};
use gnunet_service_runtime::{
    ActivatedSocket, Activation, BoundListeners, CreatedPath, private_parents, service_options,
};
use socket2::SockRef;
use std::{
    error::Error,
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdTcpListener},
    os::unix::{
        ffi::OsStrExt,
        fs::{PermissionsExt, symlink},
        net::UnixListener as StdUnixListener,
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

macro_rules! verify {
    ($condition:expr $(,)?) => {
        if !$condition {
            return Err(io::Error::other(concat!(
                "check failed at ",
                file!(),
                ":",
                line!(),
                ": ",
                stringify!($condition)
            ))
            .into());
        }
    };
}
macro_rules! verify_eq {
    ($left:expr, $right:expr $(,)?) => {
        match (&$left, &$right) {
            (left, right) => {
                if left != right {
                    return Err(io::Error::other(format!(
                        "equality check failed at {}:{}: {:?} != {:?}",
                        file!(),
                        line!(),
                        left,
                        right
                    ))
                    .into());
                }
            }
        }
    };
}
macro_rules! verify_ne {
    ($left:expr, $right:expr $(,)?) => {
        match (&$left, &$right) {
            (left, right) => {
                if left == right {
                    return Err(io::Error::other(format!(
                        "inequality check failed at {}:{}: {:?}",
                        file!(),
                        line!(),
                        left
                    ))
                    .into());
                }
            }
        }
    };
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "gn-service-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
fn set(
    c: &mut Configuration,
    section: &[u8],
    key: &[u8],
    value: &[u8],
) -> Result<(), Box<dyn Error>> {
    c.set_value(section, key, Some(value))?;
    Ok(())
}
fn unix_config(section: &[u8], path: &Path) -> Result<Configuration, Box<dyn Error>> {
    let mut c = Configuration::default();
    set(&mut c, section, b"UNIXPATH", path.as_os_str().as_bytes())?;
    c.set_number(section, b"PORT", 0)?;
    Ok(c)
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn free_v4_port() -> io::Result<u16> {
    let socket = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(socket.local_addr()?.port())
}

#[test]
fn explicit_sections_keep_bind_paths_and_cleanup_separate() -> Result<(), Box<dyn Error>> {
    let own = OwnedDirectory::new()?;
    let stats = own.join("statistics.sock");
    let resolver = own.join("resolver.sock");
    let mut c = unix_config(b"statistics", &stats)?;
    set(
        &mut c,
        b"resolver",
        b"UNIXPATH",
        resolver.as_os_str().as_bytes(),
    )?;
    runtime()?.block_on(async {
        let first = BoundListeners::bind(&c, b"STATISTICS", Activation::default()).await?;
        let second = BoundListeners::bind(&c, b"resolver", Activation::default()).await?;
        verify_eq!(
            first.unix_paths().collect::<Vec<_>>(),
            vec![stats.as_path()]
        );
        verify_eq!(
            second.unix_paths().collect::<Vec<_>>(),
            vec![resolver.as_path()]
        );
        verify!(stats.exists() && resolver.exists());
        drop(first);
        verify!(!stats.exists() && resolver.exists());
        let rebound = BoundListeners::bind(&c, b"statistics", Activation::default()).await?;
        drop(rebound);
        drop(second);
        verify!(!stats.exists() && !resolver.exists());
        Ok(())
    })
}
#[test]
fn private_parents_preserve_existing_modes_and_create_private_children()
-> Result<(), Box<dyn Error>> {
    let own = OwnedDirectory::new()?;
    fs::set_permissions(&own.0, fs::Permissions::from_mode(0o750))?;
    let path = own.join("a/b/service.sock");
    private_parents(&path)?;
    verify_eq!(fs::metadata(&own.0)?.permissions().mode() & 0o777, 0o750);
    verify_eq!(
        fs::metadata(own.join("a"))?.permissions().mode() & 0o777,
        0o700
    );
    verify_eq!(
        fs::metadata(own.join("a/b"))?.permissions().mode() & 0o777,
        0o700
    );
    Ok(())
}
#[test]
fn successful_unix_bind_has_private_mode_and_drop_closes_before_unlink()
-> Result<(), Box<dyn Error>> {
    let own = OwnedDirectory::new()?;
    let path = own.join("a/b/service.sock");
    let c = unix_config(b"resolver", &path)?;
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&c, b"resolver", Activation::default()).await?;
        verify_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o700);
        let client = tokio::net::UnixStream::connect(&path).await?;
        let listeners = bound.listeners();
        verify!(matches!(listeners[0], Listener::Unix(_)));
        if let Listener::Unix(listener) = listeners[0] {
            let accepted = listener.accept().await?;
            drop(accepted);
        }
        drop(client);
        drop(listeners);
        drop(bound);
        verify!(!path.exists());
        let again = StdUnixListener::bind(&path)?;
        drop(again);
        fs::remove_file(&path)?;
        Ok(())
    })
}
#[test]
fn closed_stale_socket_is_reclaimed() -> Result<(), Box<dyn Error>> {
    let own = OwnedDirectory::new()?;
    let path = own.join("stale.sock");
    drop(StdUnixListener::bind(&path)?);
    let c = unix_config(b"service", &path)?;
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&c, b"service", Activation::default()).await?;
        verify!(path.exists());
        drop(bound);
        verify!(!path.exists());
        Ok(())
    })
}
#[test]
fn live_socket_is_not_removed_after_probe() -> Result<(), Box<dyn Error>> {
    let own = OwnedDirectory::new()?;
    let path = own.join("live.sock");
    let existing = StdUnixListener::bind(&path)?;
    let c = unix_config(b"service", &path)?;
    runtime()?.block_on(async {
        verify!(
            BoundListeners::bind(&c, b"service", Activation::default())
                .await
                .is_err()
        );
        verify!(path.exists());
        Ok::<(), Box<dyn Error>>(())
    })?;
    existing.set_nonblocking(true)?;
    verify!(existing.accept().is_ok());
    drop(existing);
    Ok(())
}
#[test]
fn ordinary_file_and_symlink_are_never_removed() -> Result<(), Box<dyn Error>> {
    let own = OwnedDirectory::new()?;
    let target = own.join("file");
    fs::write(&target, b"unchanged")?;
    let alias = own.join("alias");
    symlink(&target, &alias)?;
    runtime()?.block_on(async {
        for path in [&target, &alias] {
            let c = unix_config(b"service", path)?;
            verify!(
                BoundListeners::bind(&c, b"service", Activation::default())
                    .await
                    .is_err()
            );
            verify_eq!(fs::read(&target)?, b"unchanged");
            verify!(fs::symlink_metadata(&alias)?.file_type().is_symlink());
        }
        Ok(())
    })
}
#[test]
fn inode_guard_leaves_replacement_and_explicit_remove_is_idempotent() -> Result<(), Box<dyn Error>>
{
    let own = OwnedDirectory::new()?;
    let path = own.join("owned");
    let old = fs::File::create(&path)?;
    let guard = CreatedPath::capture(path.clone())?;
    verify_eq!(guard.path(), path);
    fs::remove_file(&path)?;
    fs::write(&path, b"replacement")?;
    guard.remove()?;
    drop(guard);
    verify_eq!(fs::read(&path)?, b"replacement");
    drop(old);
    let guard = CreatedPath::capture(path.clone())?;
    guard.remove()?;
    guard.remove()?;
    drop(guard);
    verify!(!path.exists());
    Ok(())
}
#[test]
fn bound_unix_guard_leaves_replacement_inode_after_listener_drop() -> Result<(), Box<dyn Error>> {
    let own = OwnedDirectory::new()?;
    let path = own.join("service.sock");
    let c = unix_config(b"service", &path)?;
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&c, b"service", Activation::default()).await?;
        fs::remove_file(&path)?;
        fs::write(&path, b"replacement")?;
        drop(bound);
        verify_eq!(fs::read(&path)?, b"replacement");
        Ok(())
    })
}
#[test]
fn inherited_listeners_bypass_addresses_and_never_unlink_paths() -> Result<(), Box<dyn Error>> {
    let own = OwnedDirectory::new()?;
    let inherited = own.join("inherited.sock");
    let configured = own.join("unused.sock");
    let listener = StdUnixListener::bind(&inherited)?;
    let mut c = unix_config(b"resolver", &configured)?;
    c.set_number(b"resolver", b"PORT", 65536)?;
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(
            &c,
            b"resolver",
            Activation {
                sockets: vec![ActivatedSocket::Unix(listener)],
            },
        )
        .await?;
        verify_eq!(bound.listeners().len(), 1);
        verify_eq!(bound.unix_paths().count(), 0);
        verify!(bound.failures().is_empty());
        verify!(!configured.exists());
        drop(bound);
        verify!(inherited.exists());
        Ok(())
    })
}
#[test]
fn ipv4_bind_is_tcp_reusable_and_accepts_loopback() -> Result<(), Box<dyn Error>> {
    let mut c = Configuration::default();
    c.set_number(b"resolver", b"PORT", u64::from(free_v4_port()?))?;
    set(&mut c, b"resolver", b"BINDTO", b"127.0.0.1")?;
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&c, b"resolver", Activation::default()).await?;
        verify_eq!(bound.listeners().len(), 1);
        if let Listener::Tcp(listener) = bound.listeners()[0] {
            verify!(SockRef::from(listener).reuse_address()?);
            verify!(listener.local_addr()?.is_ipv4());
            let client = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
            let accepted = listener.accept().await?;
            drop(accepted);
            drop(client);
        }
        Ok(())
    })
}
#[test]
fn ipv6_listener_is_v6only_and_disable6_filters_explicit_bindto() -> Result<(), Box<dyn Error>> {
    let probe = StdTcpListener::bind((Ipv6Addr::LOCALHOST, 0))?;
    let port = probe.local_addr()?.port();
    drop(probe);
    let mut c = Configuration::default();
    c.set_number(b"service", b"PORT", u64::from(port))?;
    set(&mut c, b"service", b"BINDTO", b"::1")?;
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&c, b"service", Activation::default()).await?;
        if let Listener::Tcp(listener) = bound.listeners()[0] {
            verify!(SockRef::from(listener).only_v6()?);
            let client = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
            let accepted = listener.accept().await?;
            drop(accepted);
            drop(client);
        }
        drop(bound);
        set(&mut c, b"service", b"DISABLEV6", b"YES")?;
        verify!(
            BoundListeners::bind(&c, b"service", Activation::default())
                .await
                .is_err()
        );
        Ok(())
    })
}
#[test]
fn partial_endpoint_failure_is_retained_without_owning_foreign_path() -> Result<(), Box<dyn Error>>
{
    let own = OwnedDirectory::new()?;
    let path = own.join("foreign.sock");
    let foreign = StdUnixListener::bind(&path)?;
    let mut c = unix_config(b"resolver", &path)?;
    c.set_number(b"resolver", b"PORT", u64::from(free_v4_port()?))?;
    set(&mut c, b"resolver", b"BINDTO", b"127.0.0.1")?;
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&c, b"resolver", Activation::default()).await?;
        verify_eq!(bound.listeners().len(), 1);
        verify_eq!(bound.failures().len(), 1);
        verify_eq!(bound.unix_paths().count(), 0);
        verify_eq!(bound.failures()[0].kind(), io::ErrorKind::AddrInUse);
        drop(bound);
        verify!(path.exists());
        Ok::<(), Box<dyn Error>>(())
    })?;
    drop(foreign);
    Ok(())
}
#[test]
fn absent_port_overflow_and_bad_bindto_are_actual_errors() -> Result<(), Box<dyn Error>> {
    runtime()?.block_on(async {
        let mut c = Configuration::default();
        verify!(
            BoundListeners::bind(&c, b"resolver", Activation::default())
                .await
                .is_err()
        );
        c.set_number(b"resolver", b"PORT", 65536)?;
        verify!(
            BoundListeners::bind(&c, b"resolver", Activation::default())
                .await
                .is_err()
        );
        c.set_number(b"resolver", b"PORT", 12345)?;
        set(&mut c, b"resolver", b"BINDTO", b"\xff")?;
        verify!(
            BoundListeners::bind(&c, b"resolver", Activation::default())
                .await
                .is_err()
        );
        Ok(())
    })
}
#[test]
fn service_options_use_the_requested_acl_and_tolerant_section() -> Result<(), Box<dyn Error>> {
    let mut c = Configuration::default();
    set(&mut c, b"statistics", b"ACCEPT_FROM", b"127.0.0.1;")?;
    set(&mut c, b"statistics", b"TOLERANT", b"YES")?;
    set(&mut c, b"resolver", b"REJECT_FROM", b"127.0.0.1;")?;
    set(&mut c, b"resolver", b"TOLERANT", b"NO")?;
    let stats = service_options(&c, b"statistics", ShutdownMode::Soft)?;
    let resolver = service_options(&c, b"resolver", ShutdownMode::Immediate)?;
    let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
    verify!(stats.tolerant && stats.access.allows(local));
    verify!(!resolver.tolerant && !resolver.access.allows(local));
    verify_eq!(stats.shutdown, ShutdownMode::Soft);
    verify_eq!(resolver.shutdown, ShutdownMode::Immediate);
    set(&mut c, b"resolver", b"ACCEPT_FROM6", b"::1;")?;
    let resolver = service_options(&c, b"resolver", ShutdownMode::Soft)?;
    verify!(resolver.access.allows(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    set(&mut c, b"resolver", b"TOLERANT", b"invalid")?;
    verify!(service_options(&c, b"resolver", ShutdownMode::Soft).is_err());
    set(&mut c, b"resolver", b"TOLERANT", b"NO")?;
    set(&mut c, b"resolver", b"ACCEPT_FROM", b"malformed")?;
    verify!(service_options(&c, b"resolver", ShutdownMode::Soft).is_err());
    Ok(())
}
#[test]
fn long_unix_path_uses_the_existing_official_shortening_algorithm() -> Result<(), Box<dyn Error>> {
    let own = OwnedDirectory::new()?;
    let path = own.join(&format!("{}-service.sock", "a".repeat(130)));
    let c = unix_config(b"service", &path)?;
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&c, b"service", Activation::default()).await?;
        let actual = bound
            .unix_paths()
            .next()
            .ok_or("missing shortened path")?
            .to_path_buf();
        verify_ne!(actual, path);
        verify!(!path.exists());
        verify!(actual.exists());
        drop(bound);
        verify!(!actual.exists());
        Ok(())
    })
}
#[test]
fn inherited_tcp_is_converted_and_accepted_without_config_endpoint() -> Result<(), Box<dyn Error>> {
    let native = StdTcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))?;
    let address = native.local_addr()?;
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(
            &Configuration::default(),
            b"arbitrary-service",
            Activation {
                sockets: vec![ActivatedSocket::Tcp(native)],
            },
        )
        .await?;
        verify_eq!(bound.unix_paths().count(), 0);
        let client = tokio::net::TcpStream::connect(address).await?;
        if let Listener::Tcp(listener) = bound.listeners()[0] {
            let accepted = listener.accept().await?;
            drop(accepted);
        }
        drop(client);
        drop(bound);
        verify!(tokio::net::TcpStream::connect(address).await.is_err());
        Ok(())
    })
}
