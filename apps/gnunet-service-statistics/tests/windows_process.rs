//! Normal Windows service startup, private transport and official snapshot restart.
#![cfg(windows)]
use gnunet_native::process::{LaunchLimits, Stdio};
use gnunet_service_runtime::{
    Activation,
    local::Stream,
    process::{ChildRegistry, OriginalChild},
};
use gnunet_service_startup::daemon::{self, Reexec};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fs,
    future::poll_fn,
    io,
    net::{Ipv4Addr, TcpListener},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type Failure = Box<dyn Error>;
type Result<T> = std::result::Result<T, Failure>;
const PERSISTENT: &[u8] = b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x09s\0p\0";

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gn-stats-{}-{nonce:x}", std::process::id()));
        fs::create_dir(&path)?;
        fs::create_dir(path.join("config.d"))?;
        fs::write(
            path.join("service.conf"),
            format!(
                "[statistics]\nUNIXPATH = {}\nDATABASE = {}\nUNIX_MATCH_UID = NO\nUNIX_MATCH_GID = NO\n",
                path.join("ipc").display(),
                path.join("values").display(),
            ),
        )?;
        Ok(Self(path))
    }
    fn environment(&self) -> Vec<(OsString, OsString)> {
        let mut values: Vec<_> = std::env::vars_os()
            .filter(|(key, _)| {
                !key.to_str().is_some_and(|key| {
                    let key = key.to_ascii_uppercase();
                    key.starts_with("GNUNET_") || key.starts_with("LISTEN_")
                })
            })
            .collect();
        values.push(("GNUNET_BASE_CONFIG".into(), self.0.join("config.d").into()));
        values
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

async fn exchange(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    restarted: bool,
) -> Result<()> {
    if !restarted {
        stream.write_all(PERSISTENT).await?;
        // Volatile values must be absent after the real service restarts.
        stream
            .write_all(b"\0\x14\0\xa8\0\0\0\0\0\0\0\0\0\0\0\x07s\0q\0")
            .await?;
        stream.write_all(b"\0\x04\0\xae").await?;
        let mut ack = [0; 4];
        stream.read_exact(&mut ack).await?;
        assert_eq!(&ack, b"\0\x04\0\xaf", "normal service barrier reply");
    } else {
        stream.write_all(b"\0\x06\0\xa9\0\0").await?;
        let mut values = [0; 24];
        stream.read_exact(&mut values).await?;
        assert_eq!(
            &values, b"\0\x14\0\xaa\x80\0\0\0\0\0\0\0\0\0\0\x09s\0p\0\0\x04\0\xab",
            "normal service restored an incorrect official snapshot",
        );
    }
    Ok(())
}

async fn restart(
    directory: &Directory,
    registry: &mut ChildRegistry,
    original: &mut Option<OriginalChild>,
    startup: &mut Option<daemon::Parent>,
    activated: bool,
) -> Result<()> {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gnunet-service-statistics"));
    let arguments = vec![
        OsString::from("-d"),
        OsString::from("-c"),
        directory.0.join("service.conf").into(),
    ];
    for attempt in 0..2 {
        let (activation, address) = if activated {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let address = listener.local_addr()?;
            (
                Activation::from_sockets(vec![Socket::from(listener)])?,
                Some(address),
            )
        } else {
            (Activation::default(), None)
        };
        let launched = daemon::launch(
            registry,
            Reexec {
                executable: &executable,
                argv0: OsStr::new("gnunet-service-statistics"),
                arguments: &arguments,
                environment: directory.environment(),
                directory: &directory.0,
                stderr: Stdio::Inherit,
                activation,
            },
            LaunchLimits::default(),
        );
        let parent = match launched {
            Ok(parent) => parent,
            Err(error) => {
                *original = error.child.clone();
                return Err(Box::new(error));
            }
        };
        *original = Some(parent.child().clone());
        *startup = Some(parent);
        let parent = startup.as_mut().ok_or("missing startup owner")?;
        let receipt = parent.wait().await?;
        assert_eq!(
            receipt.child(),
            parent.child(),
            "readiness changed child identity"
        );
        if let Some(address) = address {
            let mut stream = tokio::net::TcpStream::connect(address).await?;
            exchange(&mut stream, attempt != 0).await?;
        } else {
            let mut stream = Stream::connect(&directory.0.join("ipc")).await?;
            exchange(&mut stream, attempt != 0).await?;
        }
        let mut control = parent
            .take_control()
            .ok_or("missing original service control")?;
        control.begin(registry, 15)?;
        poll_fn(|cx| control.poll_send(cx)).await?;
        let mut exit = registry.exit_observer(parent.child())?;
        poll_fn(|cx| exit.poll_exit(cx)).await?;
        let reaped = registry
            .reap_child(parent.child())?
            .ok_or("missing actual service exit")?;
        *original = None;
        drop(startup.take());
        assert_eq!(reaped.exit_code, 0, "normal service shutdown failed");
        assert_eq!(fs::read(directory.0.join("values"))?, PERSISTENT);
        assert!(
            !gnunet_native::paths::exists(&directory.0.join("ipc"))?,
            "service retained its owned socket node"
        );
    }
    Ok(())
}

fn normal_restart(activated: bool) -> Result<()> {
    let directory = Directory::new()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut registry = ChildRegistry::new(1)?;
    let mut original = None;
    let mut startup = None;
    let result = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(20),
            restart(
                &directory,
                &mut registry,
                &mut original,
                &mut startup,
                activated,
            ),
        )
        .await
        .map_err(|error| Box::new(error) as Failure)?
    });
    // Keep any launch failure's activation/source owners in result until the
    // admitted original child is physically retired. Never reopen by PID.
    if let Some(child) = original {
        runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                daemon::retire_child(&mut registry, &child, 1),
            )
            .await??;
            Ok::<(), Failure>(())
        })?;
    }
    result
}

#[test]
fn configured_private_local_service_persists_and_restarts() -> Result<()> {
    normal_restart(false)
}

#[test]
fn activated_loopback_service_persists_and_restarts() -> Result<()> {
    normal_restart(true)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert refusal and unchanged native socket identity after an actual database load attempt"
)]
fn database_loading_refuses_an_actual_local_socket_node() -> Result<()> {
    use gnunet_statistics_store::{Limits, Stage, Store};
    let directory = Directory::new()?;
    let path = directory.0.join("ipc");
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.bind(&SockAddr::unix(&path)?)?;
    let mut node = gnunet_native::local_path::LocalPath::capture(path.clone())?;
    socket.listen(1)?;
    let store = Store::new(
        path.clone(),
        Limits {
            max_file_bytes: 1024,
            max_records: 8,
            max_frame_bytes: 64,
        },
    )?;
    let error = match store.load::<4, 32, 1, 2, 4>() {
        Ok(_) => return Err("AF_UNIX node was loaded as a database".into()),
        Err(error) => error,
    };
    assert_eq!(
        error.stage(),
        Stage::Inspect,
        "socket was opened as a database"
    );
    assert!(
        gnunet_native::local_path::is_socket(&path)?,
        "database load changed the endpoint"
    );
    drop(socket);
    node.remove()?;
    Ok(())
}
