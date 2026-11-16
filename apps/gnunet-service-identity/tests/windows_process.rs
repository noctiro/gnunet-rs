//! Normal Windows IDENTITY startup, private IPC and marked-store restart.
#![cfg(windows)]
use gnunet_native::process::{LaunchLimits, Stdio};
use gnunet_service_runtime::{
    Activation,
    local::Stream,
    process::{ChildRegistry, OriginalChild},
};
use gnunet_service_startup::daemon::{self, Reexec};
use gnunet_wire::official::identity::{KeyType, Request, Response, SecretKeyView};
use socket2::Socket;
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fs,
    future::poll_fn,
    io,
    net::{Ipv4Addr, TcpListener},
    path::PathBuf,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

type Failure = Box<dyn Error>;
type Result<T> = std::result::Result<T, Failure>;

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce)?;
        let path =
            std::env::temp_dir().join(format!("gn-identity-{:032x}", u128::from_be_bytes(nonce)));
        fs::create_dir(&path)?;
        fs::create_dir(path.join("config.d"))?;
        fs::write(
            path.join("service.conf"),
            format!(
                "[identity]\nUNIXPATH = {}\n\nUNIX_MATCH_UID = NO\nUNIX_MATCH_GID = NO\n[identity-rust]\nDIRECTORY = {}\n",
                path.join("ipc").display(),
                path.join("store").display(),
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

async fn send(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    request: Request<'_>,
) -> Result<()> {
    let mut bytes = Zeroizing::new(vec![0; request.encoded_len()?]);
    request.encode(&mut bytes)?;
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn frame(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<Zeroizing<Vec<u8>>> {
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    let length = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if !(4..=128).contains(&length) {
        return Err("unexpected identity frame size".into());
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    bytes[..4].copy_from_slice(&head);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}

async fn exchange(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    restarted: bool,
) -> Result<()> {
    // Published structural fixture, never generated secret material.
    let mut mock = [0x42; 36];
    mock[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
    if !restarted {
        send(
            stream,
            Request::Create {
                name: b"alpha",
                key: SecretKeyView::new(&mock)?,
            },
        )
        .await?;
        assert!(matches!(
            Response::decode(&frame(stream).await?)?,
            Response::ResultCode { code: 0 }
        ));
    }
    send(stream, Request::Lookup { name: b"alpha" }).await?;
    match Response::decode(&frame(stream).await?)? {
        Response::Update {
            name: Some(b"alpha"),
            key,
        } => assert_eq!(key.expose_serialized(), &mock),
        _ => return Err("identity lookup did not restore original inventory".into()),
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
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_gnunet-service-identity"));
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
                argv0: OsStr::new("gnunet-service-identity"),
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
