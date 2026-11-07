//! Current public Listener/Connection observation on owned numeric TCP only.
#![forbid(unsafe_code)]
use gnunet_service_runtime::connection::Connection;
use gnunet_service_runtime::service::{Listener, PeerAddress};
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::{
    error::Error,
    future::poll_fn,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsFd, AsRawFd},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
use tokio::io::AsyncReadExt;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn options(fd: &impl AsFd, inspector: &Path) -> Result<String> {
    let socket = SockRef::from(fd);
    let delay = socket.tcp_nodelay()?;
    let nonblocking =
        OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?).contains(OFlag::O_NONBLOCK);
    let cloexec =
        FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD)?).contains(FdFlag::FD_CLOEXEC);
    let linger = socket.linger()?;
    // Only a duplicate is transferred to the independent read-only C query child;
    // original descriptors/options/parent flags remain owned and unchanged here.
    let duplicate = fd.as_fd().try_clone_to_owned()?;
    let query = Command::new(inspector)
        .arg("--inspect")
        .stdin(Stdio::from(duplicate))
        .output()?;
    if !query.status.success() {
        return Err(io::Error::other("read-only native option query child failed").into());
    }
    let query = String::from_utf8(query.stdout)?;
    let query = query.trim();
    let seconds = linger.map_or(0, |duration| duration.as_secs());
    Ok(format!(
        "{{\"nodelay\":{},\"nonblocking\":{},\"cloexec\":{},\"keepalive\":{},\"reuseaddr\":{},\"type\":{},\"linger_on\":{},\"linger_seconds\":{},\"native_readonly_duplicate\":{query}}}",
        u8::from(delay),
        u8::from(nonblocking),
        u8::from(cloexec),
        u8::from(socket.keepalive()?),
        u8::from(socket.reuse_address()?),
        i32::from(socket.r#type()?),
        u8::from(linger.is_some()),
        seconds
    ))
}
async fn run(family: &str, preset: &str, mode: &str, inspector: &Path) -> Result<()> {
    let address = match family {
        "v4" => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "v6" => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        _ => return Err("family must be v4/v6".into()),
    };
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    match preset {
        "default" => {}
        "off" => {
            socket.set_tcp_nodelay(false)?;
            #[cfg(target_os = "macos")]
            socket.set_nosigpipe(false)?;
        }
        "on" => {
            socket.set_tcp_nodelay(true)?;
            #[cfg(target_os = "macos")]
            socket.set_nosigpipe(true)?;
        }
        _ => return Err("preset must be default/off/on".into()),
    }
    socket.bind(&address.into())?;
    socket.listen(5)?;
    let listener = tokio::net::TcpListener::from_std(socket.into())?;
    let address = listener.local_addr()?;
    let before = options(&listener, inspector)?;
    let mut client = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    let (mut accepted, peer, raw_before) = match mode {
        "canonical" => {
            let accepted = tokio::time::timeout(
                Duration::from_secs(2),
                poll_fn(|cx| Listener::Tcp(&listener).poll_canonical_connection(cx)),
            )
            .await??;
            if !accepted.diagnostics().is_empty() {
                return Err("unexpected actual native init diagnostic".into());
            }
            let (connection, peer, _diagnostics) = accepted.into_parts();
            (connection, peer, None)
        }
        "poll" => {
            let (connection, peer) = tokio::time::timeout(
                Duration::from_secs(2),
                poll_fn(|cx| Listener::Tcp(&listener).poll_connection(cx)),
            )
            .await??;
            (connection, peer, None)
        }
        "wrapper" => {
            let (stream, peer) =
                tokio::time::timeout(Duration::from_secs(2), listener.accept()).await??;
            let raw = options(&stream, inspector)?;
            (
                Connection::from_tcp(stream),
                PeerAddress::Tcp(peer),
                Some(raw),
            )
        }
        _ => return Err("mode must be canonical/poll/wrapper".into()),
    };
    if !matches!(peer,PeerAddress::Tcp(a)if a.ip().is_loopback()) {
        return Err("non-loopback accepted peer".into());
    }
    let after = options(&accepted, inspector)?;
    client.write_all(b"q")?;
    let mut payload = [0];
    tokio::time::timeout(Duration::from_secs(2), accepted.read_exact(&mut payload)).await??;
    if payload != *b"q" {
        return Err("actual payload mismatch".into());
    }
    let raw = raw_before.unwrap_or_else(|| "null".into());
    writeln!(
        io::stdout().lock(),
        "{{\"actor\":\"rust-public\",\"family\":\"{family}\",\"preset\":\"{preset}\",\"accept_mode\":\"{mode}\",\"listener\":{before},\"accepted_fd\":{},\"fd_setsize\":{},\"before_wrapper\":{raw},\"accepted\":{after},\"actual_payload\":true}}",
        accepted.as_fd().as_raw_fd(),
        libc::FD_SETSIZE
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("FAMILY PRESET MODE INSPECTOR required".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(&args[0], &args[1], &args[2], Path::new(&args[3])))
}
