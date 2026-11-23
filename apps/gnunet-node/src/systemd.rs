//! Readiness and stop notifications from the original process.
use std::{
    env,
    ffi::OsStr,
    io,
    os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixDatagram},
        },
    },
};

pub(super) struct Notify(UnixDatagram);

impl Notify {
    pub(super) fn from_environment() -> io::Result<Self> {
        let address = env::var_os("NOTIFY_SOCKET").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "--systemd requires NOTIFY_SOCKET")
        })?;
        Self::connect(&manager_address(&address)?)
    }

    fn connect(address: &SocketAddr) -> io::Result<Self> {
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        socket.connect_addr(address)?;
        Ok(Self(socket))
    }

    pub(super) fn ready(&self) -> io::Result<()> {
        self.send(b"READY=1")
    }

    pub(super) fn stopping(&self) -> io::Result<()> {
        self.send(b"STOPPING=1")
    }

    fn send(&self, state: &[u8]) -> io::Result<()> {
        if self.0.send(state)? == state.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial systemd notification",
            ))
        }
    }
}

fn manager_address(value: &OsStr) -> io::Result<SocketAddr> {
    match value.as_bytes() {
        [b'/', ..] => SocketAddr::from_pathname(value),
        [b'@', name @ ..] if !name.is_empty() => SocketAddr::from_abstract_name(name),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET requires an absolute path or a Linux abstract name",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert the exact datagrams and accepted address forms"
    )]
    fn sends_lifecycle_notifications_to_the_original_socket() -> io::Result<()> {
        let name = format!("@gnunet-node-notify-{}", std::process::id());
        let address = manager_address(OsStr::new(&name))?;
        let receiver = UnixDatagram::bind_addr(&address)?;
        receiver.set_read_timeout(Some(Duration::from_secs(1)))?;
        let notify = Notify::connect(&address)?;
        notify.ready()?;
        notify.stopping()?;

        let mut buffer = [0; 16];
        for expected in [b"READY=1".as_slice(), b"STOPPING=1".as_slice()] {
            let count = receiver.recv(&mut buffer)?;
            assert_eq!(&buffer[..count], expected);
        }
        assert!(
            manager_address(OsStr::new("/run/systemd/notify"))?
                .as_pathname()
                .is_some()
        );
        assert!(manager_address(OsStr::new("relative-path")).is_err());
        assert!(manager_address(OsStr::new("@")).is_err());
        Ok(())
    }
}
