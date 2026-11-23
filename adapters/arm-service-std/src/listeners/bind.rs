//! Native socket preparation kept outside listener leases and service state.
use super::{ActivatedSocket, Address, CreatedPath, LocalListenerAccess, RegisteredListener};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;

pub(super) struct Bound {
    pub port: RegisteredListener,
    pub path: Option<CreatedPath>,
    pub address: Address,
}

pub(super) enum Access {
    Current(LocalListenerAccess),
    #[cfg(windows)]
    Account(Box<gnunet_service_runtime::local_listener::AccountBind>),
}

pub(super) async fn prepare(
    address: &Address,
    access: Access,
    warnings: &mut Vec<io::Error>,
) -> io::Result<Bound> {
    match address {
        Address::Unix(path) => {
            use gnunet_service_runtime::local_listener;
            let prepared = match access {
                Access::Current(access) => local_listener::prepare(path.clone(), access, 5).await?,
                #[cfg(windows)]
                Access::Account(bind) => bind.listen(5)?,
            };
            #[cfg(unix)]
            let (port, path, diagnostics) = {
                let (socket, path, diagnostics) = prepared.into_parts();
                (RegisteredListener::new(socket)?, path, diagnostics)
            };
            #[cfg(windows)]
            let (port, path, diagnostics) = RegisteredListener::from_prepared_local(prepared)?;
            warnings.extend(diagnostics);
            Ok(Bound {
                port,
                path: Some(path),
                address: address.clone(),
            })
        }
        Address::Tcp(address) => {
            let socket = Socket::new(
                Domain::for_address(*address),
                Type::STREAM,
                Some(Protocol::TCP),
            )?;
            #[cfg(unix)]
            if let Err(error) = socket.set_reuse_address(true) {
                warnings.push(error);
            }
            #[cfg(windows)]
            gnunet_native::network::set_exclusive_address_use(
                std::os::windows::io::AsSocket::as_socket(&socket),
            )?;
            if address.is_ipv6()
                && let Err(error) = socket.set_only_v6(true)
            {
                warnings.push(error);
            }
            socket.set_nonblocking(true)?;
            socket.bind(&SockAddr::from(*address))?;
            socket.listen(5)?;
            let actual = socket
                .local_addr()?
                .as_socket()
                .ok_or(io::ErrorKind::InvalidData)?;
            Ok(Bound {
                port: RegisteredListener::new(socket)?,
                path: None,
                address: Address::Tcp(actual),
            })
        }
        Address::Abstract(bytes) => {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::ffi::OsStrExt;
                if bytes.first() != Some(&0) {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
                socket.set_nonblocking(true)?;
                socket.bind(&SockAddr::unix(std::ffi::OsStr::from_bytes(bytes))?)?;
                socket.listen(5)?;
                Ok(Bound {
                    port: RegisteredListener::new(socket)?,
                    path: None,
                    address: address.clone(),
                })
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _linux_name = bytes;
                Err(io::ErrorKind::Unsupported.into())
            }
        }
    }
}

pub(super) fn adopt(socket: ActivatedSocket) -> io::Result<Bound> {
    let (port, address) = match socket {
        ActivatedSocket::Unix(socket) => {
            #[cfg(unix)]
            let address = {
                let native = socket.local_addr()?;
                let address = native
                    .as_pathname()
                    .map(|path| Address::Unix(path.to_owned()));
                #[cfg(target_os = "linux")]
                let address = address.or_else(|| {
                    use std::os::linux::net::SocketAddrExt;
                    let name = native.as_abstract_name()?;
                    let mut bytes = Vec::with_capacity(1 + name.len());
                    bytes.push(0);
                    bytes.extend_from_slice(name);
                    Some(Address::Abstract(bytes))
                });
                address.ok_or(io::ErrorKind::InvalidInput)?
            };
            #[cfg(windows)]
            let address = {
                use gnunet_native::local_socket::{Address as NativeAddress, local_address};
                match local_address(std::os::windows::io::AsSocket::as_socket(&socket))? {
                    NativeAddress::Path(path) => Address::Unix(path),
                    NativeAddress::Unnamed => return Err(io::ErrorKind::InvalidInput.into()),
                }
            };
            #[cfg(unix)]
            let port = RegisteredListener::new(Socket::from(socket))?;
            #[cfg(windows)]
            let port = RegisteredListener::from_activated_local(socket)?;
            (port, address)
        }
        ActivatedSocket::Tcp(socket) => {
            let address = socket.local_addr()?;
            (
                RegisteredListener::new(Socket::from(socket))?,
                Address::Tcp(address),
            )
        }
    };
    Ok(Bound {
        port,
        path: None,
        address,
    })
}
