//! Fresh Windows AF_UNIX listener and its pre-listen ACL evidence.
use super::{
    EndpointPrincipals, EndpointProtection, LocalPath, prepare_parents_for, validate_parent,
};
use crate::{filesystem::FileIdentity, local_socket, socket_activation::Source};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    io,
    os::windows::io::AsSocket,
    path::{Path, PathBuf},
};

/// An absolute named AF_UNIX endpoint and the verified principals for its bind.
pub struct ListenerBinding {
    path: PathBuf,
    address: SockAddr,
    principals: EndpointPrincipals,
}

impl ListenerBinding {
    /// Resolve the name once before inspecting any existing filesystem node.
    pub fn new(path: PathBuf, principals: EndpointPrincipals) -> io::Result<Self> {
        let path = std::path::absolute(path)?;
        let address = local_socket::named_address(&path)?;
        Ok(Self {
            path,
            address,
            principals,
        })
    }

    /// Absolute name retained for an optional original-node liveness check.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Prepare missing parents for the selected access. Existing ACLs stay in place.
    pub fn prepare_parents(&self) -> io::Result<()> {
        prepare_parents_for(&self.path, &self.principals)
    }

    /// Bind a fresh socket, install the selected ACL on its original node and listen.
    /// Refuses an existing endpoint. The caller excludes concurrent namespace and
    /// ACL changes, and thread impersonation, through preparation and handoff.
    pub fn listen(self, backlog: i32) -> io::Result<ProtectedListener> {
        validate_parent(&self.path)?;
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.bind(&self.address)?;
        let path = LocalPath::capture(self.path)?;
        BoundListener { socket, path }.listen(self.principals, backlog)
    }
}

// No socket reference escapes before ACL installation and the first listen.
struct BoundListener {
    socket: Socket,
    path: LocalPath,
}

impl BoundListener {
    fn listen(self, principals: EndpointPrincipals, backlog: i32) -> io::Result<ProtectedListener> {
        let socket = self.socket.as_socket();
        let path = self.path.path();
        if local_socket::local_address(socket)?.as_pathname() != Some(path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bound local socket did not retain its original name",
            ));
        }
        let node = self.path.original_file()?.try_clone()?;
        let identity = FileIdentity::of(&node)?;
        drop(EndpointProtection::matching_node(path, identity)?);
        self.path.install_access(&principals)?;
        self.socket.listen(backlog)?;
        let protection =
            EndpointProtection::retain(socket, path.to_owned(), node, identity, principals);
        Ok(ProtectedListener {
            socket: self.socket,
            path: self.path,
            protection,
        })
    }
}

/// Original listening socket, path cleanup and evidence of its pre-listen ACL.
/// The socket closes before the path owner attempts cleanup on drop.
#[derive(Debug)]
pub struct ProtectedListener {
    socket: Socket,
    path: LocalPath,
    protection: EndpointProtection,
}

impl ProtectedListener {
    /// Borrow the original unregistered listener for the native activation handoff.
    pub fn launch_source(&self) -> Source<'_> {
        Source::new(self.socket.as_socket()).with_protection(&self.protection)
    }

    /// Transfer the original socket, path cleanup and evidence for registration.
    /// The recipient keeps the path owner until the original socket closes.
    pub fn into_parts(self) -> (Socket, LocalPath, EndpointProtection) {
        (self.socket, self.path, self.protection)
    }
}
