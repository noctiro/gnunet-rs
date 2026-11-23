//! Local service admission from Unix peer credentials or Windows listener ACLs.
use crate::{
    accepted::{AcceptError, SocketEvent},
    connection::Connection,
};
#[cfg(windows)]
use gnunet_native::local_path::EndpointAccess;
use std::io;
/// Local admission configured by `UNIX_MATCH_UID` and `UNIX_MATCH_GID`.
/// UID matching takes precedence over GID matching.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnixAccess {
    /// Require service-owner access.
    pub match_uid: bool,
    /// Otherwise require service-group access.
    pub match_gid: bool,
}
impl UnixAccess {
    /// Read an explicitly configured local policy. An absent pair leaves the
    /// caller's default policy in effect. Malformed options are rejected.
    pub fn from_config(
        config: &gnunet_config::Configuration,
        section: &[u8],
    ) -> Result<Option<Self>, gnunet_config::Error> {
        let read = |key: &[u8]| match config.get_yesno(section, key) {
            Ok(value) => Ok(Some(value)),
            Err(gnunet_config::Error::Missing) => Ok(None),
            Err(error) => Err(error),
        };
        let match_uid = read(b"UNIX_MATCH_UID")?;
        let match_gid = read(b"UNIX_MATCH_GID")?;
        Ok(
            (match_uid.is_some() || match_gid.is_some()).then_some(Self {
                match_uid: match_uid.unwrap_or(false),
                match_gid: match_gid.unwrap_or(false),
            }),
        )
    }

    /// Decide admission for this original local connection. A failed native
    /// check is reported and refuses this stream without suspending acceptance
    /// or stopping the service. The caller closes a refused stream.
    pub fn admits(self, connection: &Connection, report: impl FnOnce(SocketEvent)) -> bool {
        match self.allows(connection) {
            Ok(allowed) => allowed,
            Err(error) => {
                report(SocketEvent::Failed(AcceptError::Credentials(error)));
                false
            }
        }
    }

    /// On Unix, check this connection against the current effective service
    /// identity. On Windows, use a DACL installed before the original AF_UNIX
    /// listener started accepting. An unidentified Windows listener or a TCP
    /// stream cannot satisfy a configured local restriction.
    pub fn allows(self, connection: &Connection) -> io::Result<bool> {
        #[cfg(windows)]
        {
            self.allows_windows_listener(connection.windows_listener_access())
        }
        #[cfg(unix)]
        {
            if !self.match_uid && !self.match_gid {
                return Ok(true);
            }
            self.allows_unix(connection)
        }
    }
    #[cfg(windows)]
    pub(crate) fn allows_windows_listener(
        self,
        access: Option<EndpointAccess>,
    ) -> io::Result<bool> {
        if !self.match_uid && !self.match_gid {
            return Ok(true);
        }
        let access = access.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "original Windows AF_UNIX listener ACL is unverified",
            )
        })?;
        Ok(self.permits_windows_access(access))
    }
    #[cfg(windows)]
    pub(crate) fn permits_windows_access(self, access: EndpointAccess) -> bool {
        match access {
            EndpointAccess::Owner => true,
            EndpointAccess::PrimaryGroup => !self.match_uid,
            EndpointAccess::Everyone => !self.match_uid && !self.match_gid,
        }
    }
    #[cfg(unix)]
    fn allows_unix(self, connection: &Connection) -> io::Result<bool> {
        let (uid, gid) = connection.unix_peer_credentials()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected original Unix connection",
            )
        })?;
        let our_uid = nix::unistd::geteuid().as_raw();
        let our_gid = nix::unistd::getegid().as_raw();
        if self.match_uid {
            return Ok(uid == our_uid);
        }
        if gid == our_gid {
            return Ok(true);
        }
        let Some(user) = gnunet_native::accounts::user_by_uid(uid)? else {
            return Ok(false);
        };
        user.belongs_to_group(our_gid)
    }
}
