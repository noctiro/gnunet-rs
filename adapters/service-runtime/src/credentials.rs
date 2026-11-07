//! Kernel Unix peer credentials and explicit service admission policy.
use crate::connection::Connection;
use std::io;
/// Explicit Unix peer admission. UID matching takes precedence over GID matching.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnixAccess {
    /// Require the kernel-reported effective peer UID to match this service.
    pub match_uid: bool,
    /// Otherwise require matching effective GID or membership in its group.
    pub match_gid: bool,
}
impl UnixAccess {
    /// Check this original connection against the current effective service identity.
    pub fn allows(self, connection: &Connection) -> io::Result<bool> {
        if !self.match_uid && !self.match_gid {
            return Ok(true);
        }
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
        let Some(user) = uzers::get_user_by_uid(uid) else {
            return Ok(false);
        };
        let groups = user
            .groups()
            .ok_or_else(|| io::Error::other("native group membership lookup unavailable"))?;
        Ok(groups.iter().any(|group| group.gid() == our_gid))
    }
}
