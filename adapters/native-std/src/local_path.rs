//! Windows AF_UNIX filesystem endpoints, native ACLs and original-object cleanup.
use crate::{
    filesystem::FileIdentity,
    identity::{self, Sid},
    local_socket,
    paths::{absolute_wide_path, metadata::attributes},
    process::PrimaryToken,
};
use std::{
    fs::File,
    io,
    mem::size_of,
    os::windows::io::{
        AsRawHandle, AsRawSocket, AsSocket, BorrowedSocket, FromRawHandle, OwnedSocket, RawSocket,
    },
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileDispositionInfoEx, OPEN_EXISTING, READ_CONTROL, ReOpenFile, SetFileInformationByHandle,
    WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_AF_UNIX;

#[cfg(feature = "socket-io")]
mod listener;
mod security;

#[cfg(feature = "socket-io")]
pub use listener::{ListenerBinding, ProtectedListener};

/// Filesystem access to a local endpoint, independently of peer authentication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EndpointAccess {
    /// Grant connect access to the selected primary-token user.
    #[default]
    Owner,
    /// Also grant connect access to the process token's actual primary group SID.
    PrimaryGroup,
    /// Also grant connect access to Everyone. Only the owner can change its ACL.
    Everyone,
}

#[derive(Clone)]
pub(crate) enum ProtectedAccess {
    Owner,
    PrimaryGroup(Sid),
    Everyone,
}

/// Access policy selected from a verified primary token for a future local bind.
/// A supervisor retains file custody and grants the target account connect access.
#[derive(Clone)]
pub struct EndpointPrincipals {
    pub(crate) custodian: Sid,
    pub(crate) user: Sid,
    pub(crate) access: ProtectedAccess,
}

impl EndpointPrincipals {
    /// Select the binder's primary-token user and optional primary group.
    pub fn for_current_process(access: EndpointAccess) -> io::Result<Self> {
        let token = identity::primary_token()?;
        let user = identity::token_user(&token)?;
        let access = Self::resolve_access(access, || identity::token_primary_group(&token))?;
        Ok(Self {
            custodian: user.clone(),
            user,
            access,
        })
    }

    /// Read the selected user and, for group access, its actual primary group
    /// from the authenticated launch token. This does not grant access by itself.
    pub fn for_account(token: &PrimaryToken, access: EndpointAccess) -> io::Result<Self> {
        Ok(Self {
            custodian: identity::process_user()?,
            user: token.user().clone(),
            access: Self::resolve_access(access, || token.primary_group())?,
        })
    }

    fn resolve_access(
        access: EndpointAccess,
        group: impl FnOnce() -> io::Result<Sid>,
    ) -> io::Result<ProtectedAccess> {
        Ok(match access {
            EndpointAccess::Owner => ProtectedAccess::Owner,
            EndpointAccess::PrimaryGroup => ProtectedAccess::PrimaryGroup(group()?),
            EndpointAccess::Everyone => ProtectedAccess::Everyone,
        })
    }

    pub(crate) fn verify_receiver(&self, token: &PrimaryToken) -> io::Result<()> {
        let group_matches = match &self.access {
            ProtectedAccess::PrimaryGroup(group) => &token.primary_group()? == group,
            _ => true,
        };
        if &self.user != token.user() || !group_matches {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pre-listen endpoint principals do not match the launch token",
            ));
        }
        Ok(())
    }
}

/// Access installed on the original named listener before it began
/// accepting. A late path or ACL observation cannot construct this proof.
#[repr(transparent)]
pub struct EndpointProtection(Box<ProtectedNode>);

struct ProtectedNode {
    path: PathBuf,
    socket: RawSocket,
    _node: File,
    identity: FileIdentity,
    principals: EndpointPrincipals,
}

const _: () = assert!(size_of::<Option<EndpointProtection>>() == size_of::<usize>());

impl EndpointProtection {
    /// The verified admission policy of this original listener.
    pub fn access(&self) -> EndpointAccess {
        match &self.0.principals.access {
            ProtectedAccess::Owner => EndpointAccess::Owner,
            ProtectedAccess::PrimaryGroup(_) => EndpointAccess::PrimaryGroup,
            ProtectedAccess::Everyone => EndpointAccess::Everyone,
        }
    }

    pub(crate) fn record(&self) -> (&EndpointPrincipals, FileIdentity) {
        (&self.0.principals, self.0.identity)
    }

    pub(crate) fn verify_source(&self, socket: BorrowedSocket<'_>) -> io::Result<()> {
        self.checked_node(socket).map(drop)
    }

    pub(crate) fn duplicate_source(
        &self,
        original: BorrowedSocket<'_>,
    ) -> io::Result<(OwnedSocket, Self)> {
        let node = self.checked_node(original)?;
        let duplicate = original.try_clone_to_owned()?;
        let protection = Self::retain(
            duplicate.as_socket(),
            self.0.path.clone(),
            node,
            self.0.identity,
            self.0.principals.clone(),
        );
        Ok((duplicate, protection))
    }

    fn checked_node(&self, socket: BorrowedSocket<'_>) -> io::Result<File> {
        if socket.as_raw_socket() != self.0.socket
            || local_socket::local_address(socket)?.as_pathname() != Some(self.0.path.as_path())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listener protection does not match the original socket and bound name",
            ));
        }
        Self::matching_node(&self.0.path, self.0.identity)
    }

    pub(crate) fn import(
        socket: BorrowedSocket<'_>,
        identity: FileIdentity,
        principals: EndpointPrincipals,
    ) -> io::Result<Self> {
        let local_socket::Address::Path(path) = local_socket::local_address(socket)? else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        let node = Self::matching_node(&path, identity)?;
        Ok(Self::retain(socket, path, node, identity, principals))
    }

    fn retain(
        socket: BorrowedSocket<'_>,
        path: PathBuf,
        node: File,
        identity: FileIdentity,
        principals: EndpointPrincipals,
    ) -> Self {
        Self(Box::new(ProtectedNode {
            path,
            socket: socket.as_raw_socket(),
            _node: node,
            identity,
            principals,
        }))
    }

    fn matching_node(path: &Path, expected: FileIdentity) -> io::Result<File> {
        let node = open_socket_node(path, FILE_READ_ATTRIBUTES)?;
        if FileIdentity::of(&node)? != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "listener path no longer identifies the protected original object",
            ));
        }
        Ok(node)
    }
}

impl std::fmt::Debug for EndpointProtection {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("EndpointProtection")
            .field("access", &self.access())
            .finish_non_exhaustive()
    }
}

const SHARING: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const OPEN_FLAGS: u32 = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;

#[expect(
    unsafe_code,
    reason = "CreateFileW borrows a bounded terminated native path and transfers one original noninheritable file handle on success"
)]
fn open_node(path: &Path, access: u32) -> io::Result<File> {
    let path = absolute_wide_path(path)?;
    // SAFETY: path remains terminated and live; null security means noninheritable.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            SHARING,
            ptr::null(),
            OPEN_EXISTING,
            OPEN_FLAGS,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this successful CreateFileW handle has exactly one owner.
    Ok(unsafe { File::from_raw_handle(raw) })
}

fn socket_tag(info: &FILE_ATTRIBUTE_TAG_INFO) -> bool {
    info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && info.ReparseTag == IO_REPARSE_TAG_AF_UNIX
}

fn open_socket_node(path: &Path, access: u32) -> io::Result<File> {
    let file = open_node(path, access)?;
    if !socket_tag(&attributes(&file)?) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "existing node is not an AF_UNIX endpoint",
        ));
    }
    Ok(file)
}

/// Inspect the final node without following a reparse point. This only identifies
/// an AF_UNIX filesystem node; it proves neither liveness nor peer identity.
pub fn is_socket(path: &Path) -> io::Result<bool> {
    attributes(&open_node(path, FILE_READ_ATTRIBUTES)?).map(|info| socket_tag(&info))
}

/// Create missing parent directories with protected native security descriptors.
/// Existing directories retain their security. The final parent must be owned
/// by the process user, SYSTEM or Administrators, and must not grant mutation to
/// other principals. Read/list/traverse grants are permitted. Reparse parents and
/// unsupported ACE forms fail closed. Callers exclude concurrent namespace/ACL
/// mutation and thread impersonation during startup; ancestors resolve normally.
pub fn prepare_parents(path: &Path, access: EndpointAccess) -> io::Result<()> {
    prepare_parents_for(path, &EndpointPrincipals::for_current_process(access)?)
}

/// Prepare parents using the access selected for this bind. Existing directories
/// keep their ACL and must already allow the intended clients to traverse.
pub fn prepare_parents_for(path: &Path, principals: &EndpointPrincipals) -> io::Result<()> {
    let absolute = parent(path)?;
    let descriptor = security::descriptor(principals, security::Object::Directory)?;
    // A Windows path prefix (for example `\\?\C:`) is not a directory.
    // Inspect only actual ancestors, starting with the volume/share root.
    let ancestors: Vec<_> = absolute.ancestors().collect();
    for directory in ancestors.into_iter().rev() {
        match std::fs::metadata(directory) {
            Ok(info) if info.is_dir() => continue,
            Ok(_) => return Err(io::ErrorKind::NotADirectory.into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        security::create_directory(directory, &descriptor)?;
    }
    validate_parent_directory(&absolute)
}

/// Check the namespace of an existing endpoint before probing it. This opens
/// the final parent without following a reparse point and preserves its ACL.
pub fn validate_parent(path: &Path) -> io::Result<()> {
    validate_parent_directory(&parent(path)?)
}

fn parent(path: &Path) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::path::absolute(parent)
}

fn validate_parent_directory(path: &Path) -> io::Result<()> {
    let parent = open_node(path, READ_CONTROL | FILE_READ_ATTRIBUTES)?;
    let info = attributes(&parent)?;
    if info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local endpoint parent must be an ordinary directory",
        ));
    }
    crate::identity::validate_parent(&parent)
}

/// An owned AF_UNIX node's original open file, independent of later path lookup.
///
/// Capture only a caller-owned newly bound or explicitly reclaimed stale node;
/// exclude concurrent namespace mutation between bind/probe and capture. Removal
/// reopens this original object for DELETE and performs a POSIX disposition. It
/// never removes a replacement by pathname. The initial handle deliberately has
/// no DELETE access, so clients need not share delete access while connecting.
/// A captured owner's Drop makes one best-effort cleanup attempt without waiting
/// for clients. An inspected node has no automatic cleanup. Use
/// [`Self::remove`] to observe failure and retain the owner for retry.
#[derive(Debug)]
pub struct LocalPath(Node);

/// An original existing AF_UNIX node opened only for inspection and explicit
/// reclamation. Drop closes its file handle without removing the node. It has
/// no ACL-setting API and never gains cleanup authority from a liveness probe.
#[derive(Debug)]
pub struct ObservedLocalPath(Node);
impl ObservedLocalPath {
    /// Verify the name still identifies this exact original AF_UNIX node.
    pub fn verify_current(&self) -> io::Result<()> {
        let file = self.0.file.as_ref().ok_or(io::ErrorKind::NotFound)?;
        EndpointProtection::matching_node(&self.0.path, FileIdentity::of(file)?).map(drop)
    }

    /// Explicitly reclaim this original node after establishing it is stale.
    /// Failure retains the original handle for retry. Dropping this observation
    /// after either outcome never schedules another removal attempt.
    pub fn remove(&mut self) -> io::Result<()> {
        self.0.remove()
    }
}

#[derive(Debug)]
struct Node {
    file: Option<File>,
    path: PathBuf,
}
impl LocalPath {
    /// Capture the original final reparse node with security-query, DACL and
    /// owner-setting access, for a newly caller-owned endpoint.
    /// Errors retain their Win32 code; a non-AF_UNIX node is never adopted.
    pub fn capture(path: PathBuf) -> io::Result<Self> {
        Node::open(
            path,
            READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES,
        )
        .map(Self)
    }
    /// Open an existing node without enabling automatic cleanup. Explicit
    /// `remove` is available only after the caller establishes reclamation
    /// authority. Dropping or canceling a liveness probe leaves the node intact.
    pub fn inspect(path: PathBuf) -> io::Result<ObservedLocalPath> {
        Node::open(path, READ_CONTROL | FILE_READ_ATTRIBUTES).map(ObservedLocalPath)
    }
    /// Diagnostic creation path; it is never reopened for removal or ACL changes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0.path
    }

    /// Set the original node's owner to the process-token user and protect its
    /// DACL before listening. Inheritance is disabled;
    /// existing parent ACLs are never modified. This grants no peer SID evidence.
    pub fn set_access(&self, access: EndpointAccess) -> io::Result<()> {
        self.install_access(&EndpointPrincipals::for_current_process(access)?)
    }

    fn install_access(&self, principals: &EndpointPrincipals) -> io::Result<()> {
        security::set_access(self.original_file()?, principals)
    }

    fn original_file(&self) -> io::Result<&File> {
        self.0
            .file
            .as_ref()
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    /// Remove the original node after its socket is closed. Success disarms the
    /// owner; failure leaves it intact for retry. Sharing violations or a volume
    /// without extended POSIX disposition are returned without a pathname fallback.
    pub fn remove(&mut self) -> io::Result<()> {
        self.0.remove()
    }
}
impl Node {
    fn open(path: PathBuf, access: u32) -> io::Result<Self> {
        let file = open_socket_node(&path, access)?;
        Ok(Self {
            file: Some(file),
            path,
        })
    }
    #[expect(
        unsafe_code,
        reason = "ReOpenFile retains original-object identity and yields one owned DELETE handle; SetFileInformationByHandle borrows exact initialized disposition input"
    )]
    fn remove(&mut self) -> io::Result<()> {
        let Some(file) = &self.file else {
            return Ok(());
        };
        // SAFETY: original CreateFileW handle remains owned and live. No pathname lookup.
        let raw = unsafe { ReOpenFile(file.as_raw_handle(), DELETE, SHARING, OPEN_FLAGS) };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful ReOpenFile transfers exactly one independent handle.
        let deletion = unsafe { File::from_raw_handle(raw) };
        let info = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // SAFETY: exact structure and size, live DELETE handle, no retained input pointer.
        if unsafe {
            SetFileInformationByHandle(
                deletion.as_raw_handle(),
                FileDispositionInfoEx,
                (&info as *const FILE_DISPOSITION_INFO_EX).cast(),
                size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // Closing the POSIX delete handle removes the link while other opens may
        // finish their I/O. Never wait for those users in a destructor.
        drop(deletion);
        self.file = None;
        Ok(())
    }
}
impl Drop for LocalPath {
    fn drop(&mut self) {
        let _cleanup = self.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EndpointAccess, FILE_READ_ATTRIBUTES, READ_CONTROL, open_node, prepare_parents, security,
    };
    use std::{
        fs, io,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> io::Result<Self> {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            Ok(Self(std::env::temp_dir().join(format!(
                "gn-acl-{}-{nonce:x}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn new_parent_modes_retain_native_owner_without_broad_mutation() -> io::Result<()> {
        for access in [
            EndpointAccess::Owner,
            EndpointAccess::PrimaryGroup,
            EndpointAccess::Everyone,
        ] {
            let directory = Directory::new()?;
            prepare_parents(&directory.0.join("service.sock"), access)?;
            let file = open_node(&directory.0, READ_CONTROL | FILE_READ_ATTRIBUTES)?;
            crate::identity::validate_parent(&file)?;
            if crate::identity::file_owner(&file)? != crate::identity::process_user()? {
                return Err(io::Error::other(
                    "new parent owner differs from process-token user",
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn verbatim_paths_prepare_only_real_directory_ancestors() -> io::Result<()> {
        let directory = Directory::new()?;
        let dir = fs::canonicalize(directory.0.parent().ok_or(io::ErrorKind::NotFound)?)?
            .join(directory.0.file_name().ok_or(io::ErrorKind::NotFound)?)
            .join("nested");
        prepare_parents(&dir.join("service.sock"), EndpointAccess::Owner)?;
        let file = open_node(&dir, READ_CONTROL | FILE_READ_ATTRIBUTES)?;
        crate::identity::validate_parent(&file)
    }

    #[test]
    fn existing_world_writable_parent_is_refused_without_rewriting_its_acl() -> io::Result<()> {
        let directory = Directory::new()?;
        let principals = super::EndpointPrincipals::for_current_process(EndpointAccess::Everyone)?;
        let descriptor = security::descriptor(&principals, security::Object::Socket)?;
        security::create_directory(&directory.0, &descriptor)?;
        for _ in 0..2 {
            let error = prepare_parents(&directory.0.join("service.sock"), EndpointAccess::Owner)
                .err()
                .ok_or_else(|| io::Error::other("world-writable parent was accepted"))?;
            if error.kind() != io::ErrorKind::PermissionDenied {
                return Err(error);
            }
        }
        Ok(())
    }
}
