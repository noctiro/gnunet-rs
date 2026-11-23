//! Parent publication of original listener records for one pinned child.
use super::{
    BOOTSTRAP_KEY_PREFIX,
    mapping::Writable,
    record::{
        ENTRY, HEADER, ListenerKind, MAGIC, RECORD, VERSION, encode_access, ensure_winsock, extent,
        socket_error,
    },
};
use crate::{
    identity::{self, Sid},
    local_path::{EndpointProtection, ProtectedAccess},
    process::{AccountProfile, ActivationTarget, PrimaryToken, ProcessIdentity, SuspendedProcess},
};
use std::{
    collections::HashSet,
    error::Error,
    ffi::{OsStr, OsString},
    fmt, io,
    os::windows::io::{AsHandle, AsRawSocket, AsSocket, BorrowedHandle, BorrowedSocket},
    sync::atomic::{AtomicU32, Ordering},
};
use windows_sys::Win32::Networking::WinSock::{
    SO_PROTOCOL_INFOW, SOCKET_ERROR, SOL_SOCKET, WSADuplicateSocketW, WSAPROTOCOL_INFOW, getsockopt,
};

/// One original listener and its publisher's optional pre-listen ACL evidence.
#[derive(Clone, Copy, Debug)]
pub struct Source<'a> {
    socket: BorrowedSocket<'a>,
    protection: Option<&'a EndpointProtection>,
}
impl<'a> Source<'a> {
    /// Bare listener with no pre-listen ACL evidence.
    pub const fn new(socket: BorrowedSocket<'a>) -> Self {
        Self {
            socket,
            protection: None,
        }
    }

    /// Attach protection retained from the original pre-listen installation.
    /// Publication checks the actual bound name. The publisher
    /// retains the original node and its policy through handoff.
    pub const fn with_protection(self, protection: &'a EndpointProtection) -> Self {
        Self {
            socket: self.socket,
            protection: Some(protection),
        }
    }

    /// Pre-listen ACL evidence retained with this source.
    pub const fn protection(self) -> Option<&'a EndpointProtection> {
        self.protection
    }
}
impl AsSocket for Source<'_> {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.socket
    }
}
/// Qualified original listeners and their reserved native transfer section.
/// The child receives only read-only access to the section.
pub struct ExportSection<'a> {
    mapping: Writable,
    sources: &'a [Source<'a>],
    scope: Scope,
    target: Option<ProcessIdentity>,
}
impl fmt::Debug for ExportSection<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportSection")
            .field("count", &self.sources.len())
            .finish_non_exhaustive()
    }
}

/// Original listener sources sealed to one verified account and read-only section.
pub struct AccountExportSection<'a> {
    section: ExportSection<'a>,
    receiver: Sid,
    route: Route,
}

enum Route {
    Inherited,
    InheritedProtected(Sid),
    Bootstrap {
        publisher: Sid,
        declaration: Option<OsString>,
    },
}

#[derive(Clone, Copy)]
pub(crate) enum Delivery<'a> {
    Inherited {
        handle: BorrowedHandle<'a>,
        publisher: Option<&'a Sid>,
    },
    Bootstrap(&'a OsStr),
}

/// Exclusive launch authority for a reserved section. Only successful native
/// admission records a process identity, so a refused launch can be retried.
pub(crate) struct Admission<'a> {
    delivery: Delivery<'a>,
    target: &'a mut Option<ProcessIdentity>,
}

impl<'a> Admission<'a> {
    fn new(delivery: Delivery<'a>, target: &'a mut Option<ProcessIdentity>) -> io::Result<Self> {
        if target.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "activation section has an original child",
            ));
        }
        Ok(Self { delivery, target })
    }

    pub(crate) const fn delivery(&self) -> Delivery<'a> {
        self.delivery
    }

    pub(crate) fn bind(self, child: &SuspendedProcess) {
        *self.target = Some(child.process().identity());
    }
}

impl<'a> AccountExportSection<'a> {
    /// Prepare transfer to the verified service account before native process
    /// admission. A local listener must carry its original pre-listen policy
    /// for that account. Same-session launches inherit the read-only section.
    /// A session crossing requires an authenticated bootstrap grant.
    pub fn for_account(sources: &'a [Source<'a>], profile: &AccountProfile) -> io::Result<Self> {
        let token = profile.token()?;
        let bytes = extent(sources.len())?;
        let local = qualify_sources(sources, Some(token))?;
        let publisher = identity::process_user()?;
        let receiver = token.user().clone();
        let cross_session = !token.shares_supervisor_session()?;
        let (route, scope) = match (cross_session, local) {
            (true, _) => (
                Route::Bootstrap {
                    publisher,
                    declaration: None,
                },
                Scope::ProtectedAccount,
            ),
            (false, true) => (
                Route::InheritedProtected(publisher),
                Scope::ProtectedAccount,
            ),
            (false, false) => (Route::Inherited, Scope::InheritedAccount),
        };
        Ok(Self {
            section: ExportSection {
                mapping: Writable::new(bytes)?,
                sources,
                scope,
                target: None,
            },
            receiver,
            route,
        })
    }

    /// Whether this account launch requires a cross-session bootstrap grant.
    pub const fn requires_bootstrap(&self) -> bool {
        matches!(self.route, Route::Bootstrap { .. })
    }

    /// Install the per-launch Ed25519 verification key. The caller owns the
    /// matching signing key and publishes the one signed grant to the original
    /// authenticated child. Configure this before admitting that child.
    pub fn set_bootstrap_verifying_key(&mut self, key: [u8; 32]) -> io::Result<()> {
        let Route::Bootstrap { declaration, .. } = &mut self.route else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if declaration.is_some() || self.section.target.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut hint = String::with_capacity(BOOTSTRAP_KEY_PREFIX.len() + 2 * key.len());
        hint.push_str(BOOTSTRAP_KEY_PREFIX);
        for byte in key {
            hint.push(char::from(HEX[usize::from(byte >> 4)]));
            hint.push(char::from(HEX[usize::from(byte & 15)]));
        }
        *declaration = Some(hint.into());
        Ok(())
    }

    pub(crate) fn admission(&mut self, token: &PrimaryToken) -> io::Result<Admission<'_>> {
        let cross_session = !token.shares_supervisor_session()?;
        if token.user() == &self.receiver {
            for source in self.section.sources {
                if let Some(protection) = source.protection {
                    protection.record().0.verify_receiver(token)?;
                }
            }
            match &self.route {
                Route::Inherited if !cross_session => {
                    return self.section.admission();
                }
                Route::InheritedProtected(publisher) if !cross_session => {
                    return Admission::new(
                        Delivery::Inherited {
                            handle: self.section.mapping.read.as_handle(),
                            publisher: Some(publisher),
                        },
                        &mut self.section.target,
                    );
                }
                Route::Bootstrap { declaration, .. } if cross_session => {
                    let declaration = declaration.as_deref().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "cross-session activation requires a bootstrap verification key",
                        )
                    })?;
                    return Admission::new(
                        Delivery::Bootstrap(declaration),
                        &mut self.section.target,
                    );
                }
                _ => {}
            }
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "activation transport does not match the verified child account or session",
        ))
    }

    /// Seal these same original listeners for this exact suspended process.
    /// Retain the resulting publication until actual import or startup failure.
    /// On cross-session delivery failure, retire that original child to release
    /// its duplicated handle and provider reservations.
    pub fn publish(
        self,
        target: ActivationTarget<'_>,
    ) -> Result<(Publication, Option<BootstrapGrant>), PublishFailure> {
        let publisher = match self.route {
            Route::Bootstrap { publisher, .. } => Some(publisher),
            _ => None,
        };
        self.section.publish_to(target, publisher)
    }
}

enum Scope {
    Stream,
    InheritedAccount,
    ProtectedAccount,
}

impl Scope {
    fn allows(&self, kind: ListenerKind, protected: bool) -> bool {
        match (kind, protected) {
            (ListenerKind::Tcp, false) => true,
            (ListenerKind::Local, true) => !matches!(self, Self::InheritedAccount),
            (ListenerKind::Local, false) => matches!(self, Self::Stream),
            (ListenerKind::Tcp, true) => false,
        }
    }
}

fn qualify_sources(sources: &[Source<'_>], account: Option<&PrimaryToken>) -> io::Result<bool> {
    if sources.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    ensure_winsock()?;
    let scope = if account.is_some() {
        Scope::ProtectedAccount
    } else {
        Scope::Stream
    };
    let mut handles = HashSet::new();
    handles
        .try_reserve(sources.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    let mut publisher = None;
    let mut publisher_group = None;
    let mut local = false;
    for source in sources {
        if !handles.insert(source.socket.as_raw_socket()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "activation contains a repeated listener descriptor",
            ));
        }
        let kind = ListenerKind::from_protocol(&read_protocol(source.socket)?)?;
        if !scope.allows(kind, source.protection.is_some())
            || !crate::network::is_listener(source.socket)?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "original socket is not a listener for the selected activation route",
            ));
        }
        if let Some(protection) = source.protection {
            let publisher: &Sid = match &mut publisher {
                Some(publisher) => publisher,
                None => publisher.insert(identity::process_user()?),
            };
            let principals = protection.record().0;
            if &principals.custodian != publisher
                || (account.is_none() && &principals.user != publisher)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "local protection does not belong to this publisher and transfer route",
                ));
            }
            if let Some(token) = account {
                principals.verify_receiver(token)?;
            } else if let ProtectedAccess::PrimaryGroup(group) = &principals.access {
                let expected: &Sid = match &mut publisher_group {
                    Some(expected) => expected,
                    None => publisher_group
                        .insert(identity::token_primary_group(&identity::primary_token()?)?),
                };
                if group != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "local protection does not match the publisher's primary group",
                    ));
                }
            }
            protection.verify_source(source.socket)?;
        }
        local |= kind == ListenerKind::Local;
    }
    Ok(local)
}

#[expect(
    unsafe_code,
    reason = "getsockopt fills bounded aligned native protocol information for the original borrowed socket"
)]
fn read_protocol(socket: BorrowedSocket<'_>) -> io::Result<WSAPROTOCOL_INFOW> {
    let mut info = WSAPROTOCOL_INFOW::default();
    let mut length = size_of::<WSAPROTOCOL_INFOW>() as i32;
    // SAFETY: original borrowed socket; exclusive outputs have exact expected native sizes.
    if unsafe {
        getsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_PROTOCOL_INFOW,
            std::ptr::from_mut(&mut info).cast(),
            &mut length,
        )
    } == SOCKET_ERROR
    {
        return Err(socket_error());
    }
    if length as usize != size_of::<WSAPROTOCOL_INFOW>() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(info)
}
/// Native metadata publication, distinct from target import or service readiness.
pub struct Publication {
    _target: ProcessIdentity,
    count: usize,
}
impl fmt::Debug for Publication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Publication")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}
impl Publication {
    /// Number of successful native listener exports in this sealed section.
    pub fn len(&self) -> usize {
        self.count
    }
    /// Whether this publication carries no listeners.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// One sealed read-only mapping grant. The handle lives in the original child's
/// table; the publisher must use its launch's authenticated bootstrap channel.
#[must_use = "deliver the grant once or retire the original child"]
pub struct BootstrapGrant {
    recipient_pid: u32,
    target_handle: u64,
    publisher: Sid,
}

impl BootstrapGrant {
    /// PID of the original pinned process that owns the duplicated handle.
    pub const fn recipient_pid(&self) -> u32 {
        self.recipient_pid
    }

    /// Scalar handle value valid only in the original target process.
    pub const fn target_handle(&self) -> u64 {
        self.target_handle
    }

    /// Original publisher's primary SID, installed as the mapping owner.
    pub const fn publisher(&self) -> &Sid {
        &self.publisher
    }
}
/// Failed publication preserves its mapping cleanup owner and actual export
/// progress. Successful SDK exports remain target-owned debt until import or
/// target exit; closing this mapping does not cancel those provider resources.
pub struct PublishFailure {
    /// Original native/setup/view-retirement error.
    pub error: io::Error,
    /// Number of successful WSADuplicateSocket calls, never an import receipt.
    pub exported: usize,
    _target: Option<ProcessIdentity>,
    mapping: Writable,
}
impl PublishFailure {
    /// Retry only original view retirement. This cannot republish/replay tickets
    /// or settle target-side resources; explicitly retire/drain the failed child.
    pub fn close_view(&mut self) -> io::Result<()> {
        self.mapping.view.close()
    }
}
impl fmt::Debug for PublishFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishFailure")
            .field("error", &self.error)
            .field("exported", &self.exported)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for PublishFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl Error for PublishFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}
impl<'a> ExportSection<'a> {
    /// Qualify the original listeners and reserve a transfer section before
    /// child creation. Keep the sources quiescent until the child imports them.
    /// Launch admission lends the read-only section to one same-account child.
    pub fn for_listeners(sources: &'a [Source<'a>]) -> io::Result<Self> {
        let bytes = extent(sources.len())?;
        qualify_sources(sources, None)?;
        Ok(Self {
            mapping: Writable::new(bytes)?,
            sources,
            scope: Scope::Stream,
            target: None,
        })
    }

    pub(crate) fn admission(&mut self) -> io::Result<Admission<'_>> {
        Admission::new(
            Delivery::Inherited {
                handle: self.mapping.read.as_handle(),
                publisher: None,
            },
            &mut self.target,
        )
    }

    /// Publish exact listener order for this original suspended target, then
    /// retire all parent writable access. Caller excludes external resume and
    /// concurrent socket I/O/options/registration. Sources must be overlapped
    /// listeners never attached to an IOCP or event-selection registration.
    /// Keep source descriptors alive until target reconstruction is confirmed.
    /// On failure the target must not be resumed: terminate/drain it to settle
    /// any provider-side exports. No raw PID reconstruction is performed here.
    pub fn publish(self, target: ActivationTarget<'_>) -> Result<Publication, PublishFailure> {
        self.publish_to(target, None)
            .map(|(publication, _)| publication)
    }

    #[expect(
        unsafe_code,
        reason = "WSADuplicateSocketW writes exact aligned initialized record storage for a pinned original process; a release publication precedes writable-view retirement and child resume"
    )]
    fn publish_to(
        mut self,
        target: ActivationTarget<'_>,
        publisher: Option<Sid>,
    ) -> Result<(Publication, Option<BootstrapGrant>), PublishFailure> {
        let process = target.process();
        let mut exported = 0;
        let count = self.sources.len();
        let result = (|| {
            if !self
                .target
                .as_ref()
                .is_some_and(|admitted| admitted.matches(process))
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "activation section was not admitted to this suspended process",
                ));
            }
            for source in self.sources {
                if let Some(protection) = source.protection {
                    protection.verify_source(source.socket)?;
                }
            }
            let pointer = self.mapping.view.pointer_mut();
            for socket in self.sources {
                // SAFETY: each exact record lies in the bounded zeroed view;
                // HEADER/ENTRY are four-byte aligned and the original target's
                // process owner pins its native PID throughout this operation.
                let output = unsafe {
                    pointer
                        .add(HEADER + exported * ENTRY)
                        .cast::<WSAPROTOCOL_INFOW>()
                };
                // SAFETY: live borrowed socket, original target, exact writable output.
                if unsafe {
                    WSADuplicateSocketW(
                        socket.socket.as_raw_socket() as usize,
                        process.id(),
                        output,
                    )
                } == SOCKET_ERROR
                {
                    return Err(socket_error());
                }
                exported += 1;
                // SAFETY: successful SDK call initialized the protocol record;
                // the final aligned word belongs exclusively to this entry.
                unsafe {
                    let kind = ListenerKind::from_protocol(&*output)?;
                    if !self.scope.allows(kind, socket.protection.is_some()) {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    let access = encode_access(socket.protection.map(EndpointProtection::record));
                    std::ptr::copy_nonoverlapping(
                        access.as_ptr(),
                        output.cast::<u8>().add(RECORD),
                        access.len(),
                    );
                }
            }
            let values = [
                VERSION,
                count as u32,
                ENTRY as u32,
                process.id(),
                extent(count)? as u32,
                0,
                0,
            ];
            for (index, value) in values.into_iter().enumerate() {
                // SAFETY: fixed header words all lie before the record area.
                unsafe { pointer.add(4 + index * 4).cast::<u32>().write(value) };
            }
            // SAFETY: page-aligned zeroed storage supports an AtomicU32. All
            // record/header writes precede this sole release publication.
            unsafe { &*pointer.cast::<AtomicU32>() }.store(MAGIC, Ordering::Release);
            let sealed = self.mapping.seal()?;
            publisher
                .map(|publisher| {
                    let target_handle = sealed.duplicate_into(process)?;
                    Ok(BootstrapGrant {
                        recipient_pid: process.id(),
                        target_handle,
                        publisher,
                    })
                })
                .transpose()
        })();
        match result {
            Ok(grant) => {
                let published = Publication {
                    _target: process.identity(),
                    count,
                };
                target.published();
                Ok((published, grant))
            }
            Err(error) => Err(PublishFailure {
                error,
                exported,
                _target: self.target,
                mapping: self.mapping,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};

    #[test]
    fn account_section_requires_matching_family_and_access_tag() -> io::Result<()> {
        if !Scope::ProtectedAccount.allows(ListenerKind::Tcp, false)
            || Scope::ProtectedAccount.allows(ListenerKind::Tcp, true)
            || !Scope::ProtectedAccount.allows(ListenerKind::Local, true)
            || Scope::ProtectedAccount.allows(ListenerKind::Local, false)
            || Scope::InheritedAccount.allows(ListenerKind::Local, true)
        {
            return Err(io::Error::other("invalid activation protocol admission"));
        }
        Ok(())
    }

    #[test]
    fn preflight_accepts_only_unique_listeners_before_child_admission() -> io::Result<()> {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let connected = TcpStream::connect(tcp.local_addr()?)?;
        let listener = Source::new(tcp.as_socket());
        for (socket, expected) in [
            (listener, io::ErrorKind::InvalidInput),
            (Source::new(udp.as_socket()), io::ErrorKind::Unsupported),
            (
                Source::new(connected.as_socket()),
                io::ErrorKind::InvalidInput,
            ),
        ] {
            if !matches!(ExportSection::for_listeners(&[listener, socket]), Err(error) if error.kind() == expected)
            {
                return Err(io::Error::other("invalid listener batch passed preflight"));
            }
        }
        ExportSection::for_listeners(&[listener])?;
        Ok(())
    }
}
