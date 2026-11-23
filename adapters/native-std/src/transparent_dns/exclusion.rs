//! Exact upstream socket mark leases and configured Linux ingress observations.
mod probe;

pub use probe::{PendingReceive, ProbeReceipt, ProbeRequest, ProbeSocket, UnqualifiedDatagram};

use super::{
    Datagram, Listener, ListenerFamily, NetworkNamespace, TransparentPort,
    link::{LinkAttachment, LinkEvent, LinkQuery, LinkRecord, LinkRole},
};
use std::{
    ffi::{CStr, CString},
    fmt,
    fs::File,
    io,
    mem::size_of,
    num::NonZeroU32,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[derive(Debug)]
struct MarkLease {
    socket: OwnedFd,
    previous: u32,
    state: MarkState,
}

#[derive(Clone, Copy, Debug)]
enum MarkState {
    Prepared,
    Applied,
    Restored,
    Refused(Option<i32>),
}

/// An original socket's exact native restoration refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarkFailure {
    /// Position of the socket in the original application input.
    pub socket: usize,
    /// Native errno, without translating it into an invented replacement code.
    pub errno: Option<i32>,
}

impl fmt::Display for MarkFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.errno {
            Some(errno) => write!(
                f,
                "socket {}: {}",
                self.socket,
                io::Error::from_raw_os_error(errno)
            ),
            None => write!(
                f,
                "socket {}: native mark restoration refused without errno",
                self.socket
            ),
        }
    }
}
impl std::error::Error for MarkFailure {}

/// All native restoration failures remain queryable from the original owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreError {
    /// First refusal in reverse restoration order.
    pub first: MarkFailure,
    /// Number of original socket restorations still refused.
    pub count: usize,
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} mark restorations refused; {}",
            self.count, self.first
        )
    }
}
impl std::error::Error for RestoreError {}

/// Original apply failure and the owners retained after attempted rollback.
#[derive(Debug)]
pub struct ApplyFailure {
    /// The original acquisition, validation or native set error.
    pub error: io::Error,
    /// Actual rollback failures, independently of the original error.
    pub rollback: Option<RestoreError>,
    /// Original duplicated sockets and their restoration observations.
    pub marks: BypassMarks,
}

impl fmt::Display for ApplyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)?;
        if let Some(rollback) = self.rollback {
            write!(f, "; {rollback}")?;
        }
        Ok(())
    }
}
impl std::error::Error for ApplyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Bypass marks on exact duplicated original Internet UDP socket objects.
///
/// Each duplicate retains the original open file description, so restoring it
/// cannot touch a different socket that later reuses the application's fd.
/// The caller must exclusively manage these sockets' mark policy while leased.
/// Stop capture rules and pending upstream work before explicit restoration.
/// Drop attempts remaining restoration; use [`Self::restore`] to observe errors.
#[derive(Debug)]
pub struct BypassMarks {
    leases: Vec<MarkLease>,
}

impl BypassMarks {
    /// Duplicate and validate the complete original upstream socket set before
    /// applying any mark. Every socket must belong to the capture namespace.
    /// This installs no routing or interception rules and sends no packet.
    ///
    /// # Errors
    /// Reports the original failure and attempts reverse rollback of every
    /// earlier mutation. Any rollback refusal retains its exact socket owner.
    pub fn apply<'fd>(
        sockets: impl IntoIterator<Item = BorrowedFd<'fd>>,
        namespace: NetworkNamespace,
        mark: NonZeroU32,
    ) -> Result<Self, ApplyFailure> {
        let mut marks = Self { leases: Vec::new() };
        let result = (|| {
            for socket in sockets {
                marks.leases.try_reserve(1).map_err(io::Error::other)?;
                let socket = socket.try_clone_to_owned()?;
                internet_udp(socket.as_fd())?;
                namespace.require(NetworkNamespace::observe(socket.as_fd())?)?;
                let previous = option32(socket.as_fd(), libc::SO_MARK)?;
                let state = if previous == mark.get() {
                    MarkState::Restored
                } else {
                    MarkState::Prepared
                };
                marks.leases.push(MarkLease {
                    socket,
                    previous,
                    state,
                });
            }
            for lease in &mut marks.leases {
                if matches!(lease.state, MarkState::Prepared) {
                    set_mark(lease.socket.as_fd(), mark.get())?;
                    lease.state = MarkState::Applied;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            let rollback = marks.restore().err();
            return Err(ApplyFailure {
                error,
                rollback,
                marks,
            });
        }
        Ok(marks)
    }

    /// Restore each mutated original once, in reverse acquisition order.
    /// Native failures are cached; this never retries a refused mutation.
    ///
    /// # Errors
    /// Returns actual native failure counts and the first refusal. All exact
    /// per-socket observations remain available through [`Self::failures`].
    pub fn restore(&mut self) -> Result<(), RestoreError> {
        let mut failed: Option<RestoreError> = None;
        for (index, lease) in self.leases.iter_mut().enumerate().rev() {
            if matches!(lease.state, MarkState::Applied) {
                lease.state = match set_mark(lease.socket.as_fd(), lease.previous) {
                    Ok(()) => MarkState::Restored,
                    Err(error) => MarkState::Refused(error.raw_os_error()),
                };
            }
            if let MarkState::Refused(errno) = lease.state {
                let entry = MarkFailure {
                    socket: index,
                    errno,
                };
                match &mut failed {
                    Some(failed) => failed.count += 1,
                    None => {
                        failed = Some(RestoreError {
                            first: entry,
                            count: 1,
                        })
                    }
                }
            }
        }
        failed.map_or(Ok(()), Err)
    }

    /// Exact original restoration errors without allocating a second list.
    pub fn failures(&self) -> impl Iterator<Item = MarkFailure> + '_ {
        self.leases
            .iter()
            .enumerate()
            .filter_map(|(socket, lease)| match lease.state {
                MarkState::Refused(errno) => Some(MarkFailure { socket, errno }),
                MarkState::Prepared | MarkState::Applied | MarkState::Restored => None,
            })
    }
}

impl Drop for BypassMarks {
    fn drop(&mut self) {
        let _restored = self.restore();
    }
}

fn internet_udp(socket: BorrowedFd<'_>) -> io::Result<()> {
    let family = option32(socket, libc::SO_DOMAIN)?;
    if (family != libc::AF_INET as u32 && family != libc::AF_INET6 as u32)
        || option32(socket, libc::SO_TYPE)? != libc::SOCK_DGRAM as u32
        || option32(socket, libc::SO_PROTOCOL)? != libc::IPPROTO_UDP as u32
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bypass marks require original IPv4/IPv6 UDP sockets",
        ));
    }
    Ok(())
}

#[expect(
    unsafe_code,
    reason = "copy one exact-width native Linux socket option from a retained fd"
)]
fn option32(socket: BorrowedFd<'_>, option: libc::c_int) -> io::Result<u32> {
    let mut value = 0u32;
    let mut bytes = size_of::<u32>() as libc::socklen_t;
    // SAFETY: borrowed original socket, writable aligned output and exact extent.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&raw mut value).cast(),
            &raw mut bytes,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if bytes as usize != size_of::<u32>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native socket option width differs",
        ));
    }
    Ok(value)
}

#[expect(
    unsafe_code,
    reason = "set SO_MARK only on this lease's retained original socket"
)]
fn set_mark(socket: BorrowedFd<'_>, mark: u32) -> io::Result<()> {
    // SAFETY: one complete native u32 and its exact original live socket.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&raw const mark).cast(),
            size_of::<u32>() as libc::socklen_t,
        )
    } != 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct Ingress {
    link: Arc<Link>,
    vrf: Option<Arc<Link>>,
}

#[derive(Debug)]
struct Link {
    name: CString,
    attachment: LinkAttachment,
    observation: IngressObservation,
}

#[derive(Debug)]
struct LiveIngress {
    index: NonZeroU32,
    active: AtomicBool,
    source: Arc<()>,
    master: Option<IngressObservation>,
}

/// An admitted original ingress observation. Observed retirement is sticky for
/// all its admitted datagrams. This does not retain a native device reference.
#[derive(Clone, Debug)]
pub struct IngressObservation(Arc<LiveIngress>);
impl IngressObservation {
    fn new(index: NonZeroU32, source: &Arc<()>) -> Self {
        Self::with_master(index, source, None)
    }

    fn with_master(
        index: NonZeroU32,
        source: &Arc<()>,
        master: Option<IngressObservation>,
    ) -> Self {
        Self(Arc::new(LiveIngress {
            index,
            active: AtomicBool::new(true),
            source: Arc::clone(source),
            master,
        }))
    }

    /// Whether the owning source still considers its original ingress active.
    #[must_use]
    pub fn active(&self) -> bool {
        self.0.active.load(Ordering::Acquire) && self.0.master.as_ref().is_none_or(Self::active)
    }

    pub(super) fn master(&self) -> Option<&Self> {
        self.0.master.as_ref()
    }

    pub(super) fn index(&self) -> NonZeroU32 {
        self.0.index
    }

    pub(super) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    fn retire(&self) -> bool {
        self.0.active.swap(false, Ordering::AcqRel)
    }
}

impl Link {
    fn observe_change(
        &self,
        name: Option<&CStr>,
        role: LinkRole,
        attachment: LinkAttachment,
    ) -> Observation {
        if !self.observation.active() {
            return Observation::Unchanged;
        }
        if role == LinkRole::Loopback
            || name
                .is_some_and(|name| name != self.name.as_c_str() || attachment != self.attachment)
        {
            return Observation::retirement(self.observation.retire());
        }
        if name.is_some() {
            return Observation::Unchanged;
        }
        Observation::Incomplete
    }

    fn recheck(&self, current: io::Result<LinkRecord<'_>>) -> io::Result<()> {
        current
            .map_err(LinkCheckError::Native)
            .and_then(|record| self.match_record(record))
            .map_err(|error| self.apply(error))
    }

    fn match_record(&self, record: LinkRecord<'_>) -> Result<(), LinkCheckError> {
        Self::compare(
            record.role,
            record.index == self.observation.index()
                && record.name == Some(self.name.as_c_str())
                && record.attachment == self.attachment,
        )
    }

    fn compare(role: LinkRole, matches: bool) -> Result<(), LinkCheckError> {
        if role == LinkRole::Loopback {
            Err(LinkCheckError::Loopback)
        } else if matches {
            Ok(())
        } else {
            Err(LinkCheckError::Changed)
        }
    }

    fn apply(&self, error: LinkCheckError) -> io::Error {
        let error = match error {
            LinkCheckError::Loopback => loopback_ingress(),
            LinkCheckError::Changed => {
                io::Error::new(io::ErrorKind::NotFound, "configured ingress link changed")
            }
            LinkCheckError::Native(error)
                if matches!(error.raw_os_error(), Some(libc::ENODEV | libc::ENXIO)) =>
            {
                error
            }
            LinkCheckError::Native(error) => return error,
        };
        self.observation.retire();
        error
    }
}

#[derive(Debug)]
enum LinkCheckError {
    Changed,
    Loopback,
    Native(io::Error),
}

/// A received UDP datagram paired with its original configured ingress.
/// A numeric interface index alone cannot create this reply path.
#[derive(Debug)]
pub struct AdmittedDatagram {
    datagram: Datagram,
    ingress: IngressObservation,
    reply_sequence: AtomicU64,
}

impl AdmittedDatagram {
    /// Complete UDP body bytes written into the original receive buffer.
    #[must_use]
    pub const fn body_len(&self) -> usize {
        self.datagram.bytes
    }

    pub(super) const fn datagram(&self) -> &Datagram {
        &self.datagram
    }

    pub(super) fn source(&self) -> &Arc<()> {
        &self.ingress.0.source
    }

    /// The watch-owned lifetime observation associated with this datagram.
    #[must_use]
    pub const fn ingress(&self) -> &IngressObservation {
        &self.ingress
    }
}

/// Outcome of applying a native notification to one original watch generation.
#[derive(Debug)]
pub enum Observation {
    /// No observed change in the original association.
    Unchanged,
    /// The reported change retired an original association.
    Retired,
    /// The original watch needs a fresh generation after an incomplete event.
    Incomplete,
}

impl Observation {
    fn retirement(retired: bool) -> Self {
        if retired {
            Self::Retired
        } else {
            Self::Unchanged
        }
    }
}

/// The result of checking the admitted original ingress before one send.
/// The borrow ties the result to its source. Linux can still replace the
/// native interface between userspace validation and kernel route lookup.
pub struct ReplyQualification<'a> {
    admitted: &'a AdmittedDatagram,
    started: std::time::Instant,
}

impl ReplyQualification<'_> {
    pub(super) const fn admitted(&self) -> &AdmittedDatagram {
        self.admitted
    }

    pub(super) fn ensure_fresh(&self) -> io::Result<()> {
        probe::check_probe_age(self.started)
    }
}

/// Immutable names allowed to enter a transparent DNS capture generation.
/// A configured name alone grants no admission or reply authority.
#[derive(Debug)]
pub struct ConfiguredIngresses(Box<[CString]>);

impl ConfiguredIngresses {
    /// Validate a distinct, nonempty list of at most 4096 Linux interface names.
    ///
    /// # Errors
    /// Rejects invalid, duplicate or missing names and reports allocation errors.
    pub fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> io::Result<Self> {
        let mut configured = Vec::new();
        for name in names {
            if name.is_empty()
                || name.len() >= libc::IFNAMSIZ
                || matches!(name, "." | "..")
                || name.bytes().any(|byte| {
                    matches!(byte, 0 | b'/' | b':' | 0x0b) || byte.is_ascii_whitespace()
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid Linux ingress name",
                ));
            }
            if configured.len() == 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "too many configured Linux ingress interfaces",
                ));
            }
            configured.try_reserve(1).map_err(io::Error::other)?;
            configured.push(CString::new(name).map_err(io::Error::other)?);
        }
        configured.sort_unstable();
        if configured.is_empty() || configured.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configured Linux ingress names must be nonempty and distinct",
            ));
        }
        Ok(Self(configured.into_boxed_slice()))
    }

    /// Check whether an interface name is configured, independent of its lifetime.
    /// Pass the name bytes without the terminating NUL.
    #[must_use]
    pub fn contains(&self, name: &[u8]) -> bool {
        self.0
            .binary_search_by(|entry| entry.as_bytes().cmp(name))
            .is_ok()
    }
}

/// Live ingress observations in one retained original network namespace.
///
/// The query socket and namespace descriptor retain namespace identity. Linux
/// interface name/index queries do not retain a net_device generation, however;
/// this check cannot prove atomic continuity through interface replacement and
/// send. It does not recover an original OUTPUT zone after loopback diversion.
#[derive(Debug)]
pub struct Ingresses {
    namespace: File,
    cookie: NetworkNamespace,
    probe: Option<ProbeSocket>,
    source: Arc<()>,
    probe_sequence: AtomicU64,
    links: Vec<Ingress>,
    vrfs: Vec<Arc<Link>>,
    validation_retired: bool,
}

impl Ingresses {
    /// Resolve explicit non-loopback names without changing interface state.
    /// First startup requires every configured interface to be present.
    ///
    /// # Errors
    /// Reports cancellation, timeout, namespace, allocation or native errors.
    /// Do not change the calling thread's namespace during this synchronous call.
    pub fn resolve_before(
        names: &ConfiguredIngresses,
        until: std::time::Instant,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<Self> {
        Self::resolve_inner(names, until, false, cancelled)
    }

    /// Resolve the available configured ingress names within one deadline.
    /// Natively absent names are skipped. Every enrolled interface must pass
    /// the same checks as initial startup, and at least one must be present.
    /// The deadline does not carry over to later active link queries.
    ///
    /// # Errors
    /// Reports native validation, timeout and cancellation failures.
    pub fn resolve_available_before(
        names: &ConfiguredIngresses,
        until: std::time::Instant,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<Self> {
        Self::resolve_inner(names, until, true, cancelled)
    }

    fn resolve_inner(
        names: &ConfiguredIngresses,
        until: std::time::Instant,
        allow_missing: bool,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<Self> {
        let check = || {
            if cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if std::time::Instant::now() >= until {
                return Err(io::ErrorKind::TimedOut.into());
            }
            Ok::<(), io::Error>(())
        };
        check()?;
        let namespace = File::open("/proc/thread-self/ns/net")?;
        let mut query = LinkQuery::open(Some(until))?;
        let source = Arc::new(());
        let mut links: Vec<Ingress> = Vec::new();
        let mut vrfs: Vec<Arc<Link>> = Vec::new();
        links
            .try_reserve_exact(names.0.len())
            .map_err(io::Error::other)?;
        for name in names.0.iter() {
            check()?;
            let record = match query.by_name(name) {
                Err(error)
                    if allow_missing
                        && matches!(error.raw_os_error(), Some(libc::ENODEV | libc::ENXIO)) =>
                {
                    continue;
                }
                result => result?,
            };
            if record.role == LinkRole::Loopback {
                return Err(loopback_ingress());
            }
            let index = record.index;
            let attachment = record.attachment;
            if attachment.vrf {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "configure the original ingress interface under the VRF, not its master",
                ));
            }
            if links
                .iter()
                .any(|ingress| ingress.link.observation.index() == index)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate configured ingress",
                ));
            }
            let mut vrf = None;
            if let Some(master_index) = attachment.master {
                let master = query.by_index(master_index)?;
                if let Some(known) = vrfs
                    .iter()
                    .find(|link| link.observation.index() == master_index)
                {
                    known.recheck(Ok(master))?;
                    vrf = Some(Arc::clone(known));
                } else if master.attachment.vrf {
                    if master.role != LinkRole::Network || master.attachment.master.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "invalid original ingress VRF master",
                        ));
                    }
                    let name = master.name.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "original VRF master name is missing",
                        )
                    })?;
                    vrfs.try_reserve(1).map_err(io::Error::other)?;
                    let master = Arc::new(Link {
                        name: name.to_owned(),
                        attachment: master.attachment,
                        observation: IngressObservation::new(master_index, &source),
                    });
                    vrfs.push(Arc::clone(&master));
                    vrf = Some(master);
                }
            }
            let observation = IngressObservation::with_master(
                index,
                &source,
                vrf.as_ref().map(|master| master.observation.clone()),
            );
            let link = Arc::new(Link {
                name: name.clone(),
                attachment,
                observation,
            });
            // The master lookup did not authorize an intervening attachment change.
            link.recheck(query.by_name(&link.name))?;
            links.push(Ingress { link, vrf });
        }
        if links.is_empty() {
            return Err(io::Error::from_raw_os_error(libc::ENODEV));
        }
        links.sort_unstable_by_key(|ingress| ingress.link.observation.index());
        vrfs.sort_unstable_by_key(|link| link.observation.index());
        same_namespace(&namespace)?;
        check()?;
        query.finish_startup();
        Ok(Self {
            namespace,
            cookie: query.namespace(),
            probe: Some(ProbeSocket::new(query, Arc::clone(&source))),
            source,
            probe_sequence: AtomicU64::new(0),
            links,
            vrfs,
            validation_retired: false,
        })
    }

    /// Kernel namespace of the retained original link query socket.
    #[must_use]
    pub const fn namespace(&self) -> NetworkNamespace {
        self.cookie
    }

    /// Enroll a wildcard UDP listener in this capture source.
    /// The caller supplies the transparent-socket permissions and routing rules.
    ///
    /// # Errors
    /// Preserves namespace, socket-option and bind failures.
    pub fn bind_listener(
        &self,
        family: ListenerFamily,
        port: TransparentPort,
    ) -> io::Result<Listener> {
        self.ensure_current_namespace()?;
        Listener::bind(family, port, self.namespace(), Arc::clone(&self.source))
    }

    /// Consume a pending retirement found during admission or reply validation.
    /// A later link notification cannot revive that observation.
    #[must_use]
    pub fn take_validation_retirement(&mut self) -> bool {
        std::mem::take(&mut self.validation_retired)
    }

    /// Check the same original watch-owned observation without native I/O.
    /// A reused ifindex from another source does not grant reply authority.
    #[must_use]
    pub fn retains(&self, observation: &IngressObservation) -> bool {
        observation.active()
            && self
                .position(observation.0.index.get())
                .is_some_and(|index| self.links[index].link.observation.same(observation))
    }

    /// Apply an original kernel link notification. An observed rename or
    /// loopback role retires the ingress even if a later lookup sees its
    /// original settings. A change without a name requires a fresh watch before
    /// packet I/O can resume.
    pub fn observe(&mut self, event: LinkEvent<'_>) -> Observation {
        let ifindex = match event {
            LinkEvent::Deleted { ifindex } | LinkEvent::Changed { ifindex, .. } => ifindex,
        };
        let link = self
            .position(ifindex)
            .map(|position| &self.links[position].link)
            .or_else(|| {
                self.vrfs
                    .binary_search_by_key(&ifindex, |link| link.observation.index().get())
                    .ok()
                    .map(|position| &self.vrfs[position])
            });
        let Some(link) = link else {
            return Observation::Unchanged;
        };
        match event {
            LinkEvent::Deleted { .. } => Observation::retirement(link.observation.retire()),
            LinkEvent::Changed {
                name,
                role,
                attachment,
                ..
            } => link.observe_change(name, role, attachment),
        }
    }

    /// Check a change notification for a configured ingress or former VRF
    /// master that might be available. The caller must observe the event first.
    /// Only a fresh namespace observation can authorize a replacement generation.
    #[must_use]
    pub fn might_return(&self, configured: &ConfiguredIngresses, event: LinkEvent<'_>) -> bool {
        let LinkEvent::Changed {
            ifindex,
            name: Some(name),
            role: LinkRole::Network,
            attachment,
        } = event
        else {
            return false;
        };
        if attachment.vrf {
            return attachment.master.is_none()
                && self
                    .vrfs
                    .iter()
                    .any(|link| link.name.as_c_str() == name && !link.observation.active());
        }
        configured.contains(name.to_bytes())
            && !self.position(ifindex).is_some_and(|position| {
                let link = &self.links[position].link;
                link.name.as_c_str() == name && link.observation.active()
            })
    }

    /// Compare a fresh observation against the authorized generation without
    /// transferring any ingress or listener authority between their lifetimes.
    #[must_use]
    pub fn introduces_ingress(&self, previous: &Self) -> bool {
        self.links.iter().any(|ingress| {
            let link = &ingress.link;
            link.observation.active()
                && !previous
                    .position(link.observation.index().get())
                    .is_some_and(|position| {
                        let old = &previous.links[position].link;
                        old.observation.active()
                            && old.name == link.name
                            && old.attachment == link.attachment
                    })
        })
    }

    /// Whether at least one original configured ingress remains active.
    #[must_use]
    pub fn has_active(&self) -> bool {
        self.links
            .iter()
            .any(|ingress| ingress.link.observation.active())
    }

    fn position(&self, ifindex: u32) -> Option<usize> {
        self.links
            .binary_search_by_key(&ifindex, |ingress| ingress.link.observation.index().get())
            .ok()
    }

    /// Check namespace fidelity before creating a listener or reply socket.
    /// Already-open sockets and validation queries retain their own namespace.
    ///
    /// # Errors
    /// Reports procfs access errors or a different current thread namespace.
    pub fn ensure_current_namespace(&self) -> io::Result<()> {
        same_namespace(&self.namespace)
    }
}

impl Drop for Ingresses {
    fn drop(&mut self) {
        for link in &self.links {
            link.link.observation.retire();
        }
        for link in &self.vrfs {
            link.observation.retire();
        }
    }
}

fn same_namespace(original: &File) -> io::Result<()> {
    let current = File::open("/proc/thread-self/ns/net")?.metadata()?;
    let original = original.metadata()?;
    if current.dev() == original.dev() && current.ino() == original.ino() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transparent DNS network namespace changed",
        ))
    }
}

fn loopback_ingress() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "scoped ingress cannot be loopback",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transparent_dns::ReplySocket;
    use std::{net::SocketAddr, num::NonZeroU64};

    pub(super) fn vrf_fixture() -> io::Result<Ingresses> {
        let source = Arc::new(());
        let cookie = NetworkNamespace::fixture(NonZeroU64::MIN);
        let slave_index = NonZeroU32::MIN;
        let master_index = NonZeroU32::new(2).ok_or(io::ErrorKind::InvalidInput)?;
        let master = Arc::new(Link {
            name: c"vrf0".to_owned(),
            attachment: LinkAttachment {
                master: None,
                vrf: true,
            },
            observation: IngressObservation::new(master_index, &source),
        });
        let slave = Ingress {
            link: Arc::new(Link {
                name: c"eth0".to_owned(),
                attachment: LinkAttachment {
                    master: Some(master_index),
                    vrf: false,
                },
                observation: IngressObservation::with_master(
                    slave_index,
                    &source,
                    Some(master.observation.clone()),
                ),
            }),
            vrf: Some(Arc::clone(&master)),
        };
        Ok(Ingresses {
            namespace: File::open("/dev/null")?,
            cookie,
            probe: Some(ProbeSocket::new(
                LinkQuery::fixture(OwnedFd::from(File::open("/dev/null")?), cookie),
                Arc::clone(&source),
            )),
            source,
            probe_sequence: AtomicU64::new(0),
            links: vec![slave],
            vrfs: vec![master],
            validation_retired: false,
        })
    }

    #[test]
    fn returning_vrf_requires_a_new_ingress_generation() -> io::Result<()> {
        let configured = ConfiguredIngresses::new(["eth0"])?;
        let mut original = vrf_fixture()?;
        let replacement = vrf_fixture()?;
        let slave = original.links.first().ok_or(io::ErrorKind::NotFound)?;
        let retained = slave.link.observation.clone();
        let master = slave.vrf.as_ref().ok_or(io::ErrorKind::NotFound)?;
        let master_event = LinkEvent::Changed {
            ifindex: master.observation.index().get(),
            name: Some(c"vrf0"),
            role: LinkRole::Network,
            attachment: master.attachment,
        };
        let slave_event = LinkEvent::Changed {
            ifindex: retained.index().get(),
            name: Some(c"eth0"),
            role: LinkRole::Network,
            attachment: slave.link.attachment,
        };
        let deleted = LinkEvent::Deleted {
            ifindex: master.observation.index().get(),
        };
        if !matches!(original.observe(master_event), Observation::Unchanged)
            || original.might_return(&configured, master_event)
            || !matches!(original.observe(slave_event), Observation::Unchanged)
            || original.might_return(&configured, slave_event)
            || replacement.introduces_ingress(&original)
        {
            return Err(io::Error::other(
                "ordinary notifications requested a refresh",
            ));
        }
        if !matches!(original.observe(deleted), Observation::Retired)
            || !original.might_return(&configured, master_event)
            || !original.might_return(&configured, slave_event)
            || !replacement.introduces_ingress(&original)
            || original.retains(&retained)
            || replacement.retains(&retained)
        {
            return Err(io::Error::other(
                "VRF return reused retired capture authority",
            ));
        }
        Ok(())
    }

    #[test]
    fn a_foreign_listener_in_the_same_namespace_cannot_be_read() -> io::Result<()> {
        let cookie = NetworkNamespace::fixture(NonZeroU64::MIN);
        let ingress = Ingresses {
            namespace: File::open("/dev/null")?,
            cookie,
            probe: None,
            source: Arc::new(()),
            probe_sequence: AtomicU64::new(0),
            links: Vec::new(),
            vrfs: Vec::new(),
            validation_retired: false,
        };
        let mut listener = Listener {
            socket: OwnedFd::from(File::open("/dev/null")?),
            family: ListenerFamily::Ipv4,
            namespace: cookie,
            source: Arc::new(()),
        };
        let mut body = [0; 1];
        if !matches!(ingress.receive_unqualified(&listener, &mut body), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        {
            return Err(io::Error::other(
                "a foreign capture reached the native read",
            ));
        }
        listener.source = Arc::clone(&ingress.source);
        if !matches!(ingress.receive_unqualified(&listener, &mut body), Err(error) if error.raw_os_error() == Some(libc::ENOTSOCK))
        {
            return Err(io::Error::other(
                "an enrolled capture skipped the native read",
            ));
        }
        Ok(())
    }

    #[test]
    fn matching_reply_tuple_requires_original_namespace_and_source() -> io::Result<()> {
        let captured = NetworkNamespace::fixture(NonZeroU64::MIN);
        let other_cookie = NonZeroU64::new(2).ok_or_else(|| io::Error::other("fixture cookie"))?;
        let other = NetworkNamespace::fixture(other_cookie);
        let local = SocketAddr::from(([192, 0, 2, 53], 53));
        let interface = NonZeroU32::MIN;
        let source = Arc::new(());
        let foreign = Arc::new(());
        let original_ingress = IngressObservation::new(interface, &source);
        let admit = |namespace, ingress| AdmittedDatagram {
            datagram: Datagram {
                bytes: 1,
                peer: SocketAddr::from(([192, 0, 2, 11], 2000)),
                original: local,
                interface,
                namespace,
            },
            ingress,
            reply_sequence: AtomicU64::new(0),
        };
        let reply = ReplySocket {
            socket: OwnedFd::from(File::open("/dev/null")?),
            local,
            namespace: other,
            source: Arc::clone(&source),
            bound_ingress: original_ingress.clone(),
        };
        let captured = admit(captured, original_ingress.clone());
        if reply.route_matches(&captured)
            || !matches!(
                reply.send(ReplyQualification {
                    admitted: &captured,
                    started: std::time::Instant::now(),
                }, &[0]),
                Err(error) if error.kind() == io::ErrorKind::InvalidInput
            )
        {
            return Err(io::Error::other("a reply matched a foreign namespace"));
        }
        let foreign = admit(other, IngressObservation::new(interface, &foreign));
        if reply.route_matches(&foreign)
            || !matches!(
                reply.send(ReplyQualification {
                    admitted: &foreign,
                    started: std::time::Instant::now(),
                }, &[0]),
                Err(error) if error.kind() == io::ErrorKind::InvalidInput
            )
        {
            return Err(io::Error::other("a reply matched a foreign capture source"));
        }
        let reincarnated = admit(other, IngressObservation::new(interface, &source));
        if reply.route_matches(&reincarnated) {
            return Err(io::Error::other("a reply matched a reused ingress index"));
        }
        if !reply.route_matches(&admit(other, original_ingress)) {
            return Err(io::Error::other(
                "a reply refused the original capture source",
            ));
        }
        Ok(())
    }

    #[test]
    fn observed_rename_retires_a_restored_live_mapping() -> io::Result<()> {
        let index = NonZeroU32::new(7).ok_or(io::ErrorKind::InvalidInput)?;
        let original = c"original";
        let source = Arc::new(());
        let link = Link {
            name: original.to_owned(),
            attachment: LinkAttachment::default(),
            observation: IngressObservation::new(index, &source),
        };
        let retained = link.observation.clone();
        let same_index_from_other_source = IngressObservation::new(index, &Arc::new(()));
        if !matches!(
            link.observe_change(Some(original), LinkRole::Network, link.attachment),
            Observation::Unchanged
        ) || !matches!(
            link.observe_change(None, LinkRole::Network, link.attachment),
            Observation::Incomplete
        ) || !retained.active()
        {
            return Err(io::Error::other("an unchanged mapping retired"));
        }
        if !matches!(
            link.observe_change(Some(c"renamed"), LinkRole::Network, link.attachment),
            Observation::Retired
        ) || !matches!(
            link.observe_change(Some(original), LinkRole::Network, link.attachment),
            Observation::Unchanged
        ) || retained.active()
            || !same_index_from_other_source.active()
        {
            return Err(io::Error::other(
                "a restored mapping revived a retired ingress",
            ));
        }
        Ok(())
    }

    #[test]
    fn ordinary_probe_retires_a_link_whose_original_attachment_changed() -> io::Result<()> {
        let index = NonZeroU32::new(7).ok_or(io::ErrorKind::InvalidInput)?;
        let master = NonZeroU32::new(8).ok_or(io::ErrorKind::InvalidInput)?;
        let name = c"original";
        let original = LinkAttachment::default();
        for attachment in [
            LinkAttachment {
                master: Some(master),
                vrf: false,
            },
            LinkAttachment {
                master: None,
                vrf: true,
            },
        ] {
            let link = Link {
                name: name.to_owned(),
                attachment: original,
                observation: IngressObservation::new(index, &Arc::new(())),
            };
            let observed = |attachment| LinkRecord {
                index,
                name: Some(name),
                role: LinkRole::Network,
                attachment,
            };
            link.recheck(Ok(observed(original)))?;
            if !matches!(link.recheck(Ok(observed(attachment))), Err(error) if error.kind() == io::ErrorKind::NotFound)
                || link.observation.active()
            {
                return Err(io::Error::other(
                    "ordinary probe retained a link after its attachment changed",
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn reported_loopback_retires_the_original_without_a_later_lookup() -> io::Result<()> {
        let index = NonZeroU32::MIN;
        let link = Link {
            name: c"original".to_owned(),
            attachment: LinkAttachment::default(),
            observation: IngressObservation::new(index, &Arc::new(())),
        };
        let event = link.observe_change(Some(c"original"), LinkRole::Loopback, link.attachment);
        if !matches!(event, Observation::Retired) || link.observation.active() {
            return Err(io::Error::other(
                "original loopback observation did not retire",
            ));
        }
        Ok(())
    }

    #[test]
    fn a_direct_lookup_retires_confirmed_loss_and_preserves_ambiguous_errors() -> io::Result<()> {
        let index = NonZeroU32::new(7).ok_or(io::ErrorKind::InvalidInput)?;
        let another = NonZeroU32::new(8).ok_or(io::ErrorKind::InvalidInput)?;
        let source = Arc::new(());
        let replacement = IngressObservation::new(index, &source);
        for observed in [
            Ok(LinkRecord {
                index: another,
                role: LinkRole::Network,
                name: Some(c"original"),
                attachment: LinkAttachment::default(),
            }),
            Ok(LinkRecord {
                index,
                role: LinkRole::Loopback,
                name: Some(c"original"),
                attachment: LinkAttachment::default(),
            }),
            Err(io::Error::from_raw_os_error(libc::ENODEV)),
            Err(io::Error::from_raw_os_error(libc::ENXIO)),
        ] {
            let link = Link {
                name: c"original".to_owned(),
                attachment: LinkAttachment::default(),
                observation: IngressObservation::new(index, &source),
            };
            let admitted = link.observation.clone();
            let interrupted = link.recheck(Err(io::ErrorKind::Interrupted.into()));
            if !matches!(interrupted, Err(error) if error.kind() == io::ErrorKind::Interrupted)
                || !admitted.active()
            {
                return Err(io::Error::other(
                    "an interrupted lookup revoked the ingress",
                ));
            }
            if link.recheck(observed).is_ok() || admitted.active() || !replacement.active() {
                return Err(io::Error::other(
                    "confirmed loss did not retire its exact ingress",
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn vrf_reply_keeps_original_slave_and_master_lifetimes() -> io::Result<()> {
        let master_index = NonZeroU32::new(12).ok_or(io::ErrorKind::InvalidInput)?;
        let first_index = NonZeroU32::new(13).ok_or(io::ErrorKind::InvalidInput)?;
        let second_index = NonZeroU32::new(14).ok_or(io::ErrorKind::InvalidInput)?;
        let namespace = NetworkNamespace::fixture(NonZeroU64::MIN);
        let source = Arc::new(());
        let master = Link {
            name: c"vrf-local".to_owned(),
            attachment: LinkAttachment {
                master: None,
                vrf: true,
            },
            observation: IngressObservation::new(master_index, &source),
        };
        let admit = |index: NonZeroU32| {
            let peer = SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                2048,
                0,
                master_index.get(),
            ));
            let original = SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 53),
                53,
                0,
                index.get(),
            ));
            AdmittedDatagram {
                datagram: Datagram {
                    bytes: 1,
                    peer,
                    original,
                    interface: index,
                    namespace,
                },
                ingress: IngressObservation::with_master(
                    index,
                    &source,
                    Some(master.observation.clone()),
                ),
                reply_sequence: AtomicU64::new(0),
            }
        };
        let first = admit(first_index);
        let second = admit(second_index);
        super::super::address::validate(
            first.datagram.peer,
            first.datagram.original,
            first_index,
            master_index,
        )?;
        if super::super::address::validate(
            first.datagram.peer,
            first.datagram.original,
            first_index,
            first_index,
        )
        .is_ok()
        {
            return Err(io::Error::other(
                "ordinary ingress accepted a VRF-scoped peer",
            ));
        }
        let (binding, owner) = super::super::reply_binding(&first);
        let reply = ReplySocket {
            socket: OwnedFd::from(File::open("/dev/null")?),
            local: binding,
            namespace,
            source: Arc::clone(&source),
            bound_ingress: owner.clone(),
        };
        if !matches!(binding, SocketAddr::V6(address) if address.scope_id() == master_index.get())
            || !reply.route_matches(&first)
            || !reply.route_matches(&second)
        {
            return Err(io::Error::other(
                "VRF routes did not use the shared original bound master",
            ));
        }
        let retired = first.ingress.retire();
        if !retired
            || reply.route_matches(&first)
            || !reply.route_matches(&second)
            || !reply.active()
        {
            return Err(io::Error::other(
                "slave retirement changed a different original slave",
            ));
        }
        if !matches!(
            master.observe_change(Some(c"replacement"), LinkRole::Network, master.attachment),
            Observation::Retired
        ) || reply.route_matches(&second)
            || second.ingress.active()
            || reply.active()
        {
            return Err(io::Error::other(
                "master retirement did not revoke both slaves and the cache",
            ));
        }
        Ok(())
    }

    #[test]
    fn a_same_name_slave_detach_revokes_only_the_original_slave() -> io::Result<()> {
        let slave_index = NonZeroU32::new(6).ok_or(io::ErrorKind::InvalidInput)?;
        let master_index = NonZeroU32::new(7).ok_or(io::ErrorKind::InvalidInput)?;
        let source = Arc::new(());
        let master = IngressObservation::new(master_index, &source);
        let slave = Link {
            name: c"original".to_owned(),
            attachment: LinkAttachment {
                master: Some(master_index),
                vrf: false,
            },
            observation: IngressObservation::with_master(
                slave_index,
                &source,
                Some(master.clone()),
            ),
        };
        if !matches!(
            slave.observe_change(
                Some(&slave.name),
                LinkRole::Network,
                LinkAttachment::default()
            ),
            Observation::Retired
        ) || slave.observation.active()
            || !master.active()
            || !matches!(
                slave.observe_change(Some(&slave.name), LinkRole::Network, slave.attachment),
                Observation::Unchanged
            )
        {
            return Err(io::Error::other(
                "same-name attachment loss did not independently retire the original slave",
            ));
        }
        Ok(())
    }
}
