//! Native qualification of persistent interfaces before restart cleanup.
use super::{
    identity, ioctl,
    lifetime::{InterfaceLease, Lifetime},
};
use crate::{
    DeviceHandle,
    platform::{control_socket, index, request},
    recovery::Record,
};
use gnunet_native::filesystem::FileIdentity;
use std::{
    error::Error,
    fmt, io,
    mem::size_of,
    os::{
        fd::OwnedFd,
        unix::fs::{FileTypeExt, OpenOptionsExt},
    },
};
const SET_DESCRIPTION: libc::c_ulong = nix::request_code_write!(b'i', 41, size_of::<libc::ifreq>());
const GET_DESCRIPTION: libc::c_ulong =
    nix::request_code_readwrite!(b'i', 42, size_of::<libc::ifreq>());
use crate::recovery::marker;
pub(crate) mod discover;
mod names;
fn mismatch() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "persistent TUN no longer matches its original recovery identity",
    )
}
pub(super) fn install(
    fd: &OwnedFd,
    lease: &mut InterfaceLease,
    device: &str,
    requested_birth: Option<[u8; 32]>,
) -> io::Result<()> {
    let birth = match requested_birth {
        Some(birth) => birth,
        None => {
            let mut bytes = [0; 32];
            gnunet_native::entropy::fill(&mut bytes)?;
            bytes
        }
    };
    if birth == [0; 32] {
        return Err(io::Error::other("zero persistent TUN correlation marker"));
    }
    let mut device_name = [0; 16];
    if !crate::recovery::canonical_unit(device) || device.len() >= device_name.len() {
        return Err(mismatch());
    }
    device_name[..device.len()].copy_from_slice(device.as_bytes());
    let stat = nix::sys::stat::fstat(fd)?;
    let record = Record {
        name: lease.name,
        device: device_name,
        index: lease.index.ok_or_else(mismatch)?,
        birth,
        file: FileIdentity::unix(stat.st_dev, stat.st_ino),
    };
    publish(lease, record)
}
fn publish(lease: &mut InterfaceLease, record: Record) -> io::Result<()> {
    let mut bytes = marker::encode(&record);
    let mut req = request(lease.name()?)?;
    req.ifr_ifru.ifru_buffer = libc::ifreq_buffer {
        length: bytes.len(),
        buffer: bytes.as_mut_ptr().cast(),
    };
    ioctl(&lease.socket, SET_DESCRIPTION, &mut req)?;
    check_marker_at(&lease.socket, lease.name()?, &record)?;
    lease.recovery = Some(Box::new(record));
    Ok(())
}
pub(super) fn install_created(
    lease: &mut InterfaceLease,
    device: &str,
    birth: [u8; 32],
) -> io::Result<()> {
    if !crate::recovery::canonical_unit(device) || device.len() >= 16 || birth == [0; 32] {
        return Err(mismatch());
    }
    let metadata = std::fs::symlink_metadata(format!("/dev/{device}"))?;
    if !metadata.file_type().is_char_device() {
        return Err(mismatch());
    }
    let mut device_name = [0; 16];
    device_name[..device.len()].copy_from_slice(device.as_bytes());
    let record = Record {
        name: lease.name,
        device: device_name,
        index: lease.index.ok_or_else(mismatch)?,
        birth,
        file: FileIdentity::from_metadata(&metadata),
    };
    publish(lease, record)
}
fn read_marker_at(socket: &OwnedFd, name: &str) -> io::Result<Option<Record>> {
    let mut bytes = [0; marker::BYTES];
    let original = bytes.as_mut_ptr().cast();
    let mut req = request(name)?;
    req.ifr_ifru.ifru_buffer = libc::ifreq_buffer {
        length: bytes.len(),
        buffer: original,
    };
    ioctl(socket, GET_DESCRIPTION, &mut req)?;
    #[expect(
        unsafe_code,
        reason = "Successful SIOCGIFDESCR initializes ifru_buffer; returned pointers are compared and never dereferenced"
    )]
    // SAFETY: exact getter initialized the union; only the original owned buffer is read.
    let returned = unsafe { req.ifr_ifru.ifru_buffer };
    if returned.buffer.is_null() {
        return Ok(None);
    }
    if returned.buffer != original {
        return Err(mismatch());
    }
    if returned.length != bytes.len() {
        return Ok(None);
    }
    Ok(marker::decode(&bytes))
}
pub(super) fn check_marker_at(socket: &OwnedFd, name: &str, record: &Record) -> io::Result<()> {
    match read_marker_at(socket, name)? {
        Some(actual) if actual.same_identity(record) => Ok(()),
        _ => Err(mismatch()),
    }
}
pub(super) fn locate(socket: &OwnedFd, record: &Record) -> io::Result<Option<[u8; 16]>> {
    let Some(name) = names::locate(record.index)? else {
        return Ok(None);
    };
    check_marker_at(socket, crate::recovery::read_name(&name)?, record)?;
    Ok(Some(name))
}
pub(super) fn check_created(fd: &OwnedFd, lease: &InterfaceLease) -> io::Result<()> {
    let actual = identity(fd)?;
    if actual.name != lease.name()? || Some(actual.index) != lease.index {
        return Err(mismatch());
    }
    if let Some(record) = &lease.recovery {
        let stat = nix::sys::stat::fstat(fd)?;
        if FileIdentity::unix(stat.st_dev, stat.st_ino) != record.file {
            return Err(mismatch());
        }
        check_marker_at(&lease.socket, &actual.name, record)?;
    }
    Ok(())
}
/// An absent-name observation or a newly reacquired, qualified exclusive device.
/// Absence is time-local; it does not certify an earlier destroy acknowledgement.
#[derive(Debug)]
pub enum Observation {
    /// No interface currently occupies the recorded index; no device was opened.
    Absent(Record),
    /// The original selector matched a physically opened native TUN.
    Ready(Cleanup),
}
/// Fresh physical cleanup ownership. Drop releases its FD and leaves persistent
/// cleanup outstanding; callers must explicitly call [`Self::close`].
#[derive(Debug)]
#[must_use]
pub struct Cleanup {
    handle: DeviceHandle,
}
impl Cleanup {
    /// Close the reacquired FD once, then destroy the qualified interface.
    /// Concurrent administrative/device access must remain excluded. Native
    /// destruction may block; this is not a cancellable async operation.
    ///
    /// # Errors
    /// Retains independent close and interface errors in `DeviceCleanupError`.
    pub fn close(self) -> io::Result<()> {
        self.handle.close()
    }
    pub(crate) fn into_handle(self) -> DeviceHandle {
        self.handle
    }
}
/// Failed recovery keeps the selector and original native/identity error.
#[derive(Debug)]
pub struct Failure {
    record: Box<Record>,
    error: io::Error,
    opened: Option<DeviceHandle>,
}
impl Failure {
    /// Inspect the unchanged selector without acquiring any native authority.
    #[must_use]
    pub fn record(&self) -> &Record {
        &self.record
    }
    /// Original native or qualification failure.
    #[must_use]
    pub const fn error(&self) -> &io::Error {
        &self.error
    }
    /// Take the actual descriptor acquired before failed qualification, if any.
    /// It has packet ownership only and cannot destroy an interface. Close it
    /// explicitly before retrying; descriptor-close errors remain observable.
    #[must_use]
    pub fn take_opened(&mut self) -> Option<DeviceHandle> {
        self.opened.take()
    }
    /// Recover the selector, original cause and unqualified descriptor owner.
    /// No retry is initiated.
    #[must_use]
    pub fn into_parts(self) -> (Record, io::Error, Option<DeviceHandle>) {
        (*self.record, self.error, self.opened)
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "persistent TUN recovery: {}", self.error)
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}
struct Qualified {
    name: [u8; 16],
    socket: OwnedFd,
    handle: DeviceHandle,
    lifetime: Lifetime,
}
struct QualificationFailure {
    error: io::Error,
    opened: Option<DeviceHandle>,
}
impl From<io::Error> for QualificationFailure {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            opened: None,
        }
    }
}
fn qualify(record: &Record) -> Result<Option<Qualified>, QualificationFailure> {
    let socket: OwnedFd = control_socket()?.into();
    let Some(actual_name) = locate(&socket, record)? else {
        return Ok(None);
    };
    let name = crate::recovery::read_name(&actual_name)?;
    // Devfs open can clone an absent tunN. Inspect the existing character node
    // first, under the caller's serialized administration/device-access scope.
    let path = format!("/dev/{}", record.device_name()?);
    let before = std::fs::symlink_metadata(&path)?;
    if !before.file_type().is_char_device() || FileIdentity::from_metadata(&before) != record.file {
        return Err(mismatch().into());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    let handle = DeviceHandle::from_fd(file.into());
    let checked = (|| -> io::Result<Lifetime> {
        let stat = nix::sys::stat::fstat(handle.fd()?)?;
        if FileIdentity::unix(stat.st_dev, stat.st_ino) != record.file {
            return Err(mismatch());
        }
        let info = identity(handle.fd()?)?;
        if info.name != name || info.index != record.index {
            return Err(mismatch());
        }
        check_marker_at(&socket, name, record)?;
        if index(name)? != record.index {
            return Err(mismatch());
        }
        match super::read_int(handle.fd()?, super::lifetime::GET_TRANSIENT) {
            Ok(0) => Ok(Lifetime::Manual),
            Ok(1) => Ok(Lifetime::Transient),
            Ok(_) => Err(mismatch()),
            Err(error) if error.raw_os_error() == Some(libc::ENOTTY) => Ok(Lifetime::Manual),
            Err(error) => Err(error),
        }
    })();
    match checked {
        Ok(lifetime) => Ok(Some(Qualified {
            name: actual_name,
            socket,
            handle,
            lifetime,
        })),
        Err(error) => Err(QualificationFailure {
            error,
            opened: Some(handle),
        }),
    }
}
pub(crate) fn recover(record: Record) -> Result<Observation, Failure> {
    match qualify(&record) {
        Ok(None) => Ok(Observation::Absent(record)),
        Ok(Some(Qualified {
            name,
            socket,
            mut handle,
            lifetime,
        })) => {
            let lease = InterfaceLease::recovered(socket, record, lifetime, name);
            handle.interface = Some(lease);
            Ok(Observation::Ready(Cleanup { handle }))
        }
        Err(QualificationFailure { error, opened }) => Err(Failure {
            record: Box::new(record),
            error,
            opened,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn description_abi_matches_native_headers() -> io::Result<()> {
        crate::native_abi::check(
            "freebsd_tun_recovery_abi.c",
            &[
                SET_DESCRIPTION,
                GET_DESCRIPTION,
                size_of::<libc::ifreq_buffer>() as u64,
                std::mem::offset_of!(libc::ifreq_buffer, length) as u64,
                std::mem::offset_of!(libc::ifreq_buffer, buffer) as u64,
            ],
        )
    }
    #[test]
    fn missing_original_index_returns_only_the_unchanged_selector() -> io::Result<()> {
        let mut random = [0; 6];
        gnunet_native::entropy::fill(&mut random)?;
        let name = format!(
            "gn{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            random[0], random[1], random[2], random[3], random[4], random[5]
        );
        let mut bytes = [0; 16];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        let mut device = [0; 16];
        device[..5].copy_from_slice(b"tun17");
        // Metadata-only selector. A missing index must not cause /dev/tun17 to
        // be opened/cloned or yield administrative ownership of any interface.
        let inventory = names::snapshot()?;
        let record = Record {
            name: bytes,
            device,
            index: (1..=(names::MAXIMUM as u32 + 1))
                .find(|index| !inventory.iter().any(|row| row.index == *index))
                .ok_or_else(|| io::Error::other("no unused bounded native index"))?,
            birth: [3; 32],
            file: FileIdentity::unix(7, 123),
        };
        let expected = record.clone();
        match record.recover().map_err(io::Error::other)? {
            Observation::Absent(actual) if actual == expected => Ok(()),
            _ => Err(io::Error::other(
                "missing interface acquired cleanup authority",
            )),
        }
    }
}
