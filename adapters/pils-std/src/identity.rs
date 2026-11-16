//! Official raw32 seed with an original private namespace and writer lease.
//! Synchronous preparation completes outside socket polling.
mod namespace;
use gnunet_native::{
    DirectorySync,
    filesystem::{EntryInfo, FileIdentity, FileInfo, file_info, private_single_file_identity},
};
use gnunet_pils::MasterKey;
use namespace::Namespace;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};
use zeroize::Zeroizing;

fn exact(file: &File) -> io::Result<FileInfo> {
    let info = match file_info(file)? {
        EntryInfo::File(info) if info.bytes == 32 => info,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PILS requires an exact raw32 file",
            ));
        }
    };
    if private_single_file_identity(file)? != info.identity {
        return Err(io::Error::other("PILS private key observation changed"));
    }
    Ok(info)
}
struct RawKey {
    file: File,
    bytes: Zeroizing<[u8; 32]>,
    identity: FileIdentity,
}
fn read_key(namespace: &Namespace, mut file: File) -> io::Result<RawKey> {
    let before = exact(&file)?;
    namespace.verify_key(&file)?;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Zeroizing::new([0; 32]);
    file.read_exact(bytes.as_mut())?;
    let mut trailing = Zeroizing::new([0; 1]);
    if file.read(trailing.as_mut())? != 0 || exact(&file)? != before {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PILS key changed during read",
        ));
    }
    namespace.verify_key(&file)?;
    Ok(RawKey {
        file,
        bytes,
        identity: before.identity,
    })
}
/// Original key and exclusive cooperating-writer fence. Retain this lease until
/// physical streams close and the pure secret owner has been erased.
pub struct KeyLease {
    key: File,
    identity: FileIdentity,
    namespace: Namespace,
    directory_sync: DirectorySync,
}
impl KeyLease {
    /// Check original directory, lock, key name and current private access.
    /// No key reload, write or synchronization occurs here.
    pub fn verify_fence(&self) -> io::Result<()> {
        self.namespace.verify()?;
        if exact(&self.key)?.identity != self.identity {
            return Err(io::Error::other("PILS held key identity changed"));
        }
        self.namespace.verify_key(&self.key)
    }
    /// Actual naming-barrier capability, independently of successful file sync.
    /// Windows reports Unavailable; that is never a durable-name receipt.
    pub fn directory_sync(&self) -> DirectorySync {
        self.directory_sync
    }
}
/// Read an existing private raw32 seed without creating a lock, key or directory.
/// Callers exclude concurrent namespace administration and file mutation.
pub fn load_existing(path: &Path) -> io::Result<MasterKey> {
    let namespace = Namespace::existing(path)?;
    let raw = read_key(&namespace, namespace.open_key(false)?)?;
    Ok(MasterKey::from_seed(*raw.bytes))
}
/// Load or create the official raw32 seed under a native private writer lock.
/// Only initial absence permits creation. Malformed/foreign objects are refused.
/// File synchronization is required; naming-barrier capability stays explicit.
/// Failed publication/barriers return no key or lease even with uncertain effects.
/// Callers own the namespace and exclude hostile mutation.
pub fn load_or_create(path: &Path) -> io::Result<(MasterKey, KeyLease)> {
    let namespace = Namespace::writer(path)?;
    let file = match namespace.open_key(true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return create(namespace),
        Err(error) => return Err(error),
    };
    let raw = read_key(&namespace, file)?;
    namespace.verify()?;
    raw.file.sync_all()?;
    let directory_sync = namespace.sync()?;
    let reread = read_key(&namespace, raw.file)?;
    if reread.identity != raw.identity || reread.bytes.as_ref() != raw.bytes.as_ref() {
        return Err(io::Error::other("PILS synchronized key changed"));
    }
    adopt(namespace, reread, directory_sync)
}
fn create(namespace: Namespace) -> io::Result<(MasterKey, KeyLease)> {
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(seed.as_mut()).map_err(io::Error::other)?;
    let (name, mut file) = namespace.staging()?;
    let result = (|| {
        // Interrupted writes may have effects; never replay an unknown prefix.
        let mut offset = 0;
        while offset < seed.len() {
            let count = file.write(&seed[offset..])?;
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            offset += count;
        }
        file.sync_all()?;
        exact(&file)?;
        namespace.publish(&name, &file)?;
        namespace.sync()
    })();
    let directory_sync = match result {
        Ok(sync) => sync,
        Err(original) => {
            return match namespace.discard(&name, &file) {
                Ok(()) => Err(original),
                Err(cleanup) => Err(io::Error::other(CreationFailure { original, cleanup })),
            };
        }
    };
    // Retain the published original handle; no pathname reopen changes authority.
    let raw = read_key(&namespace, file)?;
    if raw.bytes.as_ref() != seed.as_ref() {
        return Err(io::Error::other("PILS published key readback changed"));
    }
    adopt(namespace, raw, directory_sync)
}
fn adopt(
    namespace: Namespace,
    raw: RawKey,
    directory_sync: DirectorySync,
) -> io::Result<(MasterKey, KeyLease)> {
    let lease = KeyLease {
        key: raw.file,
        identity: raw.identity,
        namespace,
        directory_sync,
    };
    lease.verify_fence()?;
    Ok((MasterKey::from_seed(*raw.bytes), lease))
}
#[derive(Debug)]
struct CreationFailure {
    original: io::Error,
    cleanup: io::Error,
}
impl std::fmt::Display for CreationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PILS creation: {}; independent staging cleanup: {}",
            self.original, self.cleanup
        )
    }
}
impl std::error::Error for CreationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
