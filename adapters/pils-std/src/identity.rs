//! Official raw32 seed with an original private namespace and writer lease.
//! Synchronous preparation completes outside socket polling.
mod namespace;
use gnunet_native::{
    DirectorySync,
    filesystem::{
        EntryInfo, FileInfo, PrivateFileSnapshot, file_info, private_single_file_identity,
    },
};
use gnunet_pils::MasterKey;
use namespace::Namespace;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};
use zeroize::Zeroizing;
#[cfg(test)]
mod tests;

fn exact(file: &File) -> io::Result<FileInfo> {
    let observed = file_info(file)?;
    let info = match observed {
        EntryInfo::File(info) if info.bytes == 32 => info,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("PILS requires an exact raw32 file: observed={observed:?}"),
            ));
        }
    };
    let private = private_single_file_identity(file)?;
    if private != info.identity {
        return Err(io::Error::other(format!(
            "PILS private key observation changed: metadata={info:?}, private_identity={private:?}"
        )));
    }
    Ok(info)
}
struct RawKey {
    file: File,
    bytes: Zeroizing<[u8; 32]>,
    snapshot: PrivateFileSnapshot,
}
fn read_key(namespace: &Namespace, mut file: File) -> io::Result<RawKey> {
    let before = exact(&file)?;
    namespace.verify_key_name(before.identity)?;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Zeroizing::new([0; 32]);
    file.read_exact(bytes.as_mut())?;
    let mut trailing = Zeroizing::new([0; 1]);
    let trailing_bytes = file.read(trailing.as_mut())?;
    if trailing_bytes != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "PILS key changed during read: unexpected_tail={trailing_bytes}, before={before:?}"
            ),
        ));
    }
    let after = exact(&file)?;
    if after != before {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("PILS key changed during read: before={before:?}, after={after:?}"),
        ));
    }
    let snapshot = PrivateFileSnapshot::new(after, bytes.as_ref());
    namespace.verify_key_snapshot(&file, &snapshot)?;
    Ok(RawKey {
        file,
        bytes,
        snapshot,
    })
}
/// Original key and exclusive cooperating-writer fence. Retain this lease until
/// physical streams close and the pure secret owner has been erased.
pub struct KeyLease {
    key: File,
    snapshot: PrivateFileSnapshot,
    namespace: Namespace,
    directory_sync: DirectorySync,
}
impl KeyLease {
    /// Check the original directory and lock, and match the held private file
    /// and its current name to the snapshot captured at the final readback.
    /// A FreeBSD ctime change can trigger exact byte verification without
    /// changing the active key.
    pub fn verify_fence(&self) -> io::Result<()> {
        self.namespace
            .verify_key_snapshot(&self.key, &self.snapshot)
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
    let raw = read_key(&namespace, namespace.open_key()?)?;
    Ok(MasterKey::from_seed(*raw.bytes))
}
/// Load or create the official raw32 seed under a native private writer lock.
/// Only initial absence permits creation. Malformed/foreign objects are refused.
/// File synchronization is required; naming-barrier capability stays explicit.
/// Failed publication/barriers return no key or lease even with uncertain effects.
/// Callers own the namespace and exclude hostile mutation.
pub fn load_or_create(path: &Path) -> io::Result<(MasterKey, KeyLease)> {
    let namespace = Namespace::writer(path)?;
    let file = match namespace.open_key() {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return create(namespace),
        Err(error) => return Err(error),
    };
    let raw = read_key(&namespace, file)?;
    namespace.sync_key(&raw.file)?;
    let directory_sync = namespace.sync()?;
    let reread = read_key(&namespace, raw.file)?;
    if reread.snapshot.initial().identity != raw.snapshot.initial().identity
        || reread.bytes.as_ref() != raw.bytes.as_ref()
    {
        return Err(io::Error::other("PILS synchronized key changed"));
    }
    adopt(namespace, reread, directory_sync)
}
fn create(namespace: Namespace) -> io::Result<(MasterKey, KeyLease)> {
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(seed.as_mut()).map_err(io::Error::other)?;
    let (file, directory_sync) = namespace.publish(&seed)?;
    // Publication consumed the synchronized writer. Read back through its
    // original read lease; no later pathname lookup selects a key.
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
        snapshot: raw.snapshot,
        namespace,
        directory_sync,
    };
    lease.verify_fence()?;
    Ok((MasterKey::from_seed(*raw.bytes), lease))
}
