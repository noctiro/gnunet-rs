//! Original directories, native access checks and explicit naming barriers.
mod close;
#[cfg(target_os = "freebsd")]
mod freebsd;
mod identity;
pub use close::close;
mod info;
mod links;
mod lock;
#[cfg(windows)]
mod mapping;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
mod mount;
mod open;
mod private_data;
pub mod publication;
mod reader;
mod special;
pub use links::file_links;
pub use lock::ExclusiveFile;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub use mount::MountPoint;
pub use private_data::private_data_file_info;
mod readonly;
mod times;
pub use identity::{FileIdentity, FileIdentityParts, InvalidIdentity};
pub use info::{EntryInfo, FileInfo, file_info};
#[cfg(windows)]
pub use mapping::ReadMapping;
pub use open::open_regular;
pub use reader::FileReader;
pub use readonly::validate_readonly;
mod entries;
pub use entries::Entries;
mod directories;
pub use directories::CreateDirectoryError;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
pub use crate::paths::Directory;
pub use times::{FileTimes, file_times};
#[cfg(unix)]
pub use unix::{Directory, validate_private_file};

#[cfg(windows)]
/// Qualify an ordinary file's process-user owner and restrictive DACL.
/// Administrative principals remain trusted. This grants no namespace authority.
pub fn validate_private_file(file: &std::fs::File) -> std::io::Result<()> {
    if !crate::paths::is_regular_file(file)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ordinary private file required",
        ));
    }
    crate::identity::validate_private(file)
}

/// Qualify an original ordinary private file with exactly one native hard link,
/// returning its complete identity observation. Unix reuses one metadata
/// snapshot for mode, owner, link count and identity. This grants no naming or
/// mutation authority; administrative namespace exclusion stays with the caller.
pub fn private_single_file_identity(file: &std::fs::File) -> std::io::Result<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = unix::private_metadata(file)?;
        if meta.nlink() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "single-link private file required",
            ));
        }
        Ok(FileIdentity::from_metadata(&meta))
    }
    #[cfg(windows)]
    {
        validate_private_file(file)?;
        if file_links(file)? != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "single-link private file required",
            ));
        }
        FileIdentity::of(file)
    }
}
