//! Shared original-source observations and native/private/protocol path boundaries.
use gnunet_native::filesystem::{Directory, EntryInfo, FileInfo};
use std::{
    borrow::Cow,
    ffi::OsStr,
    fs::File,
    io,
    path::{Component, Path, PathBuf},
};

pub(crate) fn file_info(file: &File) -> io::Result<FileInfo> {
    match gnunet_native::filesystem::file_info(file)? {
        EntryInfo::File(info) => Ok(info),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ordinary source file required",
        )),
    }
}

pub(crate) fn named_info(path: &Path) -> io::Result<FileInfo> {
    let (parent, name) = selected(path)?;
    match parent.entry_info(name)? {
        EntryInfo::File(info) => Ok(info),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ordinary original source entry required",
        )),
    }
}

pub(crate) fn open_exact(path: &Path) -> io::Result<File> {
    let (parent, name) = selected(path)?;
    parent.open_file(name)
}

fn selected(path: &Path) -> io::Result<(Directory, &OsStr)> {
    let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((Directory::open(parent)?, name))
}

pub(crate) fn absolute_normalized(path: &Path) -> bool {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return false;
    }
    let mut rebuilt = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                rebuilt.push(component.as_os_str())
            }
            _ => return false,
        }
    }
    rebuilt.as_os_str() == path.as_os_str()
}

pub(crate) fn owned_path(path: &Path) -> Result<PathBuf, gnunet_types::Error> {
    let mut owned = PathBuf::new();
    owned
        .try_reserve(path.as_os_str().len())
        .map_err(|_| gnunet_types::Error::Capacity)?;
    owned.push(path);
    Ok(owned)
}

pub(crate) fn protocol_filename(path: &Path) -> io::Result<Cow<'_, [u8]>> {
    #[cfg(unix)]
    {
        Ok(gnunet_native::os_bytes::encode(path.as_os_str()))
    }
    #[cfg(windows)]
    {
        path.to_str()
            .map(|text| Cow::Borrowed(text.as_bytes()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "protocol filename requires Unicode on Windows",
                )
            })
    }
}
