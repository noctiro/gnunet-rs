//! Bounded default/native and explicitly selected NSS database discovery.
use crate::{Cause, budget::Budget};
use gnunet_native::filesystem::{Directory, EntryInfo, FileIdentity};
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
};
pub(super) struct Profile {
    pub path: PathBuf,
    original: Directory,
    sql: bool,
}
impl Profile {
    fn open(path: PathBuf) -> Result<Option<Self>, Cause> {
        let original = match Directory::open(&path) {
            Ok(original) => original,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let sql = ordinary(&original, "cert9.db")?;
        if !sql && !ordinary(&original, "cert8.db")? {
            return Ok(None);
        }
        original.validate_namespace()?;
        Ok(Some(Self {
            path,
            original,
            sql,
        }))
    }
    pub fn check(&self) -> io::Result<()> {
        self.original.validate_namespace()?;
        let current = Directory::open(&self.path)?;
        if FileIdentity::of(current.as_file())? != FileIdentity::of(self.original.as_file())? {
            return Err(io::Error::other("original NSS profile directory changed"));
        }
        Ok(())
    }
    pub fn database(&self) -> io::Result<OsString> {
        self.check()?;
        let mut value = if self.sql {
            OsString::from("sql:")
        } else {
            OsString::new()
        };
        value.push(&self.path);
        Ok(value)
    }
}
fn ordinary(directory: &Directory, name: &str) -> io::Result<bool> {
    match directory.entry_info(std::ffi::OsStr::new(name)) {
        Ok(EntryInfo::File(_)) => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ordinary NSS database file required",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
pub(super) async fn discover(
    selected: Option<&Path>,
    budget: &Budget,
) -> Result<Vec<Profile>, Cause> {
    if let Some(selected) = selected {
        let profile = Profile::open(selected.to_owned())?
            .ok_or("selected NSS_DATABASE contains no cert9.db or cert8.db")?;
        return Ok(vec![profile]);
    }
    let mut roots = Vec::new();
    #[cfg(windows)]
    if let Some(appdata) = std::env::var_os("APPDATA") {
        roots.push(PathBuf::from(appdata).join("Mozilla/Firefox/Profiles"));
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(PathBuf::from(home).join("Library/Application Support/Firefox/Profiles"));
    }
    #[cfg(unix)]
    if let Some(home) = std::env::var_os("HOME") {
        for browser in ["firefox", "icecat"] {
            roots.push(PathBuf::from(&home).join(".mozilla").join(browser));
        }
    }
    let mut profiles = Vec::new();
    let mut scanned = 0usize;
    for root in roots {
        budget.check().await?;
        let directory = match Directory::open(&root) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for name in directory.entries()? {
            budget.check().await?;
            scanned += 1;
            if scanned > 4096 {
                return Err("NSS profile scan capacity reached".into());
            }
            let name = name?;
            if matches!(directory.entry_info(&name)?, EntryInfo::Directory(_)) {
                push(&mut profiles, root.join(name))?;
            }
        }
    }
    #[cfg(unix)]
    if let Some(home) = std::env::var_os("HOME") {
        push(&mut profiles, PathBuf::from(home).join(".pki/nssdb"))?;
    }
    profiles.sort_by(|a, b| a.path.cmp(&b.path));
    profiles.dedup_by(|a, b| a.path == b.path);
    Ok(profiles)
}
fn push(profiles: &mut Vec<Profile>, path: PathBuf) -> Result<(), Cause> {
    if profiles.len() == 128 {
        return Err("NSS profile capacity reached".into());
    }
    if let Some(profile) = Profile::open(path)? {
        profiles.try_reserve(1)?;
        profiles.push(profile);
    }
    Ok(())
}
