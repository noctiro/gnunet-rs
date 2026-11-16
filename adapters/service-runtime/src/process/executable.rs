//! Explicit Windows image selection without ambient cwd/PATH changes.
use super::EnvironmentSnapshot;
use std::{
    env,
    ffi::{OsStr, OsString},
    fs, io,
    path::{Component, Path, PathBuf, Prefix},
};

pub(super) fn absolute(path: &Path, environment: &EnvironmentSnapshot) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    if let Some(Component::Prefix(prefix)) = path.components().next() {
        let Prefix::Disk(drive) = prefix.kind() else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let same_drive = matches!(environment.current_dir().components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(current) | Prefix::VerbatimDisk(current) if current.eq_ignore_ascii_case(&drive)));
        let base = if same_drive {
            environment.current_dir()
        } else {
            let key = format!("={}:", char::from(drive));
            let base = Path::new(
                environment
                    .variable_os(OsStr::new(&key))?
                    .ok_or(io::ErrorKind::NotFound)?,
            );
            if !base.is_absolute()
                || !matches!(base.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(current) | Prefix::VerbatimDisk(current) if current.eq_ignore_ascii_case(&drive)))
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            base
        };
        return Ok(base.join(
            path.strip_prefix(prefix.as_os_str())
                .map_err(io::Error::other)?,
        ));
    }
    Ok(environment.current_dir().join(path))
}
fn candidate(path: PathBuf) -> io::Result<Option<PathBuf>> {
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => return Ok(Some(path)),
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if path.extension().is_none() {
        let mut suffixed: OsString = path.into_os_string();
        suffixed.push(".exe");
        let path = PathBuf::from(suffixed);
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => return Ok(Some(path)),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}
/// Resolve a Windows executable using only the explicit environment and cwd.
/// Bare names search its PATH; paths retain native root and per-drive semantics.
/// An absent extension permits an `.exe` suffix. No shell, ambient PATH lookup,
/// working-directory mutation or process creation occurs.
pub fn resolve_executable(
    filename: &OsStr,
    environment: &EnvironmentSnapshot,
) -> io::Result<PathBuf> {
    if filename.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let path = Path::new(filename);
    let mut components = path.components();
    let bare =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if !bare {
        return candidate(absolute(path, environment)?)?
            .ok_or_else(|| io::ErrorKind::NotFound.into());
    }
    let paths = environment
        .variable_os(OsStr::new("PATH"))?
        .ok_or(io::ErrorKind::NotFound)?;
    for directory in env::split_paths(paths) {
        if let Some(path) = candidate(absolute(&directory.join(filename), environment)?)? {
            return Ok(path);
        }
    }
    Err(io::ErrorKind::NotFound.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relative_drive_paths_use_only_the_explicit_snapshot() -> io::Result<()> {
        let environment = EnvironmentSnapshot::from_values(
            [("=D:".into(), "D:\\owned".into())],
            PathBuf::from("C:\\base"),
            Default::default(),
        )?;
        if absolute(Path::new("D:child.exe"), &environment)? != Path::new("D:\\owned\\child.exe")
            || absolute(Path::new("\\rooted.exe"), &environment)? != Path::new("C:\\rooted.exe")
            || absolute(Path::new("E:missing.exe"), &environment).is_ok()
        {
            return Err(io::Error::other(
                "native drive resolution escaped its explicit context",
            ));
        }
        Ok(())
    }
}
