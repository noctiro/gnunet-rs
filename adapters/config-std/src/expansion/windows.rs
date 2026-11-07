//! Windows filename semantics, separate from GNUnet's shared value grammar.
use super::*;

pub(super) fn filename(
    config: &Configuration,
    input: &[u8],
    environment: &impl Environment,
    observer: Option<crate::diagnostic::BorrowedObserver<'_>>,
) -> Result<PathBuf, Error> {
    let path = if let Some(suffix) = input.strip_prefix(b"~") {
        let home = environment
            .home_dir()
            .map_err(|error| crate::io_error("<home directory>", error))?
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| config.missing_home(observer))?;
        let base = path_bytes(&home)?;
        let suffix = suffix
            .strip_prefix(b"/")
            .or_else(|| suffix.strip_prefix(b"\\"))
            .unwrap_or(suffix);
        let separator = !base.ends_with(b"/") && !base.ends_with(b"\\");
        let size = base
            .len()
            .checked_add(suffix.len())
            .and_then(|n| n.checked_add(usize::from(separator)))
            .filter(|n| *n <= config.limits.max_expanded_bytes)
            .ok_or(Error::Capacity)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(base);
        if separator {
            bytes.push(b'\\');
        }
        // Append bytes rather than PathBuf::push: a prefix inside ~'s suffix
        // must not replace the selected home directory.
        bytes.extend_from_slice(suffix);
        bytes_path(&bytes)?
    } else {
        bytes_path(input)?
    };
    let absolute = if path.is_absolute() {
        path
    } else {
        environment
            .absolute_path(&path)
            .map_err(|error| crate::io_error(&path, error))?
    };
    if !absolute.is_absolute() {
        return Err(crate::io_error(
            absolute,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "filename context returned a relative path",
            ),
        ));
    }
    if path_bytes(&absolute)?.len() > config.limits.max_expanded_bytes {
        return Err(Error::Capacity);
    }
    Ok(absolute)
}
