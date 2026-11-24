//! Windows filename semantics, separate from GNUnet's shared value grammar.
use super::*;

pub(super) fn decode_filename(input: &[u8]) -> Result<PathBuf, Error> {
    // GNUnet path expressions use '/' after variable references. Win32
    // accepts that separator on ordinary paths but not on verbatim paths.
    if let Some(tail) = input.strip_prefix(br"\\?\")
        && tail.contains(&b'/')
    {
        let disk = tail.first().is_some_and(u8::is_ascii_alphabetic)
            && tail
                .get(1..3)
                .is_some_and(|suffix| matches!(suffix, b":\\" | b":/"));
        let unc = tail.get(..4).is_some_and(|prefix| {
            prefix.eq_ignore_ascii_case(b"UNC\\") || prefix.eq_ignore_ascii_case(b"UNC/")
        });
        if disk || unc {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(input.len())
                .map_err(|_| Error::Capacity)?;
            bytes.extend(
                input
                    .iter()
                    .map(|&byte| if byte == b'/' { b'\\' } else { byte }),
            );
            return bytes_path(&bytes);
        }
    }
    bytes_path(input)
}

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
        decode_filename(&bytes)?
    } else {
        decode_filename(input)?
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
