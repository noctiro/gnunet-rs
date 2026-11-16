//! Official local-network address shaping without OS-global state.
#[cfg(unix)]
use std::{
    ffi::OsString,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        net::SocketAddr,
    },
};
use std::{
    io,
    path::{Path, PathBuf},
};
fn native_path_fits(path: &Path) -> bool {
    #[cfg(unix)]
    {
        SocketAddr::from_pathname(path).is_ok()
    }
    #[cfg(windows)]
    {
        socket2::SockAddr::unix(path).is_ok()
    }
}
fn native_path(bytes: Vec<u8>) -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }
    #[cfg(windows)]
    {
        String::from_utf8(bytes)
            .map(PathBuf::from)
            .map_err(|_| io::ErrorKind::InvalidData.into())
    }
}

/// Apply `GNUNET_NETWORK_shorten_unixpath` to the exact expanded byte path.
/// Native short paths are unchanged. Long paths drop complete trailing path
/// components and append the first sixteen official Crockford SHA512 characters
/// without inserting a slash. Native bounds are checked before any socket I/O.
/// Windows AF_UNIX uses valid UTF-8 names; general WTF-8 local paths are refused.
/// The source delimiter remains `/`, including on Windows.
pub fn shorten_unixpath(path: &Path) -> io::Result<PathBuf> {
    #[cfg(unix)]
    let original = path.as_os_str().as_bytes();
    #[cfg(windows)]
    let original = path.to_str().ok_or(io::ErrorKind::InvalidInput)?.as_bytes();
    if original.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if native_path_fits(path) {
        return Ok(path.to_owned());
    }
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let hash = gnunet_crypto::hash512(original);
    let mut suffix = [0; 16];
    for (index, byte) in suffix.iter_mut().enumerate() {
        let mut value = 0_usize;
        for bit in 0..5 {
            let p = index * 5 + bit;
            value = (value << 1) | usize::from((hash[p / 8] >> (7 - p % 8)) & 1);
        }
        *byte = ALPHABET[value];
    }
    let mut prefix = original.to_vec();
    loop {
        let slash = prefix.iter().rposition(|b| *b == b'/').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot shorten Unix path while retaining its official uniqueness suffix",
            )
        })?;
        prefix.truncate(slash);
        let mut candidate = prefix.clone();
        candidate.extend_from_slice(&suffix);
        let candidate = native_path(candidate)?;
        if native_path_fits(&candidate) {
            return Ok(candidate);
        }
    }
}
