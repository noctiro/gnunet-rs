//! Official local-network address shaping without OS-global state.
use std::{
    ffi::OsString,
    io,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        net::SocketAddr,
    },
    path::{Path, PathBuf},
};

/// Apply `GNUNET_NETWORK_shorten_unixpath` to the exact expanded byte path.
/// Native short paths are unchanged. Long paths drop complete trailing path
/// components and append the first sixteen official Crockford SHA512 characters
/// without inserting a slash. The native sockaddr length is checked by std.
pub fn shorten_unixpath(path: &Path) -> io::Result<PathBuf> {
    let original = path.as_os_str().as_bytes();
    if original.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if SocketAddr::from_pathname(path).is_ok() {
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
        let candidate = PathBuf::from(OsString::from_vec(candidate));
        if SocketAddr::from_pathname(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
}
