//! Bounded versioned envelope codec; no platform or service interpretation.
use super::{Failure, HEADER, Limits, Namespace, failure, os};
use gnunet_crypto::hash512_parts;
use gnunet_native::filesystem::{Directory, PrivateFileSnapshot, private_data_file_info};
use gnunet_types::Error;
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};
use zeroize::Zeroizing;

pub(super) struct Decoded {
    pub(super) generation: u64,
    pub(super) body: Zeroizing<Vec<u8>>,
    pub(super) header: [u8; HEADER],
}

pub(super) fn read(
    file: &mut File,
    namespace: Namespace,
    limits: Limits,
) -> Result<Decoded, Failure> {
    let len = file.metadata().map_err(|e| os("image-size", e))?.len();
    if len < HEADER as u64 || len > limits.body_bytes as u64 + HEADER as u64 {
        return Err(failure("image-size", Error::Storage, None));
    }
    let mut head = [0u8; HEADER];
    file.read_exact(&mut head)
        .map_err(|e| os("image-header", e))?;
    let generation = u64::from_be_bytes(
        head[8..16]
            .try_into()
            .map_err(|_| failure("image-header", Error::Storage, None))?,
    );
    let body_len = u64::from_be_bytes(
        head[16..24]
            .try_into()
            .map_err(|_| failure("image-header", Error::Storage, None))?,
    );
    if &head[..8] != namespace.magic() || generation == 0 || body_len != len - HEADER as u64 {
        return Err(failure("image-format", Error::Storage, None));
    }
    let mut body = Zeroizing::new(Vec::new());
    body.try_reserve_exact(body_len as usize)
        .map_err(|_| failure("load-allocation", Error::Capacity, None))?;
    body.resize(body_len as usize, 0);
    file.read_exact(&mut body)
        .map_err(|e| os("image-body", e))?;
    if hash512_parts(&[&head[..24], &body]) != head[24..88] {
        return Err(failure("image-checksum", Error::Storage, None));
    }
    Ok(Decoded {
        generation,
        body,
        header: head,
    })
}

pub(super) fn write(
    file: &mut File,
    namespace: Namespace,
    generation: u64,
    body: &[u8],
) -> Result<[u8; HEADER], Failure> {
    let mut head = [0; HEADER];
    head[..8].copy_from_slice(namespace.magic());
    head[8..16].copy_from_slice(&generation.to_be_bytes());
    head[16..24].copy_from_slice(&(body.len() as u64).to_be_bytes());
    let checksum = hash512_parts(&[&head[..24], body]);
    head[24..].copy_from_slice(&checksum);
    file.write_all(&head)
        .map_err(|error| os("write-header", error))?;
    file.write_all(body)
        .map_err(|error| os("write-body", error))?;
    Ok(head)
}

/// Compare the exact prepared image through the retained original reader.
/// One bounded scratch buffer suffices even for the largest configured image.
pub(super) fn verify(
    directory: &Directory,
    name: &OsStr,
    file: &mut File,
    header: &[u8; HEADER],
    body: &[u8],
) -> Result<(), Failure> {
    let before = private_data_file_info(file).map_err(|e| os("readback-policy", e))?;
    if before.bytes != (HEADER + body.len()) as u64 {
        return Err(failure("readback-mismatch", Error::Storage, None));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| os("readback-seek", e))?;
    let mut observed = [0; HEADER];
    file.read_exact(&mut observed)
        .map_err(|e| os("readback-header", e))?;
    if &observed != header {
        return Err(failure("readback-mismatch", Error::Storage, None));
    }
    let mut buffer = Zeroizing::new([0; 8192]);
    for expected in body.chunks(buffer.len()) {
        let chunk = &mut buffer[..expected.len()];
        file.read_exact(chunk).map_err(|e| os("readback-body", e))?;
        if chunk != expected {
            return Err(failure("readback-mismatch", Error::Storage, None));
        }
    }
    if file
        .read(&mut buffer[..1])
        .map_err(|e| os("readback-body", e))?
        != 0
    {
        return Err(failure("readback-mismatch", Error::Storage, None));
    }
    let after = private_data_file_info(file).map_err(|e| os("readback-policy", e))?;
    if after != before {
        if cfg!(target_os = "freebsd") {
            // Reuse the native fence: a ctime-only advance requires a new
            // stable content read from the original file at the selected name.
            let digest = gnunet_crypto::hash256_parts(&[header, body]);
            return PrivateFileSnapshot::with_sha256(before, digest)
                .verify(directory, name, file)
                .map_err(|e| os("readback-drift", e));
        }
        return Err(os(
            "readback-drift",
            std::io::Error::other(format!(
                "snapshot original metadata changed: before={before:?}, after={after:?}"
            )),
        ));
    }
    Ok(())
}
