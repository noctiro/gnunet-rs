//! Bounded versioned envelope codec; no platform or service interpretation.
use super::{Failure, HEADER, Limits, Namespace, failure, os};
use gnunet_crypto::hash512_parts;
use gnunet_types::Error;
use std::{
    fs::File,
    io::{Read, Write},
};
use zeroize::Zeroizing;
pub(super) fn read(
    file: &mut File,
    namespace: Namespace,
    limits: Limits,
) -> Result<(u64, Zeroizing<Vec<u8>>), Failure> {
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
    Ok((generation, body))
}

pub(super) fn write(
    file: &mut File,
    namespace: Namespace,
    generation: u64,
    body: &[u8],
) -> Result<(), Failure> {
    let mut head = [0; HEADER];
    head[..8].copy_from_slice(namespace.magic());
    head[8..16].copy_from_slice(&generation.to_be_bytes());
    head[16..24].copy_from_slice(&(body.len() as u64).to_be_bytes());
    let checksum = hash512_parts(&[&head[..24], body]);
    head[24..].copy_from_slice(&checksum);
    file.write_all(&head)
        .map_err(|error| os("write-header", error))?;
    file.write_all(body)
        .map_err(|error| os("write-body", error))
}
