//! Original public included-HELLO import, before the worker starts.
use crate::{Failure, buffer, reporting::Reports};
use gnunet_peerstore::{self as core, Storage};
use gnunet_peerstore_host::backend::Wal;
use std::{
    fs,
    io::{self, Read},
    path::Path,
};
pub(crate) fn import_hellos(
    wal: &mut Wal,
    path: &Path,
    maximum: usize,
    reports: &Reports<'_, '_>,
) -> Result<(), Failure> {
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut count = 0_usize;
    for e in entries {
        let e = e?;
        if !e.file_type()?.is_file() {
            continue;
        }
        count = count.checked_add(1).ok_or("HELLO file count overflow")?;
        if count > maximum {
            return Err("included HELLO file budget exhausted".into());
        }
        let mut input = Vec::new();
        input.try_reserve_exact(65536)?;
        fs::File::open(e.path())?
            .take(65536)
            .read_to_end(&mut input)?;
        if input.len() == 65536 {
            reports.warning(
                "peerstore.hello.oversized",
                format_args!("peerstore skip oversized HELLO {:?}", e.path()),
            );
            reports.startup_check()?;
            continue;
        }
        let end = input.iter().position(|b| *b == 0).unwrap_or(input.len());
        let input = &input[..end];
        let mut scratch = buffer(65535)?;
        let hello = match gnunet_hello::Hello::parse_url(
            input,
            &mut scratch,
            gnunet_hello::Limits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 65535,
            },
        ) {
            Ok(h) => h,
            Err(error) => {
                reports.warning(
                    "peerstore.hello.invalid",
                    format_args!("peerstore skip invalid HELLO {:?}: {error}", e.path()),
                );
                reports.startup_check()?;
                continue;
            }
        };
        let mut value = buffer(hello.message_len()?)?;
        hello.encode_message(&mut value)?;
        wal.store(
            core::Record {
                peer: *hello.peer().as_bytes(),
                expiry: hello.expiration().as_micros(),
                subsystem: Some(b"peerstore"),
                key: Some(b"peerstore-peer-hello-uri"),
                value: &value,
            },
            false,
        )?;
    }
    Ok(())
}
