#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible index tests assert actual durable state, checked ciphertext and cancellation boundaries"
)]
use super::*;
use content::TAG_BYTES;
use gnunet_crypto::hash512;
use std::{
    ffi::OsString,
    sync::atomic::{AtomicU64, Ordering},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-index-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn database(&self) -> PathBuf {
        self.0.join("index")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn actual_validation_duplicate_path_sorted_list_cancel_and_durable_unindex() -> TestResult {
    let directory = Directory::new()?;
    let path = directory
        .0
        .join(OsString::from_vec(if cfg!(target_vendor = "apple") {
            b"original-\xc3\xa9".to_vec()
        } else {
            b"original-\xff".to_vec()
        }));
    let other = directory.0.join("same-content");
    let bytes = vec![0x35; BLOCK_BYTES + 13];
    fs::write(&path, &bytes)?;
    fs::write(&other, &bytes)?;
    let file_id = hash512(&bytes);
    let mut index = Index::open(
        directory.database(),
        Limits {
            max_entries: 2,
            ..Limits::default()
        },
    )?;
    assert!(matches!(
        index.register([0; 64], &path, 0, 0),
        Err(Error::HashMismatch)
    ));
    assert!(index.entries()?.next().is_none());
    assert!(matches!(
        index.register_with(file_id, &path, 0, 0, |count| count == 0),
        Err(Error::Protocol(ProtocolError::Cancelled))
    ));
    assert!(index.entries()?.next().is_none());
    let registered = index.register(file_id, &path, 0, 0)?;
    assert!(registered.added);
    assert_eq!(registered.verification, Verification::WholeFileHash);
    let duplicate = index.register(file_id, &other, 0, 0)?;
    assert!(!duplicate.added);
    assert_eq!(
        index
            .entries()?
            .next()
            .ok_or("missing original entry")?
            .filename,
        path.as_os_str().as_bytes()
    );
    let native_device = u64::try_from(u128::from(
        nix::sys::statvfs::fstatvfs(File::open(&path)?)?.filesystem_id(),
    ))?;
    let identifiers = index.register(file_id, &path, native_device, fs::metadata(&path)?.ino())?;
    assert_eq!(identifiers.verification, Verification::Identifiers);
    let empty = directory.0.join("empty");
    fs::write(&empty, [])?;
    let empty_id = hash512(&[]);
    assert!(index.register(empty_id, &empty, 0, 0)?.added);
    let expected = {
        let mut ids = [file_id, empty_id];
        ids.sort_unstable();
        ids
    };
    let first = index
        .entry_after(None)?
        .ok_or("first entry missing")?
        .file_id;
    let second = index
        .entry_after(Some(&first))?
        .ok_or("second entry missing")?
        .file_id;
    assert_eq!([first, second], expected);
    assert!(index.entry_after(Some(&second))?.is_none());
    index.checkpoint()?;
    drop(index);
    let mut index = Index::open(directory.database(), Limits::default())?;
    assert_eq!(index.entries()?.len(), 2);
    assert!(index.remove(&file_id)?);
    assert!(!index.remove(&file_id)?);
    drop(index);
    let mut index = Index::open(directory.database(), Limits::default())?;
    let entries: Vec<_> = index.entries()?.map(|entry| entry.file_id).collect();
    assert_eq!(entries, [empty_id]);
    Ok(())
}

#[test]
fn type6_resolves_real_partial_tail_and_refuses_modified_or_unindexed_sources() -> TestResult {
    let directory = Directory::new()?;
    let path = directory.0.join("source");
    let body: Vec<_> = (0..BLOCK_BYTES + 21)
        .map(|i| (i * 19 + i / BLOCK_BYTES) as u8)
        .collect();
    fs::write(&path, &body)?;
    let file_id = hash512(&body);
    let mut index = Index::open(directory.database(), Limits::default())?;
    index.register(file_id, &path, 0, 0)?;
    let mut expected = vec![0; BLOCK_BYTES + TAG_BYTES];
    let encoded = content::encode_data(&body[BLOCK_BYTES..], &mut expected)?;
    let query = encoded.key().query;
    let length = encoded.bytes().len();
    let record = OnDemand {
        file_id,
        offset: BLOCK_BYTES as u64,
    };
    assert_eq!(OnDemand::decode(&record.encode())?, record);
    assert!(matches!(
        OnDemand::decode(&record.encode()[..71]),
        Err(Error::MalformedRecord)
    ));
    let mut output = vec![0; BLOCK_BYTES + TAG_BYTES];
    let resolved = index.resolve(&query, &record.encode(), &mut output)?;
    assert_eq!(resolved.bytes(), &expected[..length]);
    assert_eq!(resolved.source(), record);
    let mut tiny = [0x5a; 1];
    assert!(matches!(
        index.resolve(&query, &record.encode(), &mut tiny),
        Err(Error::Protocol(ProtocolError::Capacity))
    ));
    assert_eq!(tiny, [0x5a]);
    fs::write(&path, vec![0x91; body.len()])?;
    let error = index
        .resolve(&query, &record.encode(), &mut output)
        .err()
        .ok_or("modified source was accepted")?;
    assert!(matches!(error, Error::BlockMismatch));
    assert!(error.remove_on_demand_record());
    assert!(output[..length].iter().all(|byte| *byte == 0));
    assert!(index.remove(&file_id)?);
    let error = index
        .resolve(&query, &record.encode(), &mut output)
        .err()
        .ok_or("unindexed source was accepted")?;
    assert!(matches!(error, Error::NotIndexed));
    assert!(!error.remove_on_demand_record());
    Ok(())
}
