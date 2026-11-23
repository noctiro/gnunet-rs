//! Offline operation and real exclusive writer ownership with synthetic rows.
use super::*;
use gnunet_namestore::{OwnedRecords, RecordData, RecordFlags, RecordType, Row, SecretKey, Zone};
use gnunet_native::filesystem::Directory;
use gnunet_wire::official::identity::KeyType;
use std::{ffi::OsStr, fs, io, path::PathBuf};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> io::Result<Self> {
        let root = std::env::temp_dir();
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce)?;
        let name = format!("gnunet-dbtool-{:032x}", u128::from_be_bytes(nonce));
        Directory::open(&root)?.create_private_directory(OsStr::new(&name))?;
        Ok(Self(root.join(name)))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Compare real offline generations, inventory and lease conflict"
)]
fn offline_reset_publishes_empty_authority_under_the_service_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Scratch::new()?;
    let limits = Limits::default();
    let path = root.0.join("namestore");
    let options = Options::new(path.clone(), limits, limits.image_bytes)?;
    let (writer, _) = backend::Store::open(
        backend::Namespace::Namestore,
        path,
        backend::Limits {
            body_bytes: limits.image_bytes,
        },
    )?;
    drop(writer);

    // A crash after namespace publication can leave the first image absent.
    assert!(options.open()?.recover().is_err());
    options.open()?.maintain(Maintenance::Initialize)?;
    let (empty, mut store) = options.open()?.recover()?.into_parts();
    assert_eq!(store.generation(), 1);
    assert!(empty.snapshot()?.rows().is_empty());
    let mut fixture = [42; 36];
    fixture[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
    let records = OwnedRecords::serialize(
        &[RecordData {
            expiration_time: u64::MAX,
            record_type: RecordType::A,
            flags: RecordFlags::from_bits_preserve(0),
            data: &[192, 0, 2, 1],
        }],
        limits.record_bytes,
    )?;
    let original = Core::new(
        limits,
        vec![Row::new(
            Zone::new(SecretKey::new(fixture)?),
            b"original".to_vec(),
            records,
            None,
            1,
        )?],
        critical_type,
    )?;
    let receipt = store.commit(
        1,
        snapshot::encode(&original.snapshot()?, limits.image_bytes)?,
    )?;
    assert_eq!(receipt.generation(), 2);
    assert!(
        matches!(options.open(), Err(Error::Storage(error)) if error.stage == "writer-lock" && error.reason == Fault::Conflict)
    );
    drop(store);

    options.open()?.maintain(Maintenance::Initialize)?;
    let (existing, store) = options.open()?.recover()?.into_parts();
    assert_eq!(store.generation(), 2);
    assert_eq!(existing.snapshot()?.rows().len(), 1);
    drop(store);
    options.open()?.maintain(Maintenance::Reset)?;
    let (reset, store) = options.open()?.recover()?.into_parts();
    assert_eq!(store.generation(), 3);
    assert!(reset.snapshot()?.rows().is_empty());
    Ok(())
}
