//! Real included-URL verification and ordinary WAL persistence, without services.
#![expect(
    clippy::panic_in_result_fn,
    reason = "The fixture asserts actual URL refusals, stored bytes and durable reopen"
)]
use gnunet_crypto::{EddsaPrivateKey, EddsaSignature};
use gnunet_hello::{AbsoluteTime, HelloBuilder, Limits, SignatureProfile};
use gnunet_peerstore::{Filter, Storage};
use gnunet_peerstore_host::{
    backend::Wal,
    bootstrap::{Directory, Event, Failure, Import, KEY, SUBSYSTEM, SkipReason, StoreOutcome},
};
use gnunet_types::Error;
use std::{fs, path::PathBuf};

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut id = [0; 16];
        getrandom::fill(&mut id)?;
        let base = fs::canonicalize(std::env::temp_dir())?;
        let name = format!("gnunet-bootstrap-{:032x}", u128::from_le_bytes(id));
        gnunet_native::filesystem::Directory::open(&base)?
            .create_private_directory(std::ffi::OsStr::new(&name))?;
        let root = base.join(name);
        Ok(Self(root))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn url(expiry: u64, invalid: bool) -> Result<Vec<u8>, Error> {
    let key = EddsaPrivateKey::from_seed([73; 32]);
    let mut scratch = [0; 1024];
    let mut builder = HelloBuilder::new(
        &mut scratch,
        Limits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 1024,
            maximum_addresses: 8,
        },
    );
    builder.add_address(b"tcp://192.0.2.73:2086")?;
    let expiry = AbsoluteTime::from_micros(expiry);
    let hello = if invalid {
        builder.with_signature(
            key.public_key(),
            EddsaSignature::from_bytes([0; 64]),
            expiry,
        )
    } else {
        builder.sign(&key, expiry, SignatureProfile::Gnunet029)?
    };
    let mut bytes = vec![0; hello.url_len()?];
    let length = hello.write_url(&mut bytes)?.len();
    bytes.truncate(length);
    Ok(bytes)
}

#[test]
fn shared_import_checks_original_urls_before_durable_multiple_store()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Temporary::new()?;
    let files = root.0.join("hellos");
    fs::create_dir(&files)?;
    fs::write(files.join("valid"), url(900, false)?)?;
    fs::write(files.join("signature"), url(900, true)?)?;
    fs::write(files.join("expired"), url(99, false)?)?;
    fs::write(files.join("oversized"), vec![b'x'; 65536])?;
    let directory = Directory::new(files, 4)?;
    let now = AbsoluteTime::from_micros(100);
    let mut refusals = Vec::new();
    let mut stored = None;
    let wal_path = root.0.join("wal");
    gnunet_native::filesystem::Directory::open(&root.0)?
        .create_private_directory(std::ffi::OsStr::new("wal"))?;
    {
        let mut wal = Wal::open(&wal_path, Default::default())?;
        for event in Import::open(Some(&directory), SignatureProfile::Gnunet029, now)? {
            match event? {
                Event::Included(included) => {
                    assert!(stored.is_none(), "invalid files reached storage");
                    let record = included.record();
                    assert_eq!(record.subsystem, Some(SUBSYSTEM));
                    assert_eq!(record.key, Some(KEY));
                    assert_eq!(record.expiry, 900);
                    assert_eq!(wal.import_hello(&included)?, StoreOutcome::Stored);
                    assert_eq!(wal.sequence(), 1);
                    stored = Some((record.peer, record.value.to_vec()));
                }
                Event::Skipped { reason, .. } => refusals.push(reason),
            }
        }
        assert_eq!(wal.records(), 1);
    }
    assert_eq!(refusals.len(), 3);
    assert!(refusals.contains(&SkipReason::Oversized));
    assert!(refusals.contains(&SkipReason::Invalid(Error::Authentication)));
    assert!(refusals.contains(&SkipReason::Invalid(Error::Timeout)));
    let (peer, value) = stored.ok_or("valid URL was not stored")?;
    let mut wal = Wal::open(&wal_path, Default::default())?;
    let filter = Filter {
        peer: Some(peer),
        subsystem: Some(SUBSYSTEM),
        key: Some(KEY),
    };
    let row = wal
        .next(filter, 0)?
        .ok_or("durable bootstrap record missing")?;
    assert_eq!(row.record.value, value);
    assert_eq!(row.record.expiry, 900);
    assert!(wal.next(filter, row.sequence)?.is_none());
    let sequence = wal.sequence();
    for event in Import::open(Some(&directory), SignatureProfile::Gnunet029, now)? {
        if let Event::Included(included) = event? {
            assert_eq!(wal.import_hello(&included)?, StoreOutcome::AlreadyPresent);
        }
    }
    assert_eq!(wal.records(), 1);
    assert_eq!(
        wal.sequence(),
        sequence,
        "restart import appended a duplicate"
    );
    // Official MULTIPLE remains an append even for an exact duplicate.
    assert_eq!(
        wal.store(
            gnunet_peerstore::Record {
                peer,
                expiry: 900,
                subsystem: Some(SUBSYSTEM),
                key: Some(KEY),
                value: &value,
            },
            false
        )?,
        sequence + 1
    );
    assert_eq!(wal.records(), 2);
    Ok(())
}

#[test]
fn optional_configuration_and_traversal_are_finite() -> Result<(), Box<dyn std::error::Error>> {
    let root = Temporary::new()?;
    let resources = root.0.join("sdk-resources");
    let mut config = gnunet_config::Configuration::default();
    assert!(Directory::configured(&config)?.is_none());
    config.set_value(b"peerstore", b"USE_INCLUDED_HELLOS", Some(b"YES"))?;
    config.set_value(
        b"PATHS",
        b"GNUNET_DATADIR",
        Some(
            resources
                .to_str()
                .ok_or("resource path is not UTF-8")?
                .as_bytes(),
        ),
    )?;
    config.set_value(b"PATHS", b"DATADIR", Some(b"/other-installation"))?;
    let selected = Directory::configured(&config)?.ok_or("enabled resources missing")?;
    assert_eq!(selected.path(), resources.join("hellos"));
    assert_eq!(selected.maximum_entries(), 1024);
    fs::create_dir(root.0.join("non-file-one"))?;
    fs::create_dir(root.0.join("non-file-two"))?;
    let selected = Directory::new(root.0.clone(), 1)?;
    let mut import = Import::open(
        Some(&selected),
        SignatureProfile::Gnunet029,
        AbsoluteTime::UNIX_EPOCH,
    )?;
    assert!(matches!(
        import.next(),
        Some(Err(Failure::Protocol(Error::Capacity)))
    ));
    assert!(import.next().is_none());
    assert!(
        Import::open(None, SignatureProfile::Gnunet029, AbsoluteTime::UNIX_EPOCH)?
            .next()
            .is_none()
    );
    Ok(())
}
