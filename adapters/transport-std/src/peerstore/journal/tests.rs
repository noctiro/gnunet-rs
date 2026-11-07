//! Real temp-directory component cases, without IPC service or Node execution.
use super::codec::record_bytes;
use super::*;
use gnunet_crypto::EddsaPrivateKey;
struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn directory() -> Result<Cleanup, Error> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| Error::Entropy)?;
    let path = std::env::temp_dir().join(format!(
        "gnunet-own-journal-{:032x}",
        u128::from_be_bytes(random)
    ));
    fs::create_dir(&path).map_err(|_| Error::Storage)?;
    Ok(Cleanup(path))
}
fn record(peer: PeerId, value: &[u8]) -> Record {
    Record {
        peer,
        subsystem: own_wire::SUBSYSTEM.to_vec(),
        key: own_wire::KEY.to_vec(),
        value: value.to_vec(),
        expiry: 999,
    }
}
fn address(key: &EddsaPrivateKey, generated: u64) -> Result<Vec<u8>, Error> {
    let native = b"tcp-127.0.0.1:2086";
    let region = own_wire::signed_region(native, generated)?;
    let row = own_wire::AddressRecord {
        signature: key.sign(29, &region)?,
        generated,
        network: 1,
        native,
    };
    let mut value = vec![0; row.encoded_len()?];
    row.encode(&mut value)?;
    Ok(value)
}
fn hello(key: &EddsaPrivateKey, empty: bool) -> Result<Vec<u8>, Error> {
    hello_with_profile(key, empty, gnunet_hello::SignatureProfile::Gnunet029)
}
fn hello_with_profile(
    key: &EddsaPrivateKey,
    empty: bool,
    profile: gnunet_hello::SignatureProfile,
) -> Result<Vec<u8>, Error> {
    let mut storage = [0; 1024];
    let mut builder = gnunet_hello::HelloBuilder::new(
        &mut storage,
        gnunet_hello::Limits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 1024,
            maximum_addresses: 8,
        },
    );
    if !empty {
        builder.add_address(b"tcp://127.0.0.1:2086")?;
    }
    let hello = builder.sign(key, gnunet_hello::AbsoluteTime::from_micros(999), profile)?;
    let mut value = vec![0; hello.message_len()?];
    hello.encode_message(&mut value)?;
    Ok(value)
}
#[test]
fn profile_managed_reopen_and_public_remote_discovery_have_independent_authority()
-> Result<(), Error> {
    use crate::discovery::{AddressSource, VisitControl};
    use core::num::NonZeroUsize;
    use gnunet_hello::SignatureProfile::{DeterministicPidDerivation, Gnunet029};
    let d = directory()?;
    let path = d.0.join("profile-db");
    let profiles = HelloProfiles {
        managed: DeterministicPidDerivation,
        discovery: Gnunet029,
    };
    let local_key = EddsaPrivateKey::from_seed([17; 32]);
    let local = PeerId(*local_key.public_key().as_bytes());
    let local_hello = hello_with_profile(&local_key, false, profiles.managed)?;
    let remote_key = EddsaPrivateKey::from_seed([19; 32]);
    let remote = PeerId(*remote_key.public_key().as_bytes());
    let remote_hello = hello_with_profile(&remote_key, false, profiles.discovery)?;
    let mut j = Journal::open_with_profiles(&path, profiles)?;
    j.reserve_managed(ManagedQuota {
        records: 1,
        bytes: 8192,
    })?;
    // Public values are not admitted as trusted managed HELLOs, even when their
    // bytes are not parseable under any HELLO profile.
    j.store(
        Record {
            peer: remote,
            subsystem: b"peerstore".to_vec(),
            key: b"peerstore-peer-hello-uri".to_vec(),
            value: vec![0, 255],
            expiry: 999,
        },
        false,
    )?;
    j.store(
        Record {
            peer: remote,
            subsystem: b"peerstore".to_vec(),
            key: b"peerstore-peer-hello-uri".to_vec(),
            value: remote_hello.clone(),
            expiry: 999,
        },
        false,
    )?;
    let mut tx = j.prepare_managed(local, &[], Some(&local_hello), 101)?;
    assert_eq!(j.commit(&mut tx), CommitOutcome::Committed);
    drop(tx);
    drop(j);
    assert!(matches!(Journal::open(&path), Err(Error::Authentication)));
    let mut j = Journal::open_with_profiles(&path, profiles)?;
    assert_eq!(j.records().filter(|r| r.peer == remote).count(), 2);
    assert!(
        j.records()
            .any(|r| r.peer == local && r.value == local_hello)
    );
    let mut seen = Vec::new();
    let visit = j.visit(
        remote,
        101,
        0,
        NonZeroUsize::new(8).ok_or(Error::InvalidInput)?,
        &mut |address| {
            seen.push(address.to_vec());
            Ok(VisitControl::Continue)
        },
    )?;
    assert!(visit.finished);
    assert_eq!(seen, [b"tcp-127.0.0.1:2086".to_vec()]);
    drop(j);
    let mut j = Journal::open_with_profiles(
        &path,
        HelloProfiles {
            managed: profiles.managed,
            discovery: DeterministicPidDerivation,
        },
    )?;
    let mut count = 0;
    let visit = j.visit(
        remote,
        101,
        0,
        NonZeroUsize::new(8).ok_or(Error::InvalidInput)?,
        &mut |_| {
            count += 1;
            Ok(VisitControl::Continue)
        },
    )?;
    assert!(visit.finished);
    assert_eq!(count, 0);
    assert!(
        j.records()
            .any(|r| r.peer == remote && r.value == remote_hello)
    );
    Ok(())
}
fn refuse_rename(journal: &Journal, step: TestStep) -> io::Result<()> {
    if step == TestStep::BeforeRename {
        fs::create_dir(&journal.path)?;
    }
    Ok(())
}
fn obstruct_readback(journal: &Journal, step: TestStep) -> io::Result<()> {
    if step == TestStep::AfterRename {
        fs::rename(
            &journal.path,
            journal.authority.parent.join("saved-candidate"),
        )?;
        std::os::unix::fs::symlink(journal.authority.parent.join("absent"), &journal.path)?;
    }
    Ok(())
}
fn replace_fence(journal: &Journal, step: TestStep) -> io::Result<()> {
    if step == TestStep::AfterRename {
        fs::rename(
            journal.authority.parent.join(OWNER_FILE),
            journal.authority.parent.join("saved-fence"),
        )?;
        fs::write(journal.authority.parent.join(OWNER_FILE), b"new inode")?;
    }
    Ok(())
}
#[test]
fn durable_ranges_reopen_and_original_transaction_retains_the_real_fence() -> Result<(), Error> {
    let d = directory()?;
    let path = d.0.join("db");
    let mut j = Journal::open(&path)?;
    let (mut tx, first, last) = j.prepare_monotime(100, 10)?;
    assert_eq!((first, last), (100, 109));
    assert_eq!(j.highwater(), 0);
    assert_eq!(tx.outcome(), None);
    assert_eq!(j.commit(&mut tx), CommitOutcome::Committed);
    assert_eq!(j.highwater(), 109);
    assert_eq!(j.commits(), 1);
    let raw = fs::read(&path).map_err(|_| Error::Storage)?;
    assert_eq!(&raw[..4], b"GPS3");
    drop(j);
    assert!(matches!(Journal::open(&path), Err(Error::Conflict)));
    drop(tx);
    let mut j = Journal::open(&path)?;
    assert_eq!(j.highwater(), 109);
    assert_eq!(j.reserve_monotime(1, 1)?, (110, 110));
    assert_eq!(j.reserve_monotime(u64::MAX, 2), Err(Error::Overflow));
    assert_eq!(j.highwater(), 110);
    assert!(!j.transaction_pending());
    Ok(())
}
#[test]
fn managed_projection_preserves_foreign_values_and_empty_intent_withdraws_only_managed()
-> Result<(), Error> {
    let d = directory()?;
    let path = d.0.join("db");
    let mut j = Journal::open(&path)?;
    j.reserve_managed(ManagedQuota {
        records: 3,
        bytes: 8192,
    })?;
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let peer = PeerId(*key.public_key().as_bytes());
    j.store(record(peer, b"foreign\0"), false)?;
    j.reserve_monotime(100, 10)?;
    let value = address(&key, 100)?;
    let hello = hello(&key, false)?;
    let mut tx = j.prepare_managed(
        peer,
        &[ManagedAddress {
            value: &value,
            expiry: 0,
        }],
        Some(&hello),
        101,
    )?;
    assert_eq!(j.commit(&mut tx), CommitOutcome::Committed);
    assert_eq!(j.snapshot.rows.len(), 3);
    assert_eq!(j.snapshot.rows[0].record.value, b"foreign\0");
    assert_eq!(j.snapshot.rows[1].record.expiry, 0);
    assert_eq!(j.snapshot.rows[2].record.expiry, 999);
    drop(tx);
    drop(j);
    let mut j = Journal::open(&path)?;
    j.reserve_managed(ManagedQuota {
        records: 3,
        bytes: 8192,
    })?;
    assert_eq!(j.snapshot.rows.len(), 3);
    let mut tx = j.prepare_managed(peer, &[], None, 102)?;
    assert_eq!(j.commit(&mut tx), CommitOutcome::Committed);
    assert_eq!(j.snapshot.rows.len(), 1);
    assert_eq!(j.snapshot.rows[0].record.value, b"foreign\0");
    assert_eq!(j.highwater(), 109);
    Ok(())
}
#[test]
fn reserved_partition_and_invalid_signatures_refuse_before_publication() -> Result<(), Error> {
    let d = directory()?;
    let mut j = Journal::open(d.0.join("db"))?;
    let peer = PeerId([1; 32]);
    let row = record(peer, b"public\0");
    let size = record_bytes(&Stored {
        origin: Origin::Public,
        record: row.clone(),
    })?;
    j.reserve_managed(ManagedQuota {
        records: MAX_RECORDS - 1,
        bytes: MAX_BYTES - HEADER - size,
    })?;
    j.store(row, false)?;
    let raw = fs::read(&j.path).map_err(|_| Error::Storage)?;
    assert_eq!(
        j.store(record(peer, b"second\0"), false),
        Err(Error::Capacity)
    );
    assert_eq!(fs::read(&j.path).map_err(|_| Error::Storage)?, raw);
    assert!(!j.transaction_pending());
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let value = address(&key, 100)?;
    assert!(matches!(
        j.prepare_managed(
            peer,
            &[ManagedAddress {
                value: &value,
                expiry: 999
            }],
            None,
            101
        ),
        Err(Error::Authentication)
    ));
    let own = PeerId(*key.public_key().as_bytes());
    assert!(matches!(
        j.prepare_managed(
            own,
            &[ManagedAddress {
                value: &value,
                expiry: 999
            }],
            None,
            101
        ),
        Err(Error::Replay)
    ));
    let empty = hello(&key, true)?;
    assert_eq!(gnunet_hello::message_expiration(&empty)?.as_micros(), 0);
    assert!(matches!(
        j.prepare_managed(own, &[], Some(&empty), 101),
        Err(Error::Authentication)
    ));
    assert_eq!(fs::read(&j.path).map_err(|_| Error::Storage)?, raw);
    assert!(!j.transaction_pending());
    Ok(())
}
#[test]
fn prepared_abort_retires_only_the_original_without_io_or_issuing_its_range() -> Result<(), Error> {
    let d = directory()?;
    let mut j = Journal::open(d.0.join("db"))?;
    let (mut original, _, _) = j.prepare_monotime(100, 10)?;
    assert_eq!(
        j.abort_prepared(&mut original)?,
        CommitOutcome::NotCommitted(Error::Cancelled)
    );
    assert_eq!(
        original.outcome(),
        Some(CommitOutcome::NotCommitted(Error::Cancelled))
    );
    assert_eq!(
        original.failure().ok_or(Error::NotReady)?.stage,
        "prepared-abort"
    );
    assert!(!j.path.exists());
    assert!(!j.transaction_pending());
    assert_eq!(j.highwater(), 0);
    assert_eq!(j.commits(), 0);
    assert_eq!(j.abort_prepared(&mut original), Err(Error::Stale));
    assert_eq!(
        j.commit(&mut original),
        CommitOutcome::NotCommitted(Error::Stale)
    );
    assert_eq!(
        original.outcome(),
        Some(CommitOutcome::NotCommitted(Error::Cancelled))
    );
    assert_eq!(j.reserve_monotime(100, 10)?, (100, 109));
    Ok(())
}
#[test]
fn all_input_bounds_precede_hash_parse_copy_and_any_transaction_admission() -> Result<(), Error> {
    let d = directory()?;
    let mut j = Journal::open(d.0.join("db"))?;
    j.reserve_managed(ManagedQuota {
        records: 4,
        bytes: 300,
    })?;
    j.reserve_monotime(100, 1)?;
    let raw = fs::read(&j.path).map_err(|_| Error::Storage)?;
    let peer = PeerId([1; 32]);
    let too_large = vec![1; 65536];
    assert!(matches!(
        j.prepare_managed(
            peer,
            &[ManagedAddress {
                value: &too_large,
                expiry: 999
            }],
            None,
            101
        ),
        Err(Error::TooLarge)
    ));
    assert!(matches!(
        j.prepare_managed(peer, &[], Some(&too_large), 101),
        Err(Error::TooLarge)
    ));
    assert_eq!(
        validate_hello(
            peer,
            &too_large,
            101,
            gnunet_hello::SignatureProfile::Gnunet029
        ),
        Err(Error::TooLarge)
    );
    let malformed = [1; 120];
    // Each individual frame fits; the total exceeds the reserved partition.
    // Capacity must precede the first malformed-value parse or signature hash.
    assert!(matches!(
        j.prepare_managed(
            peer,
            &[
                ManagedAddress {
                    value: &malformed,
                    expiry: 999
                },
                ManagedAddress {
                    value: &malformed,
                    expiry: 999
                }
            ],
            None,
            101
        ),
        Err(Error::Capacity)
    ));
    let hello_frame_overflow = vec![1; 65441];
    assert!(matches!(
        j.prepare_managed(peer, &[], Some(&hello_frame_overflow), 101),
        Err(Error::TooLarge)
    ));
    assert_eq!(fs::read(&j.path).map_err(|_| Error::Storage)?, raw);
    assert_eq!(j.highwater(), 100);
    assert_eq!(j.commits(), 1);
    assert!(!j.transaction_pending());
    Ok(())
}
#[test]
fn rename_error_retains_original_io_and_recovery_proves_unchanged_predecessor() -> Result<(), Error>
{
    let d = directory()?;
    let mut j = Journal::open(d.0.join("db"))?;
    j.test_hook = Some(refuse_rename);
    assert_eq!(j.reserve_monotime(100, 1), Err(Error::OutcomeUnknown));
    assert_eq!(j.highwater(), 0);
    assert_eq!(j.reserve_monotime(200, 1), Err(Error::WouldBlock));
    let mut tx = j.take_deferred().ok_or(Error::NotReady)?;
    assert_eq!(tx.number(), 1);
    assert!(j.take_deferred().is_none());
    let failure = tx.failure().ok_or(Error::NotReady)?;
    assert_eq!(failure.stage, "rename");
    assert!(
        failure
            .io
            .as_ref()
            .and_then(io::Error::raw_os_error)
            .is_some()
    );
    fs::remove_dir(&j.path).map_err(|_| Error::Storage)?;
    j.test_hook = None;
    assert!(matches!(j.recover(&mut tx), CommitOutcome::NotCommitted(_)));
    assert_eq!(j.commits(), 0);
    assert_eq!(j.highwater(), 0);
    assert!(!j.transaction_pending());
    assert_eq!(tx.failure().ok_or(Error::NotReady)?.stage, "rename");
    assert!(j.io_quiescent(&tx));
    assert_eq!(j.reserve_monotime(100, 1)?, (100, 100));
    Ok(())
}
#[test]
fn after_rename_read_error_stays_unknown_until_exact_same_inode_candidate_is_recovered()
-> Result<(), Error> {
    let d = directory()?;
    let mut j = Journal::open(d.0.join("db"))?;
    j.test_hook = Some(obstruct_readback);
    let (mut tx, _, _) = j.prepare_monotime(100, 1)?;
    assert!(matches!(j.commit(&mut tx), CommitOutcome::Unknown(_)));
    assert_eq!(tx.failure().ok_or(Error::NotReady)?.stage, "readback-open");
    assert_eq!(j.abort_prepared(&mut tx), Err(Error::OutcomeUnknown));
    assert!(
        tx.failure()
            .and_then(|f| f.io.as_ref())
            .and_then(io::Error::raw_os_error)
            .is_some()
    );
    assert!(matches!(j.recover(&mut tx), CommitOutcome::Unknown(_)));
    assert!(tx.recovery_failure().is_some());
    assert_eq!(j.highwater(), 0);
    fs::remove_file(&j.path).map_err(|_| Error::Storage)?;
    fs::rename(d.0.join("saved-candidate"), &j.path).map_err(|_| Error::Storage)?;
    assert_eq!(j.recover(&mut tx), CommitOutcome::Committed);
    assert_eq!(j.highwater(), 100);
    assert_eq!(j.commits(), 1);
    assert_eq!(tx.failure().ok_or(Error::NotReady)?.stage, "readback-open");
    assert!(matches!(
        j.recover(&mut tx),
        CommitOutcome::NotCommitted(Error::Stale)
    ));
    assert_eq!(j.commits(), 1);
    Ok(())
}
#[test]
fn lost_physical_fence_is_sticky_and_never_adopts_a_replacement() -> Result<(), Error> {
    let d = directory()?;
    let mut j = Journal::open(d.0.join("db"))?;
    j.test_hook = Some(replace_fence);
    let (mut tx, _, _) = j.prepare_monotime(100, 1)?;
    assert!(matches!(
        j.commit(&mut tx),
        CommitOutcome::Unknown(Error::Conflict)
    ));
    assert!(j.authority_lost());
    fs::remove_file(d.0.join(OWNER_FILE)).map_err(|_| Error::Storage)?;
    fs::rename(d.0.join("saved-fence"), d.0.join(OWNER_FILE)).map_err(|_| Error::Storage)?;
    assert!(matches!(
        j.recover(&mut tx),
        CommitOutcome::Unknown(Error::Conflict)
    ));
    assert_eq!(j.highwater(), 0);
    assert_eq!(j.commits(), 0);
    assert!(j.authority_lost());
    assert_eq!(j.reserve_monotime(200, 1), Err(Error::WouldBlock));
    Ok(())
}
#[test]
fn changed_predecessor_and_foreign_original_handle_cannot_publish() -> Result<(), Error> {
    let d = directory()?;
    let other = directory()?;
    let mut j = Journal::open(d.0.join("db"))?;
    let mut k = Journal::open(other.0.join("db"))?;
    let (mut tx, _, _) = j.prepare_monotime(100, 1)?;
    let (mut foreign, _, _) = k.prepare_monotime(200, 1)?;
    assert_eq!(
        j.commit(&mut foreign),
        CommitOutcome::NotCommitted(Error::Stale)
    );
    assert_eq!(foreign.outcome(), None);
    assert!(k.transaction_pending());
    assert!(j.transaction_pending());
    fs::write(&j.path, b"foreign bytes").map_err(|_| Error::Storage)?;
    assert_eq!(
        j.commit(&mut tx),
        CommitOutcome::NotCommitted(Error::Conflict)
    );
    assert_eq!(
        fs::read(&j.path).map_err(|_| Error::Storage)?,
        b"foreign bytes"
    );
    assert_eq!(j.highwater(), 0);
    assert_eq!(k.commit(&mut foreign), CommitOutcome::Committed);
    Ok(())
}
#[test]
fn old_private_formats_and_symbolic_database_paths_are_rejected_without_overwrite()
-> Result<(), Error> {
    let d = directory()?;
    let path = d.0.join("db");
    let old = b"GPS2unsupported";
    fs::write(&path, old).map_err(|_| Error::Storage)?;
    assert!(matches!(Journal::open(&path), Err(Error::Storage)));
    assert_eq!(fs::read(&path).map_err(|_| Error::Storage)?, old);
    fs::remove_file(&path).map_err(|_| Error::Storage)?;
    std::os::unix::fs::symlink(d.0.join("elsewhere"), &path).map_err(|_| Error::Storage)?;
    assert!(matches!(Journal::open(&path), Err(Error::Storage)));
    assert!(
        fs::symlink_metadata(&path)
            .map_err(|_| Error::Storage)?
            .file_type()
            .is_symlink()
    );
    Ok(())
}

#[test]
fn exact_managed_address_frame_and_reserved_byte_limits_are_atomic() -> Result<(), Error> {
    let d = directory()?;
    let mut j = Journal::open(d.0.join("db"))?;
    j.reserve_monotime(u64::MAX, 1)?;
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let peer = PeerId(*key.public_key().as_bytes());
    let mut values = Vec::new();
    for native_bytes in [65322, 65323] {
        let mut native = vec![b'x'; native_bytes];
        native[..4].copy_from_slice(b"tcp-");
        let region = own_wire::signed_region(&native, u64::MAX)?;
        let record = own_wire::AddressRecord {
            signature: key.sign(29, &region)?,
            generated: u64::MAX,
            network: u32::MAX,
            native: &native,
        };
        let mut value = vec![0; record.encoded_len()?];
        record.encode(&mut value)?;
        values.push(value);
    }
    assert_eq!((values[0].len(), values[1].len()), (65444, 65445));
    let exact = 95 + values[0].len();
    assert_eq!(exact - 4, 65535);
    j.reserve_managed(ManagedQuota {
        records: 1,
        bytes: exact - 1,
    })?;
    let before = fs::read(&j.path).map_err(|_| Error::Storage)?;
    assert!(matches!(
        j.prepare_managed(
            peer,
            &[ManagedAddress {
                value: &values[0],
                expiry: u64::MAX
            }],
            None,
            100
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(fs::read(&j.path).map_err(|_| Error::Storage)?, before);
    assert!(!j.transaction_pending());
    j.reserve_managed(ManagedQuota {
        records: 1,
        bytes: exact,
    })?;
    let mut tx = j.prepare_managed(
        peer,
        &[ManagedAddress {
            value: &values[0],
            expiry: u64::MAX,
        }],
        None,
        100,
    )?;
    assert_eq!(j.commit(&mut tx), CommitOutcome::Committed);
    assert_eq!(j.snapshot.raw.len(), HEADER + exact);
    assert_eq!(j.snapshot.rows[0].record.value, values[0]);
    drop(tx);
    let before = fs::read(&j.path).map_err(|_| Error::Storage)?;
    assert!(matches!(
        j.prepare_managed(
            peer,
            &[ManagedAddress {
                value: &values[1],
                expiry: u64::MAX
            }],
            None,
            100
        ),
        Err(Error::TooLarge)
    ));
    assert_eq!(fs::read(&j.path).map_err(|_| Error::Storage)?, before);
    assert!(!j.transaction_pending());
    assert_eq!(j.highwater(), u64::MAX);
    assert_eq!(j.commits(), 2);
    drop(j);
    let j = Journal::open(d.0.join("db"))?;
    assert_eq!(j.highwater(), u64::MAX);
    assert_eq!(j.snapshot.rows[0].record.value, values[0]);
    Ok(())
}

#[test]
fn joint_valid_address_and_hello_exact_reserved_bytes_and_records_are_enforced() -> Result<(), Error>
{
    let d = directory()?;
    let mut j = Journal::open(d.0.join("db"))?;
    j.reserve_monotime(100, 1)?;
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let peer = PeerId(*key.public_key().as_bytes());
    let value = address(&key, 100)?;
    let hello = hello(&key, false)?;
    let exact = input_record_bytes(value.len(), own_wire::SUBSYSTEM.len(), own_wire::KEY.len())?
        + input_record_bytes(
            hello.len(),
            b"peerstore".len(),
            b"peerstore-peer-hello-uri".len(),
        )?;
    let before = fs::read(&j.path).map_err(|_| Error::Storage)?;
    j.reserve_managed(ManagedQuota {
        records: 1,
        bytes: exact,
    })?;
    assert!(matches!(
        j.prepare_managed(
            peer,
            &[ManagedAddress {
                value: &value,
                expiry: 999
            }],
            Some(&hello),
            101
        ),
        Err(Error::Capacity)
    ));
    j.reserve_managed(ManagedQuota {
        records: 2,
        bytes: exact - 1,
    })?;
    assert!(matches!(
        j.prepare_managed(
            peer,
            &[ManagedAddress {
                value: &value,
                expiry: 999
            }],
            Some(&hello),
            101
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(fs::read(&j.path).map_err(|_| Error::Storage)?, before);
    assert!(!j.transaction_pending());
    j.reserve_managed(ManagedQuota {
        records: 2,
        bytes: exact,
    })?;
    let mut tx = j.prepare_managed(
        peer,
        &[ManagedAddress {
            value: &value,
            expiry: 999,
        }],
        Some(&hello),
        101,
    )?;
    assert_eq!(j.commit(&mut tx), CommitOutcome::Committed);
    assert_eq!(j.snapshot.rows.len(), 2);
    assert_eq!(j.snapshot.raw.len(), HEADER + exact);
    assert_eq!(j.snapshot.rows[0].record.value, value);
    assert_eq!(j.snapshot.rows[1].record.value, hello);
    Ok(())
}

#[test]
fn public_replace_matches_official_keys_across_origins_and_later_withdrawal_preserves_it()
-> Result<(), Error> {
    let d = directory()?;
    let mut j = Journal::open(d.0.join("db"))?;
    j.reserve_managed(ManagedQuota {
        records: 3,
        bytes: 8192,
    })?;
    let key = EddsaPrivateKey::from_seed([17; 32]);
    let peer = PeerId(*key.public_key().as_bytes());
    j.reserve_monotime(100, 1)?;
    j.store(record(peer, b"foreign\0"), false)?;
    let value = address(&key, 100)?;
    let hello = hello(&key, false)?;
    let mut tx = j.prepare_managed(
        peer,
        &[ManagedAddress {
            value: &value,
            expiry: 999,
        }],
        Some(&hello),
        101,
    )?;
    assert_eq!(j.commit(&mut tx), CommitOutcome::Committed);
    drop(tx);
    assert_eq!(j.snapshot.rows.len(), 3);
    j.store(record(peer, b"replacement\0"), true)?;
    assert_eq!(j.snapshot.rows.len(), 2);
    assert!(
        j.snapshot
            .rows
            .iter()
            .all(|row| row.origin != Origin::Address)
    );
    assert!(
        j.snapshot
            .rows
            .iter()
            .any(|row| row.origin == Origin::Hello && row.record.value == hello)
    );
    assert!(
        j.snapshot
            .rows
            .iter()
            .any(|row| row.origin == Origin::Public && row.record.value == b"replacement\0")
    );
    let mut tx = j.prepare_managed(peer, &[], None, 102)?;
    assert_eq!(j.commit(&mut tx), CommitOutcome::Committed);
    drop(tx);
    assert_eq!(j.snapshot.rows.len(), 1);
    assert!(j.snapshot.rows[0].origin == Origin::Public);
    assert_eq!(j.snapshot.rows[0].record.value, b"replacement\0");
    drop(j);
    let j = Journal::open(d.0.join("db"))?;
    assert_eq!(j.snapshot.rows.len(), 1);
    assert_eq!(j.snapshot.rows[0].record.value, b"replacement\0");
    Ok(())
}
