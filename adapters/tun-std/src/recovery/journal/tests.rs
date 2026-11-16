//! Actual private checkpoint files; native TUN qualification is not exercised.
use super::frame::{BYTES, FILE_BYTES};
use super::*;
use gnunet_native::filesystem::{Directory, FileIdentity};
use std::{fs, path::PathBuf};
struct Private(PathBuf);
impl Private {
    fn new() -> io::Result<Self> {
        let mut random = [0; 16];
        gnunet_native::entropy::fill(&mut random)?;
        let nonce = u128::from_le_bytes(random);
        let path =
            std::env::temp_dir().join(format!("gn-tun-journal-{}-{nonce:x}", std::process::id()));
        let parent = Directory::open(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
        parent.create_private_directory(path.file_name().ok_or(io::ErrorKind::InvalidInput)?)?;
        Ok(Self(path))
    }
    fn path(&self) -> PathBuf {
        self.0.join("checkpoint")
    }
}
impl Drop for Private {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn check(value: bool) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(
            "checkpoint ownership/state contract mismatch",
        ))
    }
}
fn record(intent: &Intent) -> Record {
    let mut name = [0; 16];
    name[..8].copy_from_slice(b"vpn-test");
    let mut device = [0; 16];
    device[..5].copy_from_slice(b"tun17");
    Record {
        name,
        device,
        index: 41,
        birth: intent.nonce,
        file: FileIdentity::unix(7, 123),
    }
}
#[test]
fn durable_intent_identity_restart_and_cleanup_use_one_locked_file() -> io::Result<()> {
    let private = Private::new()?;
    let mut journal = Journal::open(&private.path())?;
    check(journal.state() == Some(&State::Empty))?;
    check(
        Journal::open(&private.path())
            .err()
            .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock),
    )?;
    let intent = journal.begin(Some("vpn-test"))?;
    let original = record(&intent);
    let mut foreign = original.clone();
    foreign.birth[0] ^= 1;
    check(journal.activate(foreign.clone()).is_err())?;
    journal.activate(original.clone())?;
    check(journal.clear_active(&foreign).is_err())?;
    drop(journal);
    let mut journal = Journal::open(&private.path())?;
    check(journal.state() == Some(&State::Active(original.clone())))?;
    journal.finish_active(&original)?;
    journal.finish_active(&original)?;
    drop(journal);
    check(Journal::open(&private.path())?.state() == Some(&State::Empty))?;
    check(fs::metadata(private.path())?.len() == FILE_BYTES as u64)
}
#[test]
fn copied_identical_image_cannot_replace_the_live_original() -> io::Result<()> {
    let private = Private::new()?;
    let mut journal = Journal::open(&private.path())?;
    let original = fs::read(private.path())?;
    fs::rename(private.path(), private.0.join("retained-original"))?;
    fs::write(private.path(), &original)?;
    check(journal.begin(None).is_err())?;
    check(fs::read(private.path())? == original)
}
#[test]
fn completed_write_without_sync_receipt_stays_unknown_until_reconciled() -> io::Result<()> {
    let private = Private::new()?;
    let mut journal = Journal::open(&private.path())?;
    let intent = journal.begin(Some("vpn-test"))?;
    let original = record(&intent);
    journal.files.fail_sync = true;
    check(journal.activate(original.clone()).is_err())?;
    check(journal.state().is_none())?;
    check(journal.begin(None).is_err())?;
    check(journal.reconcile()? == &State::Active(original.clone()))?;
    journal.files.fail_sync = true;
    check(journal.finish_active(&original).is_err())?;
    check(journal.state().is_none())?;
    check(journal.reconcile()? == &State::Empty)?;
    journal.finish_active(&original)
}
#[test]
fn torn_active_falls_back_to_intent_and_never_authorizes_another_allocation() -> io::Result<()> {
    let private = Private::new()?;
    let mut journal = Journal::open(&private.path())?;
    let intent = journal.begin(Some("vpn-test"))?;
    let mut bad = Frame {
        sequence: 2,
        state: State::Active(record(&intent)),
    }
    .encode();
    bad[127] ^= 1;
    let intent_frame = Frame {
        sequence: 1,
        state: State::Creating(intent.clone()),
    }
    .encode();
    drop(journal);
    let mut image = [0; FILE_BYTES];
    image[..BYTES].copy_from_slice(&bad);
    image[BYTES..].copy_from_slice(&intent_frame);
    fs::write(private.path(), image)?;
    let mut journal = Journal::open(&private.path())?;
    check(journal.state() == Some(&State::Creating(intent.clone())))?;
    check(journal.begin(None).is_err())?;
    journal.finish_failed_creation(&intent, None)
}
#[test]
fn damaged_nonzero_slot_cannot_roll_back_to_empty() -> io::Result<()> {
    let private = Private::new()?;
    let journal = Journal::open(&private.path())?;
    drop(journal);
    let mut image = fs::read(private.path())?;
    image[BYTES + 17] = 1;
    fs::write(private.path(), &image)?;
    check(Journal::open(&private.path()).is_err())?;
    check(fs::read(private.path())? == image)
}
#[test]
fn exhaustion_and_foreign_intents_leave_the_original_state_unchanged() -> io::Result<()> {
    let private = Private::new()?;
    let mut journal = Journal::open(&private.path())?;
    let intent = journal.begin(None)?;
    let mut foreign = intent.clone();
    foreign.nonce[0] ^= 1;
    check(journal.abort(&foreign).is_err())?;
    journal.abort(&intent)?;
    journal.floor = u64::MAX;
    check(journal.begin(None).is_err())?;
    check(journal.state() == Some(&State::Empty))
}
#[test]
fn discovered_partial_creation_is_checkpointed_without_claiming_requested_configuration()
-> io::Result<()> {
    let private = Private::new()?;
    let mut journal = Journal::open(&private.path())?;
    let intent = journal.begin(Some("vpn-test"))?;
    journal.fence_intent(&intent)?;
    let mut native_selector = record(&intent);
    native_selector.name = native_selector.device;
    // A fully configured creation must still honor its requested rename.
    check(journal.activate(native_selector.clone()).is_err())?;
    let mut foreign = native_selector.clone();
    foreign.birth[0] ^= 1;
    check(journal.checkpoint_discovered(&intent, foreign).is_err())?;
    // Discovery saves metadata only. Physical cleanup qualification happens in
    // the platform adapter; this test never constructs a TUN or cleanup owner.
    journal.checkpoint_discovered(&intent, native_selector.clone())?;
    check(journal.fence_intent(&intent).is_err())?;
    drop(journal);
    check(Journal::open(&private.path())?.state() == Some(&State::Active(native_selector)))
}
