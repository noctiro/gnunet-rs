#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite filesystem/receiver witnesses assert actual durable state and original IO boundaries."
)]
use super::*;
use gnunet_crypto::Entropy;
use gnunet_udp_communicator_core::{
    Identity,
    receive::{Policy as RxPolicy, Receiver},
    send::{Policy as TxPolicy, Sender},
};
use std::{fs, path::PathBuf};
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
type Test = Result<(), Box<dyn std::error::Error>>;
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "udp-replay-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        crate::test_support::private_directory(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(output).map_err(|_| Error::Entropy)
    }
}
fn message(n: u32) -> [u8; 8] {
    let mut m = [0; 8];
    m[..2].copy_from_slice(&8u16.to_be_bytes());
    m[4..].copy_from_slice(&n.to_be_bytes());
    m
}
#[test]
fn durable_receiver_restart_rejects_captured_kx_and_binds_both_identities() -> Test {
    let scratch = Scratch::new()?;
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut sender = Sender::new(
        a.peer(),
        b.peer(),
        TxPolicy {
            datagram_bytes: 192,
            secrets: 4,
            ..TxPolicy::default()
        },
        100,
    )?;
    let first = sender.initial(&a, &message(1), 7, 100, &mut Random)?;
    let next = sender.initial(&a, &message(2), 8, 101, &mut Random)?;
    let mut journal = Journal::open(&scratch.0, b.peer(), 2)?;
    let mut receiver = Receiver::new(b.peer(), a.peer(), RxPolicy::default())?;
    let mut plain = [0xa5; 160];
    let accepted = receiver.initial(&b, first.bytes(), &mut plain, &mut journal)?;
    assert_eq!(accepted.message(), Some(message(1).as_slice()));
    assert_eq!(receiver.available(), 128);
    assert_eq!(journal.latest(a.peer())?, Some(7));
    let written = fs::read(scratch.0.join(DATA))?;
    assert_eq!(written.len(), 120);
    assert_eq!(journal.commits(), 1);
    assert!(matches!(
        journal.commit_time(b.peer(), a.peer(), 7),
        Err(JournalError::Core(Error::Replay))
    ));
    assert!(matches!(
        journal.commit_time(a.peer(), a.peer(), 9),
        Err(JournalError::Core(Error::Authentication))
    ));
    drop(journal);
    drop(receiver);
    assert!(matches!(
        Journal::open(&scratch.0, a.peer(), 2),
        Err(JournalError::Core(Error::Authentication))
    ));
    let mut journal = Journal::open(&scratch.0, b.peer(), 2)?;
    let mut receiver = Receiver::new(b.peer(), a.peer(), RxPolicy::default())?;
    assert!(matches!(
        receiver.initial(&b, first.bytes(), &mut plain, &mut journal),
        Err(Error::Replay)
    ));
    assert_eq!(receiver.available(), 0);
    assert_eq!(receiver.secrets(), 0);
    assert_eq!(fs::read(scratch.0.join(DATA))?, written);
    let accepted = receiver.initial(&b, next.bytes(), &mut plain, &mut journal)?;
    assert_eq!(accepted.message(), Some(message(2).as_slice()));
    assert_eq!(journal.latest(a.peer())?, Some(8));
    assert!(journal.quiescent()?);
    Ok(())
}
#[test]
fn bounded_peer_namespace_and_monotime_reservations_survive_restart() -> Test {
    let scratch = Scratch::new()?;
    let local = [2; 32];
    let mut journal = Journal::open(&scratch.0, local, 1)?;
    journal.commit_time(local, [1; 32], 0)?;
    assert!(matches!(
        journal.commit_time(local, [1; 32], 0),
        Err(JournalError::Core(Error::Replay))
    ));
    assert!(matches!(
        journal.commit_time(local, [3; 32], 1),
        Err(JournalError::Core(Error::Capacity))
    ));
    assert_eq!(journal.reserve_monotime(10, 64)?, (10, 73));
    let state = fs::read(scratch.0.join(DATA))?;
    assert!(matches!(
        journal.reserve_monotime(u64::MAX, 2),
        Err(JournalError::Core(Error::Overflow))
    ));
    assert_eq!(fs::read(scratch.0.join(DATA))?, state);
    drop(journal);
    let mut journal = Journal::open(&scratch.0, local, 1)?;
    assert_eq!(journal.latest([1; 32])?, Some(0));
    assert_eq!(journal.reserve_monotime(1, 2)?, (74, 75));
    Ok(())
}
#[test]
fn real_postrename_parent_loss_blocks_all_admission_until_original_recovered() -> Test {
    let scratch = Scratch::new()?;
    let live = scratch.0.join("live");
    let moved = scratch.0.join("moved");
    crate::test_support::private_directory(&live)?;
    let local = [2; 32];
    let peer = [3; 32];
    let mut journal = Journal::open(&live, local, 2)?;
    journal.commit_time(local, peer, 10)?;
    let result = journal.commit_time_observed(local, peer, 11, || {
        assert!(fs::rename(&live, &moved).is_ok());
    });
    assert!(matches!(
        result,
        Err(JournalError::Native(Failure {
            stage: Stage::Fence,
            outcome: Outcome::Unknown,
            ..
        }))
    ));
    let pending = fs::read(moved.join(DATA))?;
    assert!(journal.quiescent().is_err());
    assert!(journal.latest(peer).is_err());
    assert!(matches!(
        ReplayStore::commit(&mut journal, local, peer, 12),
        Err(Error::OutcomeUnknown)
    ));
    let failure = journal.take_failure().ok_or(Error::Stale)?;
    assert_eq!(failure.stage, Stage::Recovery);
    assert_eq!(failure.outcome, Outcome::Unknown);
    assert!(journal.recover().is_err());
    fs::rename(&moved, &live)?;
    assert!(!journal.quiescent()?);
    // Equal bytes in another object do not settle the original write.
    let original_pending = live.join("original-pending");
    fs::rename(live.join(DATA), &original_pending)?;
    fs::copy(&original_pending, live.join(DATA))?;
    assert!(journal.recover().is_err());
    fs::remove_file(live.join(DATA))?;
    fs::rename(&original_pending, live.join(DATA))?;
    // Replacing the on-disk target with a different valid older snapshot must
    // not let recovery adopt it as the original pending transaction.
    let older = Snapshot {
        highwater: 0,
        records: vec![Record {
            peer,
            monotonic: 10,
        }],
    }
    .encode(local)?;
    fs::write(live.join(DATA), older)?;
    assert!(journal.recover().is_err());
    assert!(!journal.quiescent()?);
    fs::write(live.join(DATA), &pending)?;
    File::open(live.join(DATA))?.sync_all()?;
    assert!(journal.recover()?);
    assert!(journal.quiescent()?);
    assert_eq!(journal.latest(peer)?, Some(11));
    assert!(matches!(
        journal.commit_time(local, peer, 11),
        Err(JournalError::Core(Error::Replay))
    ));
    journal.commit_time(local, peer, 12)?;
    assert_eq!(journal.latest(peer)?, Some(12));
    assert_eq!(journal.commits(), 3);
    Ok(())
}
#[test]
fn corrupted_snapshot_alias_and_replaced_writer_fence_never_adopt_empty_history() -> Test {
    let scratch = Scratch::new()?;
    let local = [2; 32];
    let mut journal = Journal::open(&scratch.0, local, 2)?;
    journal.commit_time(local, [3; 32], 10)?;
    drop(journal);
    let path = scratch.0.join(DATA);
    let valid = fs::read(&path)?;
    let mut corrupt = valid.clone();
    corrupt[87] ^= 1;
    fs::write(&path, &corrupt)?;
    assert!(matches!(
        Journal::open(&scratch.0, local, 2),
        Err(JournalError::Core(Error::Storage))
    ));
    assert_eq!(fs::read(&path)?, corrupt);
    fs::write(&path, valid)?;
    let mut journal = Journal::open(&scratch.0, local, 2)?;
    fs::rename(scratch.0.join(LOCK), scratch.0.join("original-lock"))?;
    fs::write(scratch.0.join(LOCK), [])?;
    assert!(journal.quiescent().is_err());
    assert!(matches!(
        journal.commit_time(local, [3; 32], 11),
        Err(JournalError::Native(Failure {
            stage: Stage::Fence,
            outcome: Outcome::Unknown,
            ..
        }))
    ));
    drop(journal);
    fs::remove_file(&path)?;
    fs::hard_link(scratch.0.join(LOCK), &path)?;
    assert!(matches!(
        Journal::open(&scratch.0, local, 2),
        Err(JournalError::Native(Failure {
            stage: Stage::Fence,
            ..
        }))
    ));
    Ok(())
}
#[test]
fn replaced_canonical_entry_blocks_admission_until_original_is_restored() -> Test {
    let scratch = Scratch::new()?;
    let local = [2; 32];
    let mut journal = Journal::open(&scratch.0, local, 2)?;
    journal.commit_time(local, [3; 32], 9)?;
    let original = scratch.0.join("original-data");
    fs::rename(scratch.0.join(DATA), &original)?;
    fs::create_dir(scratch.0.join(DATA))?;
    assert_eq!(
        ReplayStore::commit(&mut journal, local, [3; 32], 10),
        Err(Error::OutcomeUnknown)
    );
    let failure = journal.take_failure().ok_or(Error::Stale)?;
    assert_eq!(failure.stage, Stage::Read);
    assert_eq!(failure.outcome, Outcome::Unknown);
    assert!(journal.latest([3; 32]).is_err());
    assert_eq!(journal.commits(), 1);
    fs::remove_dir(scratch.0.join(DATA))?;
    fs::rename(original, scratch.0.join(DATA))?;
    assert_eq!(journal.latest([3; 32])?, Some(9));
    journal.commit_time(local, [3; 32], 10)?;
    assert_eq!(journal.latest([3; 32])?, Some(10));
    Ok(())
}
#[test]
fn missing_history_behind_existing_fence_is_not_an_empty_database() -> Test {
    let scratch = Scratch::new()?;
    drop(Journal::open(&scratch.0, [2; 32], 2)?);
    fs::remove_file(scratch.0.join(DATA))?;
    assert!(matches!(
        Journal::open(&scratch.0, [2; 32], 2),
        Err(JournalError::Native(Failure {
            outcome: Outcome::Unknown,
            ..
        }))
    ));
    Ok(())
}
#[test]
fn subprocess_commit_probe() -> Test {
    let Some(directory) = std::env::var_os("GNUNET_UDP_REPLAY_CHILD_DIRECTORY") else {
        return Ok(());
    };
    let mut journal = Journal::open(directory, [2; 32], 2)?;
    journal.commit_time([2; 32], [3; 32], 100)?;
    if std::env::var_os("GNUNET_UDP_REPLAY_CHILD_HOLD").is_some() {
        let mut output = io::stdout().lock();
        output.write_all(b"UDP_FENCE_HELD\n")?;
        output.flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
    }
    Ok(())
}
#[test]
fn actual_process_writer_fence_survives_socket_absence_and_releases_on_process_exit() -> Test {
    let scratch = Scratch::new()?;
    let executable = std::env::current_exe()?;
    let args = [
        "--exact",
        "replay::tests::subprocess_commit_probe",
        "--nocapture",
    ];
    let mut child = Command::new(&executable)
        .args(args)
        .env("GNUNET_UDP_REPLAY_CHILD_DIRECTORY", &scratch.0)
        .env("GNUNET_UDP_REPLAY_CHILD_HOLD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut output = BufReader::new(child.stdout.take().ok_or(Error::Stale)?);
    let mut held = false;
    loop {
        let mut line = String::new();
        if output.read_line(&mut line)? == 0 {
            break;
        }
        if line.contains("UDP_FENCE_HELD") {
            held = true;
            break;
        }
    }
    assert!(held);
    assert!(Journal::open(&scratch.0, [2; 32], 2).is_err());
    let second = Command::new(&executable)
        .args(args)
        .env("GNUNET_UDP_REPLAY_CHILD_DIRECTORY", &scratch.0)
        .output()?;
    assert!(!second.status.success());
    child.kill()?;
    let _status = child.wait()?;
    let mut journal = Journal::open(&scratch.0, [2; 32], 2)?;
    assert_eq!(journal.latest([3; 32])?, Some(100));
    assert!(matches!(
        journal.commit_time([2; 32], [3; 32], 100),
        Err(JournalError::Core(Error::Replay))
    ));
    journal.commit_time([2; 32], [3; 32], 101)?;
    Ok(())
}
