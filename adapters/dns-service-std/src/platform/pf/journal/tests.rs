//! Private-file recovery fixtures; no PF, interface or privileged operation runs.
use super::*;
use std::{
    fs::{DirBuilder, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const LABEL: &str = "gnunet-rs-dns-0123456789abcdef0123456789abcdef";
const NEXT: &str = "gnunet-rs-dns-fedcba9876543210fedcba9876543210";
static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> io::Result<Self> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gnunet-pf-journal-{}-{stamp}-{serial}",
            std::process::id()
        ));
        DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
    fn open(&self) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.0.join("lease"))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn policy(label: &str) -> io::Result<Vec<u8>> {
    rules::render(
        "tun7",
        std::net::Ipv4Addr::LOCALHOST,
        std::net::Ipv6Addr::LOCALHOST,
        501,
        label,
    )
    .map(String::into_bytes)
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Private-file assertions check durable restart and occupied-record refusal"
)]
fn original_policy_survives_reopen_and_cannot_be_overwritten() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let canonical = policy(LABEL)?;
    let next = policy(NEXT)?;
    {
        let mut file = fixture.open()?;
        assert_eq!(read(&file)?, None, "new lease must have no policy debt");
        store(&mut file, LABEL, &canonical)?;
    }
    let mut reopened = fixture.open()?;
    let original = Policy {
        label: LABEL.to_owned(),
        canonical,
    };
    assert_eq!(
        read(&reopened)?,
        Some(original),
        "reopening must recover the original canonical rules"
    );
    assert!(
        matches!(store(&mut reopened, NEXT, &next), Err(error) if error.kind() == io::ErrorKind::AlreadyExists),
        "occupied original policy must refuse replacement"
    );
    assert_eq!(
        read(&reopened)?.map(|policy| policy.label),
        Some(LABEL.to_owned())
    );
    clear(&reopened)?;
    drop(reopened);
    let mut reopened = fixture.open()?;
    assert_eq!(
        read(&reopened)?,
        None,
        "confirmed retirement must survive reopening"
    );
    store(&mut reopened, NEXT, &next)?;
    assert_eq!(
        read(&reopened)?,
        Some(Policy {
            label: NEXT.to_owned(),
            canonical: next
        })
    );
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Corruption fixtures must retain nonempty uncertainty instead of silently dropping debt"
)]
fn truncated_changed_or_unbounded_records_never_mean_empty() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let mut file = fixture.open()?;
    let encoded = encode(LABEL, &policy(LABEL)?)?;
    for length in 1..encoded.len() {
        assert!(
            decode(&encoded[..length]).is_err(),
            "torn record of {length} bytes must be refused"
        );
    }
    for at in [
        0,
        8,
        12,
        HEADER_BYTES,
        HEADER_BYTES + LABEL_BYTES,
        encoded.len() - 1,
    ] {
        let mut damaged = encoded.clone();
        damaged[at] ^= 1;
        assert!(decode(&damaged).is_err(), "damage at {at} must be refused");
    }
    file.write_all(&encoded[..encoded.len() - 1])?;
    file.sync_all()?;
    drop(file);
    let mut reopened = fixture.open()?;
    assert!(
        matches!(read(&reopened), Err(error) if error.kind() == io::ErrorKind::InvalidData),
        "torn nonempty file must fence startup"
    );
    assert!(
        matches!(store(&mut reopened, LABEL, &policy(LABEL)?), Err(error) if error.kind() == io::ErrorKind::AlreadyExists),
        "torn intent must not be overwritten"
    );
    reopened.set_len(FILE_BYTES as u64 + 1)?;
    assert!(
        matches!(read(&reopened), Err(error) if error.kind() == io::ErrorKind::InvalidData),
        "oversized file must be refused before allocation"
    );
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Ownership fixtures reject partial or cross-generation cleanup selectors"
)]
fn only_a_complete_matching_generation_can_be_recorded() -> io::Result<()> {
    let canonical = policy(LABEL)?;
    assert!(
        encode(NEXT, &canonical).is_err(),
        "a new label must not adopt old policy"
    );
    let last = canonical
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or(io::ErrorKind::InvalidData)?;
    let prefix = &canonical[..last];
    let cut = prefix
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or(io::ErrorKind::InvalidData)?;
    assert!(
        encode(LABEL, &canonical[..cut]).is_err(),
        "partial rules cannot authorize cleanup"
    );
    assert!(
        encode("gnunet-rs-dns-unqualified", &canonical).is_err(),
        "noncanonical labels cannot enter the journal"
    );
    Ok(())
}
