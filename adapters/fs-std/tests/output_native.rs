//! Real native output, complete file identities and independent naming barriers.
#![cfg(any(unix, windows))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native filesystem regressions assert independent contents, ownership and barrier outcomes"
)]
use gnunet_fs_host::{
    Buffers, CommitStage, Control, DirectorySync, FileIdentity, FileIdentityParts, Limits,
    OutputDir, Repository,
};
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gn-output-{}-{stamp:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
#[cfg(unix)]
const SYNC: DirectorySync = DirectorySync::Synchronized;
#[cfg(windows)]
const SYNC: DirectorySync = DirectorySync::Unavailable;

#[test]
fn authenticated_output_keeps_original_root_and_never_publishes_a_cancelled_prefix() -> Result {
    let scratch = Scratch::new()?;
    let selected = scratch.0.join("selected");
    let held = scratch.0.join("held");
    fs::create_dir(&selected)?;
    let mut output = OutputDir::open(&selected)?;
    fs::rename(&selected, &held)?;
    fs::create_dir(&selected)?;
    let bytes: Vec<_> = (0..100_000).map(|n| (n % 251) as u8).collect();
    let mut repository = Repository::open(scratch.0.join("objects"))?;
    let mut buffers = Buffers::new();
    let content = buffers
        .publish(
            &mut bytes.as_slice(),
            bytes.len() as u64,
            &mut repository,
            Limits::default(),
            |_| Control::Continue,
        )?
        .content;
    let read = output.write_file(
        "safe/data-λ.bin",
        &mut repository,
        content,
        &mut buffers,
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(read.directory_sync, Some(SYNC));
    assert_eq!(fs::read(held.join("safe/data-λ.bin"))?, bytes);
    assert_eq!(fs::read_dir(&selected)?.count(), 0);
    assert!(
        output
            .write_file(
                "safe/data-λ.bin",
                &mut repository,
                content,
                &mut buffers,
                Limits::default(),
                |_| Control::Continue
            )
            .is_err()
    );
    assert_eq!(fs::read(held.join("safe/data-λ.bin"))?, bytes);
    assert!(matches!(
        output.write_file(
            "cancelled.bin",
            &mut repository,
            content,
            &mut buffers,
            Limits::default(),
            |work| if work.blocks == 0 {
                Control::Continue
            } else {
                Control::Cancel
            }
        ),
        Err(gnunet_fs_host::Error::Cancelled)
    ));
    let names = fs::read_dir(&held)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    assert_eq!(
        names,
        [std::ffi::OsString::from("safe")],
        "failed output must leave no temporary or final prefix"
    );
    Ok(())
}

#[test]
fn owned_directory_rejects_a_replacement_even_with_the_same_marker_bytes() -> Result {
    let scratch = Scratch::new()?;
    let mut parent = OutputDir::open(&scratch.0)?;
    let owner = [71; 32];
    let original = parent.create_owned_directory("selected", owner)?;
    let identity = original.identity()?;
    assert_eq!(original.sync_directory()?, SYNC);
    drop(original);
    fs::rename(scratch.0.join("selected"), scratch.0.join("held"))?;
    let replacement = parent.create_owned_directory("selected", owner)?;
    assert_ne!(replacement.identity()?, identity);
    drop(replacement);
    assert!(
        parent
            .attach_owned_directory("selected", owner, Some(identity))
            .is_err()
    );
    assert!(
        parent
            .attach_owned_directory("held", owner, Some(identity))
            .is_ok()
    );
    Ok(())
}

#[test]
fn local_identity_encoding_keeps_all_windows_bits_and_separates_platforms() -> Result {
    let mut bytes = [0; 32];
    bytes[0] = 2;
    bytes[15] = 9;
    bytes[31] = 1;
    let first = FileIdentity::from_bytes(bytes)?;
    bytes[16] = 7;
    let second = FileIdentity::from_bytes(bytes)?;
    assert_ne!(
        first, second,
        "the complete 128-bit identifier participates in equality"
    );
    assert!(first.same_volume(second));
    assert!(!first.same_volume(FileIdentity::unix(9, 1)));
    let FileIdentityParts::Windows { volume, id } = second.parts() else {
        return Err("Windows tag lost".into());
    };
    assert_eq!(volume, 9);
    assert_eq!(id[0], 7);
    assert_eq!(id[15], 1);
    assert_eq!(second.as_bytes(), &bytes);
    bytes[1] = 1;
    assert!(FileIdentity::from_bytes(bytes).is_err());
    assert_eq!(
        CommitStage::FileSynchronized(DirectorySync::Unavailable).directory_sync(),
        Some(DirectorySync::Unavailable)
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_rejects_renamed_or_device_spelling_before_creating_output_ancestors() -> Result {
    let scratch = Scratch::new()?;
    let selected = scratch.0.join("out");
    fs::create_dir(&selected)?;
    let mut output = OutputDir::open(&selected)?;
    let mut repository = Repository::open(scratch.0.join("objects"))?;
    let mut buffers = Buffers::new();
    let content = buffers
        .publish(
            &mut b"private".as_slice(),
            7,
            &mut repository,
            Limits::default(),
            |_| Control::Continue,
        )?
        .content;
    for name in [
        "child/CON.txt",
        "child/con .txt",
        "child/COM¹.log",
        "child/CONOUT$",
        "child/file.",
        "child/file ",
        "child/file:stream",
        "child/fi?le",
    ] {
        assert!(
            output
                .write_file(
                    name,
                    &mut repository,
                    content,
                    &mut buffers,
                    Limits::default(),
                    |_| Control::Continue
                )
                .is_err(),
            "spelling {name:?}"
        );
        assert_eq!(
            fs::read_dir(&selected)?.count(),
            0,
            "no ancestor or temporary for {name:?}"
        );
    }
    Ok(())
}
