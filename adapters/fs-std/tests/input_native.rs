//! Original-directory enumeration and source identity on native filesystems.
#![cfg(any(unix, windows))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native regression assertions compare independently created paths and original held objects"
)]
use gnunet_fs_host::input_tree::{InputDir, open_regular};
use gnunet_native::filesystem::{Directory, EntryInfo, FileIdentity, file_info};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs, io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
struct Scratch(PathBuf);
impl Scratch {
    fn create() -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gnunet-input-native-{}-{nonce}",
            std::process::id()
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
fn native_name() -> OsString {
    #[cfg(target_os = "macos")]
    {
        OsString::from("native-例")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![b'n', 0xff])
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[u16::from(b'n'), 0xd800])
    }
}
#[test]
fn independent_multi_batch_cursors_and_input_opens_stay_on_the_original_directory() -> Result {
    let scratch = Scratch::create()?;
    let selected = scratch.0.join("selected");
    fs::create_dir(&selected)?;
    let original = Directory::open(&selected)?;
    let input = InputDir::open(&selected)?;
    let mut expected = BTreeSet::new();
    // This exceeds one Windows 4 KiB enumeration batch.
    for index in 0..160 {
        let name = OsString::from(format!("entry-{index:03}"));
        let file = original.create_private_file(&name)?;
        file.set_len(index)?;
        expected.insert(name);
    }
    let native = native_name();
    drop(original.create_private_file(&native)?);
    expected.insert(native.clone());
    let observation = file_info(&input.open_child(&native)?)?;
    assert!(matches!(observation, EntryInfo::File(info) if info.bytes == 0));
    let mut first = original.entries()?;
    let head = first
        .next()
        .transpose()?
        .ok_or_else(|| io::Error::other("missing first entry"))?;
    let second: BTreeSet<_> = original.entries()?.collect::<io::Result<_>>()?;
    assert_eq!(second, expected);
    let retained = scratch.0.join("retained");
    fs::rename(&selected, &retained)?;
    fs::create_dir(&selected)?;
    fs::write(selected.join("foreign"), b"replacement")?;
    let mut seen = BTreeSet::from([head]);
    for name in first {
        assert!(seen.insert(name?));
    }
    assert_eq!(seen, expected);
    assert_eq!(
        original.entries()?.collect::<io::Result<BTreeSet<_>>>()?,
        expected
    );
    assert_eq!(file_info(&input.open_child(&native)?)?, observation);
    assert_eq!(
        FileIdentity::of(original.as_file())?,
        FileIdentity::of(input.descriptor())?
    );
    assert!(input.open_child(OsStr::new("foreign")).is_err());
    assert!(input.open_child(OsStr::new("..")).is_err());
    assert!(input.open_child(OsStr::new("nested/leaf")).is_err());
    assert!(open_regular(&retained).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn special_entries_are_observed_without_reading_or_following_them() -> Result {
    let scratch = Scratch::create()?;
    fs::write(scratch.0.join("file"), b"source")?;
    std::os::unix::fs::symlink("file", scratch.0.join("link"))?;
    nix::unistd::mkfifo(&scratch.0.join("fifo"), nix::sys::stat::Mode::S_IRUSR)?;
    let directory = Directory::open(&scratch.0)?;
    let input = InputDir::open(&scratch.0)?;
    for name in ["link", "fifo"] {
        assert_eq!(directory.entry_info(OsStr::new(name))?, EntryInfo::Other);
        assert!(input.open_child(OsStr::new(name)).is_err());
        assert!(open_regular(scratch.0.join(name)).is_err());
    }
    assert!(
        matches!(file_info(&open_regular(scratch.0.join("file"))?)?, EntryInfo::File(info) if info.bytes == 6)
    );
    Ok(())
}
