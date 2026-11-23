#![expect(
    clippy::panic_in_result_fn,
    reason = "Native pairing tests assert same-object read leases and canonical-file refusal"
)]
use super::*;
use gnunet_native::filesystem::validate_readonly;
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;
struct Scratch {
    path: PathBuf,
    directory: Directory,
}
impl Scratch {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().canonicalize()?;
        let name = format!(
            "tcp-pairing-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let directory = Directory::open(&base)?.create_private_directory(OsStr::new(&name))?;
        Ok(Self {
            path: base.join(name),
            directory,
        })
    }
    fn write(&self, name: &OsStr, bytes: &[u8]) -> io::Result<File> {
        let mut writer = self.directory.create_private_file(name)?;
        writer.write_all(bytes)?;
        let original = self.directory.open_file(name)?;
        gnunet_native::filesystem::close(writer)?;
        Ok(original)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.path);
    }
}
fn image() -> FrontierImage {
    FrontierImage {
        dirty: false,
        reserved: 0,
        ledger: [0x41; 32],
        local: EddsaPublicKey::from_bytes([0x42; 32]),
        minimum: 1,
    }
}

#[test]
fn synchronized_frontier_retires_its_sync_handle_before_original_readback() -> Result {
    let scratch = Scratch::new()?;
    let name = OsStr::new("frontier");
    let image = image();
    let bytes = image.encode();
    let original = scratch.write(name, &bytes)?;
    let prepared = prepare(
        &scratch.directory,
        name,
        scratch.directory.open_file_for_sync(name)?,
    )?;
    validate_readonly(&prepared.file)?;
    assert_eq!(prepared.identity, FileIdentity::of(&original)?);
    assert_eq!(FileIdentity::of(&prepared.file)?, prepared.identity);
    assert_eq!(prepared.bytes, bytes);
    assert!(scratch.directory.same_file(name, &prepared.file)?);
    let mut actual = [0; FRONTIER_BYTES];
    (&prepared.file).read_exact(&mut actual)?;
    assert_eq!(actual, bytes);
    assert_eq!((&prepared.file).read(&mut [0])?, 0);
    let inspected = inspect(&scratch.path.join(name))?;
    assert_eq!(inspected.image, image);
    assert_eq!(inspected.directory_sync, prepared.directory_sync);
    Ok(())
}

#[test]
fn equal_bytes_in_a_foreign_sync_owner_never_replace_the_selected_original() -> Result {
    let scratch = Scratch::new()?;
    let name = OsStr::new("frontier");
    let foreign = OsStr::new("foreign");
    let bytes = image().encode();
    let original = scratch.write(name, &bytes)?;
    let other = scratch.write(foreign, &bytes)?;
    assert_ne!(FileIdentity::of(&original)?, FileIdentity::of(&other)?);
    assert!(
        prepare(
            &scratch.directory,
            name,
            scratch.directory.open_file_for_sync(foreign)?,
        )
        .is_err()
    );
    assert!(scratch.directory.same_file(name, &original)?);
    assert!(scratch.directory.same_file(foreign, &other)?);
    assert_eq!(fs::read(scratch.path.join(name))?, bytes);
    assert_eq!(fs::read(scratch.path.join(foreign))?, bytes);
    Ok(())
}

#[test]
fn inspection_refuses_nonexact_or_malformed_frontiers_without_removal() -> Result {
    let scratch = Scratch::new()?;
    let bytes = image().encode();
    let mut malformed = bytes;
    malformed[0] ^= 1;
    let mut long = bytes.to_vec();
    long.push(0);
    for (name, body) in [
        ("short", &bytes[..FRONTIER_BYTES - 1]),
        ("long", long.as_slice()),
        ("malformed", malformed.as_slice()),
    ] {
        let original = scratch.write(OsStr::new(name), body)?;
        let path = scratch.path.join(name);
        assert!(inspect(&path).is_err());
        assert!(scratch.directory.same_file(OsStr::new(name), &original)?);
        assert_eq!(fs::read(path)?, body);
    }
    Ok(())
}
