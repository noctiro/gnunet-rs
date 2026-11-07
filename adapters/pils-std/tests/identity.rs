//! Real persisted identity, writer exclusion and crash-refusal behavior.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible protocol and real resource regressions assert independent expected outcomes"
)]
use gnunet_pils::Profile;
use gnunet_pils_host::identity::{load_existing, load_or_create};
use std::{fs, io, path::PathBuf};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> io::Result<Self> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| io::Error::other("entropy"))?;
        let path = std::env::temp_dir().join(format!(
            "gnunet-pils-identity-{:032x}",
            u128::from_be_bytes(random)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn durable_create_reopen_and_exclusive_writer_preserve_the_same_master()
-> Result<(), Box<dyn std::error::Error>> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("private.key");
    let (master, lease) = load_or_create(&path)?;
    let hash = [3; 64];
    let identity = master.derive(&hash, Profile::Reference029)?.public_key();
    let persisted = fs::read(&path)?;
    assert_eq!(persisted.len(), 32);
    assert_eq!(
        load_or_create(&path).err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    assert_eq!(fs::read(&path)?, persisted);
    assert_eq!(
        load_existing(&path)?
            .derive(&hash, Profile::Reference029)?
            .public_key(),
        identity
    );
    drop(lease);
    let (reloaded, _lease) = load_or_create(&path)?;
    assert_eq!(
        reloaded.derive(&hash, Profile::Reference029)?.public_key(),
        identity
    );
    Ok(())
}
#[test]
fn truncated_existing_key_is_never_replaced_by_a_new_identity() -> io::Result<()> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("private.key");
    fs::write(&path, b"partial")?;
    assert_eq!(
        load_or_create(&path).err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    assert_eq!(fs::read(&path)?, b"partial");
    Ok(())
}
#[cfg(unix)]
#[test]
fn actual_key_permissions_are_private_and_public_readability_is_rejected() -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new()?;
    let path = scratch.0.join("private.key");
    let (_master, _lease) = load_or_create(&path)?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert_eq!(
        load_existing(&path).err().map(|e| e.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}
