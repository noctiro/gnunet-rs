//! Real held directories, original files, hard links and replacement refusal.
use super::Directory;
use crate::paths::{FileIdentity, StatusError};
use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read, Write},
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gn-dir-{}-{now:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn require(value: bool, reason: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(reason))
    }
}
#[test]
fn held_root_and_wide_children_survive_parent_name_replacement() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let path = fixture.0.join("root");
    fs::create_dir(&path)?;
    let root = Directory::open(&path)?;
    let moved = fixture.0.join("moved");
    fs::rename(&path, &moved)?;
    fs::create_dir(&path)?;
    let child = OsString::from_wide(&[0x4e2d, 0xd800, 0x61]);
    let mut file = root.create_private_file(&child)?;
    file.write_all(b"original directory")?;
    file.sync_all()?;
    require(
        fs::read(moved.join(&child))? == b"original directory",
        "relative create followed a replacement root path",
    )?;
    require(
        !crate::paths::exists(&path.join(&child))?,
        "replacement root received an original-directory write",
    )?;
    require(
        root.same_file(&child, &file)?,
        "held-root file identity changed",
    )?;
    let reopened = Directory::from_file(root.as_file())?;
    require(
        reopened.same_file(&child, &file)?,
        "original-object reopen used a replaced pathname",
    )?;
    let shard = root.ensure_directory(OsStr::new("shard"))?;
    require(
        crate::identity::file_owner(shard.as_file())? == crate::identity::process_user()?,
        "created child directory lost its actual owner SID",
    )?;
    Ok(())
}

#[test]
fn directory_barrier_uses_the_held_object_after_its_name_is_removed() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let original_name = fixture.0.join("original");
    fs::create_dir(&original_name)?;
    let original = Directory::open(&original_name)?;
    let local_ntfs = super::sync::is_local_ntfs(original.as_file())?;
    fs::rename(original_name, fixture.0.join("moved"))?;
    let _file = original.create_private_file(OsStr::new("value"))?;
    let expected = if local_ntfs {
        crate::DirectorySync::Synchronized
    } else {
        crate::DirectorySync::Unavailable
    };
    require(
        original.sync()? == expected,
        "wrong held-directory flush result",
    )
}

#[test]
fn directory_claim_excludes_other_publishers_across_a_populated_rename() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let parent = Directory::open(&fixture.0)?;
    let (stage, target, marker) = ("stage", "target", "marker");
    let directory = parent.create_private_directory(stage.as_ref())?;
    let mut file = directory.create_private_file(marker.as_ref())?;
    file.write_all(b"staged contents")?;
    file.sync_all()?;
    let id = FileIdentity::of(&file)?;
    crate::filesystem::close(file)?;

    let original = parent.claim_directory(stage.as_ref(), &directory)?;
    original.publish(target.as_ref())?;
    let selected = parent.open_directory(target.as_ref())?;
    require(
        parent
            .claim_directory(target.as_ref(), &selected)
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock),
        "another initializer acquired a published directory before the owner released it",
    )?;
    let mut file = selected.open_file(marker.as_ref())?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    require(
        FileIdentity::of(&file)? == id && text == "staged contents",
        "publication lost the original closed child",
    )?;
    drop(original);
    parent.claim_directory(target.as_ref(), &selected)?;
    Ok(())
}

#[test]
fn hard_links_preserve_source_and_cleanup_refuses_a_replacement() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let root = Directory::open(&fixture.0)?;
    let mut file = root.create_private_file(OsStr::new("temporary"))?;
    file.write_all(b"complete payload")?;
    file.sync_all()?;
    root.link_file(&file, OsStr::new("object"))?;
    let mut object = root.open_file(OsStr::new("object"))?;
    let mut bytes = Vec::new();
    object.read_to_end(&mut bytes)?;
    require(
        bytes == b"complete payload" && FileIdentity::of(&object)? == FileIdentity::of(&file)?,
        "hard-link publication changed source object or bytes",
    )?;
    let error = match root.link_file(&file, OsStr::new("object")) {
        Ok(()) => {
            return Err(io::Error::other(
                "hard-link publication replaced an existing name",
            ));
        }
        Err(error) => error,
    };
    require(
        error.kind() == io::ErrorKind::AlreadyExists
            && error
                .get_ref()
                .is_some_and(|cause| cause.is::<StatusError>()),
        "native collision lost NT status or Win32 classification",
    )?;
    root.remove_file(OsStr::new("temporary"), &file)?;
    require(
        !crate::paths::exists(&fixture.0.join("temporary"))?
            && root.same_file(OsStr::new("object"), &file)?,
        "temporary cleanup removed the published hard link",
    )?;
    let mut replacement = root.create_private_file(OsStr::new("temporary"))?;
    replacement.write_all(b"replacement")?;
    require(
        root.remove_file(OsStr::new("temporary"), &file).is_err(),
        "old cleanup authority deleted a replacement file",
    )?;
    require(
        fs::read(fixture.0.join("temporary"))? == b"replacement",
        "replacement bytes changed during refused cleanup",
    )?;
    Ok(())
}
#[test]
fn invalid_components_are_refused_before_namespace_creation() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let root = Directory::open(&fixture.0)?;
    for name in [
        "",
        ".",
        "..",
        "child\\escape",
        "child/escape",
        "value:stream",
        "nul\0tail",
    ] {
        require(
            root.create_private_file(OsStr::new(name)).is_err(),
            "invalid component reached native creation",
        )?;
    }
    require(
        root.create_private_file(&OsString::from_wide(&[b'x' as u16; 256]))
            .is_err(),
        "overlong component reached native creation",
    )?;
    require(
        fs::read_dir(&fixture.0)?.next().is_none(),
        "invalid component created a namespace artifact",
    )
}
