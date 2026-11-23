//! Assemble siblings in a caller-trusted output namespace before publication.
use super::Result;
use gnunet_native::{
    entropy,
    filesystem::{CreateDirectoryError, Directory, EntryInfo, FileIdentity},
};
use std::{
    ffi::{OsStr, OsString},
    fs, io,
    mem::DropGuard,
    path::{Path, PathBuf},
};

pub(super) struct Output {
    parent_path: PathBuf,
    parent: Directory,
    name: OsString,
}

impl Output {
    pub(super) fn resolve(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .ok_or("node output requires a directory name")?
            .to_owned();
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent_path)?;
        let parent_path = fs::canonicalize(parent_path)?;
        let parent = Directory::open(&parent_path)?;
        let output = Self {
            parent_path,
            parent,
            name,
        };
        output.require_absent()?;
        Ok(output)
    }

    fn require_absent(&self) -> Result<()> {
        match self.parent.entry_info(&self.name) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "node output already exists: {}",
                    self.parent_path.join(&self.name).display()
                ),
            )
            .into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn verify_parent_path(&self) -> io::Result<()> {
        let named = Directory::open(&self.parent_path)?;
        if FileIdentity::of(named.as_file())? == FileIdentity::of(self.parent.as_file())? {
            Ok(())
        } else {
            Err(io::Error::other("node output parent changed"))
        }
    }

    pub(super) fn begin(self) -> Result<Stage> {
        self.require_absent()?;
        for _ in 0..32 {
            let name = staging_name()?;
            if self.name.eq_ignore_ascii_case(OsStr::new(&name)) {
                continue;
            }
            let path = self.parent_path.join(&name);
            match self.parent.create_directory(OsStr::new(&name)) {
                Ok(directory) => {
                    let staged = StagedDirectory {
                        output: self,
                        name,
                        path,
                        directory,
                    };
                    let stage = Stage {
                        pending: DropGuard::new(staged, StagedDirectory::rollback),
                    };
                    stage.pending.output.verify_parent_path()?;
                    stage.pending.output.require_absent()?;
                    return Ok(stage);
                }
                Err(CreateDirectoryError::Create(error))
                    if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("stage {}: {error}", path.display()).into()),
            }
        }
        Err("could not allocate a unique node staging directory".into())
    }
}

pub(super) struct Stage {
    pending: DropGuard<StagedDirectory, fn(StagedDirectory)>,
}

struct StagedDirectory {
    output: Output,
    name: String,
    path: PathBuf,
    directory: Directory,
}

impl Stage {
    pub(super) fn path(&self) -> &Path {
        &self.pending.path
    }

    pub(super) fn publish(self) -> Result<()> {
        let pending = self.pending;
        pending.output.verify_parent_path()?;
        pending.output.parent.publish_directory(
            OsStr::new(&pending.name),
            &pending.directory,
            &pending.output.name,
        )?;
        drop(DropGuard::dismiss(pending));
        Ok(())
    }
}

impl StagedDirectory {
    fn rollback(self) {
        let parent = &self.output.parent;
        let name = OsStr::new(&self.name);
        if parent
            .same_directory(name, &self.directory)
            .is_ok_and(|same| same)
        {
            let _cleanup = clear_directory(&self.directory)
                .and_then(|()| parent.remove_directory(name, &self.directory));
        }
    }
}

fn staging_name() -> io::Result<String> {
    let mut random = [0; 16];
    entropy::fill(&mut random)?;
    Ok(format!(".gnunet-node-{:032x}", u128::from_be_bytes(random)))
}

fn clear_directory(directory: &Directory) -> io::Result<()> {
    // Finish enumeration before removing any of the entries it observed.
    let names = directory.entries()?.collect::<io::Result<Vec<_>>>()?;
    for name in names {
        match directory.entry_info(&name)? {
            EntryInfo::Directory(info) => {
                let child = directory.open_directory(&name)?;
                if FileIdentity::of(child.as_file())? != info.identity {
                    return Err(io::Error::other("staged directory changed during cleanup"));
                }
                clear_directory(&child)?;
                directory.remove_directory(&name, &child)?;
            }
            EntryInfo::File(info) => {
                let file = directory.open_file(&name)?;
                if FileIdentity::of(&file)? != info.identity {
                    return Err(io::Error::other("staged file changed during cleanup"));
                }
                directory.remove_file(&name, &file)?;
            }
            EntryInfo::Other => return Err(io::Error::other("unexpected node staging entry")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(staging_name()?);
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn dropping_an_incomplete_stage_allows_retry() -> Result<()> {
        let scratch = Scratch::new()?;
        let output = scratch.0.join("node");
        let stage = Output::resolve(&output)?.begin()?;
        let temporary = stage.path().to_owned();
        fs::create_dir(temporary.join("bin"))?;
        fs::write(temporary.join("bin/tool"), b"unfinished")?;
        if output.try_exists()? {
            return Err("incomplete node appeared at the destination".into());
        }
        drop(stage);
        if temporary.try_exists()? {
            return Err("incomplete stage was not removed".into());
        }

        let stage = Output::resolve(&output)?.begin()?;
        fs::write(stage.path().join("tool"), b"complete")?;
        stage.publish()?;
        if fs::read(output.join("tool"))? != b"complete" || temporary.try_exists()? {
            return Err("retry did not publish the completed staging directory".into());
        }
        Ok(())
    }

    #[test]
    fn an_existing_destination_wins_publication() -> Result<()> {
        let scratch = Scratch::new()?;
        let output = scratch.0.join("node");
        let stage = Output::resolve(&output)?.begin()?;
        let temporary = stage.path().to_owned();
        fs::write(temporary.join("tool"), b"unpublished")?;
        fs::create_dir(&output)?;
        let existing = FileIdentity::of(Directory::open(&output)?.as_file())?;
        if stage.publish().is_ok()
            || temporary.try_exists()?
            || FileIdentity::of(Directory::open(&output)?.as_file())? != existing
            || fs::read_dir(output)?.next().transpose()?.is_some()
        {
            return Err(
                "publication changed an existing destination or left a staging tree".into(),
            );
        }
        Ok(())
    }

    #[test]
    fn cleanup_preserves_a_replaced_staging_name() -> Result<()> {
        let scratch = Scratch::new()?;
        let output = scratch.0.join("node");
        let stage = Output::resolve(&output)?.begin()?;
        let temporary = stage.path().to_owned();
        let moved = scratch.0.join("moved");
        fs::rename(&temporary, &moved)?;
        fs::create_dir(&temporary)?;
        fs::write(temporary.join("owner"), b"replacement")?;
        drop(stage);
        if fs::read(temporary.join("owner"))? != b"replacement"
            || !moved.is_dir()
            || output.try_exists()?
        {
            return Err("cleanup changed a name it did not own".into());
        }
        Ok(())
    }

    #[test]
    fn changed_parent_path_does_not_leave_staging_in_either_directory() -> Result<()> {
        let scratch = Scratch::new()?;
        let parent = scratch.0.join("parent");
        let moved = scratch.0.join("moved");
        let output = Output::resolve(&parent.join("node"))?;
        fs::rename(&parent, &moved)?;
        fs::create_dir(&parent)?;
        if output.begin().is_ok()
            || fs::read_dir(&parent)?.next().transpose()?.is_some()
            || fs::read_dir(&moved)?.next().transpose()?.is_some()
        {
            return Err("changed parent path redirected or leaked a staging directory".into());
        }
        Ok(())
    }
}
