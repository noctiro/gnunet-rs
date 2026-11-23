//! Exact native proof-file selection and private atomic checkpoints.
use super::{Certificate, pure};
use gnunet_native::filesystem::{
    self, Directory, ExclusiveFile,
    publication::{self, Destination},
};
use std::{
    error::Error,
    ffi::OsString,
    fs::File,
    io::{self, Read, Seek},
    path::{Path, PathBuf},
};

pub(super) type FileResult<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

enum Entry {
    Absent,
    Read {
        file: File,
        contents: Box<[u8; pure::PROOF_BYTES]>,
    },
    Locked {
        file: ExclusiveFile,
        contents: Box<[u8; pure::PROOF_BYTES]>,
    },
}

pub(super) struct ProofFile {
    path: PathBuf,
    directory: Directory,
    name: OsString,
    entry: Entry,
}

impl ProofFile {
    pub(super) fn read(path: PathBuf) -> FileResult<(Self, Option<Certificate>)> {
        let name = path
            .file_name()
            .ok_or_else(|| invalid("revocation certificate needs a file name"))?
            .to_owned();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = Directory::open(parent)?;
        let (entry, certificate) = match directory.open_file(&name) {
            Ok(file) => {
                let contents = read_exact(&file)?;
                if !directory.same_file(&name, &file)? {
                    return Err(invalid("revocation certificate changed while reading").into());
                }
                let certificate = Certificate::copy(pure::Proof::parse(&contents)?);
                (
                    Entry::Read {
                        file,
                        contents: Box::new(contents),
                    },
                    Some(certificate),
                )
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (Entry::Absent, None),
            Err(error) => return Err(error.into()),
        };
        Ok((
            Self {
                path,
                directory,
                name,
                entry,
            },
            certificate,
        ))
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn prepare_update(&mut self) -> FileResult<()> {
        self.directory.validate_namespace()?;
        if let Entry::Read { file, contents } = &self.entry {
            let lock = self.lock(file)?;
            if read_exact(lock.as_file())? != **contents {
                return Err(invalid("revocation work file contents changed before update").into());
            }
            self.entry = Entry::Locked {
                file: lock,
                contents: contents.clone(),
            };
        }
        Ok(())
    }

    pub(super) fn save(&mut self, proof: &Certificate) -> FileResult<()> {
        self.prepare_update()?;
        let original = match &self.entry {
            Entry::Locked { file, contents } => Some((file.as_file(), contents)),
            Entry::Absent => None,
            Entry::Read { .. } => {
                return Err(invalid("revocation work file has no update owner").into());
            }
        };
        let destination = if original.is_some() {
            Destination::Replace
        } else {
            Destination::Create
        };
        let published = publication::publish(
            &self.directory,
            &self.name,
            proof.bytes(),
            destination,
            || {
                if let Some((original, contents)) = original {
                    filesystem::private_single_file_identity(original)?;
                    if !self.directory.same_file(&self.name, original)?
                        || read_exact(original)? != **contents
                    {
                        return Err(invalid("revocation work file changed before publication"));
                    }
                }
                Ok(())
            },
        )?;
        let (published, _directory_sync) = published.into_parts();
        // A concurrent owner may win the lock after publication. The current
        // checkpoint is still complete, and this owner stops before any retry.
        self.entry = Entry::Locked {
            file: self.lock(&published)?,
            contents: Box::new(*proof.bytes()),
        };
        Ok(())
    }

    fn lock(&self, original: &File) -> FileResult<ExclusiveFile> {
        let expected = filesystem::private_single_file_identity(original)?;
        let update = self.directory.open_file_for_update(&self.name)?;
        let charged = ExclusiveFile::try_lock(update)?;
        if filesystem::private_single_file_identity(charged.as_file())? != expected
            || !self.directory.same_file(&self.name, charged.as_file())?
        {
            return Err(invalid("revocation work file changed before locking").into());
        }
        Ok(charged)
    }
}

fn read_exact(mut file: &File) -> io::Result<[u8; pure::PROOF_BYTES]> {
    let mut data = [0; pure::PROOF_BYTES];
    file.rewind()?;
    file.read_exact(&mut data)?;
    if file.read(&mut [0; 1])? != 0 {
        return Err(invalid("revocation certificate has trailing bytes"));
    }
    Ok(data)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
