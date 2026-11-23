//! Complete private directory publication; existing unmarked stores are refused.
use super::{DirectorySync, Failure, HeldFile, Namespace, failure, os};
use gnunet_native::filesystem::{
    Directory, ExclusiveFile, FileIdentity, private_single_file_identity, publication,
    validate_readonly,
};
use gnunet_types::Error;
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Write},
    mem::DropGuard,
    path::{Path, PathBuf},
};

pub(super) struct Opened {
    pub directory: Directory,
    pub path: PathBuf,
    pub marker: HeldFile,
    pub writer: ExclusiveFile,
    pub created: bool,
    pub parent_sync: DirectorySync,
}

pub(super) fn writer(directory: &Directory, name: &str) -> Result<ExclusiveFile, Failure> {
    let name = OsStr::new(name);
    let file = match directory.create_private_file(name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => directory
            .open_file_for_update(name)
            .map_err(|error| os("writer-open", error))?,
        Err(error) => return Err(os("writer-create", error)),
    };
    private_single_file_identity(&file).map_err(|error| os("writer-policy", error))?;
    ExclusiveFile::try_lock(file).map_err(writer_lock_error)
}

fn writer_lock_error(error: fs::TryLockError) -> Failure {
    match error {
        fs::TryLockError::Error(error) => os("writer-lock", error),
        error => failure(
            "writer-lock",
            Error::Conflict,
            Some(io::Error::other(error)),
        ),
    }
}

pub(super) fn open(path: &Path, namespace: Namespace) -> Result<Opened, Failure> {
    let name = path
        .file_name()
        .ok_or_else(|| failure("store-component", Error::InvalidInput, None))?;
    let parent_path = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = Directory::open(parent_path).map_err(|error| os("open-parent", error))?;
    if namespace == Namespace::TransportTcp {
        parent
            .validate_private()
            .map_err(|error| os("replay-parent-policy", error))?;
    }
    let parent_id =
        FileIdentity::of(parent.as_file()).map_err(|error| os("parent-identity", error))?;
    let canonical = fs::canonicalize(parent_path).map_err(|error| os("canonical-parent", error))?;
    let fence = || -> Result<(), Failure> {
        let selected = Directory::open(&canonical).map_err(|error| os("parent-fence", error))?;
        if FileIdentity::of(selected.as_file()).map_err(|error| os("parent-fence", error))?
            != parent_id
        {
            return Err(failure("parent-replaced", Error::OutcomeUnknown, None));
        }
        Ok(())
    };
    fence()?;
    let existing = match parent.open_directory(name) {
        Ok(directory) => Some(directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(os("open-store-directory", error)),
    };
    let (directory, initial, created) = match existing {
        Some(directory) => (directory, None, false),
        None => match create(&parent, name, namespace, &fence)? {
            Some((directory, marker, writer)) => (directory, Some((marker, writer)), true),
            None => (
                parent
                    .open_directory(name)
                    .map_err(|error| os("open-competing-store", error))?,
                None,
                false,
            ),
        },
    };
    directory
        .validate_private()
        .map_err(|error| os("directory-policy", error))?;
    super::namespace::guard(&directory, namespace)?;
    let (marker, writer) = match initial {
        Some(originals) => originals,
        None => {
            // The fixed public marker is the only content read before namespace
            // qualification. No lock is created in an unmarked existing store.
            let marker = match directory.open_file(OsStr::new(namespace.mark())) {
                Err(error)
                    if namespace == Namespace::GnsPublication
                        && error.kind() == io::ErrorKind::NotFound =>
                {
                    return Err(failure(
                        "initialization-pending",
                        Error::NotReady,
                        Some(error),
                    ));
                }
                result => HeldFile::qualify(
                    result.map_err(|error| os("marked-store-required", error))?,
                    "marker-policy",
                )?,
            };
            qualify_marker(&marker, namespace)?;
            let writer = writer(&directory, namespace.lock())?;
            (marker, writer)
        }
    };
    qualify_marker(&marker, namespace)?;
    fence()?;
    if !parent
        .same_directory(name, &directory)
        .map_err(|error| os("directory-fence", error))?
    {
        return Err(failure("directory-replaced", Error::OutcomeUnknown, None));
    }
    // Completes a previous process's publication even if it stopped before its
    // parent naming barrier. Unavailable is explicit on Windows.
    let parent_sync = parent.sync().map_err(|error| os("sync-parent", error))?;
    Ok(Opened {
        directory,
        path: canonical.join(name),
        marker,
        writer,
        created,
        parent_sync,
    })
}

fn qualify_marker(marker: &HeldFile, namespace: Namespace) -> Result<(), Failure> {
    use gnunet_native::filesystem::FileReader;
    marker.validate("marker-policy")?;
    validate_readonly(&marker.file).map_err(|error| os("marker-access", error))?;
    let mut bytes = [0; 64];
    let expected = namespace.marker();
    if expected.len() > bytes.len()
        || marker
            .file
            .metadata()
            .map_err(|error| os("marker-size", error))?
            .len()
            != expected.len() as u64
    {
        return Err(failure("marker-format", Error::Authentication, None));
    }
    FileReader::from_file(&marker.file)
        .and_then(|reader| reader.read_exact_at(&mut bytes[..expected.len()], 0))
        .map_err(|error| os("read-marker", error))?;
    if &bytes[..expected.len()] != expected {
        return Err(failure("marker-format", Error::Authentication, None));
    }
    Ok(())
}

struct Stage {
    name: String,
    directory: Directory,
    marker: Option<HeldFile>,
    writer: Option<ExclusiveFile>,
}

impl Stage {
    fn create_writer(&self, parent: &Directory, name: &OsStr) -> Result<ExclusiveFile, Failure> {
        let file = self
            .directory
            .create_private_file(name)
            .map_err(|error| os("writer-create", error))?;
        let mut cleanup = None;
        let pending = DropGuard::new(file, |file| {
            cleanup = self.rollback_file(parent, name, &file).err();
        });
        let result = private_single_file_identity(&pending)
            .map_err(|error| os("writer-policy", error))
            .and_then(|_| ExclusiveFile::try_lock_guarded(pending).map_err(writer_lock_error));
        result.map_err(|mut failure| {
            failure.cleanup = cleanup;
            failure
        })
    }

    fn rollback_file(&self, parent: &Directory, name: &OsStr, file: &File) -> io::Result<()> {
        verify_staging_directory(parent, self)?;
        self.directory.remove_file(name, file)
    }
}

fn create(
    parent: &Directory,
    target: &OsStr,
    namespace: Namespace,
    fence: &impl Fn() -> Result<(), Failure>,
) -> Result<Option<(Directory, HeldFile, ExclusiveFile)>, Failure> {
    let mut stage = None;
    for _ in 0..1024 {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce)
            .map_err(|error| os("initialization-entropy", error))?;
        let name = format!(".gnunet-snapshot-{:032x}", u128::from_be_bytes(nonce));
        match parent.create_private_directory(OsStr::new(&name)) {
            Ok(directory) => {
                stage = Some(Stage {
                    name,
                    directory,
                    marker: None,
                    writer: None,
                });
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(os("create-staging-directory", error)),
        }
    }
    let mut stage = stage.ok_or_else(|| failure("staging-capacity", Error::Capacity, None))?;
    let mut attempted = false;
    let result = (|| {
        stage
            .directory
            .validate_private()
            .map_err(|error| os("staging-policy", error))?;
        stage.writer = Some(stage.create_writer(parent, OsStr::new(namespace.lock()))?);
        let name = OsStr::new(namespace.mark());
        let file = stage
            .directory
            .create_private_file(name)
            .map_err(|error| os("create-marker", error))?;
        stage.marker = Some(HeldFile::qualify_created(file, "marker-policy", |file| {
            stage.rollback_file(parent, name, file)
        })?);
        let marker = stage
            .marker
            .as_mut()
            .ok_or_else(|| failure("marker-owner", Error::Storage, None))?;
        marker
            .file
            .write_all(namespace.marker())
            .map_err(|error| os("write-marker", error))?;
        // Close the only marker writer before any reader or published Store
        // retains it. Cleanup still owns this same staged object on refusal.
        publication::seal_retained(
            &stage.directory,
            OsStr::new(namespace.mark()),
            &mut marker.file,
            namespace.marker().len() as u64,
        )
        .map_err(|error| {
            let stage = if error.stage == "file-sync" {
                "sync-marker"
            } else {
                error.stage
            };
            os(stage, io::Error::new(error.cause.kind(), error))
        })?;
        stage
            .directory
            .sync()
            .map_err(|error| os("sync-staging", error))?;
        let marker = stage
            .marker
            .as_ref()
            .ok_or_else(|| failure("marker-owner", Error::Storage, None))?;
        qualify_marker(marker, namespace)?;
        let writer = stage
            .writer
            .as_ref()
            .ok_or_else(|| failure("writer-owner", Error::Storage, None))?;
        private_single_file_identity(writer.as_file())
            .map_err(|error| os("staging-writer-policy", error))?;
        if !stage
            .directory
            .same_file(OsStr::new(namespace.mark()), &marker.file)
            .map_err(|error| os("staging-marker-fence", error))?
            || !stage
                .directory
                .same_file(OsStr::new(namespace.lock()), writer.as_file())
                .map_err(|error| os("staging-writer-fence", error))?
        {
            return Err(failure("staging-source-replaced", Error::Conflict, None));
        }
        fence()?;
        attempted = true;
        match parent.publish_directory(OsStr::new(&stage.name), &stage.directory, target) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                attempted = false;
                return Ok(false);
            }
            Err(error) => return Err(os("publish-store-directory", error)),
        }
        parent.sync().map_err(|error| os("sync-parent", error))?;
        fence()?;
        Ok(true)
    })();
    match result {
        Ok(true) => {
            let marker = stage
                .marker
                .ok_or_else(|| failure("marker-owner", Error::OutcomeUnknown, None))?;
            let writer = stage
                .writer
                .ok_or_else(|| failure("writer-owner", Error::OutcomeUnknown, None))?;
            Ok(Some((stage.directory, marker, writer)))
        }
        Ok(false) => {
            cleanup(parent, &stage, namespace)
                .map_err(|error| os("cleanup-competing-staging", error))?;
            Ok(None)
        }
        Err(mut error) => {
            if attempted || error.reason == Error::OutcomeUnknown {
                error.exposure = super::Exposure::Unknown;
            }
            if !attempted {
                let staging_cleanup = cleanup(parent, &stage, namespace).err();
                error.cleanup = error.cleanup.or(staging_cleanup);
            }
            Err(error)
        }
    }
}

fn verify_staging_directory(parent: &Directory, stage: &Stage) -> io::Result<()> {
    if !parent.same_directory(OsStr::new(&stage.name), &stage.directory)? {
        return Err(io::Error::other("original staging directory changed"));
    }
    Ok(())
}

fn cleanup(parent: &Directory, stage: &Stage, namespace: Namespace) -> io::Result<()> {
    verify_staging_directory(parent, stage)?;
    let marker = stage.marker.as_ref().map_or(Ok(()), |marker| {
        stage
            .directory
            .remove_file(OsStr::new(namespace.mark()), &marker.file)
    });
    let writer = stage.writer.as_ref().map_or(Ok(()), |writer| {
        stage
            .directory
            .remove_file(OsStr::new(namespace.lock()), writer.as_file())
    });
    // Retire each held child independently, then retain the first failure.
    let sync = stage.directory.sync();
    marker.and(writer).and(sync)?;
    parent.remove_directory(OsStr::new(&stage.name), &stage.directory)?;
    parent.sync()?;
    Ok(())
}
