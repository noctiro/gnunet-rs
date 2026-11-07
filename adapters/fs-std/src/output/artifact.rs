//! No-clobber commit of caller-produced artifacts, without a content-authentication claim.
use super::{CommitStage, OutputDir, components, ensure_absent, invalid_name};
use crate::Error;
use nix::{fcntl::AtFlags, unistd::linkat};
use std::{
    fmt,
    io::{self, Read, Write},
    path::Path,
};

/// Actual local artifact write and naming observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactReport {
    /// Bytes actually written to the exclusive temporary, including a partial prefix.
    pub bytes: u64,
    /// Original final-name link and synchronization phase.
    pub stage: CommitStage,
}
/// Independent artifact production/commit and exact-temporary cleanup errors.
#[derive(Debug)]
pub struct ArtifactFailure {
    /// Actual write and naming facts; these do not authenticate supplied bytes.
    pub report: ArtifactReport,
    /// Original input, filesystem or naming failure.
    pub operation: Option<Error>,
    /// Independent original temporary cleanup or cleanup-directory sync failure.
    pub cleanup: Option<io::Error>,
}
impl fmt::Display for ArtifactFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FS artifact {:?}, {} bytes",
            self.report.stage, self.report.bytes
        )?;
        if let Some(error) = &self.operation {
            write!(f, ": {error}")?;
        }
        if let Some(error) = &self.cleanup {
            write!(f, "; cleanup: {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for ArtifactFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.operation
            .as_ref()
            .map(|error| error as &dyn std::error::Error)
            .or_else(|| self.cleanup.as_ref().map(|error| error as _))
    }
}
impl ArtifactFailure {
    fn before(operation: Error) -> Box<Self> {
        Box::new(Self {
            report: ArtifactReport {
                bytes: 0,
                stage: CommitStage::NotLinked,
            },
            operation: Some(operation),
            cleanup: None,
        })
    }
}
impl OutputDir {
    /// Stream exactly `length` caller-produced bytes into the existing anchored
    /// temporary/no-clobber commit machinery. Existing ancestors are required;
    /// neither an existing target nor a symlink is replaced. An extra or missing
    /// source byte refuses before linking. This grants no CHK authentication or
    /// publication receipt: only actual file/naming observations are returned.
    ///
    /// A linked but unconfirmed target remains present on failure. Only this
    /// call's exact temporary inode is removed, with its independent failure
    /// retained. All filesystem/reader calls are synchronous OS boundaries.
    pub fn write_artifact(
        &mut self,
        relative: impl AsRef<Path>,
        source: &mut impl Read,
        length: u64,
    ) -> Result<ArtifactReport, Box<ArtifactFailure>> {
        let parts = components(relative.as_ref()).map_err(ArtifactFailure::before)?;
        let (name, ancestors) = parts
            .split_last()
            .ok_or_else(invalid_name)
            .map_err(ArtifactFailure::before)?;
        let parent = self
            .parent_existing(ancestors)
            .map_err(ArtifactFailure::before)?;
        ensure_absent(&parent, name).map_err(ArtifactFailure::before)?;
        let mut temporary = self
            .temporary(&parent, name)
            .map_err(ArtifactFailure::before)?;
        let mut report = ArtifactReport {
            bytes: 0,
            stage: CommitStage::NotLinked,
        };
        let operation = (|| -> Result<(), Error> {
            let mut buffer = [0u8; 8192];
            while report.bytes < length {
                let count = usize::try_from((length - report.bytes).min(buffer.len() as u64))
                    .map_err(|_| Error::Limit)?;
                let read = loop {
                    match source.read(&mut buffer[..count]) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        value => break value?,
                    }
                };
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "artifact source ended before its declared length",
                    )
                    .into());
                }
                let mut offset = 0;
                while offset < read {
                    match temporary.file.write(&buffer[offset..read]) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error.into()),
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "artifact temporary wrote zero bytes",
                            )
                            .into());
                        }
                        Ok(written) => {
                            offset += written;
                            report.bytes += written as u64;
                        }
                    }
                }
            }
            let mut extra = [0u8; 1];
            let surplus = loop {
                match source.read(&mut extra) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    value => break value?,
                }
            };
            if surplus != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "artifact source exceeds its declared length",
                )
                .into());
            }
            temporary.file.sync_all()?;
            temporary.check_name()?;
            linkat(
                &parent,
                temporary.name.as_os_str(),
                &parent,
                *name,
                AtFlags::empty(),
            )?;
            report.stage = CommitStage::LinkedUnknown;
            temporary.check_link_at(&parent, name)?;
            parent.sync_all()?;
            temporary.check_link_at(&parent, name)?;
            report.stage = CommitStage::Durable;
            Ok(())
        })()
        .err();
        let cleanup = temporary.remove().and_then(|()| parent.sync_all()).err();
        match (operation, cleanup) {
            (None, None) => Ok(report),
            (operation, cleanup) => Err(Box::new(ArtifactFailure {
                report,
                operation,
                cleanup,
            })),
        }
    }
}
