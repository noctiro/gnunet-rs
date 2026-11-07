//! Typed state observations of the single native output finalizer.
use super::{OutputDir, Temporary, components, ensure_absent, invalid_name};
use crate::{
    BlockSource, Buffers, Control, Error, Limits, Progress, ReadFile, Result as HostResult,
};
use gnunet_fs::Content;
use nix::{fcntl::AtFlags, unistd::linkat};
use std::{
    convert::Infallible, ffi::OsStr, fmt, fs::File, io, os::unix::fs::MetadataExt, path::Path,
};

/// Native identity of the actual selected inode. Durable attachment additionally
/// requires its task-owner marker; identity alone does not defeat inode reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    /// Native device number.
    pub device: u64,
    /// Native inode number.
    pub inode: u64,
}
impl FileIdentity {
    pub(crate) fn of(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}
/// Actual output disposition independently of observation/cleanup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitStage {
    /// This invocation has not observed a successful final-name link.
    NotLinked,
    /// The final-name link succeeded, but its checked naming barrier did not.
    LinkedUnknown,
    /// Original final-name identity and parent sync were confirmed.
    Durable,
}
/// Exact original exclusive temporary and selected parent binding.
#[cfg_attr(
    not(feature = "service"),
    expect(
        dead_code,
        reason = "The local finalizer shares observations with the optional durable service owner; its default observer ignores the payload"
    )
)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct TempRecord<'a> {
    pub parent: FileIdentity,
    pub name: &'a OsStr,
    pub identity: FileIdentity,
    pub content: Content,
}
/// The observer must durably accept pre-link intents before output proceeds.
#[cfg_attr(
    not(feature = "service"),
    expect(
        dead_code,
        reason = "Observation payloads are consumed by the optional durable service owner; local output uses the same finalizer with a no-op observer"
    )
)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum OutputObservation<'a, R = ReadFile> {
    TempOwned(TempRecord<'a>),
    CommitIntent {
        temporary: TempRecord<'a>,
        final_name: &'a OsStr,
        final_parent: FileIdentity,
    },
    FileCommitted {
        temporary: TempRecord<'a>,
        final_name: &'a OsStr,
        final_parent: FileIdentity,
        identity: FileIdentity,
        receipt: R,
    },
    Cleanup {
        temporary: TempRecord<'a>,
        stage: CommitStage,
        outcome: Result<(), &'a io::Error>,
    },
}
/// Independent original operation, observer and physical cleanup failures.
#[derive(Debug)]
pub struct ObservedFailure<E, R = ReadFile> {
    /// Original transfer, cancellation, identity or uncertain commit failure.
    pub operation: Option<Error>,
    /// Original state-observer failure, without relabeling it as filesystem I/O.
    pub observer: Option<E>,
    /// Independent exact-inode cleanup or cleanup-directory sync failure.
    pub cleanup: Option<io::Error>,
    /// Actual output disposition, independently of state/cleanup failures.
    pub stage: CommitStage,
    /// Actual authentication receipt of this operation; durable output additionally
    /// requires stage Durable. It is never manufactured from saved fields.
    pub receipt: Option<R>,
}
impl<E, R> ObservedFailure<E, R> {
    pub(super) fn operation(error: Error) -> Box<Self> {
        Box::new(Self {
            operation: Some(error),
            observer: None,
            cleanup: None,
            stage: CommitStage::NotLinked,
            receipt: None,
        })
    }
}
impl<E: fmt::Display, R> fmt::Display for ObservedFailure<E, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS observed output {:?}", self.stage)?;
        if let Some(error) = &self.operation {
            write!(f, ": {error}")?;
        }
        if let Some(error) = &self.observer {
            write!(f, ": observer: {error}")?;
        }
        if let Some(error) = &self.cleanup {
            write!(f, ": cleanup: {error}")?;
        }
        Ok(())
    }
}
impl<E: std::error::Error + 'static, R: fmt::Debug> std::error::Error for ObservedFailure<E, R> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = &self.operation {
            Some(error)
        } else if let Some(error) = &self.observer {
            Some(error)
        } else {
            self.cleanup
                .as_ref()
                .map(|error| error as &(dyn std::error::Error + 'static))
        }
    }
}
pub(super) fn noop(_: OutputObservation<'_>) -> Result<(), Infallible> {
    Ok(())
}
pub(super) fn unobserved_failure(failure: Box<ObservedFailure<Infallible>>) -> Error {
    let ObservedFailure {
        operation,
        observer,
        cleanup,
        stage,
        receipt,
    } = *failure;
    if let Some(never) = observer {
        match never {}
    }
    match (operation, cleanup) {
        (Some(cause), Some(source)) if stage == CommitStage::NotLinked => Error::CleanupFailed {
            cause: Box::new(cause),
            source,
        },
        (Some(cause), _) => cause,
        (None, Some(source)) if stage == CommitStage::Durable => match receipt {
            Some(read) => Error::CleanupAfterCommit {
                query: read.verified.content().query,
                source,
            },
            None => Error::Io(source),
        },
        (None, Some(source)) => Error::Io(source),
        (None, None) => Error::Corrupt,
    }
}

impl Temporary<'_> {
    pub(super) fn record(&self, parent: FileIdentity, content: Content) -> TempRecord<'_> {
        TempRecord {
            parent,
            name: &self.name,
            identity: FileIdentity {
                #[cfg_attr(
                    target_os = "linux",
                    expect(
                        clippy::unnecessary_cast,
                        reason = "Preserve the native device-number widening required by the narrower macOS stat layout"
                    )
                )]
                device: self.identity.st_dev as u64,
                inode: self.identity.st_ino,
            },
            content,
        }
    }
}
impl OutputDir {
    #[cfg(any(feature = "service", test))]
    #[expect(
        clippy::too_many_arguments,
        reason = "Durable observation retains the original explicit local transfer ownership"
    )]
    pub(crate) fn write_file_observed<E>(
        &mut self,
        relative: impl AsRef<Path>,
        source: &mut impl BlockSource,
        content: Content,
        buffers: &mut Buffers,
        limits: Limits,
        control: impl FnMut(Progress) -> Control,
        observer: impl for<'a> FnMut(OutputObservation<'a>) -> Result<(), E>,
    ) -> Result<ReadFile, Box<ObservedFailure<E>>> {
        self.write_file_inner(
            relative, source, content, buffers, limits, control, false, observer,
        )
    }
    #[cfg(feature = "service")]
    #[expect(
        clippy::too_many_arguments,
        reason = "Durable observation retains original native lookup, bounded cache and output ownership"
    )]
    pub(crate) async fn download_file_observed<E>(
        &mut self,
        relative: impl AsRef<Path>,
        source: gnunet_client_host::EndpointSource,
        content: Content,
        buffers: &mut Buffers,
        cache: Option<&mut crate::Repository>,
        options: crate::network::DownloadOptions,
        control: impl FnMut(Progress) -> Control,
        observer: impl for<'a> FnMut(OutputObservation<'a>) -> Result<(), E>,
    ) -> Result<ReadFile, Box<ObservedFailure<E>>> {
        self.download_file_inner(
            relative, source, content, buffers, cache, options, control, false, observer,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The observer orders durable state around the original explicit local transfer ownership"
    )]
    pub(super) fn write_file_inner<E>(
        &mut self,
        relative: impl AsRef<Path>,
        source: &mut impl BlockSource,
        content: Content,
        buffers: &mut Buffers,
        limits: Limits,
        mut control: impl FnMut(Progress) -> Control,
        create_parents: bool,
        mut observer: impl for<'a> FnMut(OutputObservation<'a>) -> Result<(), E>,
    ) -> Result<ReadFile, Box<ObservedFailure<E>>> {
        let parts = components(relative.as_ref()).map_err(ObservedFailure::operation)?;
        buffers
            .prepare(content, limits)
            .map_err(ObservedFailure::operation)?;
        let (name, directories) = parts
            .split_last()
            .ok_or_else(invalid_name)
            .map_err(ObservedFailure::operation)?;
        let parent = if create_parents {
            self.parent(directories)
        } else {
            self.parent_existing(directories)
        }
        .map_err(ObservedFailure::operation)?;
        ensure_absent(&parent, name).map_err(ObservedFailure::operation)?;
        let parent_id = FileIdentity::of(&parent)
            .map_err(Error::from)
            .map_err(ObservedFailure::operation)?;
        let mut temporary = self
            .temporary(&parent, name)
            .map_err(ObservedFailure::operation)?;
        let observer_error = observer(OutputObservation::TempOwned(
            temporary.record(parent_id, content),
        ))
        .err();
        let result = if observer_error.is_none() {
            Some(buffers.copy_to(source, content, &mut temporary.file, limits, &mut control))
        } else {
            None
        };
        finish(
            &mut temporary,
            FinalName {
                parent: &parent,
                identity: parent_id,
                name,
            },
            parent_id,
            content,
            result,
            observer_error,
            &mut control,
            &mut observer,
        )
    }
    #[cfg(feature = "service")]
    #[expect(
        clippy::too_many_arguments,
        reason = "The observer adds durable state ordering to the original explicit native download ownership"
    )]
    pub(super) async fn download_file_inner<E>(
        &mut self,
        relative: impl AsRef<Path>,
        source: gnunet_client_host::EndpointSource,
        content: Content,
        buffers: &mut Buffers,
        cache: Option<&mut crate::Repository>,
        options: crate::network::DownloadOptions,
        mut control: impl FnMut(Progress) -> Control,
        create_parents: bool,
        mut observer: impl for<'a> FnMut(OutputObservation<'a>) -> Result<(), E>,
    ) -> Result<ReadFile, Box<ObservedFailure<E>>> {
        let parts = components(relative.as_ref()).map_err(ObservedFailure::operation)?;
        buffers
            .prepare(content, options.limits)
            .map_err(ObservedFailure::operation)?;
        let (name, directories) = parts
            .split_last()
            .ok_or_else(invalid_name)
            .map_err(ObservedFailure::operation)?;
        let parent = if create_parents {
            self.parent(directories)
        } else {
            self.parent_existing(directories)
        }
        .map_err(ObservedFailure::operation)?;
        ensure_absent(&parent, name).map_err(ObservedFailure::operation)?;
        let parent_id = FileIdentity::of(&parent)
            .map_err(Error::from)
            .map_err(ObservedFailure::operation)?;
        let mut temporary = self
            .temporary(&parent, name)
            .map_err(ObservedFailure::operation)?;
        let observer_error = observer(OutputObservation::TempOwned(
            temporary.record(parent_id, content),
        ))
        .err();
        let result = if observer_error.is_none() {
            Some(
                async {
                    let mut writer = tokio::fs::File::from_std(temporary.file.try_clone()?);
                    let transfer = buffers
                        .download(source, content, &mut writer, cache, options, &mut control)
                        .await;
                    // Drain original file work even when native transfer failed.
                    drop(writer.into_std().await);
                    transfer.map_err(Error::from)
                }
                .await,
            )
        } else {
            None
        };
        finish(
            &mut temporary,
            FinalName {
                parent: &parent,
                identity: parent_id,
                name,
            },
            parent_id,
            content,
            result,
            observer_error,
            &mut control,
            &mut observer,
        )
    }
}
// One physical finalizer serves whole-file and selected-range output.
// Authentication receipts remain distinct from naming and durability facts.
pub(super) struct FinalName<'a> {
    pub parent: &'a File,
    pub identity: FileIdentity,
    pub name: &'a OsStr,
}
pub(super) trait Receipt: Clone {
    fn progress(&self) -> Progress;
}
impl Receipt for ReadFile {
    fn progress(&self) -> Progress {
        self.progress
    }
}
#[cfg(feature = "service")]
impl Receipt for crate::network::range::ReadRange {
    fn progress(&self) -> Progress {
        self.authenticated
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "Original temporary, selected final parent, transfer result, observer and control have independent ownership"
)]
pub(super) fn finish<E, R: Receipt>(
    temporary: &mut Temporary<'_>,
    destination: FinalName<'_>,
    parent_id: FileIdentity,
    content: Content,
    result: Option<HostResult<R>>,
    mut observer_error: Option<E>,
    control: &mut impl FnMut(Progress) -> Control,
    observer: &mut impl for<'a> FnMut(OutputObservation<'a, R>) -> Result<(), E>,
) -> Result<R, Box<ObservedFailure<E, R>>> {
    let mut stage = CommitStage::NotLinked;
    let (mut receipt, mut operation) = match result {
        Some(Ok(read)) => (Some(read), None),
        Some(Err(error)) => (None, Some(error)),
        None => (None, None),
    };
    if observer_error.is_none()
        && operation.is_none()
        && let Some(completed) = receipt.as_ref()
    {
        let attempt = (|| -> HostResult<()> {
            if control(completed.progress()) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            temporary.file.sync_all()?;
            temporary.check_name()?;
            if control(completed.progress()) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            if let Err(error) = observer(OutputObservation::CommitIntent {
                temporary: temporary.record(parent_id, content),
                final_name: destination.name,
                final_parent: destination.identity,
            }) {
                observer_error = Some(error);
                return Ok(());
            }
            if control(completed.progress()) == Control::Cancel {
                return Err(Error::Cancelled);
            }
            linkat(
                temporary.parent,
                temporary.name.as_os_str(),
                destination.parent,
                destination.name,
                AtFlags::empty(),
            )?;
            stage = CommitStage::LinkedUnknown;
            temporary
                .check_link_at(destination.parent, destination.name)
                .map_err(|source| Error::CommitUnknown {
                    query: content.query,
                    source,
                })?;
            destination
                .parent
                .sync_all()
                .map_err(|source| Error::CommitUnknown {
                    query: content.query,
                    source,
                })?;
            stage = CommitStage::Durable;
            if let Err(error) = observer(OutputObservation::FileCommitted {
                temporary: temporary.record(parent_id, content),
                final_name: destination.name,
                final_parent: destination.identity,
                identity: temporary.record(parent_id, content).identity,
                receipt: completed.clone(),
            }) {
                observer_error = Some(error);
            }
            Ok(())
        })();
        if let Err(error) = attempt {
            operation = Some(error);
        }
    }
    let cleanup = temporary
        .remove()
        .and_then(|()| temporary.parent.sync_all());
    // An uncertain observer write fences subsequent state appends. Physical
    // cleanup still occurs and its independent result remains in the failure.
    if observer_error.is_none()
        && let Err(error) = observer(OutputObservation::Cleanup {
            temporary: temporary.record(parent_id, content),
            stage,
            outcome: cleanup.as_ref().map(|_| ()),
        })
    {
        observer_error = Some(error);
    }
    let cleanup = cleanup.err();
    if operation.is_none()
        && observer_error.is_none()
        && cleanup.is_none()
        && stage == CommitStage::Durable
        && let Some(read) = receipt.take()
    {
        return Ok(read);
    }
    if operation.is_none() && observer_error.is_none() && cleanup.is_none() {
        operation = Some(Error::Corrupt);
    }
    Err(Box::new(ObservedFailure {
        operation,
        observer: observer_error,
        cleanup,
        stage,
        receipt,
    }))
}
