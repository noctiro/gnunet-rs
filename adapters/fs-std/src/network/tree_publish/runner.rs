//! Native source traversal, actual DATASTORE acknowledgement and source checks.
use super::super::{
    Error as NetworkError, IndexedFile, PublishOptions, StoredFile, TimeLimit,
    publish::payload_bytes_wide,
};
use super::plan::{
    self as arenas, DirectoryPlan, Frame, Ledger, add_u64, add_usize, allocation, metadata,
};
use super::{
    InputDir, SourceError, StoredTree, TreeBudget, TreeEvent, TreeProgress, TreePublishCause,
    TreePublishFailure, TreePublishOptions, TreeStage,
};
use crate::input_tree::{self as source, FrameSource, Kind, Stamp};
use crate::{Buffers, Control, Progress};
use gnunet_client_host::EndpointSource;
use gnunet_crypto::Hash512State;
use gnunet_datastore_host::{Client, Instance, ProtocolClient, ReservationSlot, Slot};
use gnunet_fs::{Content, content::Layout, directory as dir};
use gnunet_types::Error as ProtocolError;
use std::{
    ffi::OsStr,
    fs::File,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

struct Failed {
    path: PathBuf,
    current: Progress,
    bytes: u128,
    content: Option<Content>,
    file_id: Option<[u8; 64]>,
    cause: TreePublishCause,
}
impl Failed {
    fn at(path: &Path, cause: impl Into<TreePublishCause>) -> Box<Self> {
        let cause = cause.into();
        let mut path = path.to_path_buf();
        if let TreePublishCause::Source(SourceError::Entry { name, .. }) = &cause {
            path.push(OsStr::from_bytes(name));
        }
        Box::new(Self {
            path,
            current: Progress::default(),
            bytes: 0,
            content: None,
            file_id: None,
            cause,
        })
    }
    fn accepted(mut self: Box<Self>, content: Content) -> Box<Self> {
        self.content = Some(content);
        self
    }
    fn indexed(mut self: Box<Self>, file_id: Option<[u8; 64]>) -> Box<Self> {
        self.file_id = file_id;
        self
    }
}
enum Mode {
    Full,
    Indexed {
        root: PathBuf,
        fs_source: EndpointSource,
    },
}
enum FilePublication {
    Full(StoredFile),
    Indexed(IndexedFile),
}
struct FileReceipt {
    stored: StoredFile,
    file_id: Option<[u8; 64]>,
}

struct Runner<'a, C> {
    buffers: &'a mut Buffers,
    source: EndpointSource,
    mode: Mode,
    options: TreePublishOptions,
    control: C,
    progress: TreeProgress,
    ledger: Ledger,
    wire: Vec<u8>,
    root_metadata: Vec<u8>,
    time: TimeLimit,
}
fn hash_source(hash: &mut Hash512State, path: &Path, stamp: Stamp) {
    let bytes = path.as_os_str().as_bytes();
    hash.update(&(bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    stamp.hash(hash);
}
fn fresh<'id, 'slots, 'buffers>(
    identity: &'id mut Instance,
    slots: &'slots mut [Slot<'buffers>],
    reservations: &'slots mut [ReservationSlot],
    source: EndpointSource,
    options: TreePublishOptions,
) -> Result<Client<'id, 'slots, 'buffers>, NetworkError> {
    let core = ProtocolClient::new(identity, slots, reservations, options.protocol)?;
    Client::new(core, source, options.native).map_err(Into::into)
}
impl<C: for<'event> FnMut(TreeEvent<'event>) -> Control> Runner<'_, C> {
    async fn check(&mut self, path: &Path, stage: TreeStage) -> Result<(), Box<Failed>> {
        self.time
            .during(std::future::ready(()))
            .await
            .map_err(|e| Failed::at(path, e))?;
        if (self.control)(TreeEvent {
            path,
            stage,
            progress: self.progress,
            current: Progress::default(),
            completed: None,
            file_id: None,
        }) == Control::Cancel
        {
            return Err(Failed::at(path, TreePublishCause::Cancelled));
        }
        Ok(())
    }
    fn frame(
        &mut self,
        file: File,
        path: PathBuf,
        parent_slot: Option<usize>,
        expected: Option<Stamp>,
    ) -> Result<Frame, Box<Failed>> {
        arenas::frame(
            file,
            path.clone(),
            parent_slot,
            expected,
            self.options.limits,
            &mut self.progress.entries,
            &mut self.ledger,
            &self.root_metadata,
        )
        .map_err(|error| Failed::at(&path, error))
    }
    fn admit(&mut self, size: u64, directory: bool) -> Result<PublishOptions, TreePublishCause> {
        let limits = self.options.limits;
        let encoded = Layout::new(size).encoded_tree_bytes();
        if size > self.options.publish.limits.max_file_bytes
            || encoded > self.options.publish.limits.max_encoded_bytes
        {
            return Err(TreePublishCause::Limit(TreeBudget::EncodedBytes));
        }
        let file_bytes = if directory {
            self.ledger.file_bytes
        } else {
            add_u64(
                self.ledger.file_bytes,
                size,
                limits.max_file_bytes,
                TreeBudget::FileBytes,
            )?
        };
        let directory_bytes = if directory {
            add_u64(
                self.ledger.directory_bytes,
                size,
                limits.max_directory_bytes,
                TreeBudget::DirectoryBytes,
            )?
        } else {
            self.ledger.directory_bytes
        };
        let encoded_bytes = self
            .ledger
            .encoded_bytes
            .checked_add(encoded)
            .filter(|n| *n <= limits.max_encoded_bytes)
            .ok_or(TreePublishCause::Limit(TreeBudget::EncodedBytes))?;
        let stored = payload_bytes_wide(
            Layout::new(size),
            !directory && matches!(&self.mode, Mode::Indexed { .. }),
        )?;
        let stored_bytes = self
            .ledger
            .stored_bytes
            .checked_add(stored)
            .filter(|bytes| *bytes <= limits.max_stored_bytes)
            .ok_or(TreePublishCause::Limit(TreeBudget::StoredBytes))?;
        self.ledger.file_bytes = file_bytes;
        self.ledger.directory_bytes = directory_bytes;
        self.ledger.encoded_bytes = encoded_bytes;
        self.ledger.stored_bytes = stored_bytes;
        Ok(self.options.publish)
    }
    fn accept(
        &mut self,
        done: &StoredFile,
        directory: bool,
        stored_bytes: u128,
        indexed: bool,
    ) -> Result<(), TreePublishCause> {
        let mut next = self.progress;
        if directory {
            next.directories = next
                .directories
                .checked_add(1)
                .ok_or(ProtocolError::Overflow)?;
            next.directory_bytes = next
                .directory_bytes
                .checked_add(done.content.size)
                .ok_or(ProtocolError::Overflow)?;
        } else {
            next.files = next.files.checked_add(1).ok_or(ProtocolError::Overflow)?;
            if indexed {
                next.indexed_files = next
                    .indexed_files
                    .checked_add(1)
                    .ok_or(ProtocolError::Overflow)?;
            }
            next.file_bytes = next
                .file_bytes
                .checked_add(done.content.size)
                .ok_or(ProtocolError::Overflow)?;
        }
        next.acknowledged.plaintext_bytes = next
            .acknowledged
            .plaintext_bytes
            .checked_add(done.progress.plaintext_bytes)
            .ok_or(ProtocolError::Overflow)?;
        next.acknowledged.blocks = next
            .acknowledged
            .blocks
            .checked_add(done.progress.blocks)
            .ok_or(ProtocolError::Overflow)?;
        next.acknowledged.encoded_bytes = next
            .acknowledged
            .encoded_bytes
            .checked_add(done.progress.encoded_bytes)
            .ok_or(ProtocolError::Overflow)?;
        next.stored_bytes = next
            .stored_bytes
            .checked_add(stored_bytes)
            .ok_or(ProtocolError::Overflow)?;
        self.progress = next;
        Ok(())
    }
    fn completion(
        &mut self,
        path: &Path,
        stage: TreeStage,
        done: &mut StoredFile,
        stored_bytes: u128,
        file_id: Option<[u8; 64]>,
    ) -> Result<(), Box<Failed>> {
        self.accept(
            done,
            stage == TreeStage::Directory,
            stored_bytes,
            file_id.is_some(),
        )
        .map_err(|cause| {
            Box::new(Failed {
                path: path.to_path_buf(),
                current: done.progress,
                bytes: stored_bytes,
                content: Some(done.content),
                file_id,
                cause,
            })
        })?;
        if let Some(cleanup) = done.cleanup.take() {
            return Err(
                Failed::at(path, TreePublishCause::Cleanup(Box::new(cleanup)))
                    .accepted(done.content)
                    .indexed(file_id),
            );
        }
        if (self.control)(TreeEvent {
            path,
            stage,
            progress: self.progress,
            current: Progress::default(),
            completed: Some(done.content),
            file_id,
        }) == Control::Cancel
        {
            return Err(Failed::at(path, TreePublishCause::Cancelled)
                .accepted(done.content)
                .indexed(file_id));
        }
        Ok(())
    }
    fn file_completion(
        &mut self,
        path: &Path,
        publication: FilePublication,
    ) -> Result<FileReceipt, Box<Failed>> {
        let (mut stored, bytes, file_id) = match publication {
            FilePublication::Full(stored) => {
                let bytes = stored.progress.encoded_bytes;
                (stored, bytes, None)
            }
            FilePublication::Indexed(receipt) => {
                let id = Some(receipt.file_id);
                if receipt.index_retirement_error.is_some() || receipt.stored.cleanup.is_some() {
                    // Both independent cleanup outcomes remain in the original
                    // receipt. If counter representation fails, preserve its
                    // actual ACKs separately rather than lose either cleanup.
                    let counted = self
                        .accept(&receipt.stored, false, receipt.stored_bytes, true)
                        .is_ok();
                    return Err(Box::new(Failed {
                        path: path.to_path_buf(),
                        current: if counted {
                            Progress::default()
                        } else {
                            receipt.stored.progress
                        },
                        bytes: if counted { 0 } else { receipt.stored_bytes },
                        content: Some(receipt.stored.content),
                        file_id: id,
                        cause: TreePublishCause::IndexedCleanup(Box::new(receipt)),
                    }));
                }
                (receipt.stored, receipt.stored_bytes, id)
            }
        };
        self.completion(path, TreeStage::File, &mut stored, bytes, file_id)?;
        Ok(FileReceipt { stored, file_id })
    }
    async fn bind_indexed_root(
        &mut self,
        input: &InputDir,
        named_root: &Path,
        fs_source: EndpointSource,
    ) -> Result<(), Box<Failed>> {
        let path = Path::new("");
        let canonical = self
            .time
            .during(tokio::fs::canonicalize(named_root))
            .await
            .map_err(|cause| Failed::at(path, cause))?
            .map_err(SourceError::from)
            .map_err(|cause| Failed::at(path, cause))?;
        let named = InputDir::open(&canonical).map_err(|cause| Failed::at(path, cause))?;
        if source::stamp(named.descriptor()).map_err(|cause| Failed::at(path, cause))?
            != source::stamp(input.descriptor()).map_err(|cause| Failed::at(path, cause))?
        {
            return Err(Failed::at(path, SourceError::Changed));
        }
        self.mode = Mode::Indexed {
            root: canonical,
            fs_source,
        };
        Ok(())
    }
    fn named_root_stable(&self, input: &InputDir) -> Result<(), Box<Failed>> {
        if let Mode::Indexed { root, .. } = &self.mode {
            let path = Path::new("");
            let named = InputDir::open(root).map_err(|cause| Failed::at(path, cause))?;
            if source::stamp(named.descriptor()).map_err(|cause| Failed::at(path, cause))?
                != source::stamp(input.descriptor()).map_err(|cause| Failed::at(path, cause))?
            {
                return Err(Failed::at(path, SourceError::Changed));
            }
        }
        Ok(())
    }
    async fn file(
        &mut self,
        input: &mut tokio::fs::File,
        size: u64,
        path: &Path,
        options: PublishOptions,
    ) -> Result<FilePublication, Box<Failed>> {
        let indexed = match &self.mode {
            Mode::Full => None,
            Mode::Indexed { root, fs_source } => Some((
                root.join(path),
                fs_source
                    .duplicate()
                    .map_err(NetworkError::from)
                    .map_err(|cause| Failed::at(path, cause))?,
            )),
        };
        let source = self
            .source
            .duplicate()
            .map_err(NetworkError::from)
            .map_err(|e| Failed::at(path, e))?;
        let mut identity = Instance::new();
        let mut slots = [Slot::new(&mut self.wire)];
        let mut reservations = [ReservationSlot::default(); 1];
        let store = fresh(
            &mut identity,
            &mut slots,
            &mut reservations,
            source,
            self.options,
        )
        .map_err(|e| Failed::at(path, e))?;
        let mut current = Progress::default();
        let mut bytes = 0;
        let progress = self.progress;
        let control = &mut self.control;
        if let Some((filename, fs_source)) = indexed {
            // The indexed API takes a fresh actual FD size itself. A source
            // growth after this tree's admission must be refused by its prepare
            // step before any IndexStart/PUT can exceed the tree-wide budget.
            let mut options = options;
            options.limits.max_file_bytes = options.limits.max_file_bytes.min(size);
            options.limits.max_encoded_bytes = options
                .limits
                .max_encoded_bytes
                .min(Layout::new(size).encoded_tree_bytes());
            return self
                .buffers
                .store_indexed_file(input, &filename, fs_source, store, options, |current| {
                    control(TreeEvent {
                        path,
                        stage: TreeStage::File,
                        progress,
                        current,
                        completed: None,
                        file_id: None,
                    })
                })
                .await
                .map(FilePublication::Indexed)
                .map_err(|cause| {
                    Box::new(Failed {
                        path: path.to_path_buf(),
                        current: cause.progress,
                        bytes: cause.stored_bytes,
                        content: None,
                        file_id: cause.file_id,
                        cause: TreePublishCause::Indexed(cause),
                    })
                });
        }
        self.buffers
            .store_file_tracked(
                input,
                size,
                store,
                options,
                &mut current,
                &mut bytes,
                |current| {
                    control(TreeEvent {
                        path,
                        stage: TreeStage::File,
                        progress,
                        current,
                        completed: None,
                        file_id: None,
                    })
                },
            )
            .await
            .map(FilePublication::Full)
            .map_err(|cause| {
                Box::new(Failed {
                    path: path.to_path_buf(),
                    current,
                    bytes,
                    content: None,
                    file_id: None,
                    cause: cause.into(),
                })
            })
    }
    async fn directory(
        &mut self,
        plan: &dir::BuildPlan<'_>,
        path: &Path,
        options: PublishOptions,
    ) -> Result<StoredFile, Box<Failed>> {
        let source = self
            .source
            .duplicate()
            .map_err(NetworkError::from)
            .map_err(|e| Failed::at(path, e))?;
        let mut identity = Instance::new();
        let mut slots = [Slot::new(&mut self.wire)];
        let mut reservations = [ReservationSlot::default(); 1];
        let store = fresh(
            &mut identity,
            &mut slots,
            &mut reservations,
            source,
            self.options,
        )
        .map_err(|e| Failed::at(path, e))?;
        let mut current = Progress::default();
        let mut bytes = 0;
        let progress = self.progress;
        let control = &mut self.control;
        self.buffers
            .store_directory_tracked(plan, store, options, &mut current, &mut bytes, |current| {
                control(TreeEvent {
                    path,
                    stage: TreeStage::Directory,
                    progress,
                    current,
                    completed: None,
                    file_id: None,
                })
            })
            .await
            .map_err(|cause| {
                Box::new(Failed {
                    path: path.to_path_buf(),
                    current,
                    bytes,
                    content: None,
                    file_id: None,
                    cause: cause.into(),
                })
            })
    }
    async fn verify_tree(
        &mut self,
        input: &InputDir,
        expected: [u8; 64],
    ) -> Result<(), Box<Failed>> {
        struct VerifyFrame {
            source: FrameSource,
            next: usize,
            path: PathBuf,
        }
        let limits = self.options.limits;
        let root_path = PathBuf::new();
        self.check(&root_path, TreeStage::Verify).await?;
        let file = input
            .descriptor()
            .try_clone()
            .map_err(SourceError::from)
            .map_err(|e| Failed::at(&root_path, e))?;
        let root = FrameSource::scan(
            file,
            limits.max_children,
            limits.max_name_bytes,
            limits.max_retained_name_bytes,
        )
        .map_err(|e| Failed::at(&root_path, e))?;
        let mut names = root.names_bytes;
        let mut entries = root.names.len() as u64;
        if entries > limits.max_entries {
            return Err(Failed::at(
                &root_path,
                TreePublishCause::Limit(TreeBudget::Entries),
            ));
        }
        let mut hash = Hash512State::new();
        hash.update(b"gnunet-rs native tree source v1\0");
        hash_source(&mut hash, &root_path, root.stamp);
        let mut frames = Vec::new();
        frames
            .try_reserve(limits.max_depth.saturating_add(1))
            .map_err(|_| Failed::at(&root_path, ProtocolError::Capacity))?;
        frames.push(VerifyFrame {
            source: root,
            next: 0,
            path: root_path,
        });
        while !frames.is_empty() {
            let last = frames.len() - 1;
            let path = frames[last].path.clone();
            self.check(&path, TreeStage::Verify).await?;
            if frames[last].next == frames[last].source.names.len() {
                frames[last]
                    .source
                    .verify()
                    .map_err(|e| Failed::at(&path, e))?;
                let frame = frames
                    .pop()
                    .ok_or_else(|| Failed::at(&path, ProtocolError::NotReady))?;
                names -= frame.source.names_bytes;
                continue;
            }
            let index = frames[last].next;
            frames[last].next += 1;
            let name = &frames[last].source.names[index];
            let child = path.join(OsStr::from_bytes(&name.bytes));
            if child.as_os_str().as_bytes().len() > limits.max_path_bytes {
                return Err(Failed::at(
                    &child,
                    TreePublishCause::Limit(TreeBudget::Path),
                ));
            }
            if frames.len() > limits.max_depth {
                return Err(Failed::at(
                    &child,
                    TreePublishCause::Limit(TreeBudget::Depth),
                ));
            }
            let kind = name.kind;
            let expected_stamp = name.stamp;
            let file = frames[last]
                .source
                .open(index)
                .map_err(|e| Failed::at(&child, e))?;
            if kind == Kind::Directory {
                let frame = FrameSource::scan(
                    file,
                    limits.max_children,
                    limits.max_name_bytes,
                    limits.max_retained_name_bytes.saturating_sub(names),
                )
                .map_err(|e| Failed::at(&child, e))?;
                if frame.stamp != expected_stamp {
                    return Err(Failed::at(&child, SourceError::Changed));
                }
                names = add_usize(
                    names,
                    frame.names_bytes,
                    limits.max_retained_name_bytes,
                    TreeBudget::Path,
                )
                .map_err(|e| Failed::at(&child, e))?;
                entries = add_u64(
                    entries,
                    frame.names.len() as u64,
                    limits.max_entries,
                    TreeBudget::Entries,
                )
                .map_err(|e| Failed::at(&child, e))?;
                hash_source(&mut hash, &child, frame.stamp);
                frames.push(VerifyFrame {
                    source: frame,
                    next: 0,
                    path: child,
                });
            } else {
                hash_source(&mut hash, &child, expected_stamp);
            }
        }
        if hash.finish() != expected {
            return Err(Failed::at(Path::new(""), SourceError::Changed));
        }
        Ok(())
    }
    async fn run(&mut self, input: &InputDir) -> Result<StoredTree, Box<Failed>> {
        let path = PathBuf::new();
        self.check(&path, TreeStage::Directory).await?;
        let file = input
            .descriptor()
            .try_clone()
            .map_err(SourceError::from)
            .map_err(|e| Failed::at(&path, e))?;
        let root = self.frame(file, path, None, None)?;
        let mut hash = Hash512State::new();
        hash.update(b"gnunet-rs native tree source v1\0");
        hash_source(&mut hash, &root.path, root.source.stamp);
        let mut frames = Vec::new();
        frames
            .try_reserve(self.options.limits.max_depth.saturating_add(1))
            .map_err(|_| Failed::at(&root.path, ProtocolError::Capacity))?;
        frames.push(root);
        while !frames.is_empty() {
            let last = frames.len() - 1;
            if frames[last].next < frames[last].source.names.len() {
                let index = frames[last].next;
                let name = &frames[last].source.names[index];
                let path = frames[last].path.join(OsStr::from_bytes(&name.bytes));
                if path.as_os_str().as_bytes().len() > self.options.limits.max_path_bytes {
                    return Err(Failed::at(&path, TreePublishCause::Limit(TreeBudget::Path)));
                }
                if frames.len() > self.options.limits.max_depth {
                    return Err(Failed::at(
                        &path,
                        TreePublishCause::Limit(TreeBudget::Depth),
                    ));
                }
                let kind = name.kind;
                let expected = name.stamp;
                let file = frames[last]
                    .source
                    .open(index)
                    .map_err(|e| Failed::at(&path, e))?;
                frames[last].next += 1;
                if kind == Kind::Directory {
                    self.check(&path, TreeStage::Directory).await?;
                    let frame = self.frame(file, path, Some(index), Some(expected))?;
                    hash_source(&mut hash, &frame.path, frame.source.stamp);
                    frames.push(frame);
                    continue;
                }
                self.check(&path, TreeStage::File).await?;
                hash_source(&mut hash, &path, expected);
                let options = self
                    .admit(expected.bytes, false)
                    .map_err(|e| Failed::at(&path, e))?;
                let guard = file
                    .try_clone()
                    .map_err(SourceError::from)
                    .map_err(|e| Failed::at(&path, e))?;
                self.named_root_stable(input)?;
                let mut input = tokio::fs::File::from_std(file);
                let publication = self
                    .file(&mut input, expected.bytes, &path, options)
                    .await?;
                // Retain exact full acceptance before any source-coherence failure.
                let receipt = self.file_completion(&path, publication)?;
                let done = receipt.stored;
                let file_id = receipt.file_id;
                if source::stamp(&guard)
                    .map_err(|e| Failed::at(&path, e).accepted(done.content).indexed(file_id))?
                    != expected
                {
                    return Err(Failed::at(&path, SourceError::Changed)
                        .accepted(done.content)
                        .indexed(file_id));
                }
                frames[last]
                    .source
                    .open(index)
                    .map_err(|e| Failed::at(&path, e).accepted(done.content).indexed(file_id))?;
                frames[last].entries[index].content = Some(done.content);
                continue;
            }
            let mut frame = frames
                .pop()
                .ok_or_else(|| Failed::at(Path::new(""), ProtocolError::NotReady))?;
            let path = frame.path.clone();
            self.check(&path, TreeStage::Directory).await?;
            frame.source.verify().map_err(|e| Failed::at(&path, e))?;
            // A finished frame no longer needs its enumerated basename list.
            // Release it before directory transfer/final coherence passes so
            // verification shares the same global retained-name bound.
            self.ledger.names -= frame.source.names_bytes;
            frame.source.names_bytes = 0;
            frame.source.names = Vec::new();
            // Share exact official record preparation and placement with
            // immutable durable tree preparation.
            let root_bytes = std::mem::take(&mut self.root_metadata);
            let mut prepared =
                DirectoryPlan::prepare(&mut frame.entries, &root_bytes, self.options.limits)
                    .map_err(|error| Failed::at(&path, error))?;
            let plan = prepared.plan().map_err(|error| Failed::at(&path, error))?;
            let options = self
                .admit(plan.report().wire_bytes, true)
                .map_err(|e| Failed::at(&path, e))?;
            let result = self.directory(&plan, &path, options).await;
            drop(prepared);
            self.root_metadata = root_bytes;
            let mut done = result?;
            let bytes = done.progress.encoded_bytes;
            self.completion(&path, TreeStage::Directory, &mut done, bytes, None)?;
            frame
                .source
                .verify()
                .map_err(|e| Failed::at(&path, e).accepted(done.content))?;
            self.ledger.names -= frame.source.names_bytes;
            self.ledger.metadata -= frame.metadata_bytes;
            self.ledger.records -= frame.record_bytes;
            let parent_slot = frame.parent_slot;
            drop(frame);
            if let Some(index) = parent_slot {
                let parent = frames
                    .last_mut()
                    .ok_or_else(|| Failed::at(&path, ProtocolError::NotReady))?;
                parent
                    .source
                    .open(index)
                    .map_err(|e| Failed::at(&path, e).accepted(done.content))?;
                parent.entries[index].content = Some(done.content);
            } else {
                let fingerprint = hash.finish();
                self.verify_tree(input, fingerprint)
                    .await
                    .map_err(|failure| failure.accepted(done.content))?;
                self.named_root_stable(input)
                    .map_err(|failure| failure.accepted(done.content))?;
                return Ok(StoredTree {
                    root: done,
                    progress: self.progress,
                    source_fingerprint: fingerprint,
                });
            }
        }
        Err(Failed::at(Path::new(""), ProtocolError::NotReady))
    }
}
impl Buffers {
    /// Stream full insertion of one descriptor-anchored native tree. Every child
    /// is acknowledged before its CHK enters its parent's official directory.
    /// Ordered raw basenames use kind180 CString metadata; every directory root
    /// and directory entry has the official MIME item. No payload is retained
    /// across files, and no FULL_DATA inline hint is invented.
    ///
    /// Each object explicitly creates one dedicated DATASTORE client using the
    /// caller's duplicated EndpointSource and one reused frame allocation. Its
    /// possibly weighted PUTs are submitted once. Caller control can journal
    /// actual completed CHKs; failure retains the exact current ACK prefix and
    /// original cause without an unbounded in-memory receipt list.
    ///
    /// One final descriptor-anchored stat walk after the root PUT detects
    /// changed names, identities, sizes and mtime/ctime observations even in
    /// previously stored subtrees. A source change returns a partial failure
    /// retaining the actual root ACK; it yields no completed-tree receipt. This is not an atomic
    /// filesystem snapshot: changes after their final observation require a
    /// caller-provided immutable snapshot for a stronger guarantee. Native
    /// directory/stat operations are blocking and belong on a host worker when
    /// the caller's executor must not block on filesystem operations.
    pub async fn store_tree(
        &mut self,
        input: &InputDir,
        source: EndpointSource,
        options: TreePublishOptions,
        control: impl for<'event> FnMut(TreeEvent<'event>) -> Control,
    ) -> Result<StoredTree, Box<TreePublishFailure>> {
        self.store_tree_mode(input, source, options, control, None)
            .await
    }
    /// Index every actual regular file through official IndexStart/type6 while
    /// publishing every generated directory through ordinary full insertion.
    /// The explicit named root is canonicalized and must match the selected root
    /// descriptor before any service mutation. Each original FD/path is then
    /// validated again by store_indexed_file; no /dev/fd service path is used.
    ///
    /// Both supplied services must use the same numeric deadline clock domain.
    /// An IndexStarted reply may describe an existing shared file-ID registration
    /// with an older path. Neither duplicate content nor multiple source paths
    /// implies ownership; this operation never automatically unindexes anything.
    /// Exact actual descriptor payload bytes are separate from computed leaf
    /// ciphertext bytes. Original index certainty, incomplete ACK prefixes and
    /// both independent cleanup outcomes remain in typed failures/receipts.
    pub async fn store_indexed_tree(
        &mut self,
        input: &InputDir,
        named_root: &Path,
        fs_source: EndpointSource,
        datastore: EndpointSource,
        options: TreePublishOptions,
        control: impl for<'event> FnMut(TreeEvent<'event>) -> Control,
    ) -> Result<StoredTree, Box<TreePublishFailure>> {
        self.store_tree_mode(
            input,
            datastore,
            options,
            control,
            Some((named_root, fs_source)),
        )
        .await
    }
    async fn store_tree_mode(
        &mut self,
        input: &InputDir,
        source: EndpointSource,
        options: TreePublishOptions,
        control: impl for<'event> FnMut(TreeEvent<'event>) -> Control,
        indexed: Option<(&Path, EndpointSource)>,
    ) -> Result<StoredTree, Box<TreePublishFailure>> {
        let initial = (|| -> Result<(Vec<u8>, Vec<u8>, TimeLimit), TreePublishCause> {
            if options.protocol.max_pending != 1
                || options.protocol.max_frame_bytes > 65535
                || options.protocol.max_frame_bytes == 0
            {
                return Err(ProtocolError::InvalidInput.into());
            }
            let wire = allocation(options.protocol.max_frame_bytes)?;
            let root = metadata(&[dir::MIME_ITEM], options.limits.max_metadata_bytes)?;
            if root.len() > options.limits.max_retained_metadata_bytes {
                return Err(TreePublishCause::Limit(TreeBudget::Metadata));
            }
            let time = TimeLimit::new(source.clock(), options.publish.deadline)?;
            Ok((wire, root, time))
        })();
        let (wire, root_metadata, time) = initial.map_err(|cause| {
            Box::new(TreePublishFailure {
                path: PathBuf::new(),
                progress: TreeProgress::default(),
                current: Progress::default(),
                current_stored_bytes: 0,
                acknowledged_content: None,
                indexed_file_id: None,
                cause,
            })
        })?;
        let mut runner = Runner {
            buffers: self,
            source,
            mode: Mode::Full,
            options,
            control,
            progress: TreeProgress::default(),
            ledger: Ledger::default(),
            wire,
            root_metadata,
            time,
        };
        let result = async {
            if let Some((root, fs_source)) = indexed {
                runner.bind_indexed_root(input, root, fs_source).await?;
            }
            runner.run(input).await
        }
        .await;
        result.map_err(|failure| {
            Box::new(TreePublishFailure {
                path: failure.path,
                progress: runner.progress,
                current: failure.current,
                current_stored_bytes: failure.bytes,
                acknowledged_content: failure.content,
                indexed_file_id: failure.file_id,
                cause: failure.cause,
            })
        })
    }
}
