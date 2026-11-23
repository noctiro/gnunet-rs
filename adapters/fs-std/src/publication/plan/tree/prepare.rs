//! Descriptor-anchored postorder preparation using the shared native tree arenas.
use super::super::{Artifact, Error, Limits, Plan, Put, file, indexed};
use super::{
    Event, MeasuredObject, MetadataProvider, Observer, OriginalMetadata, TreeObject, TreePlan,
    emit, inline,
};
use crate::input_tree::{self as source, FrameSource, InputDir, Kind, SourceError, Stamp};
use crate::network::{
    publish::payload_bytes_wide,
    tree_publish::{
        TreeBudget, TreePublishCause,
        plan::{self as arenas, DirectoryPlan, Frame, Ledger, add_u64, add_usize, metadata},
    },
};
use crate::{Buffers, Control, Progress, Repository};
use gnunet_crypto::Hash512State;
use gnunet_fs::{Content, Location, Uri, content::Layout, directory as dir};
use gnunet_types::Error as ProtocolError;
use std::{
    fs,
    io::Seek,
    mem::size_of,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(in crate::publication) struct Locations<'a> {
    signer: &'a mut dyn FnMut(Content) -> Result<Option<Location>, Error>,
    pub(in crate::publication) values: Vec<(usize, Location)>,
}

impl<'a> Locations<'a> {
    pub(in crate::publication) fn new(
        signer: &'a mut dyn FnMut(Content) -> Result<Option<Location>, Error>,
    ) -> Self {
        Self {
            signer,
            values: Vec::new(),
        }
    }

    pub(in crate::publication) fn sign(
        &mut self,
        ordinal: usize,
        content: Content,
    ) -> Result<Option<NonZeroUsize>, Error> {
        let Some(location) = (self.signer)(content)? else {
            return Ok(None);
        };
        if location.content() != content {
            return Err(Error::Binding);
        }
        self.values.try_reserve(1).map_err(|_| Error::Limit)?;
        self.values.push((ordinal, location));
        Ok(NonZeroUsize::new(self.values.len()))
    }
}

fn source_error(error: SourceError) -> Error {
    TreePublishCause::Source(error).into()
}
fn checked_metadata(
    bytes: &[u8],
    limit: usize,
    directory: bool,
    filename: Option<&[u8]>,
) -> Result<(), Error> {
    use gnunet_fs::metadata as md;
    let decoded = md::decode_uncompressed(
        bytes,
        md::Limits {
            max_coded_bytes: limit,
            max_plain_bytes: limit,
            max_entries: limit / md::ENTRY_BYTES,
        },
        md::Mode::Strict,
    )?;
    let md::Decoded::Present(metadata) = decoded else {
        return Err(Error::Binding);
    };
    if (dir::claims_directory(metadata.items()) == Some(true)) != directory
        || filename.is_some_and(|name| dir::filename(metadata.items()) != Some(name))
    {
        return Err(Error::Binding);
    }
    Ok(())
}
fn hash_source(hash: &mut Hash512State, path: &Path, stamp: Stamp) {
    let bytes = gnunet_native::os_bytes::encode(path.as_os_str());
    hash.update(&(bytes.len() as u64).to_be_bytes());
    hash.update(&bytes);
    stamp.hash(hash);
}
fn composed(before: Progress, now: Progress) -> Result<Progress, Error> {
    Ok(Progress {
        plaintext_bytes: before
            .plaintext_bytes
            .checked_add(now.plaintext_bytes)
            .ok_or(ProtocolError::Overflow)?,
        blocks: before
            .blocks
            .checked_add(now.blocks)
            .ok_or(ProtocolError::Overflow)?,
        encoded_bytes: before
            .encoded_bytes
            .checked_add(now.encoded_bytes)
            .ok_or(ProtocolError::Overflow)?,
    })
}
struct PreparedFrame {
    frame: Frame,
    root_metadata: Vec<u8>,
    progress: Option<DirectoryProgress>,
}

struct DirectoryProgress {
    total: u64,
    initial: u64,
    started: Instant,
}

struct DirectorySize {
    stamp: Stamp,
    total: u64,
}

struct EncoderProgress<'a> {
    path: &'a Path,
    total: u64,
    initial: u64,
    ancestors: &'a [PreparedFrame],
    started: Instant,
    last: Option<(u64, Instant)>,
}

impl EncoderProgress<'_> {
    fn report(&mut self, observer: &mut Observer<'_>, completed: u64) -> Result<(), Error> {
        if observer.is_none() {
            return Ok(());
        }
        let now = Instant::now();
        if self.last.is_some_and(|(last, when)| {
            last == completed
                || (completed != self.total
                    && now.duration_since(when) < Duration::from_millis(200))
        }) {
            return Ok(());
        }
        self.last = Some((completed, now));
        emit(
            observer,
            Event::Encoding {
                relative: self.path,
                completed,
                total: self.total,
                elapsed: now.duration_since(self.started),
            },
        )?;
        if completed == 0 {
            return Ok(());
        }
        for frame in self.ancestors.iter().rev() {
            let directory = frame.progress.as_ref().ok_or(Error::Binding)?;
            let aggregate = self
                .initial
                .checked_add(completed)
                .and_then(|n| n.checked_sub(directory.initial))
                .filter(|n| *n <= directory.total)
                .ok_or_else(|| source_error(SourceError::Changed))?;
            emit(
                observer,
                Event::Encoding {
                    relative: &frame.path,
                    completed: aggregate,
                    total: directory.total,
                    elapsed: now.duration_since(directory.started),
                },
            )?;
        }
        Ok(())
    }
}
impl std::ops::Deref for PreparedFrame {
    type Target = Frame;
    fn deref(&self) -> &Frame {
        &self.frame
    }
}
impl std::ops::DerefMut for PreparedFrame {
    fn deref_mut(&mut self) -> &mut Frame {
        &mut self.frame
    }
}
impl<T: MetadataProvider + ?Sized> MetadataProvider for &mut T {
    fn prepare(
        &mut self,
        source: &std::fs::File,
        relative: &Path,
        directory: bool,
        base: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>, Error> {
        (**self).prepare(source, relative, directory, base, max_bytes)
    }
}
struct Prepare<'a, C, M> {
    metadata: M,
    limits: Limits,
    root_metadata: Vec<u8>,
    ledger: Ledger,
    entries: u64,
    progress: Progress,
    control: C,
    root_path: Option<PathBuf>,
    root_stamp: Stamp,
    objects: Vec<TreeObject>,
    puts: Vec<Put>,
    sources: Vec<indexed::Source>,
    plan_bytes: usize,
    observer: Observer<'a>,
    inline: inline::Scratch,
}

enum Destination<'a> {
    Retained(&'a mut Repository),
    Measured(Vec<MeasuredObject>),
}

enum Outcome {
    Retained(TreePlan, Vec<Put>),
    Measured(Vec<MeasuredObject>),
}

impl<C: FnMut(Progress) -> Control, M: MetadataProvider> Prepare<'_, C, M> {
    fn check(&mut self) -> Result<(), Error> {
        if (self.control)(self.progress) == Control::Cancel {
            return Err(crate::Error::Cancelled.into());
        }
        Ok(())
    }
    fn named_root_stable(&self, input: &InputDir) -> Result<(), Error> {
        if let Some(path) = &self.root_path {
            let named = InputDir::open(path).map_err(source_error)?;
            if source::stamp(named.descriptor()).map_err(source_error)? != self.root_stamp
                || source::stamp(input.descriptor()).map_err(source_error)? != self.root_stamp
            {
                return Err(source_error(SourceError::Changed));
            }
        }
        Ok(())
    }
    fn frame(
        &mut self,
        file: std::fs::File,
        path: PathBuf,
        parent_slot: Option<usize>,
        expected: Option<Stamp>,
    ) -> Result<PreparedFrame, Error> {
        let root_metadata = self.metadata.prepare(
            &file,
            &path,
            true,
            &self.root_metadata,
            self.limits.tree.max_metadata_bytes,
        )?;
        checked_metadata(
            &root_metadata,
            self.limits.tree.max_metadata_bytes,
            true,
            None,
        )?;
        let frame = arenas::frame(
            file,
            path,
            parent_slot,
            expected,
            self.limits.tree,
            &mut self.entries,
            &mut self.ledger,
            &root_metadata,
        )?;
        Ok(PreparedFrame {
            frame,
            root_metadata,
            progress: None,
        })
    }
    fn entry_metadata(
        &mut self,
        frame: &mut Frame,
        index: usize,
        source: &std::fs::File,
        relative: &Path,
        directory: bool,
    ) -> Result<(), Error> {
        let entry = frame.entries.get_mut(index).ok_or(Error::Binding)?;
        let bytes = self.metadata.prepare(
            source,
            relative,
            directory,
            &entry.metadata,
            self.limits.tree.max_metadata_bytes,
        )?;
        let cap = self.limits.tree;
        checked_metadata(
            &bytes,
            cap.max_metadata_bytes,
            directory,
            relative
                .file_name()
                .map(crate::input_tree::protocol_name)
                .transpose()
                .map_err(source_error)?,
        )?;
        // The unchanged public planner keeps its original total-work accounting.
        if bytes == entry.metadata {
            return Ok(());
        }
        if bytes.len() > cap.max_metadata_bytes {
            return Err(Error::Limit);
        }
        let old_metadata = entry.metadata.len();
        let old_record = entry.record.len();
        let length = Content {
            key: [0; 64],
            query: [0; 64],
            size: u64::MAX,
        }
        .uri()
        .encoded_len()?
        .checked_add(5)
        .and_then(|n| n.checked_add(bytes.len()))
        .ok_or(Error::Limit)?;
        if length > cap.max_record_bytes {
            return Err(Error::Limit);
        }
        let metadata_bytes = frame
            .metadata_bytes
            .checked_sub(old_metadata)
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or(Error::Limit)?;
        let record_bytes = frame
            .record_bytes
            .checked_sub(old_record)
            .and_then(|n| n.checked_add(length))
            .ok_or(Error::Limit)?;
        let retained_metadata = self
            .ledger
            .metadata
            .checked_sub(old_metadata)
            .and_then(|n| n.checked_add(bytes.len()))
            .filter(|n| *n <= cap.max_retained_metadata_bytes)
            .ok_or(Error::Limit)?;
        let retained_records = self
            .ledger
            .records
            .checked_sub(old_record)
            .and_then(|n| n.checked_add(length))
            .filter(|n| *n <= cap.max_retained_record_bytes)
            .ok_or(Error::Limit)?;
        let total_metadata = add_u64(
            self.ledger.total_metadata,
            u64::try_from(bytes.len()).map_err(|_| Error::Limit)?,
            cap.max_total_metadata_bytes,
            TreeBudget::Metadata,
        )?;
        let total_records = add_u64(
            self.ledger.total_records,
            u64::try_from(length).map_err(|_| Error::Limit)?,
            cap.max_total_record_bytes,
            TreeBudget::Records,
        )?;
        let record = arenas::allocation(length)?;
        entry.metadata = bytes;
        entry.record = record;
        frame.metadata_bytes = metadata_bytes;
        frame.record_bytes = record_bytes;
        self.ledger.metadata = retained_metadata;
        self.ledger.records = retained_records;
        self.ledger.total_metadata = total_metadata;
        self.ledger.total_records = total_records;
        Ok(())
    }
    fn admit(
        &mut self,
        size: u64,
        directory: bool,
        destination: &Destination<'_>,
    ) -> Result<(), Error> {
        let t = self.limits.tree;
        let encoded = Layout::new(size).encoded_tree_bytes();
        if size > self.limits.file.max_file_bytes || encoded > self.limits.file.max_encoded_bytes {
            return Err(TreePublishCause::Limit(TreeBudget::EncodedBytes).into());
        }
        let file_bytes = if directory {
            self.ledger.file_bytes
        } else {
            add_u64(
                self.ledger.file_bytes,
                size,
                t.max_file_bytes,
                TreeBudget::FileBytes,
            )?
        };
        let directory_bytes = if directory {
            add_u64(
                self.ledger.directory_bytes,
                size,
                t.max_directory_bytes,
                TreeBudget::DirectoryBytes,
            )?
        } else {
            self.ledger.directory_bytes
        };
        let encoded_bytes = self
            .ledger
            .encoded_bytes
            .checked_add(encoded)
            .filter(|v| *v <= t.max_encoded_bytes)
            .ok_or(TreePublishCause::Limit(TreeBudget::EncodedBytes))?;
        if matches!(destination, Destination::Retained(_)) {
            let stored =
                payload_bytes_wide(Layout::new(size), !directory && self.root_path.is_some())?;
            self.ledger.stored_bytes = self
                .ledger
                .stored_bytes
                .checked_add(stored)
                .filter(|v| *v <= t.max_stored_bytes && *v <= self.limits.max_stored_bytes)
                .ok_or(TreePublishCause::Limit(TreeBudget::StoredBytes))?;
        }
        self.ledger.file_bytes = file_bytes;
        self.ledger.directory_bytes = directory_bytes;
        self.ledger.encoded_bytes = encoded_bytes;
        Ok(())
    }

    fn bind_child(
        &mut self,
        frame: &mut Frame,
        index: usize,
        content: Content,
        source: inline::Source<'_, '_>,
        locations: Option<&mut Locations<'_>>,
        buffers: &mut Buffers,
    ) -> Result<(), Error> {
        self.check()?;
        let entry = frame.entries.get_mut(index).ok_or(Error::Binding)?;
        let (target, slot) = if let Some(locations) = locations {
            let ordinal = self.objects.len().checked_sub(1).ok_or(Error::Binding)?;
            if let Some(slot) = locations.sign(ordinal, content)? {
                let location = locations.values[slot.get() - 1].1;
                (Uri::Location(location), Some(slot))
            } else {
                (content.uri(), None)
            }
        } else {
            (content.uri(), None)
        };
        let prefix = target.encoded_len()?.checked_add(5).ok_or(Error::Limit)?;
        let limits = self.limits.tree;
        let remaining = |retained: usize, used: usize, total: u64, consumed: u64| {
            retained
                .saturating_sub(used)
                .min(usize::try_from(total.saturating_sub(consumed)).unwrap_or(usize::MAX))
        };
        let record_limit = limits
            .max_record_bytes
            .min(entry.record.len().saturating_add(remaining(
                limits.max_retained_record_bytes,
                self.ledger.records,
                limits.max_total_record_bytes,
                self.ledger.total_records,
            )));
        let metadata_limit = limits
            .max_metadata_bytes
            .min(entry.metadata.len().saturating_add(remaining(
                limits.max_retained_metadata_bytes,
                self.ledger.metadata,
                limits.max_total_metadata_bytes,
                self.ledger.total_metadata,
            )))
            .min(record_limit.saturating_sub(prefix));
        if entry.metadata.len() > metadata_limit {
            return Err(TreePublishCause::Limit(TreeBudget::Records).into());
        }
        let inline = self.inline.metadata(
            source,
            content,
            target,
            &entry.metadata,
            metadata_limit,
            buffers,
        )?;
        self.check()?;
        if let Some(metadata) = inline {
            let extra = metadata
                .len()
                .checked_sub(entry.metadata.len())
                .ok_or(Error::Binding)?;
            self.ledger.metadata += extra;
            self.ledger.total_metadata += u64::try_from(extra).map_err(|_| Error::Limit)?;
            frame.metadata_bytes += extra;
            entry.metadata = metadata;
        }
        let needed = prefix + entry.metadata.len();
        if needed > entry.record.len() {
            let extra = needed - entry.record.len();
            entry
                .record
                .try_reserve_exact(extra)
                .map_err(|_| Error::Limit)?;
            entry.record.resize(needed, 0);
            self.ledger.records += extra;
            self.ledger.total_records += u64::try_from(extra).map_err(|_| Error::Limit)?;
            frame.record_bytes += extra;
        }
        entry.location = slot;
        entry.content = Some(content);
        Ok(())
    }

    fn measured(
        &mut self,
        objects: &mut Vec<MeasuredObject>,
        path: &Path,
        content: Content,
        progress: Progress,
    ) -> Result<(), Error> {
        let relative = crate::input::owned_path(path)?;
        let bytes = size_of::<MeasuredObject>()
            .checked_add(relative.capacity())
            .ok_or(Error::Limit)?;
        self.plan_bytes = self
            .plan_bytes
            .checked_add(bytes)
            .filter(|bytes| *bytes <= self.limits.max_plan_bytes)
            .ok_or(Error::Limit)?;
        self.progress = composed(self.progress, progress)?;
        objects.try_reserve(1).map_err(|_| Error::Limit)?;
        objects.push(MeasuredObject { relative, content });
        Ok(())
    }
    fn local_limits(&self) -> Result<Limits, Error> {
        let mut limits = self.limits;
        limits.max_puts = limits
            .max_puts
            .checked_sub(self.puts.len())
            .ok_or(Error::Limit)?;
        limits.max_plan_bytes = limits
            .max_plan_bytes
            .checked_sub(self.plan_bytes)
            .ok_or(Error::Limit)?;
        // The exact global actual payload budget was admitted before preparing
        // this object. Its own bound remains the same immutable caller policy.
        Ok(limits)
    }
    fn append(
        &mut self,
        path: &Path,
        directory: bool,
        content: Content,
        puts: Vec<Put>,
        source: Option<indexed::Source>,
    ) -> Result<(), Error> {
        let extra = path
            .as_os_str()
            .as_encoded_bytes()
            .len()
            .checked_add(size_of::<TreeObject>())
            .and_then(|v| v.checked_add(puts.len().checked_mul(size_of::<Put>())?))
            .ok_or(Error::Limit)?;
        let source_bytes = source.as_ref().map_or(0, |s| {
            size_of::<indexed::Source>().saturating_add(s.path.as_os_str().len())
        });
        let next_bytes = self
            .plan_bytes
            .checked_add(extra)
            .and_then(|v| v.checked_add(source_bytes))
            .filter(|v| *v <= self.limits.max_plan_bytes)
            .ok_or(Error::Limit)?;
        let next_puts = self
            .puts
            .len()
            .checked_add(puts.len())
            .filter(|v| *v <= self.limits.max_puts)
            .ok_or(Error::Limit)?;
        self.objects.try_reserve(1).map_err(|_| Error::Limit)?;
        self.puts
            .try_reserve(puts.len())
            .map_err(|_| Error::Limit)?;
        let indexed = if let Some(source) = source {
            self.sources.try_reserve(1).map_err(|_| Error::Limit)?;
            let slot = self.sources.len();
            self.sources.push(source);
            Some(slot)
        } else {
            None
        };
        let raw = gnunet_native::os_bytes::encode(path.as_os_str());
        let mut path = Vec::new();
        path.try_reserve_exact(raw.len())
            .map_err(|_| Error::Limit)?;
        path.extend_from_slice(&raw);
        self.objects.push(TreeObject {
            path,
            content,
            directory,
            first_put: self.puts.len(),
            put_count: puts.len(),
            indexed,
        });
        self.puts.extend(puts);
        debug_assert_eq!(self.puts.len(), next_puts);
        self.plan_bytes = next_bytes;
        self.progress = composed(
            self.progress,
            Progress {
                plaintext_bytes: content.size,
                blocks: u64::try_from(
                    next_puts - self.objects.last().ok_or(Error::Binding)?.first_put,
                )
                .map_err(|_| Error::Limit)?,
                encoded_bytes: Layout::new(content.size).encoded_tree_bytes(),
            },
        )?;
        Ok(())
    }
    fn file(
        &mut self,
        destination: &mut Destination<'_>,
        input: &mut std::fs::File,
        path: &Path,
        admitted_size: u64,
        buffers: &mut Buffers,
        ancestors: &[PreparedFrame],
    ) -> Result<Content, Error> {
        // The captured source may grow after global admission. Refuse that
        // growth before preparation can spool beyond the admitted object work.
        let mut limits = self.local_limits()?;
        limits.file.max_file_bytes = limits.file.max_file_bytes.min(admitted_size);
        limits.file.max_encoded_bytes = limits
            .file
            .max_encoded_bytes
            .min(Layout::new(admitted_size).encoded_tree_bytes());
        let before = self.progress;
        let control = &mut self.control;
        let mut encoder = EncoderProgress {
            path,
            total: admitted_size,
            initial: self
                .ledger
                .file_bytes
                .checked_sub(admitted_size)
                .ok_or(Error::Binding)?,
            ancestors,
            started: Instant::now(),
            last: None,
        };
        let observer = &mut self.observer;
        let mut progress_error = None;
        let mut report = |now: Progress| match encoder
            .report(observer, now.plaintext_bytes)
            .and_then(|()| composed(before, now))
        {
            Ok(now) => control(now),
            Err(error) => {
                progress_error = Some(error);
                Control::Cancel
            }
        };
        let repo = match destination {
            Destination::Retained(repo) => repo,
            Destination::Measured(objects) => {
                input.rewind()?;
                let result = buffers.measure(input, admitted_size, limits.file, &mut report);
                if let Some(error) = progress_error {
                    return Err(error);
                }
                let (content, progress) = result?;
                self.measured(objects, path, content, progress)?;
                return Ok(content);
            }
        };
        limits.max_stored_bytes = limits.max_stored_bytes.min(payload_bytes_wide(
            Layout::new(admitted_size),
            self.root_path.is_some(),
        )?);
        let prepared = if let Some(root) = &self.root_path {
            let result =
                indexed::prepare(repo, input, &root.join(path), buffers, limits, &mut report);
            if let Some(error) = progress_error {
                return Err(error);
            }
            let done = result?;
            (done.content, done.puts, Some(done.source))
        } else {
            let result = file::prepare_file(repo, input, buffers, limits, &mut report);
            if let Some(error) = progress_error {
                return Err(error);
            }
            let plan = result?;
            let Artifact::File(content) = plan.artifact else {
                return Err(Error::Binding);
            };
            (content, plan.puts, None)
        };
        self.append(path, false, prepared.0, prepared.1, prepared.2)?;
        Ok(prepared.0)
    }
    fn directory(
        &mut self,
        destination: &mut Destination<'_>,
        plan: &dir::BuildPlan<'_>,
        path: &Path,
        buffers: &mut Buffers,
    ) -> Result<Content, Error> {
        let limits = self.local_limits()?;
        let before = self.progress;
        let control = &mut self.control;
        let mut encoder = EncoderProgress {
            path,
            total: plan.report().wire_bytes,
            initial: 0,
            ancestors: &[],
            started: Instant::now(),
            last: None,
        };
        let observer = &mut self.observer;
        let mut progress_error = None;
        let mut report = |now: Progress| match encoder
            .report(observer, now.plaintext_bytes)
            .and_then(|()| composed(before, now))
        {
            Ok(now) => control(now),
            Err(error) => {
                progress_error = Some(error);
                Control::Cancel
            }
        };
        let repo = match destination {
            Destination::Retained(repo) => repo,
            Destination::Measured(objects) => {
                let result = buffers.measure_directory(plan, limits.file, &mut report);
                if let Some(error) = progress_error {
                    return Err(error);
                }
                let (content, progress) = result?;
                self.measured(objects, path, content, progress)?;
                return Ok(content);
            }
        };
        let nodes = file::file_budget(plan.report().wire_bytes, limits)?.0;
        let mut rows = Vec::new();
        rows.try_reserve_exact(nodes).map_err(|_| Error::Limit)?;
        let mut sink = file::Sink { repo, rows };
        let result = buffers.publish_directory(plan, &mut sink, limits.file, report);
        if let Some(error) = progress_error {
            return Err(error);
        }
        let done = result?;
        file::validate_puts(&sink.rows, done.content, limits)?;
        self.append(path, true, done.content, sink.rows, None)?;
        Ok(done.content)
    }
    fn scan_source(
        &mut self,
        input: &InputDir,
        report: bool,
    ) -> Result<([u8; 64], Vec<DirectorySize>), Error> {
        struct Verify {
            source: FrameSource,
            next: usize,
            path: PathBuf,
            slot: usize,
            total: u64,
        }
        self.check()?;
        let limits = self.limits.tree;
        let root = FrameSource::scan(
            input
                .descriptor()
                .try_clone()
                .map_err(SourceError::from)
                .map_err(source_error)?,
            limits.max_children,
            limits.max_name_bytes,
            limits.max_retained_name_bytes,
        )
        .map_err(source_error)?;
        let mut names = root.names_bytes;
        let mut entries = root.names.len() as u64;
        if entries > limits.max_entries {
            return Err(TreePublishCause::Limit(TreeBudget::Entries).into());
        }
        let mut hash = Hash512State::new();
        hash.update(b"gnunet-rs native tree source v2\0");
        hash_source(&mut hash, Path::new(""), root.stamp);
        let mut frames = Vec::new();
        let mut sizes = Vec::new();
        if report {
            emit(
                &mut self.observer,
                Event::Scanning {
                    relative: Path::new(""),
                    directory: true,
                },
            )?;
        }
        frames
            .try_reserve(limits.max_depth.saturating_add(1))
            .map_err(|_| Error::Limit)?;
        frames.push(Verify {
            source: root,
            next: 0,
            path: PathBuf::new(),
            slot: 0,
            total: 0,
        });
        if report {
            sizes.try_reserve(1).map_err(|_| Error::Limit)?;
            sizes.push(DirectorySize {
                stamp: frames[0].source.stamp,
                total: 0,
            });
        }
        while !frames.is_empty() {
            self.check()?;
            let last = frames.len() - 1;
            let path = frames[last].path.clone();
            if frames[last].next == frames[last].source.names.len() {
                frames[last].source.verify().map_err(source_error)?;
                let done = frames.pop().ok_or(Error::Binding)?;
                names -= done.source.names_bytes;
                if report {
                    sizes.get_mut(done.slot).ok_or(Error::Binding)?.total = done.total;
                    if let Some(parent) = frames.last_mut() {
                        parent.total = add_u64(
                            parent.total,
                            done.total,
                            limits.max_file_bytes,
                            TreeBudget::FileBytes,
                        )?;
                    }
                }
                continue;
            }
            let index = frames[last].next;
            frames[last].next += 1;
            let name = &frames[last].source.names[index];
            let child = path.join(&name.native);
            if child.as_os_str().as_encoded_bytes().len() > limits.max_path_bytes {
                return Err(TreePublishCause::Limit(TreeBudget::Path).into());
            }
            if frames.len() > limits.max_depth {
                return Err(TreePublishCause::Limit(TreeBudget::Depth).into());
            }
            let kind = name.kind;
            let expected_stamp = name.stamp;
            let file = frames[last].source.open(index).map_err(source_error)?;
            if report {
                emit(
                    &mut self.observer,
                    Event::Scanning {
                        relative: &child,
                        directory: kind == Kind::Directory,
                    },
                )?;
            }
            if kind == Kind::Directory {
                let source = FrameSource::scan(
                    file,
                    limits.max_children,
                    limits.max_name_bytes,
                    limits.max_retained_name_bytes.saturating_sub(names),
                )
                .map_err(source_error)?;
                if source.stamp != expected_stamp {
                    return Err(source_error(SourceError::Changed));
                }
                names = add_usize(
                    names,
                    source.names_bytes,
                    limits.max_retained_name_bytes,
                    TreeBudget::Path,
                )?;
                entries = add_u64(
                    entries,
                    source.names.len() as u64,
                    limits.max_entries,
                    TreeBudget::Entries,
                )?;
                hash_source(&mut hash, &child, source.stamp);
                let slot = sizes.len();
                if report {
                    if slot >= self.limits.max_plan_bytes / size_of::<DirectorySize>() {
                        return Err(Error::Limit);
                    }
                    sizes.try_reserve(1).map_err(|_| Error::Limit)?;
                    sizes.push(DirectorySize {
                        stamp: source.stamp,
                        total: 0,
                    });
                }
                frames.push(Verify {
                    source,
                    next: 0,
                    path: child,
                    slot,
                    total: 0,
                });
            } else {
                hash_source(&mut hash, &child, expected_stamp);
                if report {
                    frames[last].total = add_u64(
                        frames[last].total,
                        expected_stamp.bytes,
                        limits.max_file_bytes,
                        TreeBudget::FileBytes,
                    )?;
                }
            }
        }
        Ok((hash.finish(), sizes))
    }
}

fn begin_directory(
    frame: &mut PreparedFrame,
    sizes: &mut impl Iterator<Item = DirectorySize>,
    initial: u64,
) -> Result<(), Error> {
    let size = sizes
        .next()
        .ok_or_else(|| source_error(SourceError::Changed))?;
    if size.stamp != frame.source.stamp {
        return Err(source_error(SourceError::Changed));
    }
    frame.progress = Some(DirectoryProgress {
        total: size.total,
        initial,
        started: Instant::now(),
    });
    Ok(())
}

/// Stream a native tree into immutable full or indexed prepared payloads.
/// The optional named root selects explicit indexed regular-file preparation;
/// every directory remains a real full directory object. No service mutation is
/// submitted here. Final source observations must still match the original
/// descriptor tree; this is not an atomic filesystem snapshot.
pub fn prepare_tree(
    repo: &mut Repository,
    input: &InputDir,
    named_root: Option<&Path>,
    buffers: &mut Buffers,
    limits: Limits,
    control: impl FnMut(Progress) -> Control,
) -> Result<(TreePlan, Vec<Put>), Error> {
    prepare_tree_with_metadata(
        repo,
        input,
        named_root,
        buffers,
        limits,
        &mut OriginalMetadata,
        control,
    )
}
/// Prepare the same complete tree with real per-object metadata. Original
/// descriptor/source checks, postorder PUTs and global bounds remain mandatory.
pub fn prepare_tree_with_metadata(
    repo: &mut Repository,
    input: &InputDir,
    named_root: Option<&Path>,
    buffers: &mut Buffers,
    limits: Limits,
    metadata_provider: &mut impl MetadataProvider,
    control: impl FnMut(Progress) -> Control,
) -> Result<(TreePlan, Vec<Put>), Error> {
    prepare_tree_observed(
        repo,
        input,
        named_root,
        buffers,
        limits,
        metadata_provider,
        None,
        None,
        control,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep selected tree preparation inputs and its optional reporter explicit"
)]
pub(in crate::publication) fn prepare_tree_observed(
    repo: &mut Repository,
    input: &InputDir,
    named_root: Option<&Path>,
    buffers: &mut Buffers,
    limits: Limits,
    metadata_provider: &mut impl MetadataProvider,
    observer: Observer<'_>,
    locations: Option<&mut Locations<'_>>,
    control: impl FnMut(Progress) -> Control,
) -> Result<(TreePlan, Vec<Put>), Error> {
    match walk_tree(
        Destination::Retained(repo),
        input,
        named_root,
        buffers,
        limits,
        metadata_provider,
        observer,
        locations,
        control,
    )? {
        Outcome::Retained(tree, puts) => Ok((tree, puts)),
        Outcome::Measured(_) => Err(Error::Binding),
    }
}

pub(crate) fn measure_tree_observed(
    input: &InputDir,
    named_root: &Path,
    buffers: &mut Buffers,
    limits: Limits,
    metadata_provider: &mut impl MetadataProvider,
    observer: Observer<'_>,
    control: impl FnMut(Progress) -> Control,
) -> Result<Vec<MeasuredObject>, Error> {
    match walk_tree(
        Destination::Measured(Vec::new()),
        input,
        Some(named_root),
        buffers,
        limits,
        metadata_provider,
        observer,
        None,
        control,
    )? {
        Outcome::Measured(objects) => Ok(objects),
        Outcome::Retained(_, _) => Err(Error::Binding),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep source, encoder, observer and descriptor boundaries explicit"
)]
fn walk_tree(
    mut destination: Destination<'_>,
    input: &InputDir,
    named_root: Option<&Path>,
    buffers: &mut Buffers,
    limits: Limits,
    metadata_provider: &mut impl MetadataProvider,
    observer: Observer<'_>,
    mut locations: Option<&mut Locations<'_>>,
    control: impl FnMut(Progress) -> Control,
) -> Result<Outcome, Error> {
    let root_stamp = source::stamp(input.descriptor()).map_err(source_error)?;
    let root_path = named_root
        .map(|path| {
            fs::canonicalize(path)
                .map_err(SourceError::from)
                .map_err(source_error)
        })
        .transpose()?;
    if let Some(path) = &root_path {
        let named = InputDir::open(path).map_err(source_error)?;
        if source::stamp(named.descriptor()).map_err(source_error)? != root_stamp {
            return Err(source_error(SourceError::Changed));
        }
    }
    let root_metadata = metadata(&[dir::MIME_ITEM], limits.tree.max_metadata_bytes)?;
    if root_metadata.len() > limits.tree.max_retained_metadata_bytes {
        return Err(TreePublishCause::Limit(TreeBudget::Metadata).into());
    }
    let mut prepared = Prepare {
        metadata: metadata_provider,
        limits,
        root_metadata,
        ledger: Ledger::default(),
        entries: 0,
        progress: Progress::default(),
        control,
        root_path,
        root_stamp,
        objects: Vec::new(),
        puts: Vec::new(),
        sources: Vec::new(),
        plan_bytes: size_of::<Plan>() + size_of::<TreePlan>(),
        observer,
        inline: inline::Scratch::default(),
    };
    prepared.check()?;
    let (source_hash, mut sizes) = if prepared.observer.is_some() {
        let (hash, sizes) = prepared.scan_source(input, true)?;
        emit(&mut prepared.observer, Event::ScanComplete)?;
        (Some(hash), sizes.into_iter())
    } else {
        (None, Vec::new().into_iter())
    };
    let mut root = prepared.frame(
        input
            .descriptor()
            .try_clone()
            .map_err(SourceError::from)
            .map_err(source_error)?,
        PathBuf::new(),
        None,
        None,
    )?;
    if source_hash.is_some() {
        begin_directory(&mut root, &mut sizes, 0)?;
    }
    let mut hash = Hash512State::new();
    hash.update(b"gnunet-rs native tree source v2\0");
    hash_source(&mut hash, &root.path, root.source.stamp);
    let mut frames = Vec::new();
    frames
        .try_reserve(limits.tree.max_depth.saturating_add(1))
        .map_err(|_| Error::Limit)?;
    frames.push(root);
    while !frames.is_empty() {
        prepared.check()?;
        let last = frames.len() - 1;
        if frames[last].next < frames[last].source.names.len() {
            let index = frames[last].next;
            let name = &frames[last].source.names[index];
            let path = frames[last].path.join(&name.native);
            if path.as_os_str().as_encoded_bytes().len() > limits.tree.max_path_bytes {
                return Err(TreePublishCause::Limit(TreeBudget::Path).into());
            }
            if frames.len() > limits.tree.max_depth {
                return Err(TreePublishCause::Limit(TreeBudget::Depth).into());
            }
            let kind = name.kind;
            let expected = name.stamp;
            let mut file = frames[last].source.open(index).map_err(source_error)?;
            frames[last].next += 1;
            prepared.entry_metadata(
                &mut frames[last].frame,
                index,
                &file,
                &path,
                kind == Kind::Directory,
            )?;
            if kind == Kind::Directory {
                let mut frame = prepared.frame(file, path, Some(index), Some(expected))?;
                if source_hash.is_some() {
                    begin_directory(&mut frame, &mut sizes, prepared.ledger.file_bytes)?;
                }
                hash_source(&mut hash, &frame.path, frame.source.stamp);
                frames.push(frame);
                continue;
            }
            emit(&mut prepared.observer, Event::Extracted(&path))?;
            hash_source(&mut hash, &path, expected);
            prepared.admit(expected.bytes, false, &destination)?;
            prepared.named_root_stable(input)?;
            let content = prepared.file(
                &mut destination,
                &mut file,
                &path,
                expected.bytes,
                buffers,
                &frames,
            )?;
            if source::stamp(&file).map_err(source_error)? != expected {
                return Err(source_error(SourceError::Changed));
            }
            frames[last].source.open(index).map_err(source_error)?;
            prepared.bind_child(
                &mut frames[last].frame,
                index,
                content,
                inline::Source::File(&mut file),
                locations.as_deref_mut(),
                buffers,
            )?;
            continue;
        }
        let mut frame = frames.pop().ok_or(Error::Binding)?;
        let path = frame.path.clone();
        frame.source.verify().map_err(source_error)?;
        prepared.ledger.names -= frame.source.names_bytes;
        frame.source.names_bytes = 0;
        frame.source.names = Vec::new();
        let root_metadata = std::mem::take(&mut frame.root_metadata);
        let mut records = DirectoryPlan::prepare_with_locations(
            &mut frame.frame.entries,
            &root_metadata,
            limits.tree,
            locations
                .as_ref()
                .map_or(&[], |owner| owner.values.as_slice()),
        )?;
        let plan = records.plan()?;
        prepared.admit(plan.report().wire_bytes, true, &destination)?;
        let content = prepared.directory(&mut destination, &plan, &path, buffers)?;
        frame.frame.source.verify().map_err(source_error)?;
        if let Some(index) = frame.frame.parent_slot {
            let parent = frames.last_mut().ok_or(Error::Binding)?;
            parent.source.open(index).map_err(source_error)?;
            prepared.bind_child(
                &mut parent.frame,
                index,
                content,
                inline::Source::Directory(&plan),
                locations.as_deref_mut(),
                buffers,
            )?;
        }
        drop(records);
        prepared.ledger.metadata -= frame.metadata_bytes;
        prepared.ledger.records -= frame.record_bytes;
        if frame.parent_slot.is_none() {
            let expected = hash.finish();
            if source_hash.is_some_and(|source| source != expected)
                || sizes.next().is_some()
                || prepared.scan_source(input, false)?.0 != expected
            {
                return Err(source_error(SourceError::Changed));
            }
            prepared.named_root_stable(input)?;
            if let Some(locations) = locations {
                let ordinal = prepared
                    .objects
                    .len()
                    .checked_sub(1)
                    .ok_or(Error::Binding)?;
                let _root = locations.sign(ordinal, content)?;
            }
            emit(&mut prepared.observer, Event::MetadataComplete)?;
            return Ok(match destination {
                Destination::Retained(_) => Outcome::Retained(
                    TreePlan {
                        root: content,
                        objects: prepared.objects,
                        sources: prepared.sources,
                    },
                    prepared.puts,
                ),
                Destination::Measured(objects) => Outcome::Measured(objects),
            });
        }
    }
    Err(Error::Binding)
}
