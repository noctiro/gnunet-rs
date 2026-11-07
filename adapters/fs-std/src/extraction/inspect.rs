//! Metadata-only descriptor walk. No repository, payload encoder or task exists.
use super::*;
use crate::input_tree::{self as source, FrameSource, Kind};
use std::{fmt, os::unix::ffi::OsStringExt};

/// One actual extraction result. Ownership crosses the caller's bounded sink;
/// no CHK, publication task or service acknowledgement is represented here.
pub struct ExtractedObject {
    /// Exact source-root-relative path; empty identifies the selected input.
    pub relative: PathBuf,
    /// Actual descriptor kind, not a filename-based guess.
    pub directory: bool,
    /// Observed regular-file size; directories use zero. This is not bytes read.
    pub source_bytes: u64,
    /// Complete standard uncompressed v2 metadata from the selected extractor.
    pub metadata: Vec<u8>,
    /// Exact automatic query terms before manual top-level annotations.
    pub keywords: Vec<Vec<u8>>,
    /// Actual optional native provider observations for this descriptor.
    pub provider: Option<gnunet_extractor_host::Observation>,
}
impl ExtractedObject {
    /// Actual retained Rust storage for this result, excluding allocator/RSS
    /// overhead and the independent provider workspace.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.keywords.iter().try_fold(
            std::mem::size_of::<Self>()
                .checked_add(self.relative.capacity())
                .and_then(|n| n.checked_add(self.metadata.capacity()))
                .and_then(|n| {
                    n.checked_add(
                        self.keywords
                            .capacity()
                            .checked_mul(std::mem::size_of::<Vec<u8>>())?,
                    )
                })
                .ok_or(Error::Limit)?,
            |n, term| n.checked_add(term.capacity()).ok_or(Error::Limit),
        )
    }
}
/// Actual completed extraction work, including a prefix on failure. Delivering
/// an object to a sink does not prove stdout flush or any publication.
#[derive(Clone, Copy, Debug, Default)]
pub struct InspectionReport {
    /// Actual extracted file/directory objects, including the selected root.
    pub objects: u64,
    /// Actual regular-file objects inspected.
    pub files: u64,
    /// Actual directory objects inspected.
    pub directories: u64,
    /// Sum of observed regular-file sizes, without claiming payload reads.
    pub source_bytes: u64,
    /// Actual standard metadata bytes generated.
    pub metadata_bytes: u64,
    /// Actual automatic terms generated, including each object's own terms.
    pub keywords: u64,
}
/// Original extraction/sink/provider-close cause with the actual completed prefix.
#[derive(Debug)]
pub struct InspectionFailure {
    /// Actual work before refusal/cancellation, not a complete tree assertion.
    pub report: InspectionReport,
    /// Original typed cause, including independent provider cleanup when present.
    pub cause: Error,
}
impl fmt::Display for InspectionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}
impl std::error::Error for InspectionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
fn source_error(error: source::SourceError) -> Error {
    Error::Source(error)
}
struct Frame {
    source: FrameSource,
    path: PathBuf,
    next: usize,
}
impl Frame {
    fn retained_bytes(&self) -> Result<usize, Error> {
        self.source.names.iter().try_fold(
            self.source
                .names
                .capacity()
                .checked_mul(std::mem::size_of::<source::Name>())
                .and_then(|n| n.checked_add(self.path.capacity()))
                .ok_or(Error::Policy)?,
            |n, name| n.checked_add(name.bytes.capacity()).ok_or(Error::Policy),
        )
    }
}
fn emit<C: FnMut(Progress) -> Control>(
    extractor: &mut Extractor<'_, C>,
    file: &File,
    relative: &Path,
    directory: bool,
    limits: Limits,
    report: &mut InspectionReport,
    visit: &mut impl FnMut(ExtractedObject) -> Result<(), Error>,
) -> Result<(), Error> {
    extractor.context.check()?;
    let original = source::stamp(file).map_err(source_error)?;
    let maximum = extractor
        .policy
        .max_metadata_bytes
        .min(limits.max_metadata_bytes)
        .min(limits.max_retained_metadata_bytes);
    let base = if directory {
        let item = gnunet_fs::directory::MIME_ITEM;
        encode_values(
            &[Value {
                kind: item.kind,
                format: item.format,
                data: copy(item.data)?,
                plugin: item.plugin.map(copy).transpose()?,
                mime: item.mime.map(copy).transpose()?,
            }],
            Policy {
                max_metadata_bytes: maximum,
                ..extractor.policy
            },
        )?
    } else {
        Vec::new()
    };
    let object = extractor.extract_one(file, relative, directory, &base, maximum)?;
    let keywords = if !extractor.policy.extract {
        Vec::new()
    } else {
        match object.query_terms {
            Some(terms) => terms,
            None => terms(&object.wire, extractor.policy)?,
        }
    };
    if source::stamp(file).map_err(source_error)? != original {
        return Err(Error::SourceChanged);
    }
    let object = ExtractedObject {
        relative: PathBuf::from(std::ffi::OsString::from_vec(copy(
            relative.as_os_str().as_bytes(),
        )?)),
        directory,
        source_bytes: if directory { 0 } else { original.bytes },
        metadata: object.wire,
        keywords,
        provider: object.provider,
    };
    let owned = object.retained_bytes()?;
    {
        let mut budget = extractor.context.budget.borrow_mut();
        budget.add(owned)?;
        budget.replace(owned, 0)?;
    }
    let next = InspectionReport {
        objects: report.objects.checked_add(1).ok_or(Error::Policy)?,
        files: report
            .files
            .checked_add(u64::from(!directory))
            .ok_or(Error::Policy)?,
        directories: report
            .directories
            .checked_add(u64::from(directory))
            .ok_or(Error::Policy)?,
        source_bytes: report
            .source_bytes
            .checked_add(object.source_bytes)
            .filter(|n| *n <= limits.max_source_bytes)
            .ok_or(Error::Policy)?,
        metadata_bytes: report
            .metadata_bytes
            .checked_add(object.metadata.len() as u64)
            .filter(|n| *n <= limits.max_total_metadata_bytes)
            .ok_or(Error::Policy)?,
        keywords: report
            .keywords
            .checked_add(object.keywords.len() as u64)
            .ok_or(Error::Policy)?,
    };
    *report = next;
    visit(object)?;
    extractor.context.check()?;
    if source::stamp(file).map_err(source_error)? != original {
        return Err(Error::SourceChanged);
    }
    Ok(())
}

/// Inspect selected metadata and automatic terms without hashing/encrypting or
/// copying file payloads into a repository. The caller supplies one synchronous
/// worker and a bounded streaming sink; this function creates no thread, socket
/// or artifact. Existing descriptor-root scanning refuses links/special files.
/// Native plugin and filesystem calls cannot be forcibly preempted; control is
/// checked before/after each original operation and sink delivery. Each object
/// is checked while its descriptor is held; streaming is not an atomic snapshot
/// of a mutable tree. The sink must release results or impose its own bound.
pub fn inspect_with_metadata(
    input: &Path,
    limits: Limits,
    mut policy: Policy,
    metadata: MetadataSettings,
    control: impl FnMut(Progress) -> Control,
    mut visit: impl FnMut(ExtractedObject) -> Result<(), Error>,
) -> Result<InspectionReport, Box<InspectionFailure>> {
    let mut report = InspectionReport::default();
    let outcome = (|| -> Result<(), Error> {
        policy.extract &= metadata.automatic_keywords_enabled();
        policy.validate(limits)?;
        let settings_bytes = metadata.retained_bytes()?;
        if settings_bytes > policy.max_retained_bytes {
            return Err(Error::Policy);
        }
        let context = Context {
            control: RefCell::new(control),
            progress: Cell::new(Progress::default()),
            budget: RefCell::new(Budget {
                used: settings_bytes,
                limit: policy.max_retained_bytes,
            }),
        };
        context.check()?;
        let observed = fs::symlink_metadata(input)?;
        if observed.file_type().is_symlink() || (!observed.is_file() && !observed.is_dir()) {
            return Err(Error::Policy);
        }
        let selected = source::Stamp {
            kind: if observed.is_file() {
                Kind::File
            } else {
                Kind::Directory
            },
            device: observed.dev(),
            inode: observed.ino(),
            bytes: observed.len(),
            modified: observed.mtime(),
            modified_nanos: observed.mtime_nsec(),
            changed: observed.ctime(),
            changed_nanos: observed.ctime_nsec(),
        };
        let mut extractor = Extractor::new(
            input,
            policy,
            limits,
            &context,
            metadata.format_extraction_enabled(),
        )?;
        extractor.manual = metadata.manual();
        extractor.provider = metadata.open(&context, policy, limits.max_file_bytes)?;
        let result = (|| -> Result<(), Error> {
            if observed.is_file() {
                let file = source::open_regular(input)?;
                if source::stamp(&file).map_err(source_error)? != selected {
                    return Err(source_error(source::SourceError::Changed));
                }
                return emit(
                    &mut extractor,
                    &file,
                    Path::new(""),
                    false,
                    limits,
                    &mut report,
                    &mut visit,
                );
            }
            let cap = limits.tree;
            let directory = InputDir::open(input).map_err(source_error)?;
            let original = source::stamp(directory.descriptor()).map_err(source_error)?;
            if original != selected {
                return Err(source_error(source::SourceError::Changed));
            }
            let frames = cap.max_depth.checked_add(1).ok_or(Error::Policy)?;
            let fixed = frames
                .checked_mul(std::mem::size_of::<Frame>())
                .ok_or(Error::Policy)?;
            if fixed
                .checked_add(settings_bytes)
                .is_none_or(|n| n > policy.max_retained_bytes)
            {
                return Err(Error::Policy);
            }
            let mut stack = Vec::new();
            stack.try_reserve_exact(frames).map_err(|_| Error::Policy)?;
            let first = FrameSource::scan(
                directory.descriptor().try_clone()?,
                cap.max_children,
                cap.max_name_bytes,
                cap.max_retained_name_bytes,
            )
            .map_err(source_error)?;
            if first.stamp != original {
                return Err(source_error(source::SourceError::Changed));
            }
            stack.push(Frame {
                source: first,
                path: PathBuf::new(),
                next: 0,
            });
            let mut entries = stack[0].source.names.len() as u64;
            let mut charged_stack = 0;
            loop {
                context.check()?;
                let retained = stack.iter().try_fold(
                    stack
                        .capacity()
                        .checked_mul(std::mem::size_of::<Frame>())
                        .ok_or(Error::Policy)?,
                    |n, frame| n.checked_add(frame.retained_bytes()?).ok_or(Error::Policy),
                )?;
                let names = stack.iter().try_fold(0usize, |n, frame| {
                    n.checked_add(frame.source.names_bytes).ok_or(Error::Policy)
                })?;
                if entries > cap.max_entries
                    || names > cap.max_retained_name_bytes
                    || retained
                        .checked_add(settings_bytes)
                        .is_none_or(|n| n > policy.max_retained_bytes)
                {
                    return Err(Error::Policy);
                }
                context
                    .budget
                    .borrow_mut()
                    .replace(charged_stack, retained)?;
                charged_stack = retained;
                if report.objects == 0 {
                    emit(
                        &mut extractor,
                        directory.descriptor(),
                        Path::new(""),
                        true,
                        limits,
                        &mut report,
                        &mut visit,
                    )?;
                }
                let depth = stack.len();
                let Some(parent) = stack.last_mut() else {
                    break;
                };
                if parent.next == parent.source.names.len() {
                    parent.source.verify().map_err(source_error)?;
                    stack.pop();
                    continue;
                }
                let index = parent.next;
                parent.next += 1;
                let name = &parent.source.names[index];
                let path_bytes = parent
                    .path
                    .as_os_str()
                    .as_bytes()
                    .len()
                    .checked_add(name.bytes.len())
                    .and_then(|n| n.checked_add(usize::from(!parent.path.as_os_str().is_empty())))
                    .ok_or(Error::Policy)?;
                if path_bytes > cap.max_path_bytes || depth > cap.max_depth {
                    return Err(Error::Policy);
                }
                let mut path = PathBuf::new();
                path.try_reserve_exact(path_bytes)
                    .map_err(|_| Error::Policy)?;
                path.push(&parent.path);
                path.push(std::ffi::OsStr::from_bytes(&name.bytes));
                let child = parent.source.open(index).map_err(source_error)?;
                let directory = name.kind == Kind::Directory;
                let original = name.stamp;
                emit(
                    &mut extractor,
                    &child,
                    &path,
                    directory,
                    limits,
                    &mut report,
                    &mut visit,
                )?;
                parent.source.open(index).map_err(source_error)?;
                if directory {
                    let frame = FrameSource::scan(
                        child,
                        cap.max_children,
                        cap.max_name_bytes,
                        cap.max_retained_name_bytes.saturating_sub(names),
                    )
                    .map_err(source_error)?;
                    if frame.stamp != original {
                        return Err(source_error(source::SourceError::Changed));
                    }
                    entries = entries
                        .checked_add(frame.names.len() as u64)
                        .ok_or(Error::Policy)?;
                    stack.push(Frame {
                        source: frame,
                        path,
                        next: 0,
                    });
                }
            }
            Ok(())
        })();
        metadata::finish(extractor.provider.take(), result)
    })();
    outcome
        .map(|()| report)
        .map_err(|cause| Box::new(InspectionFailure { report, cause }))
}

#[cfg(test)]
mod tests;
