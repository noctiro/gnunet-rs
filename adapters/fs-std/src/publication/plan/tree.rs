//! Bounded postorder object plans and authenticated complete parent membership.
mod inline;
mod prepare;
#[cfg(test)]
mod tests;
use super::{Error, Limits, Put, file, indexed};
use crate::{Buffers, Control, Progress, ReadFile, Repository};
use gnunet_fs::{Content, Uri, content::Layout, directory as dir, metadata};
pub(crate) use prepare::measure_tree_observed;
pub(in crate::publication) use prepare::{Locations, prepare_tree_observed};
pub use prepare::{prepare_tree, prepare_tree_with_metadata};
use std::{collections::HashMap, mem::size_of};

/// Real scanner, extractor and plaintext encoder events for publication commands.
pub enum Event<'a> {
    /// A named original source entry was visited during counting.
    Scanning {
        /// Source-relative path.
        relative: &'a std::path::Path,
        /// Whether this entry is a directory.
        directory: bool,
    },
    /// The bounded original-source prepass completed.
    ScanComplete,
    /// A regular file's selected metadata extraction completed.
    Extracted(&'a std::path::Path),
    /// All selected metadata was processed.
    MetadataComplete,
    /// Plaintext encoded during this invocation, never DATASTORE acceptance bytes.
    Encoding {
        /// Source-relative path.
        relative: &'a std::path::Path,
        /// Plaintext bytes actually consumed.
        completed: u64,
        /// Directory artifact length, file length, or descendant file total.
        total: u64,
        /// Elapsed time from this object or directory's start.
        elapsed: std::time::Duration,
    },
}

/// Optional synchronous observer owned by this publication invocation.
pub type Observer<'a> = Option<&'a mut dyn FnMut(Event<'_>) -> Control>;

pub(crate) fn emit(observer: &mut Observer<'_>, event: Event<'_>) -> Result<(), Error> {
    if observer
        .as_deref_mut()
        .is_some_and(|observe| observe(event) == Control::Cancel)
    {
        return Err(crate::Error::Cancelled.into());
    }
    Ok(())
}

pub(crate) fn root_file_progress<'a>(
    observer: &'a mut Observer<'_>,
    total: u64,
    mut control: impl FnMut(Progress) -> Control + 'a,
) -> impl FnMut(Progress) -> Control + 'a {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let mut last = None;
    move |progress| {
        if observer.is_some() {
            let now = Instant::now();
            let completed = progress.plaintext_bytes;
            let already_reported = last.is_some_and(|(before, when)| {
                before == completed
                    || (completed != total && now.duration_since(when) < Duration::from_millis(200))
            });
            if !already_reported {
                last = Some((completed, now));
                if emit(
                    observer,
                    Event::Encoding {
                        relative: std::path::Path::new(""),
                        completed,
                        total,
                        elapsed: now.duration_since(start),
                    },
                )
                .is_err()
                {
                    return Control::Cancel;
                }
            }
        }
        control(progress)
    }
}

/// Computed content of a descriptor-stable source object, without storage.
pub struct MeasuredObject {
    /// Source-root-relative path, empty for the selected root.
    pub relative: std::path::PathBuf,
    /// Exact CHK and size of the encoded source object.
    pub content: Content,
}

/// Explicit transformation of standard directory metadata from the original
/// opened descriptor. Returning bytes grants no publication or source receipt.
pub trait MetadataProvider {
    /// Preserve required filename/directory fields, return one complete official
    /// uncompressed v2 container within `max_bytes`, and leave source position
    /// unchanged. The planner rechecks original descriptors and total budgets.
    fn prepare(
        &mut self,
        source: &std::fs::File,
        relative: &std::path::Path,
        directory: bool,
        base: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>, Error>;
}
struct OriginalMetadata;
impl MetadataProvider for OriginalMetadata {
    fn prepare(
        &mut self,
        _: &std::fs::File,
        _: &std::path::Path,
        _: bool,
        base: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>, Error> {
        if base.len() > max_bytes {
            return Err(Error::Limit);
        }
        super::owned(base)
    }
}
/// One actual object and its exact contiguous portion of the weighted PUT plan.
#[derive(Clone, Debug)]
pub struct TreeObject {
    /// Literal root-relative Unix bytes; only the final root has an empty path.
    pub path: Vec<u8>,
    /// Genuine CHK of this file or complete directory artifact.
    pub content: Content,
    /// Directory artifacts are always fully stored.
    pub directory: bool,
    /// First zero-based position in the shared ordered PUT plan.
    pub first_put: usize,
    /// Exact number of data/index nodes for this object.
    pub put_count: usize,
    /// Original source index for an on-demand regular file, otherwise None.
    pub indexed: Option<usize>,
}
/// Immutable recursive intent. Field validation alone authenticates no payload.
#[derive(Clone, Debug)]
pub struct TreePlan {
    /// Actual directory CHK at the final postorder object.
    pub root: Content,
    /// Complete postorder object coverage, including duplicate content by path.
    pub objects: Vec<TreeObject>,
    /// Named sources in their exact required FS registration order.
    pub sources: Vec<indexed::Source>,
}
impl TreePlan {
    /// Resolve a PUT's original on-demand source in logarithmic object work.
    #[must_use]
    pub fn source_for_put(&self, index: usize) -> Option<&indexed::Source> {
        let at = self
            .objects
            .partition_point(|o| o.first_put <= index)
            .checked_sub(1)?;
        let object = self.objects.get(at)?;
        if index.checked_sub(object.first_put)? >= object.put_count {
            return None;
        }
        self.sources.get(object.indexed?)
    }
}
/// Genuine complete directory syntax, object authentication and parent membership.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedTree {
    root: dir::VerifiedDirectory,
    files: usize,
    directories: usize,
    entries: usize,
}
impl VerifiedTree {
    /// Actual root directory receipt from the strict authenticated parser.
    #[must_use]
    pub const fn root(self) -> dir::VerifiedDirectory {
        self.root
    }
    /// Completely authenticated regular-file objects, including repeated content.
    #[must_use]
    pub const fn files(self) -> usize {
        self.files
    }
    /// Completely authenticated and parsed directories, including the root.
    #[must_use]
    pub const fn directories(self) -> usize {
        self.directories
    }
    /// Actual parent entries matched exactly once to all non-root objects.
    #[must_use]
    pub const fn entries(self) -> usize {
        self.entries
    }
}
fn range<'a>(object: &TreeObject, puts: &'a [Put]) -> Result<&'a [Put], Error> {
    let end = object
        .first_put
        .checked_add(object.put_count)
        .ok_or(Error::Limit)?;
    puts.get(object.first_put..end).ok_or(Error::Binding)
}
fn parent(path: &[u8]) -> &[u8] {
    path.iter()
        .rposition(|b| *b == b'/')
        .map_or(&[], |at| &path[..at])
}
fn structure<'a>(
    tree: &'a TreePlan,
    puts: &[Put],
    limits: Limits,
) -> Result<HashMap<&'a [u8], usize>, Error> {
    let cap = limits.tree;
    if tree.objects.is_empty()
        || tree.objects.len().saturating_sub(1) as u128 > u128::from(cap.max_entries)
        || tree.sources.len() > tree.objects.len()
    {
        return Err(Error::Limit);
    }
    let last = tree.objects.last().ok_or(Error::Binding)?;
    if !last.path.is_empty() || !last.directory || last.content != tree.root {
        return Err(Error::Binding);
    }
    let mut paths = HashMap::new();
    paths
        .try_reserve(tree.objects.len())
        .map_err(|_| Error::Limit)?;
    let mut used_sources = Vec::new();
    used_sources
        .try_reserve_exact(tree.sources.len())
        .map_err(|_| Error::Limit)?;
    used_sources.resize(tree.sources.len(), false);
    let mut next = 0usize;
    let mut file_bytes = 0u64;
    let mut directory_bytes = 0u64;
    let mut encoded_bytes = 0u128;
    let mut stored_bytes = 0u128;
    let mut names = 0usize;
    for (index, object) in tree.objects.iter().enumerate() {
        if object.path.len() > cap.max_path_bytes
            || object.path.contains(&0)
            || (!object.path.is_empty()
                && object.path.split(|b| *b == b'/').any(|p| {
                    p.is_empty() || matches!(p, b"." | b"..") || p.len() > cap.max_name_bytes
                }))
            || (!object.path.is_empty()
                && object.path.split(|b| *b == b'/').count() > cap.max_depth)
            || (object.path.is_empty() && index + 1 != tree.objects.len())
            || paths.insert(object.path.as_slice(), index).is_some()
            || object.first_put != next
        {
            return Err(Error::Binding);
        }
        names = names.checked_add(object.path.len()).ok_or(Error::Limit)?;
        let slice = range(object, puts)?;
        if let Some(source) = object.indexed {
            if object.directory {
                return Err(Error::Binding);
            }
            let used = used_sources.get_mut(source).ok_or(Error::Binding)?;
            if *used {
                return Err(Error::Binding);
            }
            *used = true;
            indexed::validate(
                tree.sources.get(source).ok_or(Error::Binding)?,
                object.content,
                slice,
                limits,
            )?;
        } else {
            file::validate_puts(slice, object.content, limits)?;
        }
        next = next.checked_add(object.put_count).ok_or(Error::Limit)?;
        encoded_bytes = encoded_bytes
            .checked_add(Layout::new(object.content.size).encoded_tree_bytes())
            .ok_or(Error::Limit)?;
        stored_bytes = slice.iter().try_fold(stored_bytes, |n, p| {
            n.checked_add(p.payload.bytes as u128).ok_or(Error::Limit)
        })?;
        if object.directory {
            if object.content.size > cap.max_directory_extent {
                return Err(Error::Limit);
            }
            directory_bytes = directory_bytes
                .checked_add(object.content.size)
                .ok_or(Error::Limit)?;
        } else {
            file_bytes = file_bytes
                .checked_add(object.content.size)
                .ok_or(Error::Limit)?;
        }
    }
    if next != puts.len() || used_sources.iter().any(|used| !used) {
        return Err(Error::Binding);
    }
    // All paths retained by the immutable task share its plan bound. The source
    // DFS retained-name limit remains an additional preparation-time bound.
    if names
        .checked_add(
            tree.objects
                .len()
                .checked_mul(size_of::<TreeObject>())
                .ok_or(Error::Limit)?,
        )
        .is_none_or(|n| n > limits.max_plan_bytes)
        || file_bytes > cap.max_file_bytes
        || directory_bytes > cap.max_directory_bytes
        || encoded_bytes > cap.max_encoded_bytes
        || stored_bytes > cap.max_stored_bytes
    {
        return Err(Error::Limit);
    }
    let mut children = Vec::new();
    children
        .try_reserve_exact(tree.objects.len())
        .map_err(|_| Error::Limit)?;
    children.resize(tree.objects.len(), 0usize);
    for (index, object) in tree.objects.iter().enumerate().take(tree.objects.len() - 1) {
        let p = *paths.get(parent(&object.path)).ok_or(Error::Binding)?;
        if p <= index || !tree.objects[p].directory {
            return Err(Error::Binding);
        }
        children[p] = children[p].checked_add(1).ok_or(Error::Limit)?;
        if children[p] > cap.max_children {
            return Err(Error::Limit);
        }
    }
    Ok(paths)
}
pub(super) fn validate(tree: &TreePlan, puts: &[Put], limits: Limits) -> Result<(), Error> {
    structure(tree, puts, limits).map(|_| ())
}
pub(super) fn verify(
    tree: &TreePlan,
    puts: &[Put],
    repo: &mut Repository,
    buffers: &mut Buffers,
    limits: Limits,
    control: &mut impl FnMut(Progress) -> Control,
) -> Result<(ReadFile, VerifiedTree), Error> {
    let paths = structure(tree, puts, limits)?;
    let mut members = Vec::new();
    members
        .try_reserve_exact(tree.objects.len())
        .map_err(|_| Error::Limit)?;
    members.resize(tree.objects.len(), false);
    let mut path = Vec::new();
    path.try_reserve(limits.tree.max_path_bytes.min(limits.max_plan_bytes))
        .map_err(|_| Error::Limit)?;
    let mut files = 0usize;
    let mut directories = 0usize;
    let mut entries = 0usize;
    let mut root_file = None;
    let mut root_directory = None;
    for (index, object) in tree.objects.iter().enumerate() {
        let slice = range(object, puts)?;
        let read = if let Some(source) = object.indexed {
            indexed::verify(
                tree.sources.get(source).ok_or(Error::Binding)?,
                object.content,
                slice,
                repo,
                buffers,
                limits,
                &mut *control,
            )?
        } else {
            file::verify_puts(slice, object.content, repo, buffers, limits, control)?
        };
        if !object.directory {
            files += 1;
            continue;
        }
        path.clear();
        path.extend_from_slice(&object.path);
        let prefix = path.len();
        let separator = usize::from(prefix != 0);
        let mut binding_error = false;
        let receipt = buffers.visit_directory_controlled(
            repo,
            object.content,
            limits.file,
            dir::Limits {
                max_extent: limits.tree.max_directory_extent,
                max_entries: limits.tree.max_children,
                max_record_bytes: limits.tree.max_record_bytes,
                metadata: metadata::Limits {
                    max_coded_bytes: limits.tree.max_metadata_bytes,
                    max_plain_bytes: limits.tree.max_metadata_bytes,
                    max_entries: limits.tree.max_metadata_bytes / metadata::ENTRY_BYTES,
                },
                ..Default::default()
            },
            &mut *control,
            |verified| {
                let entry = verified.entry();
                let Some(name) = dir::filename(entry.metadata.items()) else {
                    binding_error = true;
                    return Err(crate::Error::Corrupt);
                };
                if name.is_empty()
                    || matches!(name, b"." | b"..")
                    || name.contains(&b'/')
                    || name.contains(&0)
                {
                    binding_error = true;
                    return Err(crate::Error::Corrupt);
                }
                if name.len() > limits.tree.max_name_bytes
                    || prefix
                        .checked_add(separator)
                        .and_then(|n| n.checked_add(name.len()))
                        .is_none_or(|n| n > limits.tree.max_path_bytes)
                {
                    return Err(crate::Error::Limit);
                }
                path.truncate(prefix);
                if separator != 0 {
                    path.push(b'/');
                }
                path.extend_from_slice(name);
                let Some(&child) = paths.get(path.as_slice()) else {
                    binding_error = true;
                    return Err(crate::Error::Corrupt);
                };
                let expected = &tree.objects[child];
                let content = match entry.uri()? {
                    Uri::Content(content) => Some(content),
                    Uri::Location(location) => Some(location.content()),
                    _ => None,
                };
                if child >= index
                    || members[child]
                    || content != Some(expected.content)
                    || (dir::claims_directory(entry.metadata.items()) == Some(true))
                        != expected.directory
                {
                    binding_error = true;
                    return Err(crate::Error::Corrupt);
                }
                members[child] = true;
                entries = entries.checked_add(1).ok_or(crate::Error::Limit)?;
                Ok(())
            },
        );
        if binding_error {
            return Err(Error::Binding);
        }
        let receipt = receipt?;
        directories += 1;
        if index + 1 == tree.objects.len() {
            root_file = Some(read);
            root_directory = Some(receipt);
            members[index] = true;
        }
    }
    if members.iter().any(|m| !m) || entries != tree.objects.len() - 1 {
        return Err(Error::Binding);
    }
    Ok((
        root_file.ok_or(Error::Binding)?,
        VerifiedTree {
            root: root_directory.ok_or(Error::Binding)?,
            files,
            directories,
            entries,
        },
    ))
}
