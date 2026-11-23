//! Publication-specific task/KSK preparation over the shared extraction core.
mod simulation;
pub use simulation::simulate;

use super::plan::tree::{Event, Observer, emit, root_file_progress};
use super::{Limits, Task, plan};
use crate::{
    Buffers, Control, Progress,
    extraction::{
        self, Budget, Context, MetadataSettings, copy, decoded, descriptor_info, keyword_bytes,
        terms, zeros,
    },
    input_tree::InputDir,
    network::BlockOptions,
};
use gnunet_fs::{Content, Keyword, Keywords, Location, Uri, metadata as md};
use gnunet_native::filesystem::Directory;
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    fmt,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
/// Publication-specific preparation policy and shared extraction selection.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Keep regular files on their original indexed source.
    pub indexed: bool,
    /// Exact shared metadata, automatic terms and extraction bounds.
    pub metadata: extraction::Policy,
    /// Maximum actual keyword tasks retained by this publication group.
    pub max_keyword_tasks: usize,
    /// Whole publication task/WAL/metadata budget, excluding payload files.
    pub max_group_plan_bytes: usize,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            indexed: true,
            metadata: extraction::Policy::default(),
            max_keyword_tasks: 256,
            max_group_plan_bytes: 64 * 1024 * 1024,
        }
    }
}
impl Policy {
    pub(crate) fn validate(self, limits: Limits) -> Result<(), Failure> {
        self.metadata.validate(extraction_limits(limits))?;
        if !(1..=4096).contains(&self.max_keyword_tasks)
            || !(4096..=512 * 1024 * 1024).contains(&self.max_group_plan_bytes)
        {
            return Err(Failure::Policy);
        }
        Ok(())
    }
}
fn extraction_limits(limits: Limits) -> extraction::Limits {
    let tree = limits.plan.tree;
    extraction::Limits {
        tree: crate::input_tree::Limits {
            max_depth: tree.max_depth,
            max_entries: tree.max_entries,
            max_children: tree.max_children,
            max_name_bytes: tree.max_name_bytes,
            max_path_bytes: tree.max_path_bytes,
            max_retained_name_bytes: tree.max_retained_name_bytes,
        },
        max_file_bytes: limits.plan.file.max_file_bytes,
        max_source_bytes: tree.max_file_bytes,
        max_metadata_bytes: tree.max_metadata_bytes,
        max_retained_metadata_bytes: tree.max_retained_metadata_bytes,
        max_total_metadata_bytes: tree.max_total_metadata_bytes,
        metadata: limits.plan.ublock.metadata,
        max_keyword_bytes: limits.plan.ublock.max_label_bytes,
    }
}
impl<C: FnMut(Progress) -> Control> Context<C> {
    fn admit_task(&self, manifest: &super::Manifest, body_bytes: usize) -> Result<(), plan::Error> {
        self.check()?;
        // Actual plan length and actual existing-codec WAL body, including row/
        // framing slack. The independently bounded single-plan workspace is
        // temporary; this charge precedes its first durable manifest append.
        let bytes = manifest
            .plan
            .retained_bytes()?
            .checked_add(body_bytes)
            .and_then(|n| n.checked_add(128))
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(std::mem::size_of::<Task>()))
            .ok_or(plan::Error::Limit)?;
        self.budget
            .borrow_mut()
            .add(bytes)
            .map_err(plan::Error::from)
    }
}
/// Original refusal; a failed preparation may leave owned immutable task files
/// but never starts a remote mutation. The group owner decides its cleanup.
#[derive(Debug)]
pub enum Failure {
    /// Invalid or excessive explicit resource/date policy.
    Policy,
    /// Original native I/O failure, with the actual errno intact.
    Io(std::io::Error),
    /// Original artifact/source/budget/cancellation refusal.
    Plan(plan::Error),
    /// Original durable Task preparation failure.
    Publication(Box<super::Failure>),
    /// Independent original provider cleanup error, preserving any earlier
    /// metadata, content, budget, stop or publication preparation failure.
    ExtractorCleanup {
        /// Earlier original failure, if any.
        original: Option<Box<Failure>>,
        /// Actual clock-free native close failure.
        cleanup: gnunet_extractor_host::NativeError,
    },
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy => f.write_str("invalid auto-share preparation policy"),
            Self::Io(e) => e.fmt(f),
            Self::Plan(e) => e.fmt(f),
            Self::Publication(e) => e.fmt(f),
            Self::ExtractorCleanup { original, cleanup } => {
                if let Some(original) = original {
                    write!(f, "{original}; ")?;
                }
                write!(f, "independent metadata provider cleanup: {cleanup}")
            }
        }
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy => None,
            Self::Io(e) => Some(e),
            Self::Plan(e) => Some(e),
            Self::Publication(e) => Some(e.as_ref()),
            Self::ExtractorCleanup {
                original: Some(e), ..
            } => Some(e.as_ref()),
            Self::ExtractorCleanup { cleanup, .. } => Some(cleanup),
        }
    }
}
impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<plan::Error> for Failure {
    fn from(e: plan::Error) -> Self {
        Self::Plan(e)
    }
}
impl From<gnunet_types::Error> for Failure {
    fn from(e: gnunet_types::Error) -> Self {
        Self::Plan(e.into())
    }
}

impl From<extraction::Error> for Failure {
    fn from(error: extraction::Error) -> Self {
        Self::Plan(error.into())
    }
}
fn finish<T>(
    provider: Option<gnunet_extractor_host::Provider>,
    result: Result<T, Failure>,
) -> Result<T, Failure> {
    match (
        result,
        provider
            .map(gnunet_extractor_host::Provider::close)
            .transpose(),
    ) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(cleanup)) => Err(Failure::ExtractorCleanup {
            original: None,
            cleanup,
        }),
        (Err(original), Err(cleanup)) => Err(Failure::ExtractorCleanup {
            original: Some(Box::new(original)),
            cleanup,
        }),
    }
}
/// Actual prepared KSK task. Its whole ordered PUT plan must settle independently.
pub struct KeywordTask {
    /// Real locked publication task, not a projected success receipt.
    pub task: Task,
    /// Literal group-relative directory, always keyword-N.
    pub name: PathBuf,
    /// Complete canonical KSK URI, for diagnostics/restoration.
    pub uri: Vec<u8>,
    /// Exact corresponding object's canonical CHK or signed LOC URI.
    pub target: Vec<u8>,
}
/// Standard metadata artifact actually written and synced inside the owned group.
#[derive(Debug)]
pub struct MetadataArtifact {
    /// Relative metadata-N name, without an alternate absolute path.
    pub name: PathBuf,
    /// Original tree-relative object (empty for the selected input itself).
    pub relative: PathBuf,
    /// Exact object CHK or signed LOC to which this metadata and KSK belong.
    pub target: Vec<u8>,
    /// Complete official uncompressed v2 metadata bytes.
    pub wire: Vec<u8>,
    /// Actual optional native observation, never an Accepted/KSKComplete fact.
    /// EmptyUnknown is a normal lack of callbacks, not whole-plugin validation.
    pub provider: Option<gnunet_extractor_host::Observation>,
}
/// Complete local preparation only; original network results remain required.
pub struct Prepared {
    /// Actual content Task, always at content.
    pub content: Task,
    /// Genuine per-object KSK tasks; empty when extraction was disabled.
    pub keywords: Vec<KeywordTask>,
    /// Canonical selected content root CHK or signed LOC URI.
    pub content_uri: Vec<u8>,
    /// Standard serialized metadata for every prepared object.
    pub metadata: Vec<MetadataArtifact>,
    /// Actual group-directory naming barrier after metadata file synchronization.
    pub directory_sync: gnunet_native::DirectorySync,
}
impl Prepared {
    /// Stable group-relative content task directory.
    #[must_use]
    pub fn content_name(&self) -> &Path {
        Path::new("content")
    }
}

fn canonical_uri(value: Uri<'_>, limits: Limits) -> Result<Vec<u8>, Failure> {
    let n = value.encoded_len()?;
    if n > limits.plan.ublock.uri.max_input_bytes {
        return Err(Failure::Policy);
    }
    let mut out = zeros(n)?;
    value.encode(&mut out)?;
    Ok(out)
}
struct Object {
    wire: Vec<u8>,
    provider: Option<gnunet_extractor_host::Observation>,
    query_terms: Option<Vec<Vec<u8>>>,
    manual_charge: usize,
}
struct Extractor<'a, C> {
    core: extraction::Extractor<'a, C>,
    objects: HashMap<PathBuf, Object>,
    retained: usize,
    total_limit: usize,
    object_limit: usize,
}
impl<'a, C: FnMut(Progress) -> Control> Extractor<'a, C> {
    fn new(
        input: &Path,
        policy: Policy,
        limits: Limits,
        context: &'a Context<C>,
        metadata: &'a MetadataSettings,
    ) -> Result<Self, plan::Error> {
        Ok(Self {
            core: extraction::Extractor::new(
                input,
                policy.metadata,
                extraction_limits(limits),
                context,
                metadata,
            )?,
            objects: HashMap::new(),
            retained: 0,
            total_limit: limits
                .plan
                .max_plan_bytes
                .min(policy.max_group_plan_bytes)
                .min(policy.metadata.max_retained_bytes),
            object_limit: usize::try_from(limits.plan.tree.max_entries)
                .unwrap_or(usize::MAX)
                .saturating_add(1),
        })
    }
    fn extract(
        &mut self,
        file: &File,
        relative: &Path,
        directory: bool,
        base: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>, plan::Error> {
        let object = self
            .core
            .extract_one(file, relative, directory, base, max_bytes)?;
        self.retain(relative, object)
    }
    fn retain(
        &mut self,
        relative: &Path,
        object: extraction::Object,
    ) -> Result<Vec<u8>, plan::Error> {
        let extraction::Object {
            wire,
            provider: provider_observation,
            query_terms,
        } = object;
        let mut manual_charge = if relative.as_os_str().is_empty() && self.core.manual.is_some() {
            wire.capacity()
                .checked_add(keyword_bytes(&query_terms)?)
                .ok_or(plan::Error::Limit)?
        } else {
            0
        };
        // One stored result per actual object; a directory's parent record and
        // its own root metadata describe the same original descriptor/path.
        let previous_object = self.objects.get(relative);
        let previous = if let Some(object) = previous_object {
            object
                .wire
                .len()
                .checked_add(keyword_bytes(&object.query_terms)?)
                .ok_or(plan::Error::Limit)?
        } else {
            0
        };
        let previous_manual = previous_object.map_or(0, |o| o.manual_charge);
        let extra = if previous == 0 {
            relative
                .as_os_str()
                .as_encoded_bytes()
                .len()
                .checked_add(std::mem::size_of::<(PathBuf, Object)>())
                .ok_or(plan::Error::Limit)?
        } else {
            0
        };
        let query_bytes = keyword_bytes(&query_terms)?;
        let retained = self
            .retained
            .checked_sub(previous)
            .and_then(|n| n.checked_add(wire.len()))
            .and_then(|n| n.checked_add(query_bytes))
            .and_then(|n| n.checked_add(extra))
            .filter(|n| *n <= self.total_limit)
            .ok_or(plan::Error::Limit)?;
        if previous == 0 && self.objects.len() >= self.object_limit {
            return Err(plan::Error::Limit);
        }
        let object_wire = copy(&wire)?;
        if manual_charge != 0 {
            manual_charge = object_wire
                .capacity()
                .checked_add(query_bytes)
                .ok_or(plan::Error::Limit)?;
        }
        self.core
            .context
            .budget
            .borrow_mut()
            .replace(previous_manual, manual_charge)?;
        self.objects
            .try_reserve(1)
            .map_err(|_| plan::Error::Limit)?;
        let key = crate::input::owned_path(relative)?;
        self.objects.insert(
            key,
            Object {
                wire: object_wire,
                provider: provider_observation,
                query_terms,
                manual_charge,
            },
        );
        self.retained = retained;
        Ok(wire)
    }
}
impl<C: FnMut(Progress) -> Control> plan::tree::MetadataProvider for Extractor<'_, C> {
    fn prepare(
        &mut self,
        source: &File,
        relative: &Path,
        directory: bool,
        base: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>, plan::Error> {
        self.extract(source, relative, directory, base, max_bytes)
    }
}

struct KeywordInput<'a> {
    path: &'a Path,
    target: Uri<'a>,
    wire: &'a [u8],
    terms: &'a [Keyword<'a>],
    blocks: BlockOptions,
    limits: Limits,
    policy: Policy,
    task_credit: bool,
    name_bytes: usize,
}
fn keyword_task<C: FnMut(Progress) -> Control>(
    input: KeywordInput<'_>,
    context: &Context<C>,
) -> Result<Option<Task>, Failure> {
    context.check()?;
    let KeywordInput {
        path,
        target,
        wire,
        terms,
        blocks,
        limits,
        policy,
        task_credit,
        name_bytes,
    } = input;
    if terms.is_empty() {
        return Ok(None);
    }
    // The cap applies only when a real new Task is needed. Empty-term objects
    // remain valid even after all original Task credits have been used.
    if !task_credit
        || terms.len() > limits.plan.ublock.uri.max_keywords
        || terms.len() > limits.plan.max_puts
    {
        return Err(Failure::Policy);
    }
    context.check()?;
    let mut items = Vec::new();
    items
        .try_reserve_exact(policy.metadata.max_metadata_items)
        .map_err(|_| Failure::Policy)?;
    for item in decoded(wire, policy.metadata)?.items() {
        items.push(item);
    }
    let mut order = Vec::new();
    order
        .try_reserve_exact(items.len())
        .map_err(|_| Failure::Policy)?;
    order.resize(items.len(), 0);
    let mut plain = zeros(policy.metadata.max_metadata_bytes)?;
    let metadata = md::plan_uncompressed(
        &items,
        &mut order,
        &mut plain,
        md::Limits {
            max_coded_bytes: policy.metadata.max_metadata_bytes,
            max_plain_bytes: policy.metadata.max_metadata_bytes,
            max_entries: policy.metadata.max_metadata_items,
        },
        md::Options {
            compression: md::Compression::Never,
            max_output_bytes: policy.metadata.max_metadata_bytes,
            ..Default::default()
        },
    )
    .map_err(plan::Error::from)?;
    context.check()?;
    Task::prepare_admitted(
        path,
        blocks,
        limits,
        |repo| {
            plan::prepare_keywords(
                repo,
                Keywords::new(terms)?,
                target,
                Some(&metadata),
                limits.plan,
            )
        },
        |manifest, bytes| {
            context.admit_task(manifest, bytes)?;
            let plan::Artifact::Keywords {
                query_uri,
                target_uri,
                ..
            } = &manifest.plan.artifact
            else {
                return Err(plan::Error::Binding);
            };
            let extra = query_uri
                .len()
                .checked_add(target_uri.len())
                .and_then(|n| n.checked_add(name_bytes))
                .ok_or(plan::Error::Limit)?;
            context
                .budget
                .borrow_mut()
                .add(extra)
                .map_err(plan::Error::from)
        },
    )
    .map(Some)
    .map_err(Failure::Publication)
}
fn artifact_content(task: &Task) -> Result<Content, Failure> {
    match &task.manifest().plan.artifact {
        plan::Artifact::File(c) | plan::Artifact::IndexedFile { content: c, .. } => Ok(*c),
        plan::Artifact::Tree(tree) => Ok(tree.root),
        _ => Err(Failure::Plan(plan::Error::Binding)),
    }
}
fn persist_metadata(root: &Directory, name: &Path, wire: &[u8]) -> Result<(), Failure> {
    let mut file = root.create_private_file(name.as_os_str())?;
    file.write_all(wire)?;
    file.sync_all()?;
    Ok(())
}
/// Prepare an actual immutable group below an exclusively caller-owned new
/// directory. No socket, native runner, subprocess or hidden thread is started.
/// Failed/partial local preparation is returned as failure for the original
/// group/version owner; it is never an automatically replayable network effect.
pub fn prepare(
    group_root: &Path,
    input: &Path,
    buffers: &mut Buffers,
    blocks: BlockOptions,
    limits: Limits,
    policy: Policy,
    control: impl FnMut(Progress) -> Control,
) -> Result<Prepared, Failure> {
    prepare_with_metadata(
        group_root,
        input,
        buffers,
        blocks,
        limits,
        policy,
        MetadataSettings::default(),
        control,
    )
}
/// The existing single publication algorithm with owned metadata selection.
/// Native provider construction/use/close happens inside this caller's worker;
/// all original source/CHK, task, keyword, deadline and cancellation owners remain.
#[expect(
    clippy::too_many_arguments,
    reason = "Original content/task limits, policy and owned metadata profile are one admitted worker request"
)]
pub fn prepare_with_metadata(
    group_root: &Path,
    input: &Path,
    buffers: &mut Buffers,
    blocks: BlockOptions,
    limits: Limits,
    policy: Policy,
    metadata: MetadataSettings,
    control: impl FnMut(Progress) -> Control,
) -> Result<Prepared, Failure> {
    prepare_with_annotations(
        group_root,
        input,
        buffers,
        blocks,
        limits,
        policy,
        Annotations {
            metadata,
            root_keywords: &RootKeywords::default(),
            observer: None,
        },
        control,
    )
}

/// An ordered list of explicit publication labels. Each occurrence retains its
/// mandatory-search marker and receives one DATASTORE PUT.
#[derive(Default)]
pub struct RootKeywords(Vec<(Vec<u8>, bool)>);

impl RootKeywords {
    /// Append one literal label admitted by the default publication bounds.
    pub fn push(&mut self, label: &[u8], mandatory: bool) -> Result<(), gnunet_types::Error> {
        use gnunet_types::Error;
        let limits = Limits::default().plan;
        if self.0.len() >= limits.ublock.uri.max_keywords
            || self.0.len() >= limits.max_puts
            || label.len()
                > limits
                    .ublock
                    .max_label_bytes
                    .min(limits.ublock.uri.max_keyword_bytes)
        {
            return Err(Error::Capacity);
        }
        if label.is_empty() {
            return Err(Error::InvalidInput);
        }
        Keyword::new(label, mandatory)?;
        self.0.try_reserve(1).map_err(|_| Error::Capacity)?;
        let mut term = Vec::new();
        term.try_reserve_exact(label.len())
            .map_err(|_| Error::Capacity)?;
        term.extend_from_slice(label);
        self.0.push((term, mandatory));
        Ok(())
    }

    /// Whether the caller supplied no explicit labels.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow ordered explicit terms, also used by standalone URI publication.
    pub fn terms(&self) -> Result<Vec<Keyword<'_>>, gnunet_types::Error> {
        let mut terms = Vec::new();
        terms
            .try_reserve_exact(self.0.len())
            .map_err(|_| gnunet_types::Error::Capacity)?;
        for (label, mandatory) in &self.0 {
            terms.push(Keyword::new(label, *mandatory)?);
        }
        Ok(terms)
    }

    /// Merge optional automatic terms by decoded label. Preserve the order and
    /// mandatory marker of every explicit term and append unmatched automatic ones.
    pub fn with_automatic<'a>(
        &'a self,
        automatic: &'a [Vec<u8>],
    ) -> Result<Vec<Keyword<'a>>, gnunet_types::Error> {
        use gnunet_types::Error;
        let mut terms = self.terms()?;
        terms
            .try_reserve_exact(automatic.len())
            .map_err(|_| Error::Capacity)?;
        let mut explicit_labels = HashSet::new();
        if !automatic.is_empty() {
            explicit_labels
                .try_reserve(self.0.len())
                .map_err(|_| Error::Capacity)?;
            explicit_labels.extend(self.0.iter().map(|(label, _)| label.as_slice()));
        }
        for term in automatic {
            if !explicit_labels.contains(term.as_slice()) {
                terms.push(Keyword::new(term, false)?);
            }
        }
        Ok(terms)
    }

    fn retained_bytes(&self) -> Option<usize> {
        let descriptors = self
            .0
            .capacity()
            .checked_mul(std::mem::size_of::<(Vec<u8>, bool)>())?;
        self.0.iter().try_fold(descriptors, |total, (label, _)| {
            total.checked_add(label.capacity())
        })
    }
}

/// Owned metadata selection and explicit labels for the published root only.
pub struct Annotations<'a> {
    /// Metadata extraction policy and manual annotations.
    pub metadata: MetadataSettings,
    /// Explicit root labels, independent of automatic extraction.
    pub root_keywords: &'a RootKeywords,
    /// Optional actual scan, extraction and plaintext encoding information.
    pub observer: Observer<'a>,
}

/// Prepare an ordinary file or tree with explicitly selected root annotations.
#[expect(
    clippy::too_many_arguments,
    reason = "Content, task bounds and annotations are one admitted worker request"
)]
pub fn prepare_with_annotations(
    group_root: &Path,
    input: &Path,
    buffers: &mut Buffers,
    blocks: BlockOptions,
    limits: Limits,
    policy: Policy,
    annotations: Annotations<'_>,
    control: impl FnMut(Progress) -> Control,
) -> Result<Prepared, Failure> {
    prepare_annotations(
        group_root,
        input,
        buffers,
        blocks,
        limits,
        policy,
        annotations,
        None,
        control,
    )
}

/// Resolve an optional signed placement once for each exact zero-anonymity
/// object. The original CHK is used if the signer delivers no placement.
/// Member LOCs are embedded before encoding the enclosing directory.
#[expect(
    clippy::too_many_arguments,
    reason = "Content, task bounds and annotations are one admitted worker request"
)]
pub fn prepare_with_locations(
    group_root: &Path,
    input: &Path,
    buffers: &mut Buffers,
    blocks: BlockOptions,
    limits: Limits,
    policy: Policy,
    annotations: Annotations<'_>,
    sign_location: &mut dyn FnMut(Content) -> Result<Option<Location>, plan::Error>,
    control: impl FnMut(Progress) -> Control,
) -> Result<Prepared, Failure> {
    if blocks.anonymity != 0 {
        return Err(Failure::Policy);
    }
    prepare_annotations(
        group_root,
        input,
        buffers,
        blocks,
        limits,
        policy,
        annotations,
        Some(sign_location),
        control,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Content, task bounds and annotations are one admitted worker request"
)]
fn prepare_annotations(
    group_root: &Path,
    input: &Path,
    buffers: &mut Buffers,
    blocks: BlockOptions,
    limits: Limits,
    policy: Policy,
    annotations: Annotations<'_>,
    mut sign_location: Option<&mut dyn FnMut(Content) -> Result<Option<Location>, plan::Error>>,
    control: impl FnMut(Progress) -> Control,
) -> Result<Prepared, Failure> {
    let Annotations {
        metadata,
        root_keywords,
        mut observer,
    } = annotations;
    let mut policy = policy;
    policy.metadata.extract &= metadata.automatic_keywords_enabled();
    policy.validate(limits)?;
    let settings_bytes = metadata
        .retained_bytes()?
        .checked_add(root_keywords.retained_bytes().ok_or(Failure::Policy)?)
        .ok_or(Failure::Policy)?;
    if settings_bytes > policy.max_group_plan_bytes {
        return Err(Failure::Policy);
    }
    let context = Context {
        control: RefCell::new(control),
        progress: Cell::new(Progress::default()),
        budget: RefCell::new(Budget {
            used: settings_bytes,
            limit: policy.max_group_plan_bytes,
        }),
    };
    let signing = sign_location.is_some();
    let mut sign = |content| -> Result<Option<Location>, plan::Error> {
        context.check()?;
        let location = sign_location.as_mut().ok_or(plan::Error::Binding)?(content)?;
        context.check()?;
        if location.is_some() {
            context
                .budget
                .borrow_mut()
                .add(2 * std::mem::size_of::<(usize, Location)>())?;
        }
        Ok(location)
    };
    let mut locations = signing.then(|| plan::tree::Locations::new(&mut sign));
    context.check()?;
    let group = Directory::open(group_root)?;
    let group_id = crate::FileIdentity::of(group.as_file())?;
    let observed = fs::symlink_metadata(input)?;
    if observed.file_type().is_symlink() || (!observed.is_dir() && !observed.is_file()) {
        return Err(Failure::Policy);
    }
    if observed.is_dir() && fs::canonicalize(group_root)?.starts_with(fs::canonicalize(input)?) {
        return Err(Failure::Policy);
    }
    let mut extractor = Extractor::new(input, policy, limits, &context, &metadata)?;
    extractor.core.content_file_bytes = if observed.is_dir() {
        limits.plan.tree.max_file_bytes
    } else {
        limits.plan.file.max_file_bytes
    };
    if observed.is_file() && observed.len() > extractor.core.content_file_bytes {
        return Err(Failure::Plan(plan::Error::Limit));
    }
    extractor.core.manual = metadata.manual();
    extractor.core.provider =
        metadata.open(&context, policy.metadata, extractor.core.content_file_bytes)?;
    let result = (|| -> Result<Prepared, Failure> {
        let content = if observed.is_dir() {
            let directory = InputDir::open(input).map_err(|e| {
                Failure::Plan(crate::network::tree_publish::TreePublishCause::Source(e).into())
            })?;
            Task::prepare_admitted(
                group_root.join("content"),
                blocks,
                limits,
                |repo| {
                    let (tree, puts) = plan::tree::prepare_tree_observed(
                        repo,
                        &directory,
                        policy.indexed.then_some(input),
                        buffers,
                        limits.plan,
                        &mut extractor,
                        observer.take(),
                        locations.as_mut(),
                        |p| context.report(p),
                    )?;
                    Ok(plan::Plan {
                        artifact: plan::Artifact::Tree(tree),
                        puts,
                    })
                },
                |manifest, bytes| context.admit_task(manifest, bytes),
            )
            .map_err(Failure::Publication)?
        } else {
            let mut file = crate::input::open_exact(input)?;
            if !file.metadata()?.is_file() {
                return Err(Failure::Policy);
            }
            let stamp = descriptor_info(&file)?;
            emit(
                &mut observer,
                Event::Scanning {
                    relative: Path::new(""),
                    directory: false,
                },
            )?;
            emit(&mut observer, Event::ScanComplete)?;
            extractor.extract(
                &file,
                Path::new(""),
                false,
                &[],
                policy.metadata.max_metadata_bytes,
            )?;
            emit(&mut observer, Event::Extracted(Path::new("")))?;
            emit(&mut observer, Event::MetadataComplete)?;
            let report = root_file_progress(&mut observer, stamp.bytes, |p| context.report(p));
            let task = Task::prepare_admitted(
                group_root.join("content"),
                blocks,
                limits,
                |repo| {
                    if policy.indexed {
                        let prepared = plan::indexed::prepare(
                            repo,
                            &mut file,
                            input,
                            buffers,
                            limits.plan,
                            report,
                        )?;
                        Ok(plan::Plan {
                            artifact: plan::Artifact::IndexedFile {
                                content: prepared.content,
                                source: prepared.source,
                            },
                            puts: prepared.puts,
                        })
                    } else {
                        plan::prepare_file(repo, &mut file, buffers, limits.plan, report)
                    }
                },
                |manifest, bytes| context.admit_task(manifest, bytes),
            )
            .map_err(Failure::Publication)?;
            if descriptor_info(&file)? != stamp {
                return Err(Failure::Plan(crate::Error::SourceChanged.into()));
            }
            if let Some(locations) = &mut locations {
                let _root = locations.sign(0, artifact_content(&task)?)?;
            }
            task
        };
        context.check()?;
        let root = artifact_content(&content)?;
        let count = match &content.manifest().plan.artifact {
            plan::Artifact::Tree(t) => t.objects.len(),
            _ => 1,
        };
        let root_uri = locations
            .as_ref()
            .and_then(|owner| owner.values.last())
            .filter(|(index, _)| *index + 1 == count)
            .map_or(root.uri(), |(_, location)| Uri::Location(*location));
        let content_uri = canonical_uri(root_uri, limits)?;
        let mut locations = locations
            .into_iter()
            .flat_map(|owner| owner.values)
            .peekable();
        let keyword_capacity = if policy.metadata.extract {
            count.min(policy.max_keyword_tasks)
        } else {
            usize::from(!root_keywords.is_empty())
        };
        let collection = count
            .checked_mul(std::mem::size_of::<MetadataArtifact>())
            .and_then(|n| {
                n.checked_add(keyword_capacity.checked_mul(std::mem::size_of::<KeywordTask>())?)
            })
            .ok_or(Failure::Policy)?;
        context.budget.borrow_mut().add(
            collection
                .checked_add(content_uri.capacity())
                .ok_or(Failure::Policy)?,
        )?;
        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(count)
            .map_err(|_| Failure::Policy)?;
        let mut keywords = Vec::new();
        keywords
            .try_reserve_exact(keyword_capacity)
            .map_err(|_| Failure::Policy)?;
        let no_explicit = RootKeywords::default();
        for i in 0..count {
            context.check()?;
            let (relative, target) = match &content.manifest().plan.artifact {
                plan::Artifact::Tree(t) => {
                    let object = &t.objects[i];
                    (
                        Path::new(
                            crate::output::from_protocol_name(&object.path)
                                .map_err(plan::Error::from)?,
                        ),
                        object.content,
                    )
                }
                _ => (Path::new(""), root),
            };
            let mut object = extractor
                .objects
                .remove(relative)
                .ok_or(Failure::Plan(plan::Error::Binding))?;
            let query_charge = keyword_bytes(&object.query_terms)?;
            let selected_terms = if policy.metadata.extract {
                if let Some(terms) = object.query_terms.take() {
                    terms
                } else {
                    terms(&object.wire, policy.metadata)?
                }
            } else {
                Vec::new()
            };
            let target = if locations.peek().is_some_and(|(index, _)| *index == i) {
                Uri::Location(locations.next().ok_or(Failure::Policy)?.1)
            } else {
                target.uri()
            };
            let target_uri = canonical_uri(target, limits)?;
            let name = PathBuf::from(format!("metadata-{i}"));
            // Original metadata body is already charged once in Extractor. Reserve
            // the final collection's extra names/target before any persistent write.
            let descriptor = relative
                .as_os_str()
                .as_encoded_bytes()
                .len()
                .checked_add(target_uri.capacity())
                .and_then(|n| n.checked_add(name.as_os_str().as_encoded_bytes().len()))
                .ok_or(Failure::Policy)?;
            context.budget.borrow_mut().add(descriptor)?;
            context.check()?;
            persist_metadata(&group, &name, &object.wire)?;
            context.check()?;
            let explicit = if relative.as_os_str().is_empty() {
                root_keywords
            } else {
                &no_explicit
            };
            let terms = explicit.with_automatic(&selected_terms)?;
            if !terms.is_empty() {
                let keyword_name = PathBuf::from(format!("keyword-{}", keywords.len()));
                let keyword_path = group_root.join(&keyword_name);
                let input = KeywordInput {
                    path: &keyword_path,
                    target,
                    wire: &object.wire,
                    terms: &terms,
                    blocks,
                    limits,
                    policy,
                    task_credit: keywords.len() < policy.max_keyword_tasks,
                    name_bytes: keyword_name.as_os_str().as_encoded_bytes().len(),
                };
                if let Some(task) = keyword_task(input, &context)? {
                    let plan::Artifact::Keywords { query_uri, .. } = &task.manifest().plan.artifact
                    else {
                        return Err(Failure::Plan(plan::Error::Binding));
                    };
                    let query = copy(query_uri)?;
                    keywords.push(KeywordTask {
                        task,
                        name: keyword_name,
                        uri: query,
                        target: copy(&target_uri)?,
                    });
                }
            }
            // The root's query snapshot has fulfilled its actual Task inputs.
            // Keep the final metadata wire charged, release only those terms.
            drop(terms);
            drop(selected_terms);
            context.budget.borrow_mut().replace(query_charge, 0)?;
            metadata.push(MetadataArtifact {
                name,
                relative: crate::input::owned_path(relative)?,
                target: target_uri,
                wire: object.wire,
                provider: object.provider,
            });
        }
        if !extractor.objects.is_empty() {
            return Err(Failure::Plan(plan::Error::Binding));
        }
        context.check()?;
        let directory_sync = group.sync()?;
        if crate::FileIdentity::of(Directory::open(group_root)?.as_file())? != group_id {
            return Err(Failure::Policy);
        }
        context.check()?;
        Ok(Prepared {
            content,
            keywords,
            content_uri,
            metadata,
            directory_sync,
        })
    })();
    finish(extractor.core.provider.take(), result)
}
