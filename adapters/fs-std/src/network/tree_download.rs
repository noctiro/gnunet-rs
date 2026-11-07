//! Recursive native retrieval over authenticated directory membership.
pub(crate) mod driver;
pub(crate) mod inline;
pub(crate) mod namespace;
mod one_shot;
pub(crate) mod paths;
use super::DownloadOptions;
use crate::{Buffers, Control, Error, OutputDir, Repository};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{
    Content,
    directory::{self as dir, walk},
};
use std::{
    fmt,
    path::{Path, PathBuf},
};

/// Explicit bounds for a complete native directory extraction. Each path is
/// visited separately, including different paths containing the same CHK.
#[derive(Clone, Copy, Debug)]
pub struct TreeDownloadOptions {
    /// One original endpoint-clock deadline and file retrieval policy.
    pub transfer: DownloadOptions,
    /// Per-directory strict parser and metadata bounds.
    pub directory: dir::Limits,
    /// Root is depth zero.
    pub max_depth: usize,
    /// All parent entry records, excluding the root.
    pub max_entries: usize,
    /// Scheduled file and directory bytes across all paths.
    pub max_total_bytes: u128,
    /// Sum of retained root-relative path bytes, with shared ownership.
    pub max_path_bytes: usize,
    /// Arena for exact unresolved namespace identifiers.
    pub max_namespace_bytes: usize,
    /// An optional hint above this bound is ignored in favor of native retrieval.
    pub max_inline_bytes: usize,
    /// Total admitted hint bytes across this operation.
    pub max_total_inline_bytes: usize,
    /// Actual namespace search graph, retained result and metadata bounds.
    pub namespace: crate::search::Limits,
}
impl TreeDownloadOptions {
    /// Bounded extraction with no overwrite, no symlink traversal and no cycle.
    #[must_use]
    pub fn new(transfer: DownloadOptions) -> Self {
        Self {
            transfer,
            directory: dir::Limits::default(),
            max_depth: 64,
            max_entries: 4096,
            max_total_bytes: 1024 * 1024 * 1024,
            max_path_bytes: 16 * 1024 * 1024,
            max_namespace_bytes: 1024 * 1024,
            max_inline_bytes: 65536,
            max_total_inline_bytes: 16 * 1024 * 1024,
            namespace: crate::search::Limits::default(),
        }
    }
}

/// Known completed output, independent of any currently active transfer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TreeDownloadProgress {
    /// The new root directory was created and its naming barriers synced.
    pub root_created: bool,
    /// New directories whose naming barriers completed, including the root.
    pub directories_created: usize,
    /// Fully authenticated and strictly parsed directory objects.
    pub directories_verified: usize,
    /// Fully authenticated files known durably linked into their exact paths.
    pub files_committed: usize,
    /// Plaintext bytes in those committed files; directory wire bytes excluded.
    pub file_bytes: u128,
}
/// Every original path task finished, and the anchored output directory synced.
#[derive(Clone, Copy, Debug)]
pub struct DownloadedTree {
    /// Known output progress.
    pub progress: TreeDownloadProgress,
    /// Source-bound directory ownership and scheduled-byte accounting.
    pub walk: walk::Summary,
}
/// Original failure plus known output prefix. Extraction is not a transaction:
/// completed files stay useful, and the failing name can exist after a naming
/// barrier fails. Inspect the original cause before reconciling that path.
#[derive(Debug)]
pub struct TreeDownloadFailure {
    /// Caller-relative original destination of the failed object.
    pub path: PathBuf,
    /// Only known successful output barriers are counted.
    pub progress: TreeDownloadProgress,
    /// Current walk history, absent when setup failed before admission.
    pub walk: Option<walk::Summary>,
    /// Actual original network, authentication, path, resource or storage error.
    pub cause: Error,
    /// Original cancellation, deadline or clock refusal from a control checkpoint.
    /// The operation cause still retains its own progress and cleanup/commit facts.
    pub interruption: Option<Error>,
    /// Independent physical retirement failure from an original namespace lookup.
    pub namespace_cleanup: Option<crate::search::Error>,
}
impl fmt::Display for TreeDownloadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = &self.interruption {
            write!(f, "{error}; ")?;
        }
        write!(f, "FS tree output {:?}: {}", self.path, self.cause)
    }
}
impl std::error::Error for TreeDownloadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

impl OutputDir {
    /// Extract an explicitly selected directory root through real FS queries.
    /// Every child comes from a strict authenticated parent entry. Existing
    /// targets, unsafe names, ancestor cycles and conflicting paths are refused;
    /// missing names use stable parent entry offsets. Native byte names survive.
    ///
    /// Verified inline hints need no service retrieval. Wrong hints fall back to
    /// the actual service. SKS entries use the existing authenticated namespace
    /// search; first observed CHK/LOC is the explicit selection policy. One
    /// deadline covers the entire tree, including lookup updates and output.
    /// Cancellation/drop leaves previously committed outputs in place, removes
    /// only the active file temporary and closes its original native MQ.
    #[expect(
        clippy::too_many_arguments,
        reason = "Output, endpoint, root, buffers, cache, limits and cancellation have independent ownership"
    )]
    pub async fn download_tree(
        &mut self,
        relative: impl AsRef<Path>,
        source: EndpointSource,
        content: Content,
        buffers: &mut Buffers,
        cache: Option<&mut Repository>,
        options: TreeDownloadOptions,
        control: impl FnMut(TreeDownloadProgress) -> Control,
    ) -> std::result::Result<DownloadedTree, Box<TreeDownloadFailure>> {
        let mut target = one_shot::Target::new(self, relative.as_ref());
        driver::run(
            &mut target,
            relative.as_ref(),
            source,
            content,
            buffers,
            cache,
            options,
            control,
        )
        .await
        .map_err(|failure| {
            Box::new(TreeDownloadFailure {
                path: failure.path,
                progress: failure.progress,
                walk: failure.walk,
                cause: failure.cause,
                interruption: failure.interruption,
                namespace_cleanup: failure.namespace_cleanup,
            })
        })
    }
}
