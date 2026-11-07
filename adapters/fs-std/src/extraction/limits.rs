/// Bounds actually consumed by descriptor metadata/keyword inspection. No
/// content encoder, ciphertext, publication task or service limits occur here.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Bounded descriptor-root enumeration and live ancestor names.
    pub tree: crate::input_tree::Limits,
    /// Maximum one regular file admitted to format extraction.
    pub max_file_bytes: u64,
    /// Maximum sum of observed regular-file sizes across the walk.
    pub max_source_bytes: u64,
    /// Maximum complete metadata artifact for one inspected object.
    pub max_metadata_bytes: usize,
    /// Maximum metadata artifact retained at the current object boundary.
    pub max_retained_metadata_bytes: usize,
    /// Maximum standard metadata bytes across the completed prefix.
    pub max_total_metadata_bytes: u64,
    /// Independent metadata container/framing bounds.
    pub metadata: gnunet_fs::metadata::Limits,
    /// Maximum decoded bytes permitted by the caller's term consumer.
    pub max_keyword_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            tree: crate::input_tree::Limits::default(),
            max_file_bytes: 256 * 1024 * 1024 * 1024,
            max_source_bytes: 256 * 1024 * 1024 * 1024,
            max_metadata_bytes: 64 * 1024,
            max_retained_metadata_bytes: 16 * 1024 * 1024,
            max_total_metadata_bytes: 128 * 1024 * 1024,
            metadata: gnunet_fs::metadata::Limits::default(),
            max_keyword_bytes: gnunet_fs::ublock::Limits::default().max_label_bytes,
        }
    }
}
