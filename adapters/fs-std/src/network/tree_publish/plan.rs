//! Checked metadata, record arenas and bounded DFS storage accounting.
use super::{TreeBudget, TreeLimits, TreePublishCause};
use crate::input_tree::FrameSource;
use crate::input_tree::{Kind, Stamp};
use gnunet_fs::{Content, directory as dir, metadata as md};
use gnunet_types::Error as ProtocolError;
use std::{fs::File, path::PathBuf};

pub(crate) fn allocation(length: usize) -> Result<Vec<u8>, TreePublishCause> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ProtocolError::Capacity)?;
    bytes.resize(length, 0);
    Ok(bytes)
}
pub(crate) fn add_usize(
    total: usize,
    amount: usize,
    limit: usize,
    budget: TreeBudget,
) -> Result<usize, TreePublishCause> {
    total
        .checked_add(amount)
        .filter(|next| *next <= limit)
        .ok_or(TreePublishCause::Limit(budget))
}
pub(crate) fn add_u64(
    total: u64,
    amount: u64,
    limit: u64,
    budget: TreeBudget,
) -> Result<u64, TreePublishCause> {
    total
        .checked_add(amount)
        .filter(|next| *next <= limit)
        .ok_or(TreePublishCause::Limit(budget))
}
pub(crate) fn metadata(items: &[md::Item<'_>], cap: usize) -> Result<Vec<u8>, TreePublishCause> {
    let mut length = md::HEADER_BYTES;
    for item in items {
        length = length
            .checked_add(md::ENTRY_BYTES)
            .and_then(|n| n.checked_add(item.data.len()))
            .and_then(|n| n.checked_add(item.plugin.map_or(0, <[u8]>::len)))
            .and_then(|n| n.checked_add(item.mime.map_or(0, <[u8]>::len)))
            .ok_or(ProtocolError::Overflow)?;
    }
    if length > cap {
        return Err(TreePublishCause::Limit(TreeBudget::Metadata));
    }
    let mut plain = allocation(length - md::HEADER_BYTES)?;
    let mut order = [0; 2];
    if items.len() > order.len() {
        return Err(ProtocolError::Capacity.into());
    }
    let plan = md::plan_uncompressed(
        items,
        &mut order[..items.len()],
        &mut plain,
        md::Limits {
            max_coded_bytes: cap,
            max_plain_bytes: cap,
            max_entries: 2,
        },
        md::Options {
            compression: md::Compression::Never,
            max_output_bytes: cap,
            ..Default::default()
        },
    )?;
    let mut bytes = allocation(plan.report().wire_bytes)?;
    plan.write(&mut bytes)?;
    Ok(bytes)
}
pub(crate) struct Entry {
    pub(crate) content: Option<Content>,
    pub(crate) metadata: Vec<u8>,
    pub(crate) record: Vec<u8>,
}
pub(crate) struct Frame {
    pub(crate) source: FrameSource,
    pub(crate) entries: Vec<Entry>,
    pub(crate) next: usize,
    pub(crate) path: PathBuf,
    pub(crate) parent_slot: Option<usize>,
    pub(crate) metadata_bytes: usize,
    pub(crate) record_bytes: usize,
}
#[derive(Default)]
pub(crate) struct Ledger {
    pub(crate) names: usize,
    pub(crate) metadata: usize,
    pub(crate) records: usize,
    pub(crate) total_metadata: u64,
    pub(crate) total_records: u64,
    pub(crate) file_bytes: u64,
    pub(crate) directory_bytes: u64,
    pub(crate) encoded_bytes: u128,
    pub(crate) stored_bytes: u128,
}

/// Shared bounded source/metadata/record frame for immediate and prepared trees.
#[expect(
    clippy::too_many_arguments,
    reason = "Explicit original source, parent binding and shared global budgets"
)]
pub(crate) fn frame(
    file: File,
    path: PathBuf,
    parent_slot: Option<usize>,
    expected: Option<Stamp>,
    limits: TreeLimits,
    entries_seen: &mut u64,
    ledger: &mut Ledger,
    root_metadata: &[u8],
) -> Result<Frame, TreePublishCause> {
    let left = limits
        .max_entries
        .checked_sub(*entries_seen)
        .ok_or(TreePublishCause::Limit(TreeBudget::Entries))?;
    let source = FrameSource::scan(
        file,
        limits
            .max_children
            .min(usize::try_from(left).unwrap_or(usize::MAX)),
        limits.max_name_bytes,
        limits.max_retained_name_bytes.saturating_sub(ledger.names),
    )?;
    if expected.is_some_and(|expected| expected != source.stamp) {
        return Err(super::SourceError::Changed.into());
    }
    let count = u64::try_from(source.names.len()).map_err(|_| ProtocolError::Overflow)?;
    *entries_seen = add_u64(
        *entries_seen,
        count,
        limits.max_entries,
        TreeBudget::Entries,
    )?;
    ledger.names = add_usize(
        ledger.names,
        source.names_bytes,
        limits.max_retained_name_bytes,
        TreeBudget::Path,
    )?;
    let longest_uri = Content {
        key: [0; 64],
        query: [0; 64],
        size: u64::MAX,
    }
    .uri()
    .encoded_len()?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(source.names.len())
        .map_err(|_| ProtocolError::Capacity)?;
    let mut metadata_bytes = root_metadata.len();
    let mut record_bytes = 0usize;
    for name in &source.names {
        let mut terminated = allocation(
            name.bytes
                .len()
                .checked_add(1)
                .ok_or(ProtocolError::Overflow)?,
        )?;
        terminated[..name.bytes.len()].copy_from_slice(&name.bytes);
        let items = [
            md::Item {
                kind: 180,
                format: md::Format::CString,
                data: &terminated,
                plugin: None,
                mime: None,
            },
            dir::MIME_ITEM,
        ];
        let bytes = metadata(
            &items[..if name.kind == Kind::Directory { 2 } else { 1 }],
            limits.max_metadata_bytes,
        )?;
        let length = longest_uri
            .checked_add(5)
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or(ProtocolError::Overflow)?;
        if length > limits.max_record_bytes {
            return Err(TreePublishCause::Limit(TreeBudget::Records));
        }
        metadata_bytes = add_usize(
            metadata_bytes,
            bytes.len(),
            limits
                .max_retained_metadata_bytes
                .saturating_sub(ledger.metadata),
            TreeBudget::Metadata,
        )?;
        record_bytes = add_usize(
            record_bytes,
            length,
            limits
                .max_retained_record_bytes
                .saturating_sub(ledger.records),
            TreeBudget::Records,
        )?;
        entries.push(Entry {
            content: None,
            metadata: bytes,
            record: allocation(length)?,
        });
    }
    ledger.metadata = add_usize(
        ledger.metadata,
        metadata_bytes,
        limits.max_retained_metadata_bytes,
        TreeBudget::Metadata,
    )?;
    ledger.records = add_usize(
        ledger.records,
        record_bytes,
        limits.max_retained_record_bytes,
        TreeBudget::Records,
    )?;
    ledger.total_metadata = add_u64(
        ledger.total_metadata,
        u64::try_from(metadata_bytes).map_err(|_| ProtocolError::Overflow)?,
        limits.max_total_metadata_bytes,
        TreeBudget::Metadata,
    )?;
    ledger.total_records = add_u64(
        ledger.total_records,
        u64::try_from(record_bytes).map_err(|_| ProtocolError::Overflow)?,
        limits.max_total_record_bytes,
        TreeBudget::Records,
    )?;
    Ok(Frame {
        source,
        entries,
        next: 0,
        path,
        parent_slot,
        metadata_bytes,
        record_bytes,
    })
}

/// Shared official directory record preparation and checked placement. Entries
/// borrow their existing record arenas; no complete directory output is owned.
pub(crate) struct DirectoryPlan<'a> {
    root: dir::PreparedMetadata<'a>,
    entries: Vec<dir::PreparedEntry<'a>>,
    placements: Vec<dir::Placement>,
    options: dir::BuildOptions,
}
impl<'a> DirectoryPlan<'a> {
    pub(crate) fn prepare(
        entries: &'a mut [Entry],
        root_metadata: &'a [u8],
        limits: TreeLimits,
    ) -> Result<Self, TreePublishCause> {
        let md_limits = md::Limits {
            max_coded_bytes: limits.max_metadata_bytes,
            max_plain_bytes: limits.max_metadata_bytes,
            max_entries: limits.max_metadata_bytes / md::ENTRY_BYTES,
        };
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(entries.len())
            .map_err(|_| ProtocolError::Capacity)?;
        for entry in entries {
            let metadata = dir::PreparedMetadata::validate(
                &entry.metadata,
                &mut [],
                &mut md::NoCodec,
                md_limits,
            )?;
            prepared.push(dir::PreparedEntry::prepare(
                entry.content.ok_or(ProtocolError::NotReady)?.uri(),
                metadata,
                &mut entry.record,
            )?);
        }
        let root =
            dir::PreparedMetadata::validate(root_metadata, &mut [], &mut md::NoCodec, md_limits)?;
        let mut placements = Vec::new();
        placements
            .try_reserve_exact(prepared.len())
            .map_err(|_| ProtocolError::Capacity)?;
        placements.resize(prepared.len(), dir::Placement::default());
        Ok(Self {
            root,
            entries: prepared,
            placements,
            options: dir::BuildOptions {
                max_output_bytes: limits.max_directory_extent,
                max_source_entries: limits.max_children,
                max_entries: limits.max_children,
                max_trials: limits.max_children,
                inclusion: dir::Inclusion::Full,
                allow_partial_metadata: false,
            },
        })
    }
    pub(crate) fn plan(&mut self) -> Result<dir::BuildPlan<'_>, TreePublishCause> {
        dir::plan(self.root, &self.entries, &mut self.placements, self.options).map_err(Into::into)
    }
}
