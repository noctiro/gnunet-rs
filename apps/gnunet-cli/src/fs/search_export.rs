//! Actual retained search-result references as a standard GNUnet directory.
use gnunet::{
    fs::{Limits as UriLimits, directory as dir, metadata as md},
    fs_codec::{Compressor, Inflate},
    fs_host::{ArtifactReport, CommitStage, OutputDir, search::ResultRecord},
};
use std::{
    error::Error,
    ffi::OsString,
    fmt,
    io::{self, Read},
    path::Path,
};

type Cause = Box<dyn Error>;
const METADATA_BYTES: usize = 2 * 1024 * 1024;
const RETAINED_BYTES: usize = 32 * 1024 * 1024;
const DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;
const ENTRIES: usize = 1024;

#[derive(Clone, Copy, Debug)]
pub(super) struct Report {
    pub visible_results: usize,
    pub entries: usize,
    pub wire_bytes: Option<u64>,
    pub write: ArtifactReport,
}
#[derive(Debug)]
pub(super) struct Failure {
    pub report: Report,
    cause: Cause,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "search directory {:?}: {}", self.report, self.cause)
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}
fn bytes(length: usize) -> Result<Vec<u8>, Cause> {
    let mut result = Vec::new();
    result.try_reserve_exact(length)?;
    result.resize(length, 0);
    Ok(result)
}
fn charge(total: &mut usize, amount: usize) -> Result<(), Cause> {
    let next = total.checked_add(amount).ok_or(md::Error::Overflow)?;
    if next > RETAINED_BYTES {
        return Err("search directory retained-artifact bound exceeded".into());
    }
    *total = next;
    Ok(())
}
struct Metadata {
    plain: Vec<u8>,
    coded: Vec<u8>,
    order: Vec<usize>,
    compressor: Compressor,
}
impl Metadata {
    fn new() -> Self {
        Self {
            plain: Vec::new(),
            coded: Vec::new(),
            order: Vec::new(),
            compressor: Compressor::new(),
        }
    }
    fn encode(&mut self, items: &[md::Item<'_>]) -> Result<Vec<u8>, Cause> {
        if items.len() > 4096 {
            return Err(md::Error::Limit.into());
        }
        let required = items.iter().try_fold(0usize, |total, item| {
            total
                .checked_add(md::ENTRY_BYTES)
                .and_then(|n| n.checked_add(item.data.len()))
                .and_then(|n| n.checked_add(item.plugin.map_or(0, <[u8]>::len)))
                .and_then(|n| n.checked_add(item.mime.map_or(0, <[u8]>::len)))
                .ok_or(md::Error::Overflow)
        })?;
        if required > METADATA_BYTES - md::HEADER_BYTES {
            return Err(md::Error::Limit.into());
        }
        for buffer in [&mut self.plain, &mut self.coded] {
            if buffer.len() < required {
                buffer.try_reserve_exact(required - buffer.len())?;
                buffer.resize(required, 0);
            }
        }
        self.order
            .try_reserve(items.len().saturating_sub(self.order.len()))?;
        self.order.resize(items.len(), 0);
        let plan = md::plan(
            items,
            &mut self.order,
            &mut self.plain,
            &mut self.coded,
            &mut self.compressor,
            md::Limits {
                max_coded_bytes: METADATA_BYTES,
                max_plain_bytes: METADATA_BYTES,
                max_entries: 4096,
            },
            md::Options {
                compression: md::Compression::Adaptive,
                max_output_bytes: METADATA_BYTES,
                ..Default::default()
            },
        )?;
        let mut output = bytes(plan.report().wire_bytes)?;
        plan.write(&mut output)?;
        Ok(output)
    }
}
struct Entry<'a> {
    source: &'a ResultRecord,
    metadata: Vec<u8>,
    record: Vec<u8>,
}
/// An existing descriptor-anchored destination directory. No target is exposed
/// before the complete directory plan is written and synced without replacement.
pub(super) struct Target {
    directory: OutputDir,
    name: OsString,
}
impl Target {
    pub(super) fn open(path: &Path) -> Result<Self, Cause> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .ok_or("search output requires a new file name")?
            .to_os_string();
        Ok(Self {
            directory: OutputDir::open(parent)?,
            name,
        })
    }
    /// Called only after the original Session has been canceled. The same
    /// session's final visible URI/metadata unions are copied; unsatisfied AND
    /// matches are not exported. Search failure/Stop does not erase real results.
    pub(super) fn write(&mut self, results: &[ResultRecord]) -> Result<Report, Failure> {
        let mut report = Report {
            visible_results: results.iter().filter(|r| r.visible()).count(),
            entries: 0,
            wire_bytes: None,
            write: ArtifactReport {
                bytes: 0,
                stage: CommitStage::NotLinked,
            },
        };
        let outcome = (|| -> Result<(), Cause> {
            if report.visible_results > ENTRIES {
                return Err("search directory entry bound exceeded".into());
            }
            let mut encoder = Metadata::new();
            let root_bytes = encoder.encode(&[dir::MIME_ITEM])?;
            let mut retained = root_bytes.len();
            let mut owned = Vec::new();
            charge(
                &mut retained,
                report
                    .visible_results
                    .checked_mul(std::mem::size_of::<Entry<'_>>())
                    .ok_or(md::Error::Overflow)?,
            )?;
            owned.try_reserve_exact(report.visible_results)?;
            for result in results.iter().filter(|r| r.visible()) {
                let mut items = Vec::new();
                items.try_reserve_exact(result.metadata().len())?;
                items.extend(result.metadata().iter().map(|item| item.item()));
                let metadata = encoder.encode(&items)?;
                let record_len = result
                    .raw_uri()
                    .len()
                    .checked_add(5)
                    .and_then(|n| n.checked_add(metadata.len()))
                    .ok_or(md::Error::Overflow)?;
                charge(&mut retained, metadata.len())?;
                charge(&mut retained, record_len)?;
                owned.push(Entry {
                    source: result,
                    metadata,
                    record: bytes(record_len)?,
                });
            }
            let metadata_limits = md::Limits {
                max_coded_bytes: METADATA_BYTES,
                max_plain_bytes: METADATA_BYTES,
                max_entries: 4096,
            };
            let mut inflater = Inflate::new();
            let root = dir::PreparedMetadata::validate(
                &root_bytes,
                &mut encoder.plain,
                &mut inflater,
                metadata_limits,
            )?;
            let mut entries = Vec::new();
            entries.try_reserve_exact(owned.len())?;
            for entry in &mut owned {
                let metadata = dir::PreparedMetadata::validate(
                    &entry.metadata,
                    &mut encoder.plain,
                    &mut inflater,
                    metadata_limits,
                )?;
                let uri = entry.source.uri(UriLimits::default())?;
                entries.push(dir::PreparedEntry::prepare(
                    uri,
                    metadata,
                    &mut entry.record,
                )?);
            }
            let mut placements = Vec::new();
            placements.try_reserve_exact(entries.len())?;
            placements.resize(entries.len(), dir::Placement::default());
            let plan = dir::plan(
                root,
                &entries,
                &mut placements,
                dir::BuildOptions {
                    max_output_bytes: DIRECTORY_BYTES,
                    max_source_entries: ENTRIES,
                    max_entries: ENTRIES,
                    max_trials: ENTRIES,
                    ..Default::default()
                },
            )?;
            report.entries = plan.report().selected_entries;
            report.wire_bytes = Some(plan.report().wire_bytes);
            struct Input<'a, 'b> {
                plan: &'a dir::BuildPlan<'b>,
                offset: u64,
            }
            impl Read for Input<'_, '_> {
                fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                    let count = self
                        .plan
                        .read_at(self.offset, output)
                        .map_err(io::Error::other)?;
                    self.offset += count as u64;
                    Ok(count)
                }
            }
            let mut input = Input {
                plan: &plan,
                offset: 0,
            };
            match self
                .directory
                .write_artifact(&self.name, &mut input, plan.report().wire_bytes)
            {
                Ok(write) => {
                    report.write = write;
                    Ok(())
                }
                Err(failure) => {
                    report.write = failure.report;
                    Err(failure as Cause)
                }
            }
        })();
        match outcome {
            Ok(()) => Ok(report),
            Err(cause) => Err(Failure { report, cause }),
        }
    }
}
