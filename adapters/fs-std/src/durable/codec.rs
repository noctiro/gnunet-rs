//! Strict private v2 event bytes. The original TaskStore owns checksums and WAL ordering.
use super::model::{
    EntryBinding, Event, Manifest, ModelError, Phase, RootMode, TempFact, validate_name,
    validate_path,
};
use crate::{
    network::{DownloadOptions, tree_download::TreeDownloadOptions},
    output::{CommitStage, FileIdentity},
};
use gnunet_fs::{Content, Location, Uri, directory::walk::Kind};
use gnunet_types::AbsoluteTime;
use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
};
/// Maximum returned event body; caller may use a stricter Store body cap.
pub const MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;
/// Bounded official root/LOC URI bytes, independent of encoded proof size.
pub const MAX_URI_BYTES: usize = 16_384;
const VERSION: u16 = 2;
const MANIFEST: u16 = 1;
const ROOT: u16 = 2;
const DIR_INTENT: u16 = 3;
const DIR_CREATED: u16 = 4;
const DIR_VERIFIED: u16 = 5;
const TEMP: u16 = 6;
const INTENT: u16 = 7;
const COMMITTED: u16 = 8;
const CLEANUP: u16 = 9;
const RESET: u16 = 10;
const SELECTED: u16 = 11;
const PHASE: u16 = 12;
const FILE_ATTACHED: u16 = 13;

/// Original selection header plus a borrowed exact proof span from one WAL record.
/// This projection is not an authenticated SKS binding; reverify with real SKS.
#[derive(Debug)]
pub struct SelectionView<'a> {
    /// Expected exact driver binding recorded with the original choice.
    pub binding: EntryBinding,
    /// Expected immutable content.
    pub selected: Content,
    /// Exact original signed LOC, if selected.
    pub location: Option<Location>,
    /// Large proof stays borrowed from Store::record(index).bytes.
    pub proof: &'a [u8],
}
/// Encode complete bounded private state bytes. Native paths remain exact bytes;
/// transfer.deadline is omitted and will be rebuilt explicitly for each run.
pub fn encode_event(event: &Event<'_>) -> Result<(u16, Vec<u8>), ModelError> {
    let mut w = Writer(Vec::new());
    w.u16(VERSION)?;
    let kind = match event {
        Event::Manifest(m) => {
            m.validate()?;
            match &m.mode {
                RootMode::Directory => w.u8(0)?,
                RootMode::File { selection } => {
                    w.u8(1)?;
                    w.u64(selection.start)?;
                    w.u64(selection.end)?;
                }
            }
            put_options(&mut w, m.options)?;
            w.blob(&m.root_uri, MAX_URI_BYTES)?;
            w.blob(m.relative.as_os_str().as_bytes(), 4096)?;
            MANIFEST
        }
        Event::RootAttached(id) => {
            put_identity(&mut w, *id)?;
            ROOT
        }
        Event::FileAttached { parent, staging } => {
            put_identity(&mut w, *parent)?;
            put_identity(&mut w, *staging)?;
            FILE_ATTACHED
        }
        Event::DirectoryIntent(b) => {
            put_binding(&mut w, b)?;
            DIR_INTENT
        }
        Event::DirectoryCreated { id, identity } => {
            w.raw(id)?;
            put_identity(&mut w, *identity)?;
            DIR_CREATED
        }
        Event::DirectoryVerified { id } => {
            w.raw(id)?;
            DIR_VERIFIED
        }
        Event::TempOwned { binding, temporary } => {
            put_binding(&mut w, binding)?;
            put_identity(&mut w, temporary.parent)?;
            put_identity(&mut w, temporary.identity)?;
            validate_name(temporary.name.as_bytes())?;
            w.blob(temporary.name.as_bytes(), 4096)?;
            TEMP
        }
        Event::CommitIntent { id } => {
            w.raw(id)?;
            INTENT
        }
        Event::FileCommitted { id, identity } => {
            w.raw(id)?;
            put_identity(&mut w, *identity)?;
            COMMITTED
        }
        Event::Cleanup { id, success, stage } => {
            w.raw(id)?;
            w.u8(u8::from(*success))?;
            w.u8(stage_tag(*stage))?;
            CLEANUP
        }
        Event::ResetPending { id } => {
            w.raw(id)?;
            RESET
        }
        Event::NamespaceSelected {
            binding,
            selected,
            location,
            proof,
        } => {
            if binding.content != *selected
                || location.is_some_and(|l| l.content() != *selected)
                || proof.is_empty()
            {
                return Err(ModelError::Binding);
            }
            put_binding(&mut w, binding)?;
            put_location(&mut w, *location)?;
            w.blob(proof, MAX_EVENT_BYTES)?;
            SELECTED
        }
        Event::Phase(phase) => {
            w.u8(phase_tag(*phase))?;
            PHASE
        }
    };
    Ok((kind, w.0))
}
/// Fully decode one exact bounded body before typed State mutation. A proof body
/// remains borrowed; parsed fields do not mint source/commit verification receipts.
pub fn decode_event(kind: u16, bytes: &[u8]) -> Result<Event<'_>, ModelError> {
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(ModelError::Limit);
    }
    let mut r = Reader(bytes);
    if r.u16()? != VERSION {
        return Err(ModelError::Version);
    }
    let event = match kind {
        MANIFEST => {
            let mode = match r.u8()? {
                0 => RootMode::Directory,
                1 => RootMode::File {
                    selection: r.u64()?..r.u64()?,
                },
                _ => return Err(ModelError::Format),
            };
            let options = get_options(&mut r)?;
            let root_uri = copy(r.blob(MAX_URI_BYTES)?)?;
            let relative = path(r.blob(4096)?)?;
            let m = Manifest {
                root_uri,
                relative,
                mode,
                options,
            };
            m.validate()?;
            Event::Manifest(m)
        }
        ROOT => Event::RootAttached(get_identity(&mut r)?),
        FILE_ATTACHED => Event::FileAttached {
            parent: get_identity(&mut r)?,
            staging: get_identity(&mut r)?,
        },
        DIR_INTENT => Event::DirectoryIntent(get_binding(&mut r)?),
        DIR_CREATED => Event::DirectoryCreated {
            id: r.array()?,
            identity: get_identity(&mut r)?,
        },
        DIR_VERIFIED => Event::DirectoryVerified { id: r.array()? },
        TEMP => {
            let binding = get_binding(&mut r)?;
            let parent = get_identity(&mut r)?;
            let identity = get_identity(&mut r)?;
            let name = r.blob(4096)?;
            validate_name(name)?;
            Event::TempOwned {
                binding,
                temporary: TempFact {
                    parent,
                    identity,
                    name: OsString::from_vec(copy(name)?),
                },
            }
        }
        INTENT => Event::CommitIntent { id: r.array()? },
        COMMITTED => Event::FileCommitted {
            id: r.array()?,
            identity: get_identity(&mut r)?,
        },
        CLEANUP => Event::Cleanup {
            id: r.array()?,
            success: r.boolean()?,
            stage: get_stage(r.u8()?)?,
        },
        RESET => Event::ResetPending { id: r.array()? },
        SELECTED => {
            let binding = get_binding(&mut r)?;
            let selected = binding.content;
            let location = get_location(&mut r)?;
            if location.is_some_and(|l| l.content() != selected) {
                return Err(ModelError::Binding);
            }
            let proof = r.blob(MAX_EVENT_BYTES)?;
            if proof.is_empty() {
                return Err(ModelError::Format);
            }
            Event::NamespaceSelected {
                binding: Box::new(binding),
                selected,
                location,
                proof,
            }
        }
        PHASE => Event::Phase(get_phase(r.u8()?)?),
        _ => return Err(ModelError::Version),
    };
    if !r.0.is_empty() {
        return Err(ModelError::Format);
    }
    Ok(event)
}
/// Extract one NamespaceSelected record's proof without copying the proof body.
/// The kind argument must come from the original Store RecordView, never a guess.
pub fn selection_view(kind: u16, bytes: &[u8]) -> Result<SelectionView<'_>, ModelError> {
    match decode_event(kind, bytes)? {
        Event::NamespaceSelected {
            binding,
            selected,
            location,
            proof,
        } => Ok(SelectionView {
            binding: *binding,
            selected,
            location,
            proof,
        }),
        _ => Err(ModelError::Format),
    }
}
fn put_binding(w: &mut Writer, b: &EntryBinding) -> Result<(), ModelError> {
    validate_path(&b.path, b.parent.is_none())?;
    w.raw(&b.id)?;
    w.u8(u8::from(b.parent.is_some()))?;
    if let Some(parent) = b.parent {
        w.raw(&parent)?;
    }
    w.u8(if b.kind == Kind::Directory { 1 } else { 0 })?;
    w.blob(b.path.as_os_str().as_bytes(), 4096)?;
    put_content(w, b.content)
}
fn get_binding(r: &mut Reader<'_>) -> Result<EntryBinding, ModelError> {
    let id = r.array()?;
    let parent = if r.boolean()? { Some(r.array()?) } else { None };
    let kind = match r.u8()? {
        0 => Kind::File,
        1 => Kind::Directory,
        _ => return Err(ModelError::Format),
    };
    let path = path(r.blob(4096)?)?;
    validate_path(&path, parent.is_none())?;
    Ok(EntryBinding {
        id,
        parent,
        path,
        kind,
        content: get_content(r)?,
    })
}
fn put_content(w: &mut Writer, c: Content) -> Result<(), ModelError> {
    w.raw(&c.key)?;
    w.raw(&c.query)?;
    w.u64(c.size)
}
fn get_content(r: &mut Reader<'_>) -> Result<Content, ModelError> {
    Ok(Content {
        key: r.array()?,
        query: r.array()?,
        size: r.u64()?,
    })
}
fn put_identity(w: &mut Writer, id: FileIdentity) -> Result<(), ModelError> {
    w.u64(id.device)?;
    w.u64(id.inode)
}
fn get_identity(r: &mut Reader<'_>) -> Result<FileIdentity, ModelError> {
    Ok(FileIdentity {
        device: r.u64()?,
        inode: r.u64()?,
    })
}
fn put_location(w: &mut Writer, location: Option<Location>) -> Result<(), ModelError> {
    w.u8(u8::from(location.is_some()))?;
    if let Some(loc) = location {
        let uri = Uri::Location(loc);
        let n = uri.encoded_len()?;
        if n > MAX_URI_BYTES {
            return Err(ModelError::Limit);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(n).map_err(|_| ModelError::Limit)?;
        bytes.resize(n, 0);
        uri.encode(&mut bytes)?;
        w.blob(&bytes, MAX_URI_BYTES)?;
    }
    Ok(())
}
fn get_location(r: &mut Reader<'_>) -> Result<Option<Location>, ModelError> {
    if !r.boolean()? {
        return Ok(None);
    }
    match Uri::parse(r.blob(MAX_URI_BYTES)?, gnunet_fs::Limits::default())? {
        Uri::Location(loc) => Ok(Some(loc)),
        _ => Err(ModelError::Format),
    }
}
fn put_options(w: &mut Writer, o: TreeDownloadOptions) -> Result<(), ModelError> {
    w.u64(o.transfer.limits.max_file_bytes)?;
    w.u128(o.transfer.limits.max_encoded_bytes)?;
    w.u32(o.transfer.anonymity)?;
    w.raw(&o.transfer.target)?;
    w.u8(u8::from(o.transfer.local_only))?;
    w.u32(o.transfer.queries_per_connection)?;
    w.usize(o.transfer.io_slice_bytes)?;
    w.u64(o.directory.max_extent)?;
    w.usize(o.directory.max_entries)?;
    w.u64(o.directory.max_work)?;
    w.usize(o.directory.max_record_bytes)?;
    for n in [
        o.directory.uri.max_input_bytes,
        o.directory.uri.max_keywords,
        o.directory.uri.max_keyword_bytes,
        o.directory.uri.max_identifier_bytes,
        o.directory.metadata.max_coded_bytes,
        o.directory.metadata.max_plain_bytes,
        o.directory.metadata.max_entries,
    ] {
        w.usize(n)?;
    }
    w.usize(o.max_depth)?;
    w.usize(o.max_entries)?;
    w.u128(o.max_total_bytes)?;
    for n in [
        o.max_path_bytes,
        o.max_namespace_bytes,
        o.max_inline_bytes,
        o.max_total_inline_bytes,
        o.namespace.queries,
        o.namespace.results,
        o.namespace.retained_bytes,
        o.namespace.metadata_entries,
        o.namespace.metadata_bytes,
    ] {
        w.usize(n)?;
    }
    Ok(())
}
fn get_options(r: &mut Reader<'_>) -> Result<TreeDownloadOptions, ModelError> {
    let mut o = TreeDownloadOptions::new(DownloadOptions::new(AbsoluteTime::from_micros(0)));
    o.transfer.limits.max_file_bytes = r.u64()?;
    o.transfer.limits.max_encoded_bytes = r.u128()?;
    o.transfer.anonymity = r.u32()?;
    o.transfer.target = r.array()?;
    o.transfer.local_only = r.boolean()?;
    o.transfer.queries_per_connection = r.u32()?;
    o.transfer.io_slice_bytes = r.usize()?;
    o.directory.max_extent = r.u64()?;
    o.directory.max_entries = r.usize()?;
    o.directory.max_work = r.u64()?;
    o.directory.max_record_bytes = r.usize()?;
    o.directory.uri.max_input_bytes = r.usize()?;
    o.directory.uri.max_keywords = r.usize()?;
    o.directory.uri.max_keyword_bytes = r.usize()?;
    o.directory.uri.max_identifier_bytes = r.usize()?;
    o.directory.metadata.max_coded_bytes = r.usize()?;
    o.directory.metadata.max_plain_bytes = r.usize()?;
    o.directory.metadata.max_entries = r.usize()?;
    o.max_depth = r.usize()?;
    o.max_entries = r.usize()?;
    o.max_total_bytes = r.u128()?;
    o.max_path_bytes = r.usize()?;
    o.max_namespace_bytes = r.usize()?;
    o.max_inline_bytes = r.usize()?;
    o.max_total_inline_bytes = r.usize()?;
    o.namespace.queries = r.usize()?;
    o.namespace.results = r.usize()?;
    o.namespace.retained_bytes = r.usize()?;
    o.namespace.metadata_entries = r.usize()?;
    o.namespace.metadata_bytes = r.usize()?;
    Ok(o)
}
fn phase_tag(phase: Phase) -> u8 {
    match phase {
        Phase::Ready => 0,
        Phase::Running => 1,
        Phase::PauseRequested => 2,
        Phase::Paused => 3,
        Phase::Cancelled => 4,
        Phase::Complete => 5,
        Phase::Failed => 6,
        Phase::CancelRequested => 7,
    }
}
fn get_phase(tag: u8) -> Result<Phase, ModelError> {
    Ok(match tag {
        0 => Phase::Ready,
        1 => Phase::Running,
        2 => Phase::PauseRequested,
        3 => Phase::Paused,
        4 => Phase::Cancelled,
        5 => Phase::Complete,
        6 => Phase::Failed,
        7 => Phase::CancelRequested,
        _ => return Err(ModelError::Format),
    })
}
fn stage_tag(stage: CommitStage) -> u8 {
    match stage {
        CommitStage::NotLinked => 0,
        CommitStage::LinkedUnknown => 1,
        CommitStage::Durable => 2,
    }
}
fn get_stage(tag: u8) -> Result<CommitStage, ModelError> {
    Ok(match tag {
        0 => CommitStage::NotLinked,
        1 => CommitStage::LinkedUnknown,
        2 => CommitStage::Durable,
        _ => return Err(ModelError::Format),
    })
}
fn path(bytes: &[u8]) -> Result<PathBuf, ModelError> {
    Ok(PathBuf::from(OsString::from_vec(copy(bytes)?)))
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, ModelError> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| ModelError::Limit)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
struct Writer(Vec<u8>);
impl Writer {
    fn raw(&mut self, bytes: &[u8]) -> Result<(), ModelError> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_EVENT_BYTES)
        {
            return Err(ModelError::Limit);
        }
        self.0
            .try_reserve(bytes.len())
            .map_err(|_| ModelError::Limit)?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn blob(&mut self, bytes: &[u8], cap: usize) -> Result<(), ModelError> {
        if bytes.len() > cap {
            return Err(ModelError::Limit);
        }
        self.u32(u32::try_from(bytes.len()).map_err(|_| ModelError::Limit)?)?;
        self.raw(bytes)
    }
    fn u8(&mut self, n: u8) -> Result<(), ModelError> {
        self.raw(&[n])
    }
    fn u16(&mut self, n: u16) -> Result<(), ModelError> {
        self.raw(&n.to_be_bytes())
    }
    fn u32(&mut self, n: u32) -> Result<(), ModelError> {
        self.raw(&n.to_be_bytes())
    }
    fn u64(&mut self, n: u64) -> Result<(), ModelError> {
        self.raw(&n.to_be_bytes())
    }
    fn u128(&mut self, n: u128) -> Result<(), ModelError> {
        self.raw(&n.to_be_bytes())
    }
    fn usize(&mut self, n: usize) -> Result<(), ModelError> {
        self.u64(u64::try_from(n).map_err(|_| ModelError::Limit)?)
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn raw(&mut self, n: usize) -> Result<&'a [u8], ModelError> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(ModelError::Format)?;
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ModelError> {
        self.raw(N)?.try_into().map_err(|_| ModelError::Format)
    }
    fn u8(&mut self) -> Result<u8, ModelError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, ModelError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, ModelError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, ModelError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn u128(&mut self) -> Result<u128, ModelError> {
        Ok(u128::from_be_bytes(self.array()?))
    }
    fn usize(&mut self) -> Result<usize, ModelError> {
        usize::try_from(self.u64()?).map_err(|_| ModelError::Limit)
    }
    fn boolean(&mut self) -> Result<bool, ModelError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ModelError::Format),
        }
    }
    fn blob(&mut self, cap: usize) -> Result<&'a [u8], ModelError> {
        let n = usize::try_from(self.u32()?).map_err(|_| ModelError::Limit)?;
        if n > cap {
            return Err(ModelError::Limit);
        }
        self.raw(n)
    }
}
