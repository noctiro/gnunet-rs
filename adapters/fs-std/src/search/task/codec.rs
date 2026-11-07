//! Strict private v1 search records; large observations borrow the original WAL.
use super::model::{Counts, Event, Manifest, ModelError, Observation, Phase};
use crate::{ipc, search};
use gnunet_fs::{metadata, ublock};
use gnunet_types::AbsoluteTime;

/// Independent hard local record-body cap, separate from Store policy.
pub const MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;
/// Hard original URI byte cap, before applying caller URI limits.
pub const MAX_URI_BYTES: usize = 16_384;
const VERSION: u16 = 1;
const MANIFEST: u16 = 1;
const OBSERVATION: u16 = 2;
const PHASE: u16 = 3;
const MAGIC: &[u8; 8] = b"GFSSQ001";
/// Encode complete checked private bytes. The runtime deadline is omitted.
pub fn encode_event(event: &Event<'_>) -> Result<(u16, Vec<u8>), ModelError> {
    let mut writer = Writer(Vec::new());
    writer.u16(VERSION)?;
    let kind = match event {
        Event::Manifest(manifest) => {
            manifest.validate()?;
            writer.raw(MAGIC)?;
            put_options(&mut writer, manifest.options)?;
            writer.usize(manifest.max_observations)?;
            writer.blob(&manifest.query_uri, MAX_URI_BYTES)?;
            MANIFEST
        }
        Event::Observation(observation) => {
            writer.usize(observation.query_id)?;
            writer.u8(match observation.kind {
                ublock::Kind::Keyword => 0,
                ublock::Kind::Namespace => 1,
            })?;
            writer.raw(observation.namespace)?;
            writer.raw(observation.lookup_key)?;
            writer.u64(observation.expiration.as_micros())?;
            writer.u64(observation.observed_at.as_micros())?;
            writer.blob(observation.label, MAX_EVENT_BYTES)?;
            writer.blob(observation.wire, MAX_EVENT_BYTES)?;
            OBSERVATION
        }
        Event::Phase { phase, counts } => {
            writer.u8(phase_tag(*phase))?;
            for value in [
                counts.observations,
                counts.results,
                counts.visible,
                counts.queries,
            ] {
                writer.usize(value)?;
            }
            PHASE
        }
    };
    Ok((kind, writer.0))
}
/// Decode one exact bounded record. Observations borrow raw encrypted bodies.
pub fn decode_event(kind: u16, bytes: &[u8]) -> Result<Event<'_>, ModelError> {
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(ModelError::Limit);
    }
    let mut reader = Reader(bytes);
    if reader.u16()? != VERSION {
        return Err(ModelError::Version);
    }
    let event = match kind {
        MANIFEST => {
            if reader.raw(MAGIC.len())? != MAGIC {
                return Err(ModelError::Format);
            }
            let options = get_options(&mut reader)?;
            let max_observations = reader.usize()?;
            let query_uri = copy(reader.blob(MAX_URI_BYTES)?)?;
            let manifest = Manifest {
                query_uri,
                options,
                max_observations,
            };
            manifest.validate()?;
            Event::Manifest(manifest)
        }
        OBSERVATION => {
            let query_id = reader.usize()?;
            let kind = match reader.u8()? {
                0 => ublock::Kind::Keyword,
                1 => ublock::Kind::Namespace,
                _ => return Err(ModelError::Format),
            };
            let namespace = reader.array_ref()?;
            let lookup_key = reader.array_ref()?;
            let expiration = AbsoluteTime::from_micros(reader.u64()?);
            let observed_at = AbsoluteTime::from_micros(reader.u64()?);
            let label = reader.blob(MAX_EVENT_BYTES)?;
            let wire = reader.blob(MAX_EVENT_BYTES)?;
            Event::Observation(Observation {
                query_id,
                kind,
                namespace,
                label,
                lookup_key,
                wire,
                expiration,
                observed_at,
            })
        }
        PHASE => {
            let phase = get_phase(reader.u8()?)?;
            let counts = Counts {
                observations: reader.usize()?,
                results: reader.usize()?,
                visible: reader.usize()?,
                queries: reader.usize()?,
            };
            Event::Phase { phase, counts }
        }
        _ => return Err(ModelError::Version),
    };
    if !reader.0.is_empty() {
        return Err(ModelError::Format);
    }
    Ok(event)
}
/// Borrow one original observation record. This does not authenticate its bytes.
pub fn observation_view(kind: u16, bytes: &[u8]) -> Result<Observation<'_>, ModelError> {
    match decode_event(kind, bytes)? {
        Event::Observation(observation) => Ok(observation),
        _ => Err(ModelError::Format),
    }
}
fn put_options(writer: &mut Writer, options: search::Options) -> Result<(), ModelError> {
    writer.u32(options.anonymity)?;
    writer.u8(u8::from(options.local_only))?;
    for value in [
        options.limits.queries,
        options.limits.results,
        options.limits.retained_bytes,
        options.limits.metadata_entries,
        options.limits.metadata_bytes,
        options.block.max_wire_bytes,
        options.block.max_label_bytes,
        options.block.uri.max_input_bytes,
        options.block.uri.max_keywords,
        options.block.uri.max_keyword_bytes,
        options.block.uri.max_identifier_bytes,
        options.block.metadata.max_coded_bytes,
        options.block.metadata.max_plain_bytes,
        options.block.metadata.max_entries,
        options.protocol.max_block_bytes,
    ] {
        writer.usize(value)?;
    }
    writer.u8(u8::from(options.protocol.expected_loc_peer.is_some()))?;
    if let Some(peer) = options.protocol.expected_loc_peer {
        writer.raw(&peer)?;
    }
    writer.u8(match options.protocol.seen_replay {
        ipc::SeenReplay::RecentWindow => 0,
        ipc::SeenReplay::Continued => 1,
    })?;
    writer.usize(options.native.frame_bytes)?;
    writer.usize(options.native.io_slice_bytes)
}
fn get_options(reader: &mut Reader<'_>) -> Result<search::Options, ModelError> {
    let anonymity = reader.u32()?;
    let local_only = reader.boolean()?;
    let limits = search::Limits {
        queries: reader.usize()?,
        results: reader.usize()?,
        retained_bytes: reader.usize()?,
        metadata_entries: reader.usize()?,
        metadata_bytes: reader.usize()?,
    };
    let max_wire_bytes = reader.usize()?;
    let max_label_bytes = reader.usize()?;
    let uri = gnunet_fs::Limits {
        max_input_bytes: reader.usize()?,
        max_keywords: reader.usize()?,
        max_keyword_bytes: reader.usize()?,
        max_identifier_bytes: reader.usize()?,
    };
    let metadata = metadata::Limits {
        max_coded_bytes: reader.usize()?,
        max_plain_bytes: reader.usize()?,
        max_entries: reader.usize()?,
    };
    let max_block_bytes = reader.usize()?;
    let expected_loc_peer = if reader.boolean()? {
        Some(reader.array()?)
    } else {
        None
    };
    let seen_replay = match reader.u8()? {
        0 => ipc::SeenReplay::RecentWindow,
        1 => ipc::SeenReplay::Continued,
        _ => return Err(ModelError::Format),
    };
    let protocol = ipc::ProtocolLimits {
        max_block_bytes,
        expected_loc_peer,
        seen_replay,
    };
    let native = ipc::Limits {
        frame_bytes: reader.usize()?,
        io_slice_bytes: reader.usize()?,
    };
    Ok(search::Options {
        anonymity,
        local_only,
        deadline: AbsoluteTime::from_micros(0),
        limits,
        block: ublock::Limits {
            max_wire_bytes,
            max_label_bytes,
            uri,
            metadata,
        },
        protocol,
        native,
    })
}
fn phase_tag(phase: Phase) -> u8 {
    match phase {
        Phase::Ready => 0,
        Phase::Running => 1,
        Phase::PauseRequested => 2,
        Phase::Paused => 3,
        Phase::CancelRequested => 4,
        Phase::Cancelled => 5,
        Phase::Failed => 6,
    }
}
fn get_phase(tag: u8) -> Result<Phase, ModelError> {
    match tag {
        0 => Ok(Phase::Ready),
        1 => Ok(Phase::Running),
        2 => Ok(Phase::PauseRequested),
        3 => Ok(Phase::Paused),
        4 => Ok(Phase::CancelRequested),
        5 => Ok(Phase::Cancelled),
        6 => Ok(Phase::Failed),
        _ => Err(ModelError::Format),
    }
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, ModelError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| ModelError::Limit)?;
    output.extend_from_slice(bytes);
    Ok(output)
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
    fn u8(&mut self, value: u8) -> Result<(), ModelError> {
        self.raw(&[value])
    }
    fn u16(&mut self, value: u16) -> Result<(), ModelError> {
        self.raw(&value.to_be_bytes())
    }
    fn u32(&mut self, value: u32) -> Result<(), ModelError> {
        self.raw(&value.to_be_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<(), ModelError> {
        self.raw(&value.to_be_bytes())
    }
    fn usize(&mut self, value: usize) -> Result<(), ModelError> {
        self.u64(u64::try_from(value).map_err(|_| ModelError::Limit)?)
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn raw(&mut self, n: usize) -> Result<&'a [u8], ModelError> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(ModelError::Format)?;
        self.0 = tail;
        Ok(head)
    }
    fn array_ref<const N: usize>(&mut self) -> Result<&'a [u8; N], ModelError> {
        self.raw(N)?.try_into().map_err(|_| ModelError::Format)
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
