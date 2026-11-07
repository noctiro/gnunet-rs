//! Strict private publication records. Actual replies borrow the original Store.
use super::{
    graph_state,
    model::{Attempt, Counts, Event, Manifest, ModelError, NoEffect, Phase},
    plan::{self, Artifact, Payload, Plan, Position, Put},
    registration,
};
use crate::network::BlockOptions;
use gnunet_datastore_host::{Interruption, Outcome};
use gnunet_fs::{Content, metadata, ublock};
use gnunet_wire::official::AbsoluteTime;
/// Hard private body cap, independent of the caller's stricter physical Store.
pub const MAX_EVENT_BYTES: usize = 64 * 1024 * 1024;
/// One actual complete native response/diagnostic frame.
pub const MAX_RESPONSE_BYTES: usize = u16::MAX as usize;
pub(super) const VERSION: u16 = 3;
const MANIFEST: u16 = 1;
const INTENT: u16 = 2;
const ACCEPTED: u16 = 3;
const NOT_APPLIED: u16 = 4;
const REFUSED: u16 = 5;
const UNKNOWN: u16 = 6;
const RETRY_REFUSED: u16 = 7;
const PHASE: u16 = 8;
const MAGIC: &[u8; 8] = b"GFSPU003";
const GRAPH_RECORDED: u16 = 0x200;

/// Encode a fully checked private event with no runtime deadline/native tokens.
pub fn encode_event(event: &Event<'_>) -> Result<(u16, Vec<u8>), ModelError> {
    if let Event::Index(event) = event {
        return registration::encode_event(event);
    }
    let mut w = Writer(Vec::new());
    w.u16(VERSION)?;
    let kind = match event {
        Event::Index(_) => return Err(ModelError::Format),
        Event::Manifest(manifest) => {
            manifest.validate()?;
            w.raw(MAGIC)?;
            put_limits(&mut w, manifest.limits)?;
            put_blocks(&mut w, manifest.blocks)?;
            graph_state::put_target(&mut w, manifest.graph)?;
            w.nested(manifest.limits.max_plan_bytes, |w| {
                put_plan(w, &manifest.plan, manifest.limits)
            })?;
            MANIFEST
        }
        Event::GraphRecorded(fact) => {
            graph_state::put_recorded(&mut w, *fact)?;
            GRAPH_RECORDED
        }
        Event::Intent {
            index,
            request_hash,
        } => {
            w.usize(*index)?;
            w.raw(request_hash)?;
            INTENT
        }
        Event::Accepted {
            attempt,
            response,
            interruption,
        } => {
            put_attempt(&mut w, *attempt)?;
            put_interruption(&mut w, *interruption)?;
            w.blob(response, MAX_RESPONSE_BYTES)?;
            ACCEPTED
        }
        Event::NotApplied {
            attempt,
            reason,
            interruption,
        } => {
            put_attempt(&mut w, *attempt)?;
            w.u8(no_effect_tag(*reason))?;
            put_interruption(&mut w, *interruption)?;
            NOT_APPLIED
        }
        Event::Refused {
            attempt,
            response,
            interruption,
        } => {
            put_attempt(&mut w, *attempt)?;
            put_interruption(&mut w, *interruption)?;
            w.blob(response, MAX_RESPONSE_BYTES)?;
            REFUSED
        }
        Event::Unknown {
            attempt,
            outcome,
            response,
            interruption,
        } => {
            put_attempt(&mut w, *attempt)?;
            put_outcome(&mut w, *outcome)?;
            put_interruption(&mut w, *interruption)?;
            w.optional_blob(*response, MAX_RESPONSE_BYTES)?;
            UNKNOWN
        }
        Event::RetryRefused { attempt } => {
            put_attempt(&mut w, *attempt)?;
            RETRY_REFUSED
        }
        Event::Phase { phase, counts } => {
            w.u8(phase_tag(*phase))?;
            w.usize(counts.accepted)?;
            w.u128(counts.bytes)?;
            PHASE
        }
    };
    Ok((kind, w.0))
}
/// Decode a complete bounded original event. Payload authenticity and native
/// receipt correlation are not manufactured by this structural projection.
pub fn decode_event(kind: u16, bytes: &[u8]) -> Result<Event<'_>, ModelError> {
    if registration::is_kind(kind) {
        return registration::decode_event(kind, bytes).map(Event::Index);
    }
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(ModelError::Limit);
    }
    let mut r = Reader(bytes);
    if r.u16()? != VERSION {
        return Err(ModelError::Version);
    }
    let event = match kind {
        MANIFEST => {
            if r.raw(MAGIC.len())? != MAGIC {
                return Err(ModelError::Format);
            }
            let limits = get_limits(&mut r)?;
            let blocks = get_blocks(&mut r)?;
            let graph = graph_state::get_target(&mut r)?;
            let mut plan_reader = Reader(r.blob(limits.max_plan_bytes)?);
            let plan = get_plan(&mut plan_reader, limits)?;
            if !plan_reader.0.is_empty() {
                return Err(ModelError::Format);
            }
            let manifest = Manifest {
                plan,
                blocks,
                limits,
                graph,
            };
            manifest.validate()?;
            Event::Manifest(Box::new(manifest))
        }
        GRAPH_RECORDED => Event::GraphRecorded(graph_state::get_recorded(&mut r)?),
        INTENT => Event::Intent {
            index: r.usize()?,
            request_hash: r.array()?,
        },
        ACCEPTED => {
            let attempt = get_attempt(&mut r)?;
            let interruption = get_interruption(&mut r)?;
            Event::Accepted {
                attempt,
                response: r.blob(MAX_RESPONSE_BYTES)?,
                interruption,
            }
        }
        NOT_APPLIED => {
            let attempt = get_attempt(&mut r)?;
            let reason = get_no_effect(r.u8()?)?;
            let interruption = get_interruption(&mut r)?;
            Event::NotApplied {
                attempt,
                reason,
                interruption,
            }
        }
        REFUSED => {
            let attempt = get_attempt(&mut r)?;
            let interruption = get_interruption(&mut r)?;
            Event::Refused {
                attempt,
                response: r.blob(MAX_RESPONSE_BYTES)?,
                interruption,
            }
        }
        UNKNOWN => {
            let attempt = get_attempt(&mut r)?;
            let outcome = get_outcome(&mut r)?;
            let interruption = get_interruption(&mut r)?;
            Event::Unknown {
                attempt,
                outcome,
                response: r.optional_blob(MAX_RESPONSE_BYTES)?,
                interruption,
            }
        }
        RETRY_REFUSED => Event::RetryRefused {
            attempt: get_attempt(&mut r)?,
        },
        PHASE => Event::Phase {
            phase: get_phase(r.u8()?)?,
            counts: Counts {
                accepted: r.usize()?,
                bytes: r.u128()?,
            },
        },
        _ => return Err(ModelError::Version),
    };
    if !r.0.is_empty() {
        return Err(ModelError::Format);
    }
    Ok(event)
}
/// Borrow only the actual accepted receipt fields from its original WAL record.
/// This does not correlate a new native operation or grant any replay right.
pub fn accepted_view(
    kind: u16,
    bytes: &[u8],
) -> Result<(Attempt, &[u8], Option<Interruption>), ModelError> {
    match decode_event(kind, bytes)? {
        Event::Accepted {
            attempt,
            response,
            interruption,
        } => Ok((attempt, response, interruption)),
        _ => Err(ModelError::Format),
    }
}
fn put_plan(w: &mut Writer, plan: &Plan, limits: plan::Limits) -> Result<(), ModelError> {
    match &plan.artifact {
        Artifact::File(content) => {
            w.u8(0)?;
            w.raw(&content.key)?;
            w.raw(&content.query)?;
            w.u64(content.size)?;
        }
        Artifact::Keywords {
            query_uri,
            target_uri,
            metadata,
        } => {
            w.u8(1)?;
            w.blob(query_uri, limits.ublock.uri.max_input_bytes)?;
            w.blob(target_uri, limits.ublock.uri.max_input_bytes)?;
            w.optional_blob(metadata.as_deref(), limits.ublock.metadata.max_coded_bytes)?;
        }
        Artifact::Namespace {
            public,
            identifier,
            update,
            target_uri,
            metadata,
        } => {
            w.u8(2)?;
            w.raw(public)?;
            w.blob(identifier, limits.ublock.max_label_bytes)?;
            w.blob(update, ublock::PUBLISHER_BYTES)?;
            w.blob(target_uri, limits.ublock.uri.max_input_bytes)?;
            w.optional_blob(metadata.as_deref(), limits.ublock.metadata.max_coded_bytes)?;
        }
        Artifact::IndexedFile { content, source } => {
            w.u8(3)?;
            put_content(w, *content)?;
            put_source(w, source, limits)?;
        }
        Artifact::Tree(tree) => {
            w.u8(4)?;
            put_content(w, tree.root)?;
            w.usize(tree.objects.len())?;
            for object in &tree.objects {
                w.blob(&object.path, limits.tree.max_path_bytes)?;
                put_content(w, object.content)?;
                w.u8(u8::from(object.directory))?;
                w.usize(object.first_put)?;
                w.usize(object.put_count)?;
                w.u8(u8::from(object.indexed.is_some()))?;
                if let Some(index) = object.indexed {
                    w.usize(index)?;
                }
            }
            w.usize(tree.sources.len())?;
            for source in &tree.sources {
                put_source(w, source, limits)?;
            }
        }
    }
    w.usize(plan.puts.len())?;
    for put in &plan.puts {
        w.u32(put.kind)?;
        w.raw(&put.key)?;
        w.raw(&put.payload.hash)?;
        w.usize(put.payload.bytes)?;
        w.u8(u8::from(put.position.is_some()))?;
        if let Some(position) = put.position {
            w.u8(position.level)?;
            w.u64(position.index)?;
        }
    }
    Ok(())
}
fn get_plan(r: &mut Reader<'_>, limits: plan::Limits) -> Result<Plan, ModelError> {
    let artifact = match r.u8()? {
        0 => Artifact::File(Content {
            key: r.array()?,
            query: r.array()?,
            size: r.u64()?,
        }),
        1 => Artifact::Keywords {
            query_uri: copy(r.blob(limits.ublock.uri.max_input_bytes)?)?,
            target_uri: copy(r.blob(limits.ublock.uri.max_input_bytes)?)?,
            metadata: r
                .optional_blob(limits.ublock.metadata.max_coded_bytes)?
                .map(copy)
                .transpose()?,
        },
        2 => Artifact::Namespace {
            public: r.array()?,
            identifier: copy(r.blob(limits.ublock.max_label_bytes)?)?,
            update: copy(r.blob(ublock::PUBLISHER_BYTES)?)?,
            target_uri: copy(r.blob(limits.ublock.uri.max_input_bytes)?)?,
            metadata: r
                .optional_blob(limits.ublock.metadata.max_coded_bytes)?
                .map(copy)
                .transpose()?,
        },
        3 => Artifact::IndexedFile {
            content: get_content(r)?,
            source: get_source(r, limits)?,
        },
        4 => {
            let root = get_content(r)?;
            let count = r.usize()?;
            if count == 0
                || count > limits.max_puts
                || u64::try_from(count)
                    .ok()
                    .is_none_or(|n| n > limits.tree.max_entries.saturating_add(1))
                || count > r.0.len() / 158
                || count
                    .checked_mul(std::mem::size_of::<plan::tree::TreeObject>())
                    .is_none_or(|n| n > limits.max_plan_bytes)
            {
                return Err(ModelError::Limit);
            }
            let mut objects = Vec::new();
            objects
                .try_reserve_exact(count)
                .map_err(|_| ModelError::Limit)?;
            for _ in 0..count {
                let path = copy(r.blob(limits.tree.max_path_bytes)?)?;
                let content = get_content(r)?;
                let directory = r.boolean()?;
                let first_put = r.usize()?;
                let put_count = r.usize()?;
                if first_put
                    .checked_add(put_count)
                    .is_none_or(|n| n > limits.max_puts)
                {
                    return Err(ModelError::Limit);
                }
                let indexed = if r.boolean()? { Some(r.usize()?) } else { None };
                objects.push(plan::tree::TreeObject {
                    path,
                    content,
                    directory,
                    first_put,
                    put_count,
                    indexed,
                });
            }
            let count = r.usize()?;
            if count > limits.max_puts
                || count > r.0.len() / 124
                || count
                    .checked_mul(std::mem::size_of::<plan::indexed::Source>())
                    .is_none_or(|n| n > limits.max_plan_bytes)
            {
                return Err(ModelError::Limit);
            }
            let mut sources = Vec::new();
            sources
                .try_reserve_exact(count)
                .map_err(|_| ModelError::Limit)?;
            for _ in 0..count {
                sources.push(get_source(r, limits)?);
            }
            Artifact::Tree(plan::tree::TreePlan {
                root,
                objects,
                sources,
            })
        }
        _ => return Err(ModelError::Format),
    };
    let count = r.usize()?;
    if count == 0
        || count > limits.max_puts
        || count > r.0.len() / 141
        || count
            .checked_mul(std::mem::size_of::<Put>())
            .is_none_or(|n| n > limits.max_plan_bytes)
    {
        return Err(ModelError::Limit);
    }
    let mut puts = Vec::new();
    puts.try_reserve_exact(count)
        .map_err(|_| ModelError::Limit)?;
    for _ in 0..count {
        let kind = r.u32()?;
        let key = r.array()?;
        let payload = Payload {
            hash: r.array()?,
            bytes: r.usize()?,
        };
        let position = if r.boolean()? {
            Some(Position {
                level: r.u8()?,
                index: r.u64()?,
            })
        } else {
            None
        };
        puts.push(Put {
            kind,
            key,
            payload,
            position,
        });
    }
    Ok(Plan { artifact, puts })
}
fn put_limits(w: &mut Writer, limits: plan::Limits) -> Result<(), ModelError> {
    for n in [
        limits.max_puts,
        limits.max_plan_bytes,
        limits.max_payload_bytes,
    ] {
        w.usize(n)?;
    }
    w.u128(limits.max_stored_bytes)?;
    w.u64(limits.file.max_file_bytes)?;
    w.u128(limits.file.max_encoded_bytes)?;
    w.usize(limits.ublock.max_wire_bytes)?;
    w.usize(limits.ublock.max_label_bytes)?;
    for n in [
        limits.ublock.uri.max_input_bytes,
        limits.ublock.uri.max_keywords,
        limits.ublock.uri.max_keyword_bytes,
        limits.ublock.uri.max_identifier_bytes,
        limits.ublock.metadata.max_coded_bytes,
        limits.ublock.metadata.max_plain_bytes,
        limits.ublock.metadata.max_entries,
    ] {
        w.usize(n)?;
    }
    put_tree_limits(w, limits.tree)?;
    Ok(())
}
fn get_limits(r: &mut Reader<'_>) -> Result<plan::Limits, ModelError> {
    let max_puts = r.usize()?;
    let max_plan_bytes = r.usize()?;
    let max_payload_bytes = r.usize()?;
    let max_stored_bytes = r.u128()?;
    if max_plan_bytes > MAX_EVENT_BYTES {
        return Err(ModelError::Limit);
    }
    Ok(plan::Limits {
        max_puts,
        max_plan_bytes,
        max_payload_bytes,
        max_stored_bytes,
        file: crate::Limits {
            max_file_bytes: r.u64()?,
            max_encoded_bytes: r.u128()?,
        },
        ublock: ublock::Limits {
            max_wire_bytes: r.usize()?,
            max_label_bytes: r.usize()?,
            uri: gnunet_fs::Limits {
                max_input_bytes: r.usize()?,
                max_keywords: r.usize()?,
                max_keyword_bytes: r.usize()?,
                max_identifier_bytes: r.usize()?,
            },
            metadata: metadata::Limits {
                max_coded_bytes: r.usize()?,
                max_plain_bytes: r.usize()?,
                max_entries: r.usize()?,
            },
        },
        tree: get_tree_limits(r)?,
    })
}
fn put_content(w: &mut Writer, content: Content) -> Result<(), ModelError> {
    w.raw(&content.key)?;
    w.raw(&content.query)?;
    w.u64(content.size)
}
fn get_content(r: &mut Reader<'_>) -> Result<Content, ModelError> {
    Ok(Content {
        key: r.array()?,
        query: r.array()?,
        size: r.u64()?,
    })
}
fn put_source(
    w: &mut Writer,
    source: &plan::indexed::Source,
    limits: plan::Limits,
) -> Result<(), ModelError> {
    w.blob(&source.path, 4096.min(limits.max_plan_bytes))?;
    w.raw(&source.file_id)?;
    let stamp = source.stamp;
    w.u64(stamp.device)?;
    w.u64(stamp.inode)?;
    w.u64(stamp.bytes)?;
    for n in [
        stamp.modified,
        stamp.modified_nanos,
        stamp.changed,
        stamp.changed_nanos,
    ] {
        w.raw(&n.to_be_bytes())?;
    }
    Ok(())
}
fn get_source(
    r: &mut Reader<'_>,
    limits: plan::Limits,
) -> Result<plan::indexed::Source, ModelError> {
    let path = copy(r.blob(4096.min(limits.max_plan_bytes))?)?;
    let file_id = r.array()?;
    let stamp = plan::indexed::SourceStamp {
        device: r.u64()?,
        inode: r.u64()?,
        bytes: r.u64()?,
        modified: i64::from_be_bytes(r.array()?),
        modified_nanos: i64::from_be_bytes(r.array()?),
        changed: i64::from_be_bytes(r.array()?),
        changed_nanos: i64::from_be_bytes(r.array()?),
    };
    Ok(plan::indexed::Source {
        path,
        file_id,
        stamp,
    })
}
fn put_tree_limits(
    w: &mut Writer,
    l: crate::network::tree_publish::TreeLimits,
) -> Result<(), ModelError> {
    w.usize(l.max_depth)?;
    w.u64(l.max_entries)?;
    for n in [
        l.max_children,
        l.max_name_bytes,
        l.max_path_bytes,
        l.max_retained_name_bytes,
        l.max_metadata_bytes,
        l.max_record_bytes,
        l.max_retained_metadata_bytes,
        l.max_retained_record_bytes,
    ] {
        w.usize(n)?;
    }
    for n in [
        l.max_total_metadata_bytes,
        l.max_total_record_bytes,
        l.max_file_bytes,
        l.max_directory_bytes,
        l.max_directory_extent,
    ] {
        w.u64(n)?;
    }
    w.u128(l.max_encoded_bytes)?;
    w.u128(l.max_stored_bytes)
}
fn get_tree_limits(
    r: &mut Reader<'_>,
) -> Result<crate::network::tree_publish::TreeLimits, ModelError> {
    Ok(crate::network::tree_publish::TreeLimits {
        max_depth: r.usize()?,
        max_entries: r.u64()?,
        max_children: r.usize()?,
        max_name_bytes: r.usize()?,
        max_path_bytes: r.usize()?,
        max_retained_name_bytes: r.usize()?,
        max_metadata_bytes: r.usize()?,
        max_record_bytes: r.usize()?,
        max_retained_metadata_bytes: r.usize()?,
        max_retained_record_bytes: r.usize()?,
        max_total_metadata_bytes: r.u64()?,
        max_total_record_bytes: r.u64()?,
        max_file_bytes: r.u64()?,
        max_directory_bytes: r.u64()?,
        max_directory_extent: r.u64()?,
        max_encoded_bytes: r.u128()?,
        max_stored_bytes: r.u128()?,
    })
}
fn put_blocks(w: &mut Writer, blocks: BlockOptions) -> Result<(), ModelError> {
    w.u64(blocks.expiration.as_micros())?;
    w.u32(blocks.priority)?;
    w.u32(blocks.anonymity)?;
    w.u32(blocks.replication)
}
fn get_blocks(r: &mut Reader<'_>) -> Result<BlockOptions, ModelError> {
    Ok(BlockOptions {
        expiration: AbsoluteTime::from_micros(r.u64()?),
        priority: r.u32()?,
        anonymity: r.u32()?,
        replication: r.u32()?,
    })
}
pub(super) fn put_attempt(w: &mut Writer, attempt: Attempt) -> Result<(), ModelError> {
    w.usize(attempt.index)?;
    w.raw(&attempt.request_hash)?;
    w.usize(attempt.intent_record)
}
pub(super) fn get_attempt(r: &mut Reader<'_>) -> Result<Attempt, ModelError> {
    Ok(Attempt {
        index: r.usize()?,
        request_hash: r.array()?,
        intent_record: r.usize()?,
    })
}
pub(super) fn put_interruption(
    w: &mut Writer,
    interruption: Option<Interruption>,
) -> Result<(), ModelError> {
    w.u8(match interruption {
        None => 0,
        Some(Interruption::Cancelled) => 1,
        Some(Interruption::TimedOut) => 2,
    })
}
pub(super) fn get_interruption(r: &mut Reader<'_>) -> Result<Option<Interruption>, ModelError> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(Interruption::Cancelled)),
        2 => Ok(Some(Interruption::TimedOut)),
        _ => Err(ModelError::Format),
    }
}
fn put_outcome(w: &mut Writer, outcome: Outcome) -> Result<(), ModelError> {
    match outcome {
        Outcome::Status {
            code,
            min_expiration,
        } => {
            w.u8(0)?;
            w.raw(&code.to_be_bytes())?;
            w.u64(min_expiration.as_micros())?;
        }
        Outcome::Data { uid } => {
            w.u8(1)?;
            w.u64(uid)?;
        }
        Outcome::NotFound => w.u8(2)?,
        Outcome::Cancelled => w.u8(3)?,
        Outcome::TimedOut => w.u8(4)?,
        Outcome::NotSent => w.u8(5)?,
        Outcome::Interrupted => w.u8(6)?,
        Outcome::Unknown => w.u8(7)?,
        Outcome::ReservationLost => w.u8(8)?,
        Outcome::DropUnconfirmed => w.u8(9)?,
    }
    Ok(())
}
fn get_outcome(r: &mut Reader<'_>) -> Result<Outcome, ModelError> {
    match r.u8()? {
        0 => Ok(Outcome::Status {
            code: i32::from_be_bytes(r.array()?),
            min_expiration: AbsoluteTime::from_micros(r.u64()?),
        }),
        1 => Ok(Outcome::Data { uid: r.u64()? }),
        2 => Ok(Outcome::NotFound),
        3 => Ok(Outcome::Cancelled),
        4 => Ok(Outcome::TimedOut),
        5 => Ok(Outcome::NotSent),
        6 => Ok(Outcome::Interrupted),
        7 => Ok(Outcome::Unknown),
        8 => Ok(Outcome::ReservationLost),
        9 => Ok(Outcome::DropUnconfirmed),
        _ => Err(ModelError::Format),
    }
}
pub(super) fn no_effect_tag(reason: NoEffect) -> u8 {
    match reason {
        NoEffect::NotSubmitted => 0,
        NoEffect::NotSent => 1,
        NoEffect::CancelledBeforeSend => 2,
        NoEffect::TimedOutBeforeSend => 3,
        NoEffect::UnexposedRegistration => 4,
    }
}
pub(super) fn get_no_effect(tag: u8) -> Result<NoEffect, ModelError> {
    match tag {
        0 => Ok(NoEffect::NotSubmitted),
        1 => Ok(NoEffect::NotSent),
        2 => Ok(NoEffect::CancelledBeforeSend),
        3 => Ok(NoEffect::TimedOutBeforeSend),
        4 => Ok(NoEffect::UnexposedRegistration),
        _ => Err(ModelError::Format),
    }
}
fn phase_tag(phase: Phase) -> u8 {
    match phase {
        Phase::Ready => 0,
        Phase::Running => 1,
        Phase::PauseRequested => 2,
        Phase::Paused => 3,
        Phase::CancelRequested => 4,
        Phase::Cancelled => 5,
        Phase::Complete => 6,
        Phase::Failed => 7,
        Phase::Uncertain => 8,
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
        6 => Ok(Phase::Complete),
        7 => Ok(Phase::Failed),
        8 => Ok(Phase::Uncertain),
        _ => Err(ModelError::Format),
    }
}
fn copy(input: &[u8]) -> Result<Vec<u8>, ModelError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| ModelError::Limit)?;
    output.extend_from_slice(input);
    Ok(output)
}
pub(super) struct Writer(pub(super) Vec<u8>);
impl Writer {
    pub(super) fn raw(&mut self, bytes: &[u8]) -> Result<(), ModelError> {
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
    pub(super) fn blob(&mut self, bytes: &[u8], cap: usize) -> Result<(), ModelError> {
        if bytes.len() > cap {
            return Err(ModelError::Limit);
        }
        self.u32(u32::try_from(bytes.len()).map_err(|_| ModelError::Limit)?)?;
        self.raw(bytes)
    }
    pub(super) fn optional_blob(
        &mut self,
        bytes: Option<&[u8]>,
        cap: usize,
    ) -> Result<(), ModelError> {
        self.u8(u8::from(bytes.is_some()))?;
        if let Some(bytes) = bytes {
            self.blob(bytes, cap)?;
        }
        Ok(())
    }
    pub(super) fn nested(
        &mut self,
        cap: usize,
        write: impl FnOnce(&mut Self) -> Result<(), ModelError>,
    ) -> Result<(), ModelError> {
        let prefix = self.0.len();
        self.u32(0)?;
        let start = self.0.len();
        write(self)?;
        let length = self.0.len() - start;
        if length > cap {
            return Err(ModelError::Limit);
        }
        let value = u32::try_from(length).map_err(|_| ModelError::Limit)?;
        self.0[prefix..start].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }
    pub(super) fn u8(&mut self, n: u8) -> Result<(), ModelError> {
        self.raw(&[n])
    }
    pub(super) fn u16(&mut self, n: u16) -> Result<(), ModelError> {
        self.raw(&n.to_be_bytes())
    }
    pub(super) fn u32(&mut self, n: u32) -> Result<(), ModelError> {
        self.raw(&n.to_be_bytes())
    }
    pub(super) fn u64(&mut self, n: u64) -> Result<(), ModelError> {
        self.raw(&n.to_be_bytes())
    }
    pub(super) fn u128(&mut self, n: u128) -> Result<(), ModelError> {
        self.raw(&n.to_be_bytes())
    }
    pub(super) fn usize(&mut self, n: usize) -> Result<(), ModelError> {
        self.u64(u64::try_from(n).map_err(|_| ModelError::Limit)?)
    }
}
pub(super) struct Reader<'a>(pub(super) &'a [u8]);
impl<'a> Reader<'a> {
    pub(super) fn raw(&mut self, n: usize) -> Result<&'a [u8], ModelError> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(ModelError::Format)?;
        self.0 = tail;
        Ok(head)
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], ModelError> {
        self.raw(N)?.try_into().map_err(|_| ModelError::Format)
    }
    pub(super) fn u8(&mut self) -> Result<u8, ModelError> {
        Ok(self.array::<1>()?[0])
    }
    pub(super) fn u16(&mut self) -> Result<u16, ModelError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(super) fn u32(&mut self) -> Result<u32, ModelError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(super) fn u64(&mut self) -> Result<u64, ModelError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(super) fn u128(&mut self) -> Result<u128, ModelError> {
        Ok(u128::from_be_bytes(self.array()?))
    }
    pub(super) fn usize(&mut self) -> Result<usize, ModelError> {
        usize::try_from(self.u64()?).map_err(|_| ModelError::Limit)
    }
    pub(super) fn boolean(&mut self) -> Result<bool, ModelError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ModelError::Format),
        }
    }
    pub(super) fn blob(&mut self, cap: usize) -> Result<&'a [u8], ModelError> {
        let length = usize::try_from(self.u32()?).map_err(|_| ModelError::Limit)?;
        if length > cap {
            return Err(ModelError::Limit);
        }
        self.raw(length)
    }
    pub(super) fn optional_blob(&mut self, cap: usize) -> Result<Option<&'a [u8]>, ModelError> {
        if self.boolean()? {
            self.blob(cap).map(Some)
        } else {
            Ok(None)
        }
    }
}
