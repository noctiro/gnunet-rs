//! Bounded original signed namespace selections for local task persistence.
//!
//! This is a private local persistence codec, not a GNUnet wire format. Only
//! `verify` authenticates a decoded proof. A verified selection is immutable:
//! later wall-clock expiry does not authorize choosing a different mutable hit.
use super::{Error, Limits, QueryId, ResultId, copy, metadata_scratch, reserve};
use gnunet_fs::{
    Content, Location, Namespace, Uri, metadata as md,
    ublock::{self, Context},
};
use gnunet_fs_codec::Inflate;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};

use std::mem::size_of;

const MAGIC: &[u8; 8] = b"GFSNSP01";
const HEADER_BYTES: usize = 44;
const STEP_BYTES: usize = 24;

pub(super) struct Retained {
    pub(super) query: QueryId,
    pub(super) parent: Option<ResultId>,
    pub(super) wire: Vec<u8>,
    pub(super) observed_at: AbsoluteTime,
    pub(super) expiration: AbsoluteTime,
}
struct ProofStep {
    label: Vec<u8>,
    wire: Vec<u8>,
    observed_at: AbsoluteTime,
    expiration: AbsoluteTime,
}

/// Original root namespace and one acyclic creation lineage of accepted signed
/// records. Fields are private; projected URI/metadata cannot mint this proof.
pub struct NamespaceProof {
    namespace: [u8; 32],
    steps: Vec<ProofStep>,
}
impl std::fmt::Debug for NamespaceProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamespaceProof")
            .field("namespace", &self.namespace)
            .field("steps", &self.steps.len())
            .finish()
    }
}
/// Exact selected CHK/LOC and its original signed proof, independent of native
/// query retirement trouble. Persist the proof before beginning output effects.
#[derive(Debug)]
pub struct NamespaceSelection {
    /// Original signed records, actual labels and historical freshness facts.
    pub proof: NamespaceProof,
    /// Exact authenticated selected content, never replaced by a later lookup.
    pub selected: Content,
    /// Exact original signed placement, present only when the selected URI is LOC.
    pub location: Option<Location>,
    /// Independent physical retirement failure from the original search MQs.
    pub cleanup: Option<Error>,
}

// Reserve the one consuming export's peak fixed workspace before committing
// any result. Raw bodies and existing query labels move without another copy.
pub(super) fn retained_charge(wire: usize) -> Result<usize, Error> {
    wire.checked_add(size_of::<NamespaceProof>())
        .and_then(|n| n.checked_add(size_of::<ProofStep>()))
        .and_then(|n| n.checked_add(size_of::<ResultId>()))
        .ok_or_else(|| ProtocolError::Overflow.into())
}

impl NamespaceProof {
    /// Complete local-codec length. All arithmetic and u32 fields are checked.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        u32::try_from(self.steps.len()).map_err(|_| ProtocolError::TooLarge)?;
        self.steps.iter().try_fold(HEADER_BYTES, |total, step| {
            u32::try_from(step.label.len()).map_err(|_| ProtocolError::TooLarge)?;
            u32::try_from(step.wire.len()).map_err(|_| ProtocolError::TooLarge)?;
            total
                .checked_add(STEP_BYTES)
                .and_then(|n| n.checked_add(step.label.len()))
                .and_then(|n| n.checked_add(step.wire.len()))
                .ok_or_else(|| ProtocolError::Overflow.into())
        })
    }
    /// Encode only after complete size preflight; refusal changes no output.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        let length = self.encoded_len()?;
        if output.len() < length {
            return Err(ProtocolError::Capacity.into());
        }
        output[..8].copy_from_slice(MAGIC);
        output[8..12].copy_from_slice(&(self.steps.len() as u32).to_be_bytes());
        output[12..44].copy_from_slice(&self.namespace);
        let mut cursor = HEADER_BYTES;
        for step in &self.steps {
            output[cursor..cursor + 8].copy_from_slice(&step.observed_at.as_micros().to_be_bytes());
            output[cursor + 8..cursor + 16]
                .copy_from_slice(&step.expiration.as_micros().to_be_bytes());
            output[cursor + 16..cursor + 20]
                .copy_from_slice(&(step.label.len() as u32).to_be_bytes());
            output[cursor + 20..cursor + 24]
                .copy_from_slice(&(step.wire.len() as u32).to_be_bytes());
            cursor += STEP_BYTES;
            output[cursor..cursor + step.label.len()].copy_from_slice(&step.label);
            cursor += step.label.len();
            output[cursor..cursor + step.wire.len()].copy_from_slice(&step.wire);
            cursor += step.wire.len();
        }
        Ok(length)
    }
    /// Decode bounded owned local state. This does not authenticate it; call
    /// `verify` with the original SKS and exact persisted selected CHK/LOC.
    pub fn decode(input: &[u8], limits: Limits, block: ublock::Limits) -> Result<Self, Error> {
        if input.len() > limits.retained_bytes {
            return Err(Error::Limit);
        }
        let mut input = input;
        if take(&mut input, 8)? != MAGIC {
            return Err(ProtocolError::Unsupported.into());
        }
        let count =
            usize::try_from(word(take(&mut input, 4)?)).map_err(|_| ProtocolError::TooLarge)?;
        if count == 0 || count > limits.queries || count > limits.results {
            return Err(Error::Limit);
        }
        let namespace = take(&mut input, 32)?
            .try_into()
            .map_err(|_| ProtocolError::Truncated)?;
        let mut retained = size_of::<Self>()
            .checked_add(
                count
                    .checked_mul(size_of::<ProofStep>())
                    .ok_or(ProtocolError::Overflow)?,
            )
            .ok_or(ProtocolError::Overflow)?;
        if retained > limits.retained_bytes {
            return Err(Error::Limit);
        }
        // Validate the entire encoded shape and all lengths before allocations.
        let original = input;
        for _ in 0..count {
            let header = take(&mut input, STEP_BYTES)?;
            let label =
                usize::try_from(word(&header[16..20])).map_err(|_| ProtocolError::TooLarge)?;
            let wire =
                usize::try_from(word(&header[20..24])).map_err(|_| ProtocolError::TooLarge)?;
            step_limits(label, wire, block)?;
            retained = retained
                .checked_add(label)
                .and_then(|n| n.checked_add(wire))
                .ok_or(ProtocolError::Overflow)?;
            if retained > limits.retained_bytes {
                return Err(Error::Limit);
            }
            take(&mut input, label)?;
            take(&mut input, wire)?;
        }
        if !input.is_empty() {
            return Err(ProtocolError::Malformed.into());
        }
        input = original;
        let mut steps = Vec::new();
        reserve(&mut steps, count)?;
        for _ in 0..count {
            let header = take(&mut input, STEP_BYTES)?;
            let label = word(&header[16..20]) as usize;
            let wire = word(&header[20..24]) as usize;
            steps.push(ProofStep {
                observed_at: AbsoluteTime::from_micros(wide(&header[..8])),
                expiration: AbsoluteTime::from_micros(wide(&header[8..16])),
                label: copy(take(&mut input, label)?)?,
                wire: copy(take(&mut input, wire)?)?,
            });
        }
        Ok(Self { namespace, steps })
    }
    /// Reauthenticate every original signed UBLOCK with the existing Context,
    /// AEAD, strict URI/metadata decoder and Inflate implementation. The first
    /// label/namespace must match the original SKS, each signed update must name
    /// the next label, and the last URI must equal the exact selected CHK/LOC.
    ///
    /// Historical source-clock freshness is checked at each recorded original
    /// acceptance time, using its real outer FS expiration. These outer fields
    /// are local historical facts, not part of the UBLOCK signature. No current
    /// time or network lookup is used, and later expiry cannot change the target.
    pub fn verify(
        &self,
        original: Namespace<'_>,
        selected: Content,
        location: Option<Location>,
        limits: Limits,
        block: ublock::Limits,
    ) -> Result<(), Error> {
        if self.namespace != *original.key().as_bytes()
            || self
                .steps
                .first()
                .is_none_or(|step| step.label != original.identifier())
        {
            return Err(ProtocolError::Authentication.into());
        }
        if self.steps.len() > limits.queries || self.steps.len() > limits.results {
            return Err(Error::Limit);
        }
        let mut retained = size_of::<Self>()
            .checked_add(
                self.steps
                    .len()
                    .checked_mul(size_of::<ProofStep>())
                    .ok_or(ProtocolError::Overflow)?,
            )
            .ok_or(ProtocolError::Overflow)?;
        let mut plain = Vec::new();
        let mut metadata = Vec::new();
        let mut inflater = Inflate::new();
        let mut last_time = None;
        for (index, step) in self.steps.iter().enumerate() {
            step_limits(step.label.len(), step.wire.len(), block)?;
            retained = retained
                .checked_add(step.label.len())
                .and_then(|n| n.checked_add(step.wire.len()))
                .ok_or(ProtocolError::Overflow)?;
            if retained > limits.retained_bytes {
                return Err(Error::Limit);
            }
            if !step.expiration.is_never()
                && step.expiration.as_micros() < step.observed_at.as_micros()
            {
                return Err(ProtocolError::Authentication.into());
            }
            if last_time.is_some_and(|last| step.observed_at < last) {
                return Err(ProtocolError::TimeUncertain.into());
            }
            last_time = Some(step.observed_at);
            let context = Context::namespace(&self.namespace, &step.label, block)?;
            let length = step.wire.len() - ublock::HEADER_BYTES - ublock::TAG_BYTES;
            super::grow(&mut plain, length)?;
            let opened = context.open(&step.wire, &mut plain)?;
            let required = metadata_scratch(opened.bytes());
            if required > block.metadata.max_plain_bytes {
                return Err(ublock::Error::Metadata(md::Error::Limit).into());
            }
            super::grow(&mut metadata, required)?;
            let record = opened.decode(&mut metadata, &mut inflater, md::Mode::Strict)?;
            if let Some(next) = self.steps.get(index + 1) {
                if record.update_identifier().is_empty() || record.update_identifier() != next.label
                {
                    return Err(ProtocolError::Authentication.into());
                }
            } else {
                match (record.uri()?, location) {
                    (Uri::Content(content), None) if content == selected => {}
                    (Uri::Location(actual), Some(expected))
                        if actual == expected && actual.content() == selected => {}
                    _ => return Err(ProtocolError::Authentication.into()),
                }
            }
        }
        Ok(())
    }
    pub(super) fn from_session<'id, F, const KNOWN: usize>(
        session: &mut super::Session<'id, F, KNOWN>,
        chosen: ResultId,
    ) -> Result<(Self, Content, Option<Location>), Error>
    where
        F: FnMut() -> Result<crate::ipc::EndpointSource, crate::ipc::Error>,
    {
        if !session.owns_result(chosen) {
            return Err(ProtocolError::Stale.into());
        }
        if !session.capture_namespace_proof {
            return Err(ProtocolError::InvalidInput.into());
        }
        let result = session.result(chosen).ok_or(ProtocolError::Stale)?;
        if !result.visible() {
            return Err(ProtocolError::NotReady.into());
        }
        let (selected, location) = match result.uri(session.options.block.uri)? {
            Uri::Content(content) => (content, None),
            Uri::Location(location) => (location.content(), Some(location)),
            _ => return Err(ProtocolError::InvalidInput.into()),
        };
        let mut chain = Vec::new();
        let mut current = chosen;
        let count = loop {
            let proof = session
                .result(current)
                .and_then(|result| result.proof.as_ref())
                .ok_or(ProtocolError::NotReady)?;
            if chain.len() >= session.options.limits.queries {
                return Err(Error::Limit);
            }
            // Each accepted proof reserved its eventual fixed export workspace
            // in the original session retained-byte accounting.
            reserve(&mut chain, 1)?;
            chain.push(current);
            if let Some(parent) = proof.parent {
                // Creation origins are fixed, and parents were accepted before
                // a descendant query existed. Cyclic mutable graph edges cannot
                // replace this lineage with a later parent.
                if !session.owns_result(parent) || parent.0 >= current.0 {
                    return Err(ProtocolError::Conflict.into());
                }
                current = parent;
            } else {
                break chain.len();
            }
        };
        let root = session.results[chain[count - 1].0]
            .proof
            .as_ref()
            .ok_or(ProtocolError::NotReady)?;
        let namespace = session.queries[root.query.0]
            .spec
            .namespace
            .ok_or(ProtocolError::InvalidInput)?;
        let mut steps = Vec::new();
        reserve(&mut steps, count)?;
        for id in chain.into_iter().rev() {
            let proof = session.results[id.0]
                .proof
                .take()
                .ok_or(ProtocolError::NotReady)?;
            let query = &mut session.queries[proof.query.0];
            if query.spec.namespace != Some(namespace) {
                return Err(ProtocolError::Authentication.into());
            }
            steps.push(ProofStep {
                label: std::mem::take(&mut query.spec.label),
                wire: proof.wire,
                observed_at: proof.observed_at,
                expiration: proof.expiration,
            });
        }
        Ok((Self { namespace, steps }, selected, location))
    }
}
fn step_limits(label: usize, wire: usize, block: ublock::Limits) -> Result<(), Error> {
    if label > block.max_label_bytes || wire > block.max_wire_bytes {
        return Err(Error::Limit);
    }
    if wire < ublock::HEADER_BYTES + ublock::TAG_BYTES {
        return Err(ProtocolError::Truncated.into());
    }
    Ok(())
}
fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], Error> {
    let (head, tail) = input
        .split_at_checked(length)
        .ok_or(ProtocolError::Truncated)?;
    *input = tail;
    Ok(head)
}
fn word(input: &[u8]) -> u32 {
    u32::from_be_bytes([input[0], input[1], input[2], input[3]])
}
fn wide(input: &[u8]) -> u64 {
    u64::from_be_bytes([
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
    ])
}
