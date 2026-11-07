//! Bounded typed search history. Loading facts does not authenticate results.
use super::codec;
pub use crate::search::observation::Observation;
use crate::{durable::store::Store, search};
use gnunet_crypto::gns::EdkeySecret;
use gnunet_fs::{Uri, ublock::Kind};
use gnunet_types::AbsoluteTime;
use std::fmt;

/// Strict private history refusal, independent of native storage certainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// A private record version or type is unsupported.
    Version,
    /// Truncated, trailing, noncanonical boolean or malformed field bytes.
    Format,
    /// An explicit task, URI, observation or representation bound was exceeded.
    Limit,
    /// The original next WAL sequence/index is not contiguous.
    Order,
    /// Search kind or namespace differs from the immutable root query.
    Binding,
    /// A lifecycle or historical-summary transition is not permitted.
    Transition,
    /// The original official URI parser refused.
    Protocol(gnunet_types::Error),
}
impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS search task model: {self:?}")
    }
}
impl std::error::Error for ModelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
impl From<gnunet_types::Error> for ModelError {
    fn from(error: gnunet_types::Error) -> Self {
        Self::Protocol(error)
    }
}
/// Immutable original search inputs and complete numeric policy.
#[derive(Clone, Debug)]
pub struct Manifest {
    /// Exact originally selected KSK or SKS URI bytes.
    pub query_uri: Vec<u8>,
    /// Search/native/artifact policy. Codec omits deadline and decodes it as zero.
    pub options: search::Options,
    /// Maximum retained authenticated raw observations, separate from WAL limits.
    pub max_observations: usize,
}
impl Manifest {
    /// Reparse the original KSK/SKS under its retained artifact URI limits.
    pub fn query(&self) -> Result<Uri<'_>, ModelError> {
        match Uri::parse(&self.query_uri, self.options.block.uri)? {
            uri @ (Uri::Keywords(_) | Uri::Namespace(_)) => Ok(uri),
            _ => Err(ModelError::Format),
        }
    }
    /// Check immutable inputs without constructing runtime queries or opening sockets.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.query_uri.len() > codec::MAX_URI_BYTES
            || self.max_observations == 0
            || self.options.limits.queries == 0
            || self.options.limits.queries > 64
            || self.options.limits.results == 0
            || self.options.native.frame_bytes < gnunet_wire::official::fs::SEARCH_PREFIX
            || self.options.native.frame_bytes > u16::MAX as usize
            || self.options.native.io_slice_bytes == 0
        {
            return Err(ModelError::Limit);
        }
        u64::try_from(self.max_observations).map_err(|_| ModelError::Limit)?;
        let _query = self.query()?;
        Ok(())
    }
}
/// Historical lifecycle only. Search has no protocol completion or negative end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// The immutable manifest is durable; no runtime is implied.
    Ready,
    /// An explicit caller owns a run; loading this phase means interrupted work.
    Running,
    /// Fresh search work must stop and original native owners must retire.
    PauseRequested,
    /// The caller recorded a settled pause after native retirement.
    Paused,
    /// Cancellation intent is durable and must not resume fresh search work.
    CancelRequested,
    /// Cancellation settlement was recorded; historical results remain intact.
    Cancelled,
    /// A run failed; original observations remain for explicit recovery.
    Failed,
}
/// Last recorded runtime summary, never current authentication or availability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    /// Total durable raw observations included in this summary.
    pub observations: usize,
    /// Result records observed by that original runtime, including mandatory pending.
    pub results: usize,
    /// Results whose mandatory terms were satisfied in that original runtime.
    pub visible: usize,
    /// Query owners constructed by that runtime, including update descendants.
    pub queries: usize,
}
/// Small lifecycle records and borrowed original ciphertext observations.
#[derive(Clone, Debug)]
pub enum Event<'a> {
    /// First and sole immutable manifest.
    Manifest(Manifest),
    /// Original native observation after authentication, before aggregate admission.
    Observation(Observation<'a>),
    /// Actual producer's lifecycle and independently recorded historical summary.
    Phase {
        /// Original lifecycle fact, not inferred from search silence.
        phase: Phase,
        /// Original runtime summary. It may lag later durable raw observations.
        counts: Counts,
    },
}
/// Typed history with observation bodies borrowed later from the original Store.
pub struct State {
    /// Original immutable query and policy.
    pub manifest: Manifest,
    /// Last original durable phase, not evidence of a current runtime.
    pub phase: Phase,
    /// Zero-based original Store record indices; no ciphertext body is duplicated.
    pub observations: Vec<usize>,
    /// Last explicit historical summary, which may lag raw observation count.
    pub counts: Counts,
    applied: u64,
    last_observed: Option<AbsoluteTime>,
    kind: Kind,
    namespace: [u8; 32],
}
impl State {
    /// Read and structurally check the exact Store prefix without runtime or network work.
    /// Session replay must independently authenticate every original observation.
    pub fn load(store: &mut Store) -> Result<Self, super::Cause> {
        let first = store.read_record(0)?.ok_or(ModelError::Format)?;
        if first.sequence != 1 {
            return Err(ModelError::Order.into());
        }
        let Event::Manifest(manifest) = codec::decode_event(first.kind, first.bytes)? else {
            return Err(ModelError::Format.into());
        };
        let (kind, namespace) = match manifest.query()? {
            Uri::Namespace(value) => (Kind::Namespace, *value.key().as_bytes()),
            Uri::Keywords(_) => {
                let mut seed = [0; 32];
                seed[0] = 1;
                (Kind::Keyword, EdkeySecret::from_seed(seed).public_key())
            }
            _ => return Err(ModelError::Format.into()),
        };
        let mut state = Self {
            manifest,
            phase: Phase::Ready,
            observations: Vec::new(),
            counts: Counts::default(),
            applied: 1,
            last_observed: None,
            kind,
            namespace,
        };
        for index in 1..store.record_count() {
            let record = store.read_record(index)?.ok_or(ModelError::Order)?;
            state.apply(record.sequence, index, record.kind, record.bytes)?;
        }
        Ok(state)
    }
    /// Number of exact complete records already applied, including the manifest.
    #[must_use]
    pub const fn applied(&self) -> u64 {
        self.applied
    }
    /// Pure lifecycle, binding, bound and historical-time preflight before append.
    pub fn check(&self, event: &Event<'_>) -> Result<(), ModelError> {
        match event {
            Event::Manifest(_) => return Err(ModelError::Transition),
            Event::Observation(observation) => {
                if self.phase != Phase::Running {
                    return Err(ModelError::Transition);
                }
                if self.observations.len() >= self.manifest.max_observations
                    || observation.query_id >= self.manifest.options.limits.queries
                    || observation.label.len() > self.manifest.options.block.max_label_bytes
                    || observation.wire.len() > self.manifest.options.block.max_wire_bytes
                    || observation.wire.len() > self.manifest.options.protocol.max_block_bytes
                    || observation
                        .wire
                        .len()
                        .checked_add(gnunet_wire::official::fs::CLIENT_PUT_PREFIX)
                        .is_none_or(|bytes| bytes > self.manifest.options.native.frame_bytes)
                {
                    return Err(ModelError::Limit);
                }
                if observation.kind != self.kind || *observation.namespace != self.namespace {
                    return Err(ModelError::Binding);
                }
                if observation.label.contains(&0)
                    || observation.wire.len()
                        < gnunet_fs::ublock::HEADER_BYTES + gnunet_fs::ublock::TAG_BYTES + 2
                    || observation.observed_at.as_micros() == u64::MAX
                    || (!observation.expiration.is_never()
                        && observation.expiration.as_micros() < observation.observed_at.as_micros())
                    || self
                        .last_observed
                        .is_some_and(|last| observation.observed_at < last)
                {
                    return Err(ModelError::Format);
                }
            }
            Event::Phase { phase, counts } => {
                if counts.observations > self.observations.len()
                    || counts.results > self.manifest.options.limits.results
                    || counts.visible > counts.results
                    || counts.results > counts.observations
                    || counts.queries > self.manifest.options.limits.queries
                {
                    return Err(ModelError::Limit);
                }
                match phase {
                    Phase::Ready if self.phase != Phase::Ready || *counts != Counts::default() => {
                        return Err(ModelError::Transition);
                    }
                    Phase::Running
                        if matches!(self.phase, Phase::Cancelled | Phase::CancelRequested) =>
                    {
                        return Err(ModelError::Transition);
                    }
                    Phase::PauseRequested
                        if !matches!(self.phase, Phase::Running | Phase::PauseRequested) =>
                    {
                        return Err(ModelError::Transition);
                    }
                    Phase::Paused if self.phase != Phase::PauseRequested => {
                        return Err(ModelError::Transition);
                    }
                    Phase::CancelRequested if self.phase == Phase::Cancelled => {
                        return Err(ModelError::Transition);
                    }
                    Phase::Cancelled if self.phase != Phase::CancelRequested => {
                        return Err(ModelError::Transition);
                    }
                    Phase::Failed
                        if matches!(
                            self.phase,
                            Phase::Ready | Phase::Cancelled | Phase::CancelRequested
                        ) =>
                    {
                        return Err(ModelError::Transition);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
    /// Preflight and reserve only the affected small index before WAL I/O.
    pub fn prepare(&mut self, event: &Event<'_>) -> Result<(), ModelError> {
        self.check(event)?;
        if matches!(event, Event::Observation(_)) {
            self.observations
                .try_reserve(1)
                .map_err(|_| ModelError::Limit)?;
        }
        Ok(())
    }
    /// Apply one exact next original record after full decode/check, without
    /// manufacturing aggregate results or treating stored timestamps as signatures.
    pub fn apply(
        &mut self,
        sequence: u64,
        index: usize,
        kind: u16,
        bytes: &[u8],
    ) -> Result<(), ModelError> {
        if self.applied.checked_add(1) != Some(sequence)
            || u64::try_from(index).ok() != Some(self.applied)
        {
            return Err(ModelError::Order);
        }
        let event = codec::decode_event(kind, bytes)?;
        self.prepare(&event)?;
        match event {
            Event::Manifest(_) => return Err(ModelError::Transition),
            Event::Observation(observation) => {
                self.observations.push(index);
                self.last_observed = Some(observation.observed_at);
            }
            Event::Phase { phase, counts } => {
                self.phase = phase;
                self.counts = counts;
            }
        }
        self.applied = sequence;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
