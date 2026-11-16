//! Bounded original failures and inbound-owner observations.
use crate::Cause;
use gnunet_cadet_host::{LossCause as CadetLossCause, TransmitKind as CadetTransmitKind};
use gnunet_fs_host::server::{
    self,
    cadet_server::{self, Step as ServingStep},
};
use gnunet_program_host::reporting::Reporter;
use std::{error::Error, fmt};
const STAGE_NAMES: [&str; 10] = [
    "foreground",
    "inbound drain",
    "inbound native close",
    "inbound source close",
    "interrupted inbound read",
    "Resolver drain",
    "Resolver physical cleanup",
    "local service cleanup",
    "index worker join",
    "selected Logger",
];
#[derive(Clone, Copy)]
#[repr(usize)]
pub(super) enum Stage {
    Main,
    Drain,
    NativeClose,
    SourceClose,
    InterruptedRead,
    ResolverDrive,
    ResolverClose,
    LocalClose,
    WorkerJoin,
    Logging,
}
/// One bounded original cause per independent stage. Repeated observations
/// are diagnosed without replacing the original retained cause.
pub(super) struct Failures {
    reports: Reporter,
    causes: [Option<Cause>; STAGE_NAMES.len()],
    pub(super) terminal: Option<Terminal>,
}
impl Failures {
    pub(super) fn new(reports: Reporter) -> Self {
        Self {
            reports,
            causes: std::array::from_fn(|_| None),
            terminal: None,
        }
    }
    pub(super) fn record(&mut self, stage: Stage, cause: Cause) {
        let index = stage as usize;
        self.reports.warning(
            "fs.stage.failure",
            format_args!("FS {}: {cause}", STAGE_NAMES[index]),
        );
        if self.causes[index].is_none() {
            self.causes[index] = Some(cause);
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        self.causes.iter().all(Option::is_none)
    }
}
impl fmt::Debug for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Failures")
            .field("causes", &self.causes)
            .field("terminal", &self.terminal)
            .field("logger_failed", &self.reports.failed())
            .finish()
    }
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut separator = "";
        for (index, cause) in self.causes.iter().enumerate() {
            if let Some(cause) = cause {
                write!(f, "{separator}{}: {cause}", STAGE_NAMES[index])?;
                separator = "; ";
            }
        }
        write!(f, "; actual terminal={:?}", self.terminal)
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.causes
            .iter()
            .flatten()
            .next()
            .map(|cause| cause.as_ref())
    }
}
/// Actual stopped-owner observations retain their original typed causes. These
/// are separate from local/native writes and never assert remote completion.
pub(super) struct Terminal {
    pub(super) local: server::Report,
    pub(super) inbound: Option<cadet_server::Report>,
    pub(super) inbound_drained: bool,
    pub(super) inbound_broken: bool,
    pub(super) diagnostics: InboundDiagnostics,
    pub(super) peers: [Option<server::peers::PeerFailure>; 3],
}
impl fmt::Debug for Terminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Terminal")
            .field("local", &self.local)
            .field("inbound", &self.inbound)
            .field("inbound_drained", &self.inbound_drained)
            .field("inbound_broken", &self.inbound_broken)
            .field("diagnostics", &self.diagnostics)
            .field("peers", &self.peers)
            .finish()
    }
}
#[derive(Debug)]
struct InboundSourceFailure {
    query: u64,
    epoch: u64,
    generation: u64,
    wire: u32,
    cause: cadet_server::source::Failure,
}
impl fmt::Display for InboundSourceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "query {} on original channel {} (epoch {}, generation {}): {}",
            self.query, self.wire, self.epoch, self.generation, self.cause
        )
    }
}
impl Error for InboundSourceFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}
#[derive(Debug)]
struct InboundRejectedRecord {
    query: u64,
    epoch: u64,
    generation: u64,
    wire: u32,
    record: cadet_server::source::RejectedRecord,
}
impl fmt::Display for InboundRejectedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "query {} on original channel {} (epoch {}, generation {})",
            self.query, self.wire, self.epoch, self.generation
        )?;
        if let Ok(data) = self.record.data() {
            write!(
                f,
                " skipped original DATA uid {} type {} ({} bytes)",
                data.uid,
                data.kind,
                data.value.len()
            )?;
        }
        write!(f, ": {}", self.record.cause())
    }
}
impl Error for InboundRejectedRecord {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.record.cause())
    }
}
/// The complete original source observation remains separate from peer
/// delivery; retiring a query neither succeeds nor fabricates absence.
#[derive(Debug)]
struct InboundRetiredSource {
    query: u64,
    epoch: u64,
    generation: u64,
    wire: u32,
    retired: cadet_server::source::Retired,
}
impl fmt::Display for InboundRetiredSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "query {} on original channel {} (epoch {}, generation {}) retired locally: {:?}",
            self.query, self.wire, self.epoch, self.generation, self.retired
        )
    }
}
impl Error for InboundRetiredSource {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.retired
            .cause()
            .map(|cause| cause as &(dyn Error + 'static))
    }
}
/// Retired owner numbers are diagnostic facts, never replacement authority.
#[derive(Debug)]
struct InboundLoss {
    epoch: u64,
    channels: usize,
    pending: Option<(u64, CadetTransmitKind, bool)>,
    cause: CadetLossCause,
}
impl fmt::Display for InboundLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original epoch {} retired {} channels, pending {:?}: {:?}",
            self.epoch, self.channels, self.pending, self.cause
        )
    }
}
impl Error for InboundLoss {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            CadetLossCause::Io(error) => Some(error),
            CadetLossCause::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
#[derive(Debug)]
struct InterruptedInboundRead {
    query: u64,
    epoch: u64,
    generation: u64,
    wire: u32,
    selection: cadet_server::Selection,
}
impl fmt::Display for InterruptedInboundRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original query {} (type {}) on channel {} (epoch {}, generation {}) was physically retired before an observed source terminal",
            self.query,
            self.selection.block_type.value(),
            self.wire,
            self.epoch,
            self.generation
        )
    }
}
impl Error for InterruptedInboundRead {}
/// Operation-local failures remain observable without stopping unrelated
/// channels or turning an expected source refusal into a process failure.
#[derive(Debug, Default)]
pub(super) struct InboundDiagnostics {
    skipped: Option<InboundRejectedRecord>,
    retired: Option<InboundRetiredSource>,
    source: Option<InboundSourceFailure>,
    loss: Option<InboundLoss>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum InboundState {
    Running,
    Quiesced,
    Closed,
}
pub(super) fn observe_inbound(
    step: ServingStep<'_>,
    diagnostics: &mut InboundDiagnostics,
    reports: &Reporter,
) -> Result<InboundState, Cause> {
    match step {
        ServingStep::Activity | ServingStep::WaitDeadline => {}
        ServingStep::Listening { source, .. } => {
            reports.message(
                gnunet_program_host::policy::Level::INFO,
                "fs.cadet.listening",
                format_args!("FS CADET source={}", source.value()),
            );
        }
        ServingStep::SourceRejectedRecord {
            query,
            channel,
            record,
        } => {
            let fatal = record.cause().is_fatal();
            let failure = InboundRejectedRecord {
                query,
                epoch: channel.epoch().value(),
                generation: channel.value(),
                wire: channel.wire_id(),
                record,
            };
            if fatal {
                return Err(Box::new(failure));
            }
            reports.warning(
                "fs.inbound.observation",
                format_args!("fs inbound source record: {failure}"),
            );
            if diagnostics.skipped.is_none() {
                diagnostics.skipped = Some(failure);
            }
        }
        ServingStep::SourceRetired {
            query,
            channel,
            retired,
        } => {
            // Channel retirement cannot hide a fatal original worker or
            // unknown index outcome. Keep its exact cause and row/result.
            let fatal = retired
                .cause()
                .is_some_and(server::ProviderFailure::is_fatal);
            let observation = InboundRetiredSource {
                query,
                epoch: channel.epoch().value(),
                generation: channel.value(),
                wire: channel.wire_id(),
                retired,
            };
            if fatal {
                return Err(Box::new(observation));
            }
            reports.warning(
                "fs.inbound.observation",
                format_args!("fs inbound source retirement: {observation}"),
            );
            if diagnostics.retired.is_none() {
                diagnostics.retired = Some(observation);
            }
        }
        ServingStep::SourceUnavailable {
            query,
            channel,
            cause,
        } => {
            // Unlike a row/source-file refusal, the original dependency
            // owner is permanently closed. Serving already withdrew its
            // port; preserve the exact cause and use the existing graceful
            // shutdown/supervisor path instead of false ongoing readiness.
            return Err(Box::new(InboundSourceFailure {
                query,
                epoch: channel.epoch().value(),
                generation: channel.value(),
                wire: channel.wire_id(),
                cause,
            }));
        }
        ServingStep::SourceFailed {
            query,
            channel,
            cause,
        } => {
            let fatal = cause.is_fatal();
            let failure = InboundSourceFailure {
                query,
                epoch: channel.epoch().value(),
                generation: channel.value(),
                wire: channel.wire_id(),
                cause,
            };
            if fatal {
                return Err(Box::new(failure));
            }
            reports.warning(
                "fs.inbound.observation",
                format_args!("fs inbound source: {failure}"),
            );
            if diagnostics.source.is_none() {
                diagnostics.source = Some(failure);
            }
        }
        ServingStep::Lost { report, cause } => {
            let failure = InboundLoss {
                epoch: report.epoch.value(),
                channels: report.channels,
                pending: report.pending.map(|pending| {
                    (
                        pending.transmit.value(),
                        pending.transmit.kind(),
                        pending.exposed,
                    )
                }),
                cause,
            };
            reports.warning(
                "fs.inbound.observation",
                format_args!("fs inbound MQ: {failure}"),
            );
            if diagnostics.loss.is_none() {
                diagnostics.loss = Some(failure);
            }
        }
        ServingStep::ConnectRetry { error, retry_after } => {
            // A normal endpoint attempt retry is not a completed read failure.
            reports.warning(
                "fs.inbound.observation",
                format_args!("fs inbound connect retry after {retry_after:?}: {error}"),
            );
        }
        ServingStep::Rejected { channel, reason } => {
            reports.warning(
                "fs.inbound.observation",
                format_args!(
                    "fs inbound channel {} rejected: {reason}",
                    channel.wire_id()
                ),
            );
        }
        ServingStep::Quiesced => return Ok(InboundState::Quiesced),
        ServingStep::Closed => return Ok(InboundState::Closed),
    }
    Ok(InboundState::Running)
}
pub(super) fn collect_inbound_close(
    closed: cadet_server::Closed<'_>,
    failures: &mut Failures,
    reports: &Reporter,
) {
    match closed.native {
        Ok(report) => {
            reports.warning(
                "fs.inbound.observation",
                format_args!("fs inbound physical retirement: {report:?}"),
            );
        }
        Err(error) => failures.record(Stage::NativeClose, Box::new(error)),
    }
    if let Err(error) = closed.source {
        failures.record(Stage::SourceClose, Box::new(error));
    }
    if let Some(query) = closed.pending_query {
        failures.record(
            Stage::InterruptedRead,
            Box::new(InterruptedInboundRead {
                query: query.query,
                epoch: query.channel.epoch().value(),
                generation: query.channel.value(),
                wire: query.channel.wire_id(),
                selection: query.selection,
            }),
        );
    }
}
