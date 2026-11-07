//! Same FS protocol/storage/peer owners under standard SERVICE startup.
use crate::{
    control::Signals,
    lifecycle::{Cleanup, Resolver},
    peer,
    settings::{Settings, filled},
};
use gnunet_cadet_host::{
    ChannelSlot as CadetChannelSlot, Client as CadetClient, Instance as CadetInstance,
    Limits as CadetLimits, LossCause as CadetLossCause, PortSlot as CadetPortSlot,
    TransmitKind as CadetTransmitKind,
};
use gnunet_client::datastore as ds;
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_core_client_host::Instance as CoreInstance;
use gnunet_datastore_host::{Client as DatastoreClient, Limits as DatastoreLimits};
use gnunet_dht_client_host::Instance as DhtInstance;
use gnunet_fs::gap as gap_pure;
use gnunet_fs::service::{self as pure, ClientSlot, QuerySlot};
use gnunet_fs_host::{
    index::Index,
    server::{
        self, Event, Ports, Progress, Server,
        cadet::{Limits as RouteLimits, Router},
        cadet_server::{
            self, Server as ServingServer, Step as ServingStep,
            source::{self, Datastore as ServingSource},
        },
        dht::{Limits as DhtRouteLimits, Router as DhtRouter},
        gap::{Router as GapRouter, storage as GapStorage},
        peers::{Backend, Deferred, Pair},
        ports::{Datastore, PilsSigner},
    },
};
use gnunet_pils::{HelloLimits, client::Instance as PilsInstance};
use gnunet_pils_host::client::{Client as PilsClient, Limits as PilsLimits};
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{LiveConfiguration, broker, native_profile};
use gnunet_service_runtime::{
    BoundListeners, accepted::SocketEvent, clock::RuntimeClock, private_parents,
};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use gnunet_types::Error as ProtocolError;
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};

#[derive(Debug)]
struct ServiceFailure(Arc<server::Error>);
impl fmt::Display for ServiceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}
impl Error for ServiceFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
fn observe(event: Event, reports: &Reporter) {
    match event {
        Event::Socket(SocketEvent::Failed(error)) if error.is_emfile() => {}
        Event::Socket(SocketEvent::Failed(error)) => {
            reports.warning("fs.socket.failed", format_args!("FS socket: {error:?}"))
        }
        Event::Socket(event) => {
            reports.debug("fs.socket.activity", format_args!("FS socket: {event:?}"))
        }
        Event::Rejected(address) => reports.warning(
            "fs.client.rejected",
            format_args!("FS rejected: {address:?}"),
        ),
        Event::Fault { client, cause } => reports.warning(
            "fs.client.fault",
            format_args!("FS client {client:?}: {cause}"),
        ),
        Event::ClientClosed(_) | Event::Skipped { .. } => {}
    }
}

type Cause = Box<dyn Error>;
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
enum Stage {
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
struct Failures {
    reports: Reporter,
    causes: [Option<Cause>; STAGE_NAMES.len()],
    terminal: Option<Terminal>,
}
impl Failures {
    fn new(reports: Reporter) -> Self {
        Self {
            reports,
            causes: std::array::from_fn(|_| None),
            terminal: None,
        }
    }
    fn record(&mut self, stage: Stage, cause: Cause) {
        let index = stage as usize;
        self.reports.warning(
            "fs.stage.failure",
            format_args!("FS {}: {cause}", STAGE_NAMES[index]),
        );
        if self.causes[index].is_none() {
            self.causes[index] = Some(cause);
        }
    }
    fn is_empty(&self) -> bool {
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
struct Terminal {
    local: server::Report,
    inbound: Option<cadet_server::Report>,
    inbound_drained: bool,
    inbound_broken: bool,
    diagnostics: InboundDiagnostics,
    peers: [Option<server::peers::PeerFailure>; 3],
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
struct InboundDiagnostics {
    skipped: Option<InboundRejectedRecord>,
    retired: Option<InboundRetiredSource>,
    source: Option<InboundSourceFailure>,
    loss: Option<InboundLoss>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum InboundState {
    Running,
    Quiesced,
    Closed,
}
fn observe_inbound(
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
fn collect_inbound_close(
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

pub(super) struct Inputs<'a> {
    pub config: &'a Configuration,
    pub settings: &'a Settings,
    pub bound: &'a BoundListeners,
    pub parent: Option<ParentControl>,
    pub clock: SharedClock,
    pub reports: Reporter,
    pub child: &'a mut ChildReady,
    pub cleanup: Cleanup,
}

pub(super) async fn run(input: Inputs<'_>) -> Result<(), Box<dyn Error>> {
    let Inputs {
        config,
        settings,
        bound,
        parent,
        clock: shared_clock,
        reports,
        child,
        cleanup,
    } = input;
    let mut signals = Signals::new(parent)?;
    if reports.failed() {
        return Ok(());
    }
    let early_stop = poll_fn(|cx| {
        reports.register(cx);
        Poll::Ready(match signals.poll(cx) {
            Poll::Ready(result) => result.map(|()| true),
            Poll::Pending => Ok(false),
        })
    })
    .await?;
    if early_stop {
        return Ok(());
    }
    private_parents(&settings.directory)?;
    let index = Index::open(&settings.directory, settings.index)?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(shared_clock.clone());
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, resolver) = broker::<16, 256>(
        live.clone(),
        Default::default(),
        native_profile()?,
        clock.clone(),
    )?;
    let mut resolver = Resolver::new(resolver, cleanup.clone());
    let datastore_source =
        EndpointSource::live(live.clone(), b"datastore", context.resolution_context());
    let pils_source = EndpointSource::live(live.clone(), b"pils", context.resolution_context());
    let mut cadet_instance = CadetInstance::new();
    let mut cadet_ports = [];
    let mut cadet_channels = filled(
        if settings.direct_cadet {
            settings.queries
        } else {
            0
        },
        CadetChannelSlot::new(),
    )?;
    let direct = if settings.direct_cadet {
        let client = CadetClient::new(
            &mut cadet_instance,
            EndpointSource::live(live.clone(), b"cadet", context.resolution_context()),
            &mut cadet_ports,
            &mut cadet_channels,
            CadetLimits {
                io_slice_bytes: settings.native.io_slice_bytes,
                ..CadetLimits::default()
            },
        )?;
        Some(Router::new(
            client,
            RouteLimits {
                routes: settings.queries,
                timeout: settings.cadet_timeout,
            },
        )?)
    } else {
        None
    };
    // One explicit one-slot DATASTORE source selects only actual anonymity0
    // type9 rows for background DHT advertisement. No index worker is needed.
    let mut dht_publication_ds_instance = ds::Instance::new();
    let mut dht_publication_ds_buffer =
        [0_u8; gnunet_fs_host::server::dht::publication::DATASTORE_REQUEST_BYTES];
    let mut dht_publication_ds_slots = [ds::Slot::new(&mut dht_publication_ds_buffer)];
    let mut dht_publication_ds_reservations = [];
    let dht_publication_protocol = ds::Client::new(
        &mut dht_publication_ds_instance,
        &mut dht_publication_ds_slots,
        &mut dht_publication_ds_reservations,
        ds::Limits {
            max_pending: 1,
            max_lifetime: settings.datastore_timeout,
            ..ds::Limits::default()
        },
    )?;
    let dht_publication_source = GapStorage::Datastore::new(
        DatastoreClient::new(
            dht_publication_protocol,
            EndpointSource::live(live.clone(), b"datastore", context.resolution_context()),
            DatastoreLimits {
                reply_frames: 1,
                reply_bytes: 65535,
                io_slice_bytes: settings.native.io_slice_bytes,
                ..DatastoreLimits::default()
            },
        )?,
        settings.datastore_timeout,
    )
    .map_err(|error| error as Box<dyn Error>)?;
    // Non-anonymous search and publication share one real DHT client/reader,
    // the same explicit broker/clock and no hidden service or worker.
    let mut dht_instance = DhtInstance::new();
    let mut dht = DhtRouter::new(
        &mut dht_instance,
        EndpointSource::live(live.clone(), b"dht", context.resolution_context()),
        DhtRouteLimits {
            routes: settings.queries,
            known_hashes: settings.seen_per_query,
            block_bytes: settings.protocol.max_block_bytes,
            timeout: settings.dht_timeout,
            io_slice_bytes: settings.native.io_slice_bytes,
        },
    )?;
    dht.install_publisher(
        Box::new(dht_publication_source),
        gnunet_fs_host::server::dht::publication::Limits::default(),
    )?;
    let direct = Some(Pair::non_anonymous(direct, Some(dht), settings.queries)?);
    // Caller-owned finite GAP state. No socket, worker or index is opened
    // by these buffers; all references remain outside the peer provider.
    let mut gap_core_instance = CoreInstance::new();
    let mut gap_instance = gap_pure::Instance::new();
    let mut gap_storage_instance = gap_pure::storage::Instance::new();
    let mut gap_neighbors = filled(
        settings.gap.enabled_len(settings.gap.neighbors),
        gap_pure::NeighborSlot::default(),
    )?;
    let mut gap_results = filled(settings.gap.result_bytes()?, 0_u8)?;
    let mut gap_routes = Vec::new();
    gap_routes
        .try_reserve_exact(settings.gap.enabled_len(settings.gap.routes))
        .map_err(|_| ProtocolError::Capacity)?;
    for bytes in gap_results.chunks_exact_mut(settings.gap.frame_bytes) {
        gap_routes.push(gap_pure::RouteSlot::new(bytes));
    }
    let mut gap_paths = filled(
        settings.gap.enabled_len(settings.gap.paths),
        gap_pure::PathSlot::default(),
    )?;
    let mut gap_output = filled(settings.gap.enabled_len(settings.gap.frame_bytes), 0_u8)?;
    let gap_protocol = if settings.gap.enabled {
        Some(gap_pure::Router::new(
            &mut gap_instance,
            &mut gap_neighbors,
            &mut gap_routes,
            &mut gap_paths,
            &mut gap_output,
            settings.gap.pure,
        )?)
    } else {
        None
    };
    let mut gap_privacy_instance = gap_pure::privacy::Instance::new();
    let mut gap_cover_classes = filled(
        settings.gap.enabled_len(settings.gap.cover_classes),
        gap_pure::privacy::CreditSlot::new(),
    )?;
    let mut gap_mix_queue = filled(
        settings.gap.enabled_len(settings.gap.mix_queue),
        gap_pure::privacy::IntentSlot::new(),
    )?;
    let gap_privacy = if settings.gap.enabled {
        Some(gap_pure::privacy::Policy::new(
            &mut gap_privacy_instance,
            &mut gap_cover_classes,
            &mut gap_mix_queue,
            settings.gap.privacy,
        )?)
    } else {
        None
    };
    let gap_endpoint = EndpointSource::live(live.clone(), b"core", context.resolution_context());
    let mut gap_ds_instance = ds::Instance::new();
    let mut gap_ds_buffer = filled(settings.gap.enabled_len(65535), 0_u8)?;
    let mut gap_ds_slots = [ds::Slot::new(&mut gap_ds_buffer)];
    let mut gap_ds_reservations = [];
    let gap_datastore = if settings.gap.enabled {
        let protocol = ds::Client::new(
            &mut gap_ds_instance,
            &mut gap_ds_slots,
            &mut gap_ds_reservations,
            ds::Limits {
                max_pending: 1,
                max_lifetime: settings.datastore_timeout,
                ..ds::Limits::default()
            },
        )?;
        Some(Datastore::new(
            DatastoreClient::new(
                protocol,
                EndpointSource::live(live.clone(), b"datastore", context.resolution_context()),
                DatastoreLimits {
                    reply_frames: 1,
                    reply_bytes: 65535,
                    io_slice_bytes: settings.native.io_slice_bytes,
                    ..DatastoreLimits::default()
                },
            )?,
            settings.datastore_timeout,
        )?)
    } else {
        None
    };
    // One explicit extra native DATASTORE connection serializes only
    // optional cache PUTs and score-mutating replication selections.
    // The shared index worker is still created exactly once below.
    let mut gap_storage_peers = filled(
        settings.gap.storage_len(settings.gap.native.peer_records),
        gap_pure::storage::PeerSlot::new(),
    )?;
    let cache_bytes = settings
        .gap
        .cache_len()
        .checked_mul(settings.gap.frame_bytes)
        .ok_or(ProtocolError::Capacity)?;
    let migration_bytes = settings
        .gap
        .migration_len()
        .checked_mul(settings.gap.frame_bytes)
        .ok_or(ProtocolError::Capacity)?;
    let mut gap_cache_bytes = filled(cache_bytes, 0_u8)?;
    let mut gap_migration_bytes = filled(migration_bytes, 0_u8)?;
    let mut gap_cache_rows = Vec::new();
    gap_cache_rows
        .try_reserve_exact(settings.gap.cache_len())
        .map_err(|_| ProtocolError::Capacity)?;
    for bytes in gap_cache_bytes.chunks_exact_mut(settings.gap.frame_bytes) {
        gap_cache_rows.push(gap_pure::storage::CacheSlot::new(bytes));
    }
    let mut gap_migration_rows = Vec::new();
    gap_migration_rows
        .try_reserve_exact(settings.gap.migration_len())
        .map_err(|_| ProtocolError::Capacity)?;
    for bytes in gap_migration_bytes.chunks_exact_mut(settings.gap.frame_bytes) {
        gap_migration_rows.push(gap_pure::storage::MigrationSlot::new(bytes));
    }
    let gap_storage_owner = if settings.gap.storage_enabled() {
        Some(gap_pure::storage::Owner::new(
            &mut gap_storage_instance,
            &mut gap_storage_peers,
            &mut gap_cache_rows,
            &mut gap_migration_rows,
            settings.gap.storage,
        )?)
    } else {
        None
    };
    let mut gap_storage_ds_instance = ds::Instance::new();
    let mut gap_storage_ds_bytes = filled(settings.gap.storage_len(65535), 0_u8)?;
    let mut gap_storage_ds_slots = [ds::Slot::new(&mut gap_storage_ds_bytes)];
    let mut gap_storage_ds_reservations = [];
    let gap_storage_port = if settings.gap.storage_enabled() {
        let protocol = ds::Client::new(
            &mut gap_storage_ds_instance,
            &mut gap_storage_ds_slots,
            &mut gap_storage_ds_reservations,
            ds::Limits {
                max_pending: 1,
                max_lifetime: settings.datastore_timeout,
                ..ds::Limits::default()
            },
        )?;
        Some(
            GapStorage::Datastore::new(
                DatastoreClient::new(
                    protocol,
                    EndpointSource::live(live.clone(), b"datastore", context.resolution_context()),
                    DatastoreLimits {
                        reply_frames: 1,
                        reply_bytes: 65535,
                        io_slice_bytes: settings.native.io_slice_bytes,
                        ..DatastoreLimits::default()
                    },
                )?,
                settings.datastore_timeout,
            )
            .map_err(|e| e as Box<dyn Error>)?,
        )
    } else {
        None
    };
    let gap_storage_parts = match (gap_storage_owner, gap_storage_port) {
        (Some(owner), Some(port)) => Some((owner, port)),
        (None, None) => None,
        _ => return Err(ProtocolError::Conflict.into()),
    };
    let mut ds_instance = ds::Instance::new();
    let mut ds_buffer = filled(65535, 0_u8)?;
    let mut ds_slots = [ds::Slot::new(&mut ds_buffer)];
    let mut ds_reservations = [];
    let ds_protocol = ds::Client::new(
        &mut ds_instance,
        &mut ds_slots,
        &mut ds_reservations,
        ds::Limits {
            max_pending: 1,
            max_lifetime: settings.datastore_timeout,
            ..ds::Limits::default()
        },
    )?;
    let datastore = Datastore::new(
        DatastoreClient::new(
            ds_protocol,
            datastore_source,
            DatastoreLimits {
                reply_frames: 1,
                reply_bytes: 65535,
                io_slice_bytes: settings.native.io_slice_bytes,
                ..DatastoreLimits::default()
            },
        )?,
        settings.datastore_timeout,
    )?;
    let mut pils_instance = PilsInstance::new();
    let signer = PilsSigner::new(PilsClient::<32>::new(
        &mut pils_instance,
        pils_source,
        settings.pils_profile,
        PilsLimits {
            pending_operations: 1,
            io_slice_bytes: settings.native.io_slice_bytes,
            ..PilsLimits::default()
        },
        HelloLimits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 65535,
            maximum_addresses: 128,
        },
    )?)?;
    // Independent ordinary IPC owners; no second store backend or Index.
    // Allocate native buffers only when inbound serving was selected.
    let mut serving_cadet_id = CadetInstance::new();
    let mut serving_ports = [CadetPortSlot::new(); 1];
    let mut serving_channels = filled(
        if settings.serve_cadet {
            settings
                .serving
                .channels
                .checked_add(1)
                .ok_or(ProtocolError::Capacity)?
        } else {
            0
        },
        CadetChannelSlot::new(),
    )?;
    let mut serving_ds_id = ds::Instance::new();
    let mut serving_ds_buffer = filled(if settings.serve_cadet { 65535 } else { 0 }, 0_u8)?;
    let mut serving_ds_slots = [ds::Slot::new(&mut serving_ds_buffer)];
    let mut serving_ds_reservations = [];
    let serving_parts = if settings.serve_cadet {
        let protocol = ds::Client::new(
            &mut serving_ds_id,
            &mut serving_ds_slots,
            &mut serving_ds_reservations,
            ds::Limits {
                max_pending: 1,
                max_lifetime: settings.datastore_timeout,
                ..ds::Limits::default()
            },
        )?;
        let datastore = Datastore::new(
            DatastoreClient::new(
                protocol,
                EndpointSource::live(live.clone(), b"datastore", context.resolution_context()),
                DatastoreLimits {
                    reply_frames: 1,
                    reply_bytes: 65535,
                    io_slice_bytes: settings.native.io_slice_bytes,
                    ..DatastoreLimits::default()
                },
            )?,
            settings.datastore_timeout,
        )?;
        let client = CadetClient::new(
            &mut serving_cadet_id,
            EndpointSource::live(live.clone(), b"cadet", context.resolution_context()),
            &mut serving_ports,
            &mut serving_channels,
            CadetLimits {
                io_slice_bytes: settings.native.io_slice_bytes,
                ..CadetLimits::default()
            },
        )?;
        Some((client, datastore))
    } else {
        None
    };
    let mut fs_instance = pure::Instance::new();
    let mut clients = filled(settings.clients, ClientSlot::default())?;
    let count = settings
        .queries
        .checked_mul(settings.seen_per_query)
        .ok_or(ProtocolError::Capacity)?;
    let mut seen = filled(count, [0_u8; 64])?;
    let mut queries = Vec::new();
    queries
        .try_reserve_exact(settings.queries)
        .map_err(|_| ProtocolError::Capacity)?;
    for hashes in seen.chunks_exact_mut(settings.seen_per_query) {
        queries.push(QuerySlot::new(hashes));
    }
    let protocol = pure::Service::new(
        &mut fs_instance,
        &mut clients,
        &mut queries,
        settings.protocol,
    )?;
    let mut server = Server::new(
        protocol,
        Ports {
            datastore,
            signer,
            peers: Deferred::new(),
            index,
            clock,
        },
        settings.native,
        settings.options.clone(),
        settings.access,
    )
    .map_err(|error| Box::new(ServiceFailure(error)) as Box<dyn Error>)?;
    let mut failures = Failures::new(reports.clone());
    let mut diagnostics = InboundDiagnostics::default();
    let mut startup_ok = true;
    // The Server now owns the sole real index worker. Its original weak
    // resolution port is passed to the factory; no temporary fake resolver
    // or second Index/WAL is created. Failure leaves this Server owned so
    // the common shutdown path still actually joins that original worker.
    let gap_settings = settings.gap;
    let query_capacity = settings.queries;
    let gap_core_instance = &mut gap_core_instance;
    if let Err(error) = server.initialize_peers(move |resolver, server_clock| {
        let gap = match (gap_protocol, gap_datastore, gap_privacy) {
            (Some(protocol), Some(datastore), Some(privacy)) => {
                let source_resolver = resolver.clone();
                let mut router =
                    GapRouter::<_, _, { peer::CORE_PEERS }, { peer::CORE_SENDS }>::new(
                        gap_core_instance,
                        gap_endpoint,
                        peer::class_order(),
                        gap_settings.core,
                        protocol,
                        privacy,
                        move |source_clock| {
                            if !Arc::ptr_eq(&source_clock, &server_clock) {
                                return Err(source::Failure::service(ProtocolError::Conflict));
                            }
                            ServingSource::new(
                                datastore,
                                Some(source_resolver),
                                gap_settings.source,
                            )
                            .map_err(source::Failure::operation)
                        },
                        peer::Entropy,
                        gap_settings.native,
                    )
                    .map_err(server::gap::Error::into_provider_failure)?;
                if let Some((owner, port)) = gap_storage_parts {
                    let driver = GapStorage::Driver::new(
                        owner,
                        Box::new(port),
                        Some(resolver),
                        router.clock(),
                    )
                    .map_err(server::ProviderFailure::operation)?;
                    router
                        .install_storage(driver)
                        .map_err(server::gap::Error::into_provider_failure)?;
                }
                Some(router)
            }
            (None, None, None) => None,
            _ => return Err(server::ProviderFailure::operation(ProtocolError::Conflict)),
        };
        Pair::discovery(direct, gap, query_capacity).map_err(server::ProviderFailure::operation)
    }) {
        failures.record(Stage::Main, Box::new(ServiceFailure(error)));
        startup_ok = false;
    }
    // The independent inbound owner also receives a weak port from that
    // exact same worker, after the peer factory initialized successfully.
    let mut inbound = match if startup_ok {
        serving_parts
    } else {
        drop(serving_parts);
        None
    } {
        Some((client, datastore)) => {
            let built = server
                .on_demand_resolver()
                .map_err(|error| Box::new(ServiceFailure(error)) as Cause)
                .and_then(|resolver| {
                    let source = ServingSource::new(datastore, Some(resolver), settings.source)?;
                    ServingServer::new(client, source, settings.serving)
                        .map_err(|error| Box::new(error) as Cause)
                });
            match built {
                Ok(owner) => Some(owner),
                Err(error) => {
                    failures.record(Stage::Main, error);
                    startup_ok = false;
                    None
                }
            }
        }
        None => None,
    };
    let listeners = bound.listeners();
    let shutdown = poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Ok(()));
        }
        signals.poll(cx)
    });
    let mut shutdown = std::pin::pin!(shutdown);
    if startup_ok {
        let ready = if reports.failed() {
            Err(io::Error::other(
                "FS selected Logger failed before readiness",
            ))
        } else {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "READY fs {} route-backend={} serve-backend={} gap-policy={} gap-delay={} content-caching={} content-pushing={}",
                settings.directory.display(),
                match (settings.direct_cadet, settings.gap.enabled) {
                    (true, true) => "direct-cadet+dht+gap-core-fs-cover-budget",
                    (false, true) => "dht+gap-core-fs-cover-budget",
                    (true, false) => "direct-cadet+dht",
                    (false, false) => "dht",
                },
                if settings.serve_cadet {
                    "cadet"
                } else {
                    "disabled"
                },
                if settings.gap.enabled {
                    "local-core-cover-budget"
                } else {
                    "disabled"
                },
                settings.gap.enabled && settings.gap.privacy.randomized_delays,
                settings.gap.enabled && settings.gap.storage.caching,
                settings.gap.enabled && settings.gap.storage.pushing,
            )
            .and_then(|()| out.flush())
        };
        match ready.and_then(|()| child.ready()) {
            Ok(()) => {}
            Err(error) => {
                failures.record(Stage::Main, Box::new(error));
                startup_ok = false;
            }
        }
    }
    if reports.failed() {
        startup_ok = false;
    }
    let mut resolver_alive = true;
    let mut local_stopped = false;
    let mut inbound_broken = false;
    let mut turn = 0_u8;
    if startup_ok {
        loop {
            let stop = {
                let mut driving = std::pin::pin!(
                    server.drive(&listeners, None, |event| observe(event, &reports))
                );
                poll_fn(|cx| {
                    if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
                        if let Err(error) = result {
                            failures.record(Stage::Main, Box::new(error));
                        }
                        return Poll::Ready(true);
                    }
                    let mut ready = false;
                    let mut stop = false;
                    // Each original owner receives exactly one bounded poll
                    // even if another owner was already ready this turn.
                    for offset in 0..3 {
                        if reports.failed(){stop=true;break;}
                        match (turn + offset) % 3 {
                            0 => {
                                if let Poll::Ready(progress) = driving.as_mut().poll(cx) {
                                    ready = true;
                                    if progress == Progress::Stopped {
                                        local_stopped = true;
                                        stop = true;
                                    }
                                }
                            }
                            1 => {
                                if let Some(owner) = &mut inbound {
                                    match owner.poll(cx, None) {
                                        Poll::Pending => {}
                                        Poll::Ready(Err(error)) => {
                                            failures.record(Stage::Main, Box::new(error));
                                            inbound_broken = true;
                                            ready = true;
                                            stop = true;
                                        }
                                        Poll::Ready(Ok(step)) => {
                                            ready = true;
                                            match observe_inbound(step, &mut diagnostics,&reports) {
                                                Ok(InboundState::Running) => {}
                                                Ok(state) => {
                                                    inbound_broken = state == InboundState::Closed;
                                                    failures.record(Stage::Main, Box::new(io::Error::other(
                                                        "inbound serving stopped before shutdown request",
                                                    )));
                                                    stop = true;
                                                }
                                                Err(error) => {
                                                    failures.record(Stage::Main, error);
                                                    stop = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            2 if resolver_alive && !reports.failed() => match resolver.poll(cx,&reports) {
                                Poll::Pending => {}
                                Poll::Ready(Ok(_)) => ready = true,
                                Poll::Ready(Err(error)) => {
                                    failures.record(Stage::Main, Box::new(error));
                                    resolver_alive = false;
                                    resolver.close();
                                    ready = true;
                                    stop = true;
                                }
                            },
                            _ => {}
                        }
                    }
                    if ready || stop {
                        turn = (turn + 1) % 3;
                        Poll::Ready(stop)
                    } else {
                        Poll::Pending
                    }
                }).await
            };
            if stop {
                break;
            }
        }
    }

    // Stop admission on both frontends. The LocalServer worker stays alive
    // until inbound source jobs have produced their actual terminal result.
    server.request_shutdown();
    if let Some(owner) = &mut inbound {
        owner.request_shutdown();
    }
    let mut inbound_drained = inbound.is_none();
    let mut inbound_done = inbound.is_none() || inbound_broken;
    while !inbound_done {
        if reports.failed() && resolver_alive {
            resolver.close();
            resolver_alive = false;
        }
        let mut driving = std::pin::pin!(server.drive(&[], None, |event| observe(event, &reports)));
        poll_fn(|cx| {
            let mut ready = false;
            for offset in 0..3 {
                match (turn + offset) % 3 {
                    0 if !local_stopped => {
                        if let Poll::Ready(progress) = driving.as_mut().poll(cx) {
                            ready = true;
                            local_stopped = progress == Progress::Stopped;
                        }
                    }
                    1 if !inbound_done => {
                        if let Some(owner) = &mut inbound {
                            match owner.poll(cx, None) {
                                Poll::Pending => {}
                                Poll::Ready(Err(error)) => {
                                    failures.record(Stage::Drain, Box::new(error));
                                    inbound_broken = true;
                                    inbound_done = true;
                                    ready = true;
                                }
                                Poll::Ready(Ok(step)) => {
                                    ready = true;
                                    match observe_inbound(step, &mut diagnostics, &reports) {
                                        Ok(InboundState::Running) => {}
                                        Ok(InboundState::Quiesced) => {
                                            inbound_done = true;
                                            inbound_drained = true;
                                        }
                                        Ok(InboundState::Closed) => {
                                            failures.record(Stage::Drain, Box::new(io::Error::other(
                                                "inbound native owner closed before source drain",
                                            )));
                                            inbound_broken = true;
                                            inbound_done = true;
                                        }
                                        Err(error) => failures.record(Stage::Drain, error),
                                    }
                                }
                            }
                        }
                    }
                    2 if resolver_alive && !reports.failed() => match resolver.poll(cx, &reports) {
                        Poll::Pending => {}
                        Poll::Ready(Ok(_)) => ready = true,
                        Poll::Ready(Err(error)) => {
                            failures.record(Stage::ResolverDrive, Box::new(error));
                            resolver_alive = false;
                            resolver.close();
                            ready = true;
                        }
                    },
                    _ => {}
                }
            }
            if ready {
                turn = (turn + 1) % 3;
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
    // On a fatal native poll refusal, physically retire both original
    // owners. Closed.pending_query explicitly records an unobserved source
    // terminal; close Ok must never be relabeled as an actual GET success.
    let inbound_report = inbound.as_ref().map(|owner| owner.report());
    if let Some(owner) = &mut inbound {
        collect_inbound_close(owner.close(), &mut failures, &reports);
    }
    drop(inbound);

    // Only now may LocalServer.shutdown join the one existing index worker.
    // Poll the same Resolver independently even if local cleanup was ready;
    // a Resolver failure cannot short-circuit actual worker joining.
    let report = {
        let mut closing = std::pin::pin!(server.shutdown(|event| observe(event, &reports)));
        loop {
            if reports.failed() && resolver_alive {
                resolver.close();
                resolver_alive = false;
            }
            let selected = {
                poll_fn(|cx| {
                    let mut ready = false;
                    let mut completed = None;
                    for offset in 0..2 {
                        match (turn + offset) % 2 {
                            0 => {
                                if let Poll::Ready(report) = closing.as_mut().poll(cx) {
                                    completed = Some(report);
                                    ready = true;
                                }
                            }
                            1 if resolver_alive && !reports.failed() => {
                                match resolver.poll(cx, &reports) {
                                    Poll::Pending => {}
                                    Poll::Ready(Ok(_)) => ready = true,
                                    Poll::Ready(Err(error)) => {
                                        failures.record(Stage::ResolverDrive, Box::new(error));
                                        resolver_alive = false;
                                        resolver.close();
                                        ready = true;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if ready {
                        turn = (turn + 1) % 2;
                        Poll::Ready(completed)
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            if let Some(report) = selected {
                break report;
            }
        }
    };
    if let Some(cause) = &report.failure {
        failures.record(Stage::LocalClose, Box::new(ServiceFailure(cause.clone())));
    }
    if !report.worker_quiesced {
        failures.record(
            Stage::WorkerJoin,
            Box::new(io::Error::other(
                "FS index worker did not reach actual native quiescence",
            )),
        );
    }
    resolver.close();
    if let Some(error) = cleanup.take_error() {
        failures.record(Stage::ResolverClose, error);
    }
    let peer_causes = server
        .peer_router()
        .get()
        .map_or([None, None, None], |peers| {
            [
                peers.failure(Backend::Direct).cloned().or_else(|| {
                    peers
                        .direct()
                        .and_then(|direct| direct.failure(Backend::Direct))
                        .cloned()
                }),
                peers.failure(Backend::Gap).cloned(),
                peers
                    .direct()
                    .and_then(|direct| direct.failure(Backend::Dht))
                    .cloned(),
            ]
        });
    let peer_summary = server.peer_router().get().map(|peers| {
        for failure in peer_causes.iter().flatten() {
            reports.warning(
                "fs.inbound.observation",
                format_args!("fs peer backend retirement: {failure}"),
            );
        }
        (
            peers
                .direct()
                .and_then(|direct| direct.direct())
                .map(peer::direct_summary),
            peers.gap().map(peer::summary),
            peers
                .direct()
                .and_then(|direct| direct.dht())
                .map(|dht| (dht.report(), dht.publication_report())),
        )
    });
    reports.debug("fs.stopped",format_args!("FS actual stop={report:?} inbound={inbound_report:?} inbound-drained={inbound_drained} inbound-forced-retirement={inbound_broken} diagnostics={diagnostics:?} peers={peer_summary:?}"));
    if let Some(error) = reports.take_error() {
        failures.record(Stage::Logging, Box::new(error));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        failures.terminal = Some(Terminal {
            local: report,
            inbound: inbound_report,
            inbound_drained,
            inbound_broken,
            diagnostics,
            peers: peer_causes,
        });
        Err(Box::new(failures))
    }
}
