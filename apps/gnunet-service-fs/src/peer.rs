//! Explicit bounded foreground GAP settings and real entropy; no worker/IO loop.
use gnunet_config::Configuration;
use gnunet_core_client_host::{ClassOrder, Limits as CoreLimits, SendOutcome};
use gnunet_fs::gap;
use gnunet_fs_host::server::{cadet_server::source, gap as native};
use gnunet_service_runtime::framing::Budget;
use gnunet_types::Error as ProtocolError;
use std::{error::Error, fmt, time::Duration};

pub(super) const CORE_PEERS: usize = 64;
pub(super) const CORE_SENDS: usize = 1;
const MAX_BUFFER_BYTES: usize = 64 * 1024 * 1024;
const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;
#[derive(Clone, Copy)]
pub(super) struct Settings {
    pub enabled: bool,
    pub neighbors: usize,
    pub routes: usize,
    pub paths: usize,
    pub frame_bytes: usize,
    pub core: CoreLimits,
    pub pure: gap::Limits,
    pub native: native::Limits,
    pub source: source::Limits,
    pub privacy: gap::privacy::Limits,
    pub cover_classes: usize,
    pub mix_queue: usize,
    pub storage: gap::storage::Limits,
    pub cache_slots: usize,
    pub migration_slots: usize,
}
fn number(config: &Configuration, key: &[u8], default: usize) -> Result<usize, Box<dyn Error>> {
    config
        .get(b"fs-rust", key)
        .map(|_| config.get_number(b"fs-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()
        .map(|n| n.unwrap_or(default))
        .map_err(Into::into)
}
fn interval(config: &Configuration, key: &[u8], default: u64) -> Result<u64, Box<dyn Error>> {
    let value = config
        .get(b"fs-rust", key)
        .map(|_| config.get_time(b"fs-rust", key))
        .transpose()?
        .unwrap_or(default);
    if value == 0
        || value == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(value))
            .is_none()
    {
        return Err("GAP timeouts/residence must be finite, nonzero and representable".into());
    }
    Ok(value)
}
impl Settings {
    pub fn read(
        config: &Configuration,
        queries: usize,
        io_slice_bytes: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let explicit_enabled = config
            .get(b"fs-rust", b"GAP")
            .map(|_| config.get_yesno(b"fs-rust", b"GAP"))
            .transpose()?;
        let disabled = config
            .get(b"fs", b"DISABLE_ANON_TRANSFER")
            .map(|_| config.get_yesno(b"fs", b"DISABLE_ANON_TRANSFER"))
            .transpose()?
            .unwrap_or(false);
        let enabled = explicit_enabled.unwrap_or(!disabled);
        if enabled && disabled {
            return Err(
                "[fs-rust] GAP=YES conflicts with official [fs] DISABLE_ANON_TRANSFER=YES".into(),
            );
        }
        let neighbors = number(config, b"GAP_NEIGHBORS", CORE_PEERS)?;
        let routes = number(config, b"GAP_ROUTES", queries)?;
        let paths = number(
            config,
            b"GAP_RETURN_PATHS",
            routes.checked_mul(2).ok_or(ProtocolError::Capacity)?,
        )?;
        let block_bytes = number(
            config,
            b"GAP_BLOCK_BYTES",
            gnunet_fs::ublock::DEFAULT_WIRE_BYTES,
        )?;
        let records = number(config, b"GAP_SOURCE_RECORDS", 64)?;
        let packets = number(config, b"GAP_INPUT_PACKETS", 4)?;
        let fanout = number(config, b"GAP_FANOUT", 4)?;
        let cover_classes = number(config, b"GAP_COVER_CLASSES", 256)?;
        let mix_default = routes
            .checked_mul(fanout)
            .and_then(|n| n.checked_add(paths))
            .ok_or(ProtocolError::Capacity)?
            .min(16384);
        let mix_queue = number(config, b"GAP_MIX_QUEUE", mix_default)?;
        let randomized_delays = config
            .get(b"fs", b"DELAY")
            .map(|_| config.get_yesno(b"fs", b"DELAY"))
            .transpose()?
            .unwrap_or(false);
        let maximum_delay_ms = number(
            config,
            b"GAP_MIX_MAX_DELAY_MS",
            gap::privacy::DEFAULT_DELAY_MS as usize,
        )?;
        let cover_window = interval(
            config,
            b"GAP_COVER_WINDOW",
            gap::privacy::DEFAULT_COVER_WINDOW_US,
        )?;
        let policy_bytes = cover_classes
            .checked_mul(std::mem::size_of::<gap::privacy::CreditSlot<'static>>())
            .and_then(|n| {
                mix_queue
                    .checked_mul(std::mem::size_of::<gap::privacy::IntentSlot<'static>>())
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(ProtocolError::Capacity)?;
        let caching = config
            .get(b"fs", b"CONTENT_CACHING")
            .map(|_| config.get_yesno(b"fs", b"CONTENT_CACHING"))
            .transpose()?
            .unwrap_or(true);
        let pushing = config
            .get(b"fs", b"CONTENT_PUSHING")
            .map(|_| config.get_yesno(b"fs", b"CONTENT_PUSHING"))
            .transpose()?
            .unwrap_or(true);
        let cache_slots = number(config, b"GAP_CACHE_QUEUE", 4)?;
        let migration_slots = number(config, b"GAP_MIGRATION_QUEUE", 8)?;
        let selection_interval = config
            .get(b"fs", b"MIN_MIGRATION_DELAY")
            .map(|_| config.get_time(b"fs", b"MIN_MIGRATION_DELAY"))
            .transpose()?
            .unwrap_or(100_000);
        let busy_pause = interval(config, b"GAP_CACHE_BUSY_PAUSE", 5_000_000)?;
        let priority = number(config, b"GAP_PRIORITY", 32)?;
        let residence = interval(config, b"GAP_RESIDENCE", 60_000_000)?;
        let query = interval(config, b"GAP_QUERY_TIMEOUT", 30_000_000)?;
        let send = interval(config, b"GAP_SEND_TIMEOUT", 10_000_000)?;
        let filter_heap_bytes = number(
            config,
            b"GAP_FILTER_BYTES",
            gap::Limits::default().filter_heap_bytes,
        )?;
        let frame_bytes = block_bytes.checked_add(16).ok_or(ProtocolError::Capacity)?;
        let total = routes
            .checked_mul(
                frame_bytes
                    .checked_add(gap::GROUP_FILTER_BYTES)
                    .ok_or(ProtocolError::Capacity)?,
            )
            .ok_or(ProtocolError::Capacity)?;
        let storage_bytes = (if caching { cache_slots } else { 0 })
            .checked_add(if pushing { migration_slots } else { 0 })
            .and_then(|n| n.checked_mul(frame_bytes))
            .ok_or(ProtocolError::Capacity)?;
        if !(2..=CORE_PEERS).contains(&neighbors)
            || !(1..=4096).contains(&routes)
            || paths < routes
            || paths > 16384
            || block_bytes == 0
            || block_bytes > source::Limits::default().block_bytes
            || records == 0
            || records > 4096
            || packets == 0
            || packets > 64
            || fanout == 0
            || fanout > CORE_PEERS
            || priority > 65535
            || io_slice_bytes == 0
            || total > MAX_BUFFER_BYTES
            || cover_classes == 0
            || cover_classes > 4096
            || !(2..=16384).contains(&mix_queue)
            || maximum_delay_ms >= u32::MAX as usize
            || randomized_delays
                && (maximum_delay_ms == 0
                    || cover_window > (maximum_delay_ms as u64).saturating_mul(1000))
            || policy_bytes > MAX_POLICY_BYTES
            || !(1..=64).contains(&cache_slots)
            || !(1..=64).contains(&migration_slots)
            || enabled && pushing && (routes < 2 || paths < 2)
            || selection_interval == 0
            || selection_interval == u64::MAX
            || std::time::Instant::now()
                .checked_add(Duration::from_micros(selection_interval))
                .is_none()
            || total
                .checked_add(storage_bytes)
                .and_then(|n| n.checked_add(filter_heap_bytes))
                .is_none_or(|n| n > MAX_BUFFER_BYTES)
        {
            return Err("invalid bounded GAP neighbors/routes/paths/block/source/packet/fanout/priority limits".into());
        }
        Ok(Self {
            enabled,
            neighbors,
            routes,
            paths,
            frame_bytes,
            core: CoreLimits {
                sends: CORE_SENDS,
                source_bytes: 65535,
                frame_bytes: 65535,
                output: Budget {
                    frames: 4,
                    bytes: 4 * 65535,
                },
                io_slice_bytes,
            },
            pure: gap::Limits {
                residence_us: residence,
                fanout: u16::try_from(fanout)?,
                max_priority: 65535,
                filter_heap_bytes,
            },
            native: native::Limits {
                local_routes: queries,
                peer_records: CORE_PEERS + CORE_SENDS,
                packets,
                query_timeout: Duration::from_micros(query),
                send_timeout: Duration::from_micros(send),
                priority: u32::try_from(priority)?,
            },
            source: source::Limits {
                records,
                block_bytes,
            },
            privacy: gap::privacy::Limits {
                randomized_delays,
                cover_window_us: cover_window,
                maximum_delay_ms: u32::try_from(maximum_delay_ms)?,
            },
            cover_classes,
            mix_queue,
            storage: gap::storage::Limits {
                caching,
                pushing,
                selection_interval_us: selection_interval,
                busy_pause_us: busy_pause,
            },
            cache_slots,
            migration_slots,
        })
    }
    pub fn enabled_len(self, length: usize) -> usize {
        if self.enabled { length } else { 0 }
    }
    pub fn storage_enabled(self) -> bool {
        self.enabled && (self.storage.caching || self.storage.pushing)
    }
    pub fn storage_len(self, length: usize) -> usize {
        if self.storage_enabled() { length } else { 0 }
    }
    pub fn cache_len(self) -> usize {
        if self.enabled && self.storage.caching {
            self.cache_slots
        } else {
            0
        }
    }
    pub fn migration_len(self) -> usize {
        if self.enabled && self.storage.pushing {
            self.migration_slots
        } else {
            0
        }
    }
    pub fn result_bytes(self) -> Result<usize, ProtocolError> {
        self.enabled_len(self.routes)
            .checked_mul(self.frame_bytes)
            .ok_or(ProtocolError::Capacity)
    }
}
pub(super) fn class_order() -> ClassOrder {
    if cfg!(target_endian = "little") {
        ClassOrder::Little
    } else {
        ClassOrder::Big
    }
}
/// Actual operating-system CSPRNG port, with bounded rejection sampling.
pub(super) struct Entropy;
impl gap::Entropy for Entropy {
    fn uniform(&mut self, upper: u32) -> Result<u32, ProtocolError> {
        if upper == 0 {
            return Err(ProtocolError::InvalidInput);
        }
        let threshold = upper.wrapping_neg() % upper;
        for _ in 0..64 {
            let mut bytes = [0; 4];
            getrandom::fill(&mut bytes).map_err(|_| ProtocolError::Entropy)?;
            let value = u32::from_ne_bytes(bytes);
            if value >= threshold {
                return Ok(value % upper);
            }
        }
        Err(ProtocolError::Entropy)
    }
}
pub(super) struct Summary {
    pub connected: usize,
    pub retained: usize,
    pub completions: u64,
    pub initial_deferred: u64,
    pub initial_activations: u64,
    pub losses: u64,
    pub ingress_refused: u64,
    pub source_failures: u64,
    pub source_items: u64,
    pub source_items_retired: u64,
    pub records_rejected: u64,
    pub timeouts: u64,
    pub partial_timeouts: u64,
    pub unsupported: u64,
    pub forced_source: Option<source::Selection>,
    pub first_source_record: Option<String>,
    pub first_source_failure: Option<String>,
    pub first_source_retired: Option<String>,
    pub last_connection: Option<String>,
    pub last_loss: Option<String>,
    pub payload: Option<(u64, usize, usize, bool, SendOutcome)>,
    pub privacy: String,
    pub privacy_classes: usize,
    pub privacy_credits: u64,
    pub privacy_intents: usize,
    pub privacy_pending: bool,
    pub policy_time_retirements: u64,
    pub privacy_expired: u64,
    pub first_privacy_expired: Option<String>,
    pub storage: Option<String>,
}
impl fmt::Debug for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gap")
            .field("connected", &self.connected)
            .field("retained", &self.retained)
            .field("completions", &self.completions)
            .field("initial_deferred", &self.initial_deferred)
            .field("initial_activations", &self.initial_activations)
            .field("losses", &self.losses)
            .field("ingress_refused", &self.ingress_refused)
            .field("source_failures", &self.source_failures)
            .field("source_items", &self.source_items)
            .field("source_items_retired", &self.source_items_retired)
            .field("records_rejected", &self.records_rejected)
            .field("timeouts", &self.timeouts)
            .field("partial_timeouts", &self.partial_timeouts)
            .field("unsupported", &self.unsupported)
            .field("forced_source", &self.forced_source)
            .field("first_source_record", &self.first_source_record)
            .field("first_source_failure", &self.first_source_failure)
            .field("first_source_retired", &self.first_source_retired)
            .field("last_connection", &self.last_connection)
            .field("last_loss", &self.last_loss)
            .field("payload", &self.payload)
            .field("privacy", &self.privacy)
            .field("privacy_classes", &self.privacy_classes)
            .field("privacy_credits", &self.privacy_credits)
            .field("privacy_intents", &self.privacy_intents)
            .field("privacy_pending", &self.privacy_pending)
            .field("policy_time_retirements", &self.policy_time_retirements)
            .field("privacy_expired", &self.privacy_expired)
            .field("first_privacy_expired", &self.first_privacy_expired)
            .field("storage", &self.storage)
            .finish()
    }
}
pub(super) fn summary<S: source::BlockSource, E: gap::Entropy, const P: usize, const N: usize>(
    owner: &native::Router<'_, '_, '_, '_, S, E, P, N>,
) -> Summary {
    let r = owner.report();
    Summary {
        storage: owner.storage().map(|storage| {
            format!(
                "receipts={:?} terminals={} rejected={} first-terminal={:?} first-rejected={:?}",
                storage.owner().report(),
                storage.report().terminals,
                storage.report().rejected,
                storage.report().first_terminal,
                storage.report().first_rejected
            )
        }),
        privacy: format!(
            "limits={:?} observations={:?}",
            owner.privacy().limits(),
            owner.privacy().report()
        ),
        privacy_classes: owner.privacy().credits().count(),
        privacy_credits: owner
            .privacy()
            .credits()
            .map(|(_, _, count)| u64::from(count))
            .sum(),
        privacy_intents: owner.privacy().intents().count(),
        privacy_pending: owner.privacy().pending().is_some(),
        policy_time_retirements: r.policy_time_retirements,
        privacy_expired: r.privacy_expired,
        first_privacy_expired: r
            .first_privacy_expired
            .as_ref()
            .map(|record| format!("{record:?}")),
        connected: owner.connected_peers(),
        retained: owner.retained_results(),
        completions: r.completions,
        initial_deferred: r.initial_deferred,
        initial_activations: r.initial_activations,
        losses: r.losses,
        ingress_refused: r.ingress_refused,
        source_failures: r.source_failures,
        source_items: r.source_items,
        source_items_retired: r.source_items_retired,
        records_rejected: r.records_rejected,
        timeouts: r.timeouts,
        partial_timeouts: r.partial_timeouts,
        unsupported: r.unsupported,
        forced_source: r.forced_source,
        first_source_record: r
            .first_source_record
            .as_ref()
            .map(|record| format!("{record:?}")),
        first_source_failure: r
            .first_source_failure
            .as_ref()
            .map(|cause| format!("{cause}")),
        first_source_retired: r
            .first_source_retired
            .as_ref()
            .map(|retired| format!("{retired:?}")),
        last_connection: r
            .last_unavailable
            .as_ref()
            .map(|cause| format!("{cause}"))
            .or_else(|| {
                r.last_connect_error
                    .as_ref()
                    .map(|cause| format!("{cause}"))
            }),
        last_loss: r.last_loss.as_ref().map(|cause| format!("{cause:?}")),
        payload: r.last_completion.as_ref().and_then(|c| {
            c.payload.map(|p| {
                (
                    p.epoch().value(),
                    p.written(),
                    p.frame_bytes(),
                    p.exposed(),
                    c.outcome,
                )
            })
        }),
    }
}
type PendingDirect = (u64, gnunet_cadet_host::TransmitKind, bool);
type DirectRetirement = (u64, usize, Option<PendingDirect>, String);
pub(super) struct DirectSummary {
    losses: u64,
    retries: u64,
    unavailable: u64,
    timeouts: u64,
    hard_timeouts: u64,
    hard_retirements: u64,
    last: Option<DirectRetirement>,
}
impl fmt::Debug for DirectSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectCadet")
            .field("losses", &self.losses)
            .field("retries", &self.retries)
            .field("unavailable", &self.unavailable)
            .field("timeouts", &self.timeouts)
            .field("hard_timeouts", &self.hard_timeouts)
            .field("hard_retirements", &self.hard_retirements)
            .field("last", &self.last)
            .finish()
    }
}
pub(super) fn direct_summary(
    owner: &gnunet_fs_host::server::cadet::Router<'_, '_>,
) -> DirectSummary {
    let r = owner.report();
    DirectSummary {
        losses: r.losses,
        retries: r.connection_retries,
        unavailable: r.unavailable,
        timeouts: r.timeouts,
        hard_timeouts: r.hard_timeouts,
        hard_retirements: r.hard_retirements,
        last: r.last_retirement.as_ref().map(|retired| {
            (
                retired.report.epoch.value(),
                retired.report.channels,
                retired
                    .report
                    .pending
                    .map(|p| (p.transmit.value(), p.transmit.kind(), p.exposed)),
                format!("{:?}", retired.cause),
            )
        }),
    }
}
