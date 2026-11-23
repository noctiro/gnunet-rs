//! Native driver for GNUnet TESTING command-helper pipes.

mod helper;
#[cfg(target_os = "linux")]
pub mod netjail;
pub mod peer;
pub mod topology;

use gnunet_wire::testing::{BarrierKey, FromHelper, Init, ToHelper};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    ffi::CStr,
    fmt, io,
    num::NonZeroU32,
    process::Command,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};

const MAX_HELPERS: usize = 64;
const MAX_BARRIERS: usize = 128;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

/// A nonzero number of reaches of one named GNUnet barrier from one helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reaches {
    key: BarrierKey,
    count: NonZeroU32,
}

impl Reaches {
    /// Hash the barrier name using the same bytes as the official interpreter.
    pub fn named(name: &CStr, count: NonZeroU32) -> Self {
        let hash = gnunet_crypto::hash512(name.to_bytes());
        let mut key = [0; size_of::<BarrierKey>()];
        key.copy_from_slice(&hash[..size_of::<BarrierKey>()]);
        Self { key, count }
    }
}

/// A helper command and the barrier contributions this process owns.
pub struct Helper {
    command: Command,
    pending: BTreeMap<BarrierKey, NonZeroU32>,
}

impl Helper {
    /// Bind a directly supervised helper process to its expected barrier contributions.
    /// The driver replaces stdin and stdout with dedicated protocol pipes.
    pub fn new(command: Command, reaches: &[Reaches]) -> Result<Self, RunError> {
        if reaches.len() > MAX_BARRIERS {
            return Err(RunError::Plan("too many barrier contributions"));
        }
        let mut pending = BTreeMap::new();
        for reach in reaches {
            if pending.insert(reach.key, reach.count).is_some() {
                return Err(RunError::Plan("duplicate contribution from one helper"));
            }
        }
        Ok(Self { command, pending })
    }
}

/// The first error observed while running the original helper set.
#[derive(Debug)]
pub enum RunError {
    /// The command and barrier plan is invalid.
    Plan(&'static str),
    /// The original run deadline expired.
    Deadline,
    /// All reporting sources retired before the declared run finished.
    HelpersStopped,
    /// A helper pipe or message failed.
    Helper {
        /// Zero-based helper position in the input set.
        index: usize,
        /// Failure reported by the transport or driver.
        source: io::Error,
    },
    /// A helper task failed before reporting a process result.
    Task(tokio::task::JoinError),
    /// Retiring the original helpers also failed after the run failed.
    Cleanup {
        /// The original run failure.
        failure: Box<Self>,
        /// The first retirement failure, or the elapsed cleanup deadline.
        source: io::Error,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(reason) => write!(formatter, "invalid TESTING plan: {reason}"),
            Self::Deadline => formatter.write_str("TESTING deadline expired"),
            Self::HelpersStopped => formatter.write_str("TESTING helper reports ended prematurely"),
            Self::Helper { index, source } => write!(formatter, "TESTING helper {index}: {source}"),
            Self::Task(error) => write!(formatter, "TESTING helper task: {error}"),
            Self::Cleanup { failure, source } => {
                write!(formatter, "{failure} (retirement: {source})")
            }
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Helper { source, .. } => Some(source),
            Self::Task(error) => Some(error),
            Self::Cleanup { failure, .. } => Some(failure.as_ref()),
            Self::Plan(_) | Self::Deadline | Self::HelpersStopped => None,
        }
    }
}

struct Worker {
    release: mpsc::Sender<BarrierKey>,
    phase: WorkerPhase,
}

enum WorkerPhase {
    Active(BTreeMap<BarrierKey, NonZeroU32>),
    Finished,
}

fn reached(map: &mut BTreeMap<BarrierKey, NonZeroU32>, key: BarrierKey) -> io::Result<bool> {
    let Entry::Occupied(mut entry) = map.entry(key) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected barrier reach",
        ));
    };
    if let Some(remaining) = NonZeroU32::new(entry.get().get() - 1) {
        entry.insert(remaining);
        Ok(false)
    } else {
        entry.remove();
        Ok(true)
    }
}

fn barrier_totals<'a>(
    helpers: impl IntoIterator<Item = &'a Helper>,
) -> Result<BTreeMap<BarrierKey, NonZeroU32>, RunError> {
    let mut totals = BTreeMap::<_, NonZeroU32>::new();
    for helper in helpers {
        for (&key, &count) in &helper.pending {
            match totals.entry(key) {
                Entry::Occupied(mut entry) => {
                    let total = entry
                        .get()
                        .checked_add(count.get())
                        .ok_or(RunError::Plan("barrier count overflow"))?;
                    entry.insert(total);
                }
                Entry::Vacant(entry) => {
                    entry.insert(count);
                    if totals.len() > MAX_BARRIERS {
                        return Err(RunError::Plan("too many barriers"));
                    }
                }
            }
        }
    }
    Ok(totals)
}

fn receive(
    workers: &mut [Worker],
    totals: &mut BTreeMap<BarrierKey, NonZeroU32>,
    index: usize,
    message: FromHelper,
) -> io::Result<bool> {
    let worker = &mut workers[index];
    let WorkerPhase::Active(pending) = &mut worker.phase else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "helper reported after finishing",
        ));
    };
    match message {
        FromHelper::Finished(1) if pending.is_empty() => {
            worker.phase = WorkerPhase::Finished;
            Ok(true)
        }
        FromHelper::Finished(1) => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "helper finished before its required reaches",
        )),
        FromHelper::Finished(status) => Err(io::Error::other(format!(
            "helper reported GNUnet result {status}"
        ))),
        FromHelper::BarrierReached(key) => {
            reached(pending, key)?;
            if reached(totals, key)? {
                for worker in workers
                    .iter()
                    .filter(|worker| matches!(worker.phase, WorkerPhase::Active(_)))
                {
                    match worker.release.try_send(key) {
                        Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            return Err(io::Error::other("helper barrier release queue exhausted"));
                        }
                    }
                }
            }
            Ok(false)
        }
    }
}

/// Run an enrolled set of GNUnet command helpers over their dedicated pipes.
/// The factory supplies one configured command for each peer in launch order.
/// The driver uses the original topology bytes and reaps its direct children.
/// Call with an absolute deadline on a Tokio runtime with process I/O and time
/// enabled.
pub async fn run_helpers(
    topology: &topology::Topology,
    prepare: impl FnMut(&topology::Node) -> Result<Helper, RunError>,
    deadline: Instant,
) -> Result<(), RunError> {
    run_helpers_with(
        topology,
        prepare,
        |_, command| helper::Process::start(command),
        deadline,
    )
    .await
}

async fn run_helpers_with(
    topology: &topology::Topology,
    mut prepare: impl FnMut(&topology::Node) -> Result<Helper, RunError>,
    mut start: impl FnMut(&topology::Node, Command) -> io::Result<helper::Process>,
    deadline: Instant,
) -> Result<(), RunError> {
    if !(1..=MAX_HELPERS).contains(&topology.peer_count()) {
        return Err(RunError::Plan("helper count outside 1..=64"));
    }
    if Instant::now() >= deadline {
        return Err(RunError::Deadline);
    }
    let helpers = topology
        .peers()
        .map(|node| Ok((node, prepare(node)?)))
        .collect::<Result<Vec<_>, RunError>>()?;
    let mut totals = barrier_totals(helpers.iter().map(|(_, helper)| helper))?;
    let keys: Vec<_> = totals.keys().copied().collect();
    let init = Init::new(&keys, topology.source())
        .map_err(|_| RunError::Plan("topology frame too large"))?;
    let frame = ToHelper::Init(init);
    let mut bytes = vec![0; frame.encoded_len()];
    let _size = frame
        .encode(&mut bytes)
        .map_err(|_| RunError::Plan("invalid topology frame"))?;
    let init: Arc<[u8]> = bytes.into();
    let (events, mut incoming) = mpsc::channel(helpers.len());
    let (cancel, cancelled) = watch::channel(false);
    let mut jobs = JoinSet::new();

    let driven = timeout_at(deadline, async {
        let mut workers = Vec::with_capacity(helpers.len());
        for (index, (node, helper)) in helpers.into_iter().enumerate() {
            if Instant::now() >= deadline {
                return Err(RunError::Deadline);
            }
            let child =
                start(node, helper.command).map_err(|source| RunError::Helper { index, source })?;
            let (release, replies) = mpsc::channel(keys.len().max(1));
            jobs.spawn(child.run(
                index,
                init.clone(),
                replies,
                events.clone(),
                cancelled.clone(),
            ));
            workers.push(Worker {
                release,
                phase: WorkerPhase::Active(helper.pending),
            });
        }
        drop(events);

        let mut outstanding = workers.len();
        let mut has_senders = true;
        while outstanding != 0 {
            if !has_senders && jobs.is_empty() {
                return Err(RunError::HelpersStopped);
            }
            tokio::select! {
                event = incoming.recv(), if has_senders => {
                    let Some((index, message)) = event else {
                        has_senders = false;
                        continue;
                    };
                    if receive(&mut workers, &mut totals, index, message)
                        .map_err(|source| RunError::Helper { index, source })? {
                        outstanding -= 1;
                    }
                }
                joined = jobs.join_next(), if !jobs.is_empty() => {
                    if let Some(result) = joined {
                        result.map_err(RunError::Task)?.complete()?;
                    }
                }
            }
        }
        while let Some(joined) = jobs.join_next().await {
            joined.map_err(RunError::Task)?.complete()?;
        }
        Ok(())
    })
    .await
    .unwrap_or(Err(RunError::Deadline));

    let Err(failure) = driven else { return Ok(()) };
    let _previous = cancel.send_replace(true);
    let cleanup = timeout(CLEANUP_TIMEOUT, async {
        let mut first_error = None;
        while let Some(joined) = jobs.join_next().await {
            let result = joined
                .map_err(RunError::Task)
                .and_then(helper::Exit::retirement);
            if first_error.is_none() {
                first_error = result.err();
            }
        }
        first_error.map_or(Ok(()), |error| Err(io::Error::other(error)))
    })
    .await;
    match cleanup {
        Ok(Ok(())) => Err(failure),
        Ok(Err(source)) => Err(RunError::Cleanup {
            failure: Box::new(failure),
            source,
        }),
        Err(elapsed) => Err(RunError::Cleanup {
            failure: Box::new(failure),
            source: io::Error::new(io::ErrorKind::TimedOut, elapsed),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrier_counts_belong_to_the_original_helper() -> Result<(), RunError> {
        let reach = Reaches::named(c"ready", NonZeroU32::MIN);
        let helpers = [
            Helper::new(Command::new("first"), &[reach])?,
            Helper::new(Command::new("second"), &[reach])?,
        ];
        let mut totals = barrier_totals(&helpers)?;
        let (first, mut first_release) = mpsc::channel(1);
        let (second, mut second_release) = mpsc::channel(1);
        let mut workers = Vec::new();
        for (helper, release) in helpers.into_iter().zip([first, second]) {
            workers.push(Worker {
                release,
                phase: WorkerPhase::Active(helper.pending),
            });
        }
        let reach_message = FromHelper::BarrierReached(reach.key);
        let report = |workers: &mut [Worker], totals: &mut _, index, event| {
            receive(workers, totals, index, event)
                .map_err(|source| RunError::Helper { index, source })
        };
        if report(&mut workers, &mut totals, 0, reach_message)?
            || report(&mut workers, &mut totals, 0, reach_message).is_ok()
            || first_release.try_recv().is_ok()
        {
            return Err(RunError::Plan("duplicate report crossed the barrier"));
        }
        if report(&mut workers, &mut totals, 1, FromHelper::Finished(1)).is_ok() {
            return Err(RunError::Plan("premature success accepted"));
        }
        if report(&mut workers, &mut totals, 1, reach_message)?
            || first_release.try_recv() != Ok(reach.key)
            || second_release.try_recv() != Ok(reach.key)
        {
            return Err(RunError::Plan(
                "barrier did not release every live participant",
            ));
        }
        Ok(())
    }
}
