//! Native peer-side TESTING programs over the official command-helper pipes.

mod program;

use super::{MAX_BARRIERS, topology::Topology};
use gnunet_wire::{
    HEADER_LEN, MessageHeader,
    testing::{BarrierKey, FromHelper, ToHelper},
};
use program::{Execution, Step};
use std::{collections::BTreeMap, fmt, future::Future, io, pin::pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout, timeout_at},
};

pub use program::{ExpectedExit, Program, Task};

const BARRIER_FRAME_LEN: usize = HEADER_LEN + size_of::<BarrierKey>();
const RETIREMENT_TIMEOUT: Duration = Duration::from_secs(2);

/// Failure from the original peer program, its controller, or local retirement.
#[derive(Debug)]
pub enum PeerError {
    /// The original command-helper pipe could not be read or written.
    Pipe(io::Error),
    /// The controller supplied an invalid command-helper frame.
    Protocol(gnunet_types::Error),
    /// The controller's initialization topology is invalid.
    Topology(super::topology::Error),
    /// The local program could not be prepared or bound to the inherited barriers.
    Plan(io::Error),
    /// A local native command or asynchronous action failed.
    Command(io::Error),
    /// The original execution deadline expired.
    Deadline,
    /// The original controller disconnected before the program completed.
    ParentClosed,
    /// Independent cleanup or result delivery also failed.
    Retirement {
        /// The original failure.
        failure: Box<Self>,
        /// The subsequent failure.
        source: Box<Self>,
    },
}

impl fmt::Display for PeerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pipe(error) => write!(formatter, "TESTING helper pipe: {error}"),
            Self::Protocol(error) => write!(formatter, "TESTING helper protocol: {error}"),
            Self::Topology(error) => write!(formatter, "TESTING helper topology: {error}"),
            Self::Plan(error) => write!(formatter, "TESTING helper plan: {error}"),
            Self::Command(error) => write!(formatter, "TESTING helper command: {error}"),
            Self::Deadline => formatter.write_str("TESTING helper deadline expired"),
            Self::ParentClosed => formatter.write_str("TESTING controller disconnected"),
            Self::Retirement { failure, source } => {
                write!(formatter, "{failure} (retirement: {source})")
            }
        }
    }
}

impl std::error::Error for PeerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pipe(error) | Self::Plan(error) | Self::Command(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Topology(error) => Some(error),
            Self::Retirement { failure, .. } => Some(failure.as_ref()),
            Self::Deadline | Self::ParentClosed => None,
        }
    }
}

/// Run one locally defined TESTING program against an original controller.
///
/// The first frame supplies the topology and inherited barrier hashes. The
/// caller supplies the program factory when starting the helper. Its commands
/// are bound to that local program before any action is polled or process spawned.
/// Give the function dedicated protocol streams and a Tokio process/time runtime.
/// Explicit failure retires native children before reporting the GNUnet result.
/// Dropping this future drops local actions and requests termination of native
/// children through their process owners.
pub async fn serve(
    mut input: impl AsyncRead + Unpin,
    output: impl AsyncWrite + Unpin,
    prepare: impl FnOnce(&Topology) -> io::Result<Program>,
    deadline: Instant,
) -> Result<(), PeerError> {
    if Instant::now() >= deadline {
        return Err(PeerError::Deadline);
    }
    let bytes = timeout_at(deadline, read_init(&mut input))
        .await
        .map_err(|_| PeerError::Deadline)??;
    let ToHelper::Init(init) = ToHelper::decode(&bytes).map_err(PeerError::Protocol)? else {
        return Err(PeerError::Protocol(gnunet_types::Error::Malformed));
    };
    let mut controller = Controller::new(input, init.barriers())?;
    let mut reporter = Reporter::new(output);
    let plan = Topology::parse(init.topology().to_bytes())
        .map_err(PeerError::Topology)
        .and_then(|topology| prepare(&topology).map_err(PeerError::Plan))
        .and_then(|program| {
            program
                .bind(|key| controller.inherits(key))
                .map_err(PeerError::Plan)
        });
    drop(bytes);

    let mut execution = Execution::default();
    let result = match plan {
        Ok(steps) => timeout_at(
            deadline,
            run(steps, &mut execution, &mut controller, &mut reporter),
        )
        .await
        .unwrap_or(Err(PeerError::Deadline)),
        Err(error) => Err(error),
    };
    if result.is_err() {
        let cleanup = match timeout(RETIREMENT_TIMEOUT, execution.retire()).await {
            Ok(result) => result.map_err(PeerError::Command),
            Err(elapsed) => Err(PeerError::Command(io::Error::new(
                io::ErrorKind::TimedOut,
                elapsed,
            ))),
        };
        let can_report = matches!(
            result,
            Err(PeerError::Plan(_) | PeerError::Topology(_) | PeerError::Command(_))
        );
        let result = combine(result, cleanup);
        if !can_report || Instant::now() >= deadline {
            return result;
        }
        reporter.discard_unsent();
        return combine(
            result,
            report_and_wait(&mut controller, &mut reporter, -1, deadline).await,
        );
    }
    report_and_wait(&mut controller, &mut reporter, 1, deadline).await
}

fn combine(result: Result<(), PeerError>, cleanup: Result<(), PeerError>) -> Result<(), PeerError> {
    match (result, cleanup) {
        (Ok(()), other) | (other, Ok(())) => other,
        (Err(failure), Err(source)) => Err(PeerError::Retirement {
            failure: Box::new(failure),
            source: Box::new(source),
        }),
    }
}

async fn run(
    steps: Vec<Step>,
    execution: &mut Execution,
    controller: &mut Controller<impl AsyncRead + Unpin>,
    reporter: &mut Reporter<impl AsyncWrite + Unpin>,
) -> Result<(), PeerError> {
    for step in steps {
        match step {
            Step::Run(action) => controller.drive(execution.run(action)).await?,
            Step::Start { index, action } => {
                controller
                    .drive(async { execution.start(index, action) })
                    .await?
            }
            Step::Finish { index, limit } => {
                controller.drive(execution.finish(index, limit)).await?
            }
            Step::Barrier { key, mode } => {
                if mode.signals() && !controller.is_crossable(key)? {
                    let report = controller.drive(reporter.send(FromHelper::BarrierReached(key)));
                    execution.with_background(report).await?;
                }
                if mode.waits() {
                    execution.with_background(controller.wait(key)).await?;
                }
            }
        }
    }
    Ok(())
}

async fn read_init(input: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, PeerError> {
    let mut header = [0; HEADER_LEN];
    input
        .read_exact(&mut header)
        .await
        .map_err(PeerError::Pipe)?;
    let message = MessageHeader::decode(&header).map_err(PeerError::Protocol)?;
    if message.message_type() != gnunet_wire::message_type::CMDS_HELPER_INIT {
        return Err(PeerError::Protocol(gnunet_types::Error::Malformed));
    }
    let mut bytes = vec![0; message.size()];
    bytes[..HEADER_LEN].copy_from_slice(&header);
    input
        .read_exact(&mut bytes[HEADER_LEN..])
        .await
        .map_err(PeerError::Pipe)?;
    Ok(bytes)
}

struct Controller<R> {
    input: R,
    frame: [u8; BARRIER_FRAME_LEN],
    used: usize,
    inherited: BTreeMap<BarrierKey, bool>,
}

impl<R: AsyncRead + Unpin> Controller<R> {
    fn new(input: R, keys: &[BarrierKey]) -> Result<Self, PeerError> {
        if keys.len() > MAX_BARRIERS {
            return Err(PeerError::Protocol(gnunet_types::Error::TooLarge));
        }
        let inherited: BTreeMap<_, _> = keys.iter().map(|key| (*key, false)).collect();
        if inherited.len() != keys.len() {
            return Err(PeerError::Protocol(gnunet_types::Error::Malformed));
        }
        Ok(Self {
            input,
            frame: [0; BARRIER_FRAME_LEN],
            used: 0,
            inherited,
        })
    }

    fn inherits(&self, key: &BarrierKey) -> bool {
        self.inherited.contains_key(key)
    }

    fn is_crossable(&self, key: BarrierKey) -> Result<bool, PeerError> {
        self.inherited
            .get(&key)
            .copied()
            .ok_or(PeerError::Protocol(gnunet_types::Error::Malformed))
    }

    async fn fill(&mut self, size: usize) -> Result<bool, PeerError> {
        // Preserve partial frames when another branch wins a select.
        while self.used < size {
            let count = self
                .input
                .read(&mut self.frame[self.used..size])
                .await
                .map_err(PeerError::Pipe)?;
            if count == 0 {
                return if self.used == 0 {
                    Ok(false)
                } else {
                    Err(PeerError::Protocol(gnunet_types::Error::Truncated))
                };
            }
            self.used += count;
        }
        Ok(true)
    }

    async fn receive_release(&mut self) -> Result<bool, PeerError> {
        if !self.fill(HEADER_LEN).await? {
            return Ok(false);
        }
        let header = MessageHeader::decode(&self.frame).map_err(PeerError::Protocol)?;
        if header.size() != BARRIER_FRAME_LEN
            || header.message_type() != gnunet_wire::message_type::CMDS_HELPER_BARRIER_CROSSABLE
        {
            return Err(PeerError::Protocol(gnunet_types::Error::Malformed));
        }
        self.fill(BARRIER_FRAME_LEN).await?;
        let ToHelper::BarrierCrossable(key) =
            ToHelper::decode(&self.frame).map_err(PeerError::Protocol)?
        else {
            return Err(PeerError::Protocol(gnunet_types::Error::Malformed));
        };
        self.used = 0;
        let released = self
            .inherited
            .get_mut(&key)
            .ok_or(PeerError::Protocol(gnunet_types::Error::Malformed))?;
        if std::mem::replace(released, true) {
            return Err(PeerError::Protocol(gnunet_types::Error::Malformed));
        }
        Ok(true)
    }

    async fn drive<T>(
        &mut self,
        action: impl Future<Output = Result<T, PeerError>>,
    ) -> Result<T, PeerError> {
        let mut action = pin!(action);
        loop {
            tokio::select! {
                biased;
                message = self.receive_release() => {
                    if !message? { return Err(PeerError::ParentClosed) }
                }
                result = &mut action => return result,
            }
        }
    }

    async fn wait(&mut self, key: BarrierKey) -> Result<(), PeerError> {
        while !self.is_crossable(key)? {
            if !self.receive_release().await? {
                return Err(PeerError::ParentClosed);
            }
        }
        Ok(())
    }
}

struct Reporter<W> {
    output: W,
    frame: [u8; BARRIER_FRAME_LEN],
    written: usize,
    size: usize,
}

impl<W: AsyncWrite + Unpin> Reporter<W> {
    fn new(output: W) -> Self {
        Self {
            output,
            frame: [0; BARRIER_FRAME_LEN],
            written: 0,
            size: 0,
        }
    }

    fn discard_unsent(&mut self) {
        if self.written == 0 {
            self.size = 0;
        }
    }

    async fn send(&mut self, message: FromHelper) -> Result<(), PeerError> {
        // A local failure may interrupt a reach report. Its written prefix must
        // remain part of the same frame before the result is sent.
        if self.size != 0 {
            self.flush_frame().await?;
        }
        self.size = message
            .encode(&mut self.frame)
            .map_err(PeerError::Protocol)?;
        self.flush_frame().await
    }

    async fn flush_frame(&mut self) -> Result<(), PeerError> {
        while self.written < self.size {
            let count = self
                .output
                .write(&self.frame[self.written..self.size])
                .await
                .map_err(PeerError::Pipe)?;
            if count == 0 {
                return Err(PeerError::Pipe(io::ErrorKind::WriteZero.into()));
            }
            self.written += count;
        }
        self.output.flush().await.map_err(PeerError::Pipe)?;
        self.written = 0;
        self.size = 0;
        Ok(())
    }
}

async fn report_and_wait(
    controller: &mut Controller<impl AsyncRead + Unpin>,
    reporter: &mut Reporter<impl AsyncWrite + Unpin>,
    status: i32,
    deadline: Instant,
) -> Result<(), PeerError> {
    timeout_at(deadline, async {
        let mut report = pin!(reporter.send(FromHelper::Finished(status)));
        loop {
            tokio::select! {
                result = &mut report => { result?; break; }
                message = controller.receive_release() => {
                    // The result might already be visible while its output flush
                    // is still pending. Acknowledge EOF after completing it.
                    if !message? { return report.await; }
                }
            }
        }
        while controller.receive_release().await? {}
        Ok(())
    })
    .await
    .unwrap_or(Err(PeerError::Deadline))
}

#[cfg(test)]
mod tests;
