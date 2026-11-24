//! Bounded local command plans and the lifetime of their running actions.

use super::PeerError;
use gnunet_wire::testing::BarrierKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CStr,
    future::{Future, poll_fn},
    io,
    num::NonZeroU32,
    pin::{Pin, pin},
    process::{Command, ExitStatus, Stdio},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{process::Child, time::timeout};

const MAX_STEPS: usize = 1024;
const MAX_BACKGROUND: usize = 64;

/// Ordered TESTING commands prepared by the local helper application.
/// All background tasks must have one finish step before the program can run.
#[derive(Default)]
pub struct Program {
    origin: Arc<()>,
    next_task: usize,
    pending: BTreeSet<usize>,
    peak_background: usize,
    steps: Vec<Step>,
}

/// The unconsumed completion of an original locally declared task.
#[must_use = "finish this task in the program that started it"]
pub struct Task {
    origin: Arc<()>,
    index: usize,
}

/// Expected disposition of a locally configured executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedExit {
    /// The process exited with this code.
    Code(i32),
    /// The process was terminated by this Unix signal.
    #[cfg(unix)]
    Signal(i32),
}

impl ExpectedExit {
    fn matches(self, actual: ExitStatus) -> bool {
        match self {
            Self::Code(expected) => actual.code() == Some(expected),
            #[cfg(unix)]
            Self::Signal(expected) => {
                use std::os::unix::process::ExitStatusExt;
                actual.signal() == Some(expected)
            }
        }
    }
}

impl Program {
    /// Create an empty command plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a local asynchronous command that must complete before continuing.
    pub fn run(
        &mut self,
        action: impl Future<Output = io::Result<()>> + Send + 'static,
    ) -> io::Result<()> {
        self.push(Step::Run(Action::Future(Box::pin(action))))
    }

    /// Add an executable and the exact result that permits the program to continue.
    /// Native executable steps use null stdin and stdout to protect helper framing.
    pub fn exec(&mut self, command: Command, expected: ExpectedExit) -> io::Result<()> {
        self.push(Step::Run(Action::Process { command, expected }))
    }

    /// Add a local asynchronous command that can progress while later steps run.
    pub fn start(
        &mut self,
        action: impl Future<Output = io::Result<()>> + Send + 'static,
    ) -> io::Result<Task> {
        self.start_action(Action::Future(Box::pin(action)))
    }

    /// Start a local executable as a background task with an exact expected result.
    /// Native executable steps use null stdin and stdout to protect helper framing.
    pub fn start_process(&mut self, command: Command, expected: ExpectedExit) -> io::Result<Task> {
        self.start_action(Action::Process { command, expected })
    }

    /// Wait for the original background task, using a positive relative timeout.
    pub fn finish(&mut self, task: Task, limit: Duration) -> io::Result<()> {
        if !Arc::ptr_eq(&self.origin, &task.origin) || !self.pending.contains(&task.index) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "task belongs to another program",
            ));
        }
        if limit.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "finish timeout must be positive",
            ));
        }
        self.push(Step::Finish {
            index: task.index,
            limit,
        })?;
        let _removed = self.pending.remove(&task.index);
        Ok(())
    }

    /// Append a complete command batch, retaining its internal dependencies.
    pub fn batch(&mut self, batch: Self) -> io::Result<()> {
        if !batch.pending.is_empty() {
            return Err(missing_finish());
        }
        let batch_peak = self.pending.len() + batch.peak_background;
        if self.steps.len() + batch.steps.len() > MAX_STEPS || batch_peak > MAX_BACKGROUND {
            return Err(plan_capacity());
        }
        let origin = self.next_task;
        self.steps.extend(batch.steps.into_iter().map(|mut step| {
            match &mut step {
                Step::Start { index, .. } | Step::Finish { index, .. } => *index += origin,
                _ => {}
            }
            step
        }));
        self.next_task += batch.next_task;
        self.peak_background = self.peak_background.max(batch_peak);
        Ok(())
    }

    /// Signal one local reach of an inherited barrier and continue.
    pub fn reach(&mut self, name: &CStr) -> io::Result<()> {
        self.barrier(name, BarrierMode::Reach)
    }

    /// Wait until the controller releases an inherited barrier.
    pub fn wait(&mut self, name: &CStr) -> io::Result<()> {
        self.barrier(name, BarrierMode::Wait)
    }

    /// Signal one local reach and wait for the inherited barrier's release.
    pub fn reach_and_wait(&mut self, name: &CStr) -> io::Result<()> {
        self.barrier(name, BarrierMode::ReachAndWait)
    }

    fn barrier(&mut self, name: &CStr, mode: BarrierMode) -> io::Result<()> {
        let key = super::super::Reaches::named(name, NonZeroU32::MIN).key;
        self.push(Step::Barrier { key, mode })
    }

    fn start_action(&mut self, action: Action) -> io::Result<Task> {
        if self.pending.len() >= MAX_BACKGROUND {
            return Err(plan_capacity());
        }
        let index = self.next_task;
        self.push(Step::Start { index, action })?;
        self.next_task += 1;
        let _inserted = self.pending.insert(index);
        self.peak_background = self.peak_background.max(self.pending.len());
        Ok(Task {
            origin: self.origin.clone(),
            index,
        })
    }

    fn push(&mut self, step: Step) -> io::Result<()> {
        if self.steps.len() >= MAX_STEPS {
            return Err(plan_capacity());
        }
        self.steps.push(step);
        Ok(())
    }

    pub(super) fn bind(self, inherited: impl Fn(&BarrierKey) -> bool) -> io::Result<Vec<Step>> {
        if !self.pending.is_empty() {
            return Err(missing_finish());
        }
        if self
            .steps
            .iter()
            .any(|step| matches!(step, Step::Barrier { key, .. } if !inherited(key)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "program uses a barrier the controller did not inherit",
            ));
        }
        Ok(self.steps)
    }
}

fn plan_capacity() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "TESTING program capacity exceeded",
    )
}

fn missing_finish() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "background TESTING task has no finish step",
    )
}

pub(super) enum BarrierMode {
    Reach,
    Wait,
    ReachAndWait,
}

impl BarrierMode {
    pub(super) fn signals(&self) -> bool {
        matches!(self, Self::Reach | Self::ReachAndWait)
    }

    pub(super) fn waits(&self) -> bool {
        matches!(self, Self::Wait | Self::ReachAndWait)
    }
}

pub(super) enum Step {
    Run(Action),
    Start { index: usize, action: Action },
    Finish { index: usize, limit: Duration },
    Barrier { key: BarrierKey, mode: BarrierMode },
}

type ActionFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

pub(super) enum Action {
    Future(ActionFuture),
    Process {
        command: Command,
        expected: ExpectedExit,
    },
}

impl Action {
    fn start(self) -> io::Result<Running> {
        match self {
            Self::Future(future) => Ok(Running::Future(future)),
            Self::Process { command, expected } => {
                let child = tokio::process::Command::from(command)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()?;
                Ok(Running::Process {
                    child: Box::new(child),
                    expected,
                })
            }
        }
    }
}

enum Running {
    Future(ActionFuture),
    Process {
        child: Box<Child>,
        expected: ExpectedExit,
    },
    Complete,
}

impl Running {
    fn poll(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Future(future) => future.as_mut().poll(context),
            Self::Process { child, expected } => pin!(child.wait()).poll(context).map(|result| {
                result.and_then(|actual| {
                    if expected.matches(actual) {
                        Ok(())
                    } else {
                        Err(io::Error::other(format!(
                            "unexpected process result {actual}; expected {expected:?}"
                        )))
                    }
                })
            }),
            Self::Complete => Poll::Ready(Ok(())),
        }
    }

    fn cancel(&mut self) -> io::Result<()> {
        if let Self::Process { child, .. } = self {
            if let Err(error) = child.start_kill()
                && child.try_wait()?.is_none()
            {
                return Err(error);
            }
        } else {
            *self = Self::Complete;
        }
        Ok(())
    }

    async fn reap(&mut self) -> io::Result<()> {
        if let Self::Process { child, .. } = self {
            let _status = child.wait().await?;
            *self = Self::Complete;
        }
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct Execution {
    foreground: Option<Running>,
    background: BTreeMap<usize, Running>,
}

impl Execution {
    pub(super) fn start(&mut self, index: usize, action: Action) -> Result<(), PeerError> {
        let action = action.start().map_err(PeerError::Command)?;
        let _old = self.background.insert(index, action);
        Ok(())
    }

    pub(super) async fn run(&mut self, action: Action) -> Result<(), PeerError> {
        let foreground = self
            .foreground
            .insert(action.start().map_err(PeerError::Command)?);
        let complete = poll_fn(|context| {
            foreground
                .poll(context)
                .map(|result| result.map_err(PeerError::Command))
        });
        with_background(&mut self.background, complete).await?;
        self.foreground = None;
        Ok(())
    }

    pub(super) async fn finish(&mut self, index: usize, limit: Duration) -> Result<(), PeerError> {
        timeout(
            limit,
            poll_fn(|context| {
                poll_background(&mut self.background, context)?;
                if matches!(self.background.get(&index), Some(Running::Complete)) {
                    let _completed = self.background.remove(&index);
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }),
        )
        .await
        .map_err(|elapsed| PeerError::Command(io::Error::new(io::ErrorKind::TimedOut, elapsed)))?
    }

    pub(super) async fn with_background<T>(
        &mut self,
        action: impl Future<Output = Result<T, PeerError>>,
    ) -> Result<T, PeerError> {
        with_background(&mut self.background, action).await
    }

    pub(super) async fn retire(&mut self) -> io::Result<()> {
        let mut first_error = None;
        for action in self
            .foreground
            .iter_mut()
            .chain(self.background.values_mut())
        {
            if let Err(error) = action.cancel()
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        for action in self
            .foreground
            .iter_mut()
            .chain(self.background.values_mut())
        {
            if let Err(error) = action.reap().await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn poll_background(
    background: &mut BTreeMap<usize, Running>,
    context: &mut Context<'_>,
) -> Result<(), PeerError> {
    for action in background.values_mut() {
        if let Poll::Ready(result) = action.poll(context) {
            result.map_err(PeerError::Command)?;
            *action = Running::Complete;
        }
    }
    Ok(())
}

async fn with_background<T>(
    background: &mut BTreeMap<usize, Running>,
    action: impl Future<Output = Result<T, PeerError>>,
) -> Result<T, PeerError> {
    let mut action = pin!(action);
    poll_fn(|context| {
        poll_background(background, context)?;
        action.as_mut().poll(context)
    })
    .await
}
