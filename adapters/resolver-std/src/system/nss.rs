//! Cancellable Linux and FreeBSD name-service queries in the original child.
mod lookup;
mod protocol;

use self::protocol::{
    MAX_QUERY_BYTES, MAX_REPLY_BYTES, encode_question, read_question, read_reply,
};
use super::{Answer, Question};
use std::{
    ffi::OsString,
    future::{Future, pending},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    pin::Pin,
    process::{ExitStatus, Stdio},
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    runtime::{Builder, Handle},
    sync::{OwnedSemaphorePermit, oneshot},
};

pub(super) const MAX_OPERATIONS: usize = 16;
pub(super) const WORKER_ARGUMENT: &str = "--internal-resolver-worker";

type Outcome = io::Result<Vec<Answer>>;
type Reply = oneshot::Sender<Outcome>;

// Reaping must remain live after the originating node's reactor is dropped.
// Admission happens before spawning work and stays with each child until wait.
static SUPERVISOR: LazyLock<io::Result<Handle>> = LazyLock::new(|| {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let handle = runtime.handle().clone();
    let _thread = std::thread::Builder::new()
        .name("gnunet-resolver-processes".into())
        .spawn(move || runtime.block_on(pending::<()>()))?;
    Ok(handle)
});

pub(super) struct Worker {
    program: Arc<Path>,
}

impl Worker {
    pub(super) fn new(program: PathBuf) -> io::Result<Self> {
        if !program.is_absolute() || !program.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "system DNS worker requires a trusted absolute executable path",
            ));
        }
        Ok(Self {
            program: Arc::from(program),
        })
    }

    pub(super) fn start(
        &self,
        question: Question<'_>,
        limit: usize,
        permit: OwnedSemaphorePermit,
    ) -> io::Result<Request> {
        let supervisor = SUPERVISOR
            .as_ref()
            .map_err(|error| io::Error::new(error.kind(), error.to_string()))?;
        let mut request = [0; MAX_QUERY_BYTES];
        let size = encode_question(question, &mut request)?;
        let (sender, receiver) = oneshot::channel();
        // Only the supervisor consumes the Child and its admission permit.
        let _task = supervisor.spawn(
            Job {
                program: Arc::clone(&self.program),
                request,
                size,
                limit,
                _permit: permit,
            }
            .run(sender),
        );
        Ok(Request(receiver))
    }
}

pub(super) struct Request(oneshot::Receiver<Outcome>);

impl Request {
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Outcome> {
        Pin::new(&mut self.0).poll(cx).map(|received| {
            received.unwrap_or_else(|_| Err(io::Error::other("system DNS worker response lost")))
        })
    }
}

struct Job {
    program: Arc<Path>,
    request: [u8; MAX_QUERY_BYTES],
    size: usize,
    limit: usize,
    _permit: OwnedSemaphorePermit,
}

impl Job {
    async fn run(self, mut sender: Reply) {
        if !sender.is_closed() {
            let outcome = self.supervise(&mut sender).await;
            let _sent = sender.send(outcome);
        }
    }

    fn spawn(&self) -> io::Result<Child> {
        Command::new(self.program.as_ref())
            .arg(WORKER_ARGUMENT)
            .arg(std::process::id().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("NOTIFY_SOCKET")
            .env_remove("WATCHDOG_PID")
            .env_remove("WATCHDOG_USEC")
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDS")
            .env_remove("LISTEN_FDNAMES")
            .spawn()
    }

    async fn supervise(&self, sender: &mut Reply) -> Outcome {
        let question_bytes = &self.request[..self.size];
        let question = read_question(question_bytes)?;
        let mut child = self.spawn()?;
        let exchange = tokio::select! {
            biased;
            () = sender.closed() => Err(io::ErrorKind::Interrupted.into()),
            result = exchange(&mut child, question_bytes) => result,
        };
        let response = match exchange {
            Ok(response) => response,
            Err(error) => {
                terminate(&mut child).await?;
                return Err(error);
            }
        };
        let status = tokio::select! {
            biased;
            () = sender.closed() => {
                terminate(&mut child).await?;
                return Err(io::ErrorKind::Interrupted.into());
            }
            result = wait_original(&mut child) => result?,
        };
        if !status.success() {
            return Err(io::Error::other(format!("system DNS worker {status}")));
        }
        read_reply(&response, question, self.limit)
    }
}

async fn exchange(child: &mut Child, request: &[u8]) -> io::Result<Vec<u8>> {
    let mut input = child.stdin.take().ok_or(io::ErrorKind::BrokenPipe)?;
    input.write_all(request).await?;
    drop(input);
    let output = child.stdout.take().ok_or(io::ErrorKind::BrokenPipe)?;
    let mut response = Vec::new();
    output
        .take((MAX_REPLY_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .await?;
    if response.len() > MAX_REPLY_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(response)
}

async fn wait_original(child: &mut Child) -> io::Result<ExitStatus> {
    loop {
        match child.wait().await {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

async fn terminate(child: &mut Child) -> io::Result<()> {
    // A child already exiting may reject the signal. The consuming wait is
    // required either way. On a failed signal, wait still owns the exact child.
    drop(child.stdin.take());
    drop(child.stdout.take());
    let signal = child.start_kill();
    wait_original(child).await?;
    match signal {
        Err(error) if error.raw_os_error() != Some(libc::ESRCH) => Err(error),
        _ => Ok(()),
    }
}

pub(super) fn serve_worker(
    mut args: impl Iterator<Item = OsString>,
    input: impl Read,
    output: impl Write,
) -> io::Result<()> {
    let parent: libc::pid_t = args
        .next()
        .as_deref()
        .and_then(|argument| argument.to_str()?.parse().ok())
        .filter(|pid| *pid > 0)
        .ok_or(io::ErrorKind::InvalidInput)?;
    if args.next().is_some() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    arm_parent_death(parent)?;
    let mut bytes = Vec::new();
    input
        .take((MAX_QUERY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let question = read_question(&bytes)?;
    protocol::write_reply(
        output,
        lookup::resolve(question, super::ANSWERS_PER_QUESTION),
    )
}

#[expect(
    unsafe_code,
    reason = "Configure death of this child and verify its actual parent"
)]
fn arm_parent_death(parent: libc::pid_t) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    // SAFETY: PR_SET_PDEATHSIG interprets the second argument as a signal.
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::c_ulong::from(libc::SIGKILL as u32),
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    #[cfg(target_os = "freebsd")]
    // SAFETY: PROC_PDEATHSIG_CTL takes a live signal-number pointer for self.
    let result = unsafe {
        let mut signal = libc::SIGKILL;
        libc::procctl(
            libc::P_PID,
            0,
            libc::PROC_PDEATHSIG_CTL,
            (&raw mut signal).cast(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getppid has no arguments or memory obligations. Checking after
    // arming covers reparenting before the original child could set its signal.
    if unsafe { libc::getppid() } != parent {
        return Err(io::ErrorKind::Interrupted.into());
    }
    Ok(())
}
