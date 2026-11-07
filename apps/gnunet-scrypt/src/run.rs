use crate::{
    Failure,
    options::{Delay, Settings},
};
use gnunet_crypto::pow;
use gnunet_nse::crypto;
use gnunet_nse_host::proof::{self, Store};
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_service_startup::{ControlReceiver, ParentControl};
use gnunet_types::AbsoluteTime;
use std::{
    fmt, fs,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::{Instant, Sleep},
};

const ROUND: u8 = 10;
const CHECKPOINT: u128 = 1000;
#[derive(Debug)]
enum Stop {
    Signal(i32),
    Deadline,
    HashLimit,
    Exhausted,
    Logging,
    Clock(gnunet_types::Error),
}
impl fmt::Display for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signal(s) => write!(f, "original proof operation cancelled by signal {s}"),
            Self::Deadline => f.write_str("original proof operation deadline reached"),
            Self::HashLimit => f.write_str("original proof operation hash bound reached"),
            Self::Exhausted => {
                f.write_str("native u64 proof counter exhausted without a valid proof")
            }
            Self::Logging => f.write_str("selected proof Logger failed"),
            Self::Clock(e) => write!(f, "original proof Clock failed: {e}"),
        }
    }
}
impl std::error::Error for Stop {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clock(e) => Some(e),
            _ => None,
        }
    }
}
/// Public work/persistence facts only; no initial private seed is retained here.
#[derive(Debug, Default)]
struct Facts {
    hashes: u128,
    rounds: u128,
    next_counter: u64,
    found: Option<u64>,
    exhausted: bool,
    checkpoints: u128,
    checkpoint_attempts: u128,
    last_committed: Option<u64>,
    persistence_failed: bool,
    persistence_outcome: Option<proof::Outcome>,
    stdout_bytes: u64,
}
#[derive(Debug)]
struct Failed {
    original: Option<Failure>,
    checkpoint: Option<Failure>,
    facts: Facts,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NSE proof original={:?}; independent final checkpoint={:?}; actual facts={:?}",
            self.original, self.checkpoint, self.facts
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref().or(self.checkpoint.as_deref())
    }
}
struct Whole {
    clock: Arc<dyn RuntimeClock>,
    reporter: Reporter,
    expires: Option<AbsoluteTime>,
    hard: Option<Instant>,
    last: AbsoluteTime,
}
impl Whole {
    fn new(
        settings: &Settings,
        clock: Arc<dyn RuntimeClock>,
        reporter: Reporter,
    ) -> Result<Self, Failure> {
        // Native origin precedes the fallible canonical provider, including all
        // synchronous durable preparation. No hash/round/attachment renews it.
        let native = Instant::now();
        let now = clock.sample()?.now;
        let expires = settings
            .lifetime
            .map(|d| {
                let micros =
                    u64::try_from(d.as_micros()).map_err(|_| "proof whole target overflow")?;
                now.as_micros()
                    .checked_add(micros)
                    .map(AbsoluteTime::from_micros)
                    .ok_or("proof whole target overflow")
            })
            .transpose()?;
        let hard = settings
            .lifetime
            .map(|d| {
                native
                    .checked_add(d)
                    .ok_or("proof whole native target overflow")
            })
            .transpose()?;
        let mut whole = Self {
            clock,
            reporter,
            expires,
            hard,
            last: now,
        };
        whole.check()?;
        Ok(whole)
    }
    fn check(&mut self) -> Result<(), Failure> {
        if self.reporter.failed() {
            return Err(Box::new(Stop::Logging));
        }
        if self.hard.is_some_and(|at| Instant::now() >= at) {
            return Err(Box::new(Stop::Deadline));
        }
        let now = self.clock.sample().map_err(Stop::Clock)?.now;
        if now < self.last {
            return Err(Box::new(Stop::Clock(gnunet_types::Error::TimeUncertain)));
        }
        self.last = now;
        if self.expires.is_some_and(|at| now >= at)
            || self.hard.is_some_and(|at| Instant::now() >= at)
        {
            return Err(Box::new(Stop::Deadline));
        }
        Ok(())
    }
    fn preparation(&mut self, parent: &mut Option<ParentControl>) -> Result<(), Failure> {
        if let Some(parent) = parent {
            match parent.try_read_signal() {
                Ok(Some(s)) if s == libc::SIGINT as i8 || s == libc::SIGTERM as i8 => {
                    return Err(Box::new(Stop::Signal(i32::from(s))));
                }
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.check()
    }
}
pub(super) struct Prepared {
    settings: Settings,
    whole: Whole,
    public: [u8; 32],
    store: Store,
    counter: u64,
}
/// This is synchronous key/store startup, before any runtime or worker. All
/// private material is dropped before a Prepared public work snapshot returns.
pub(super) fn prepare(
    settings: Settings,
    clock: Arc<dyn RuntimeClock>,
    reporter: Reporter,
    parent: &mut Option<ParentControl>,
) -> Result<Prepared, Failure> {
    let mut whole = Whole::new(&settings, clock, reporter)?;
    whole.preparation(parent)?;
    let public = match fs::symlink_metadata(&settings.key) {
        Ok(_) => {
            // Existing malformed/disappearing inputs cannot trigger replacement.
            let initial = gnunet_pils_host::identity::load_existing(&settings.key)?;
            *initial.initial_public_key().as_bytes()
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let (initial, lease) = gnunet_pils_host::identity::load_or_create(&settings.key)?;
            let public = *initial.initial_public_key().as_bytes();
            drop(initial);
            drop(lease);
            public
        }
        Err(e) => return Err(e.into()),
    };
    whole.preparation(parent)?;
    let store = Store::open(settings.proof.clone())?;
    whole.preparation(parent)?;
    let counter = store.loaded()?.map(u64::from_ne_bytes).unwrap_or(0);
    whole.preparation(parent)?;
    Ok(Prepared {
        settings,
        whole,
        public,
        store,
        counter,
    })
}
struct Guard {
    whole: Whole,
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
    deadline: Option<Deadline>,
    native: Option<Pin<Box<Sleep>>>,
}
impl Guard {
    fn new(whole: Whole, parent: Option<ParentControl>) -> Result<Self, Failure> {
        let deadline = whole
            .expires
            .map(|at| Deadline::at(whole.clock.clone(), at))
            .transpose()?;
        let native = whole.hard.map(|at| Box::pin(tokio::time::sleep_until(at)));
        Ok(Self {
            whole,
            parent: parent
                .map(|p| p.register().map_err(|f| f.error))
                .transpose()?,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            deadline,
            native,
        })
    }
    fn signals(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(s))) if s == libc::SIGINT as i8 || s == libc::SIGTERM as i8 => {
                    return Err(Box::new(Stop::Signal(i32::from(s))));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(e)) => return Err(e.into()),
                Poll::Pending => {}
            }
        }
        for (stream, code) in [
            (&mut self.interrupt, libc::SIGINT),
            (&mut self.terminate, libc::SIGTERM),
        ] {
            match stream.poll_recv(cx) {
                Poll::Ready(Some(())) => return Err(Box::new(Stop::Signal(code))),
                Poll::Ready(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "original proof termination stream ended",
                    )
                    .into());
                }
                Poll::Pending => {}
            }
        }
        Ok(())
    }
    fn poll_check(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        self.whole.reporter.register(cx);
        self.signals(cx)?;
        self.whole.check()?;
        if let Some(deadline) = &mut self.deadline {
            match Pin::new(deadline).poll(cx) {
                Poll::Ready(Ok(())) => return Err(Box::new(Stop::Deadline)),
                Poll::Ready(Err(e)) => return Err(Box::new(Stop::Clock(e))),
                Poll::Pending => {}
            }
        }
        if let Some(native) = &mut self.native
            && native.as_mut().poll(cx).is_ready()
        {
            return Err(Box::new(Stop::Deadline));
        }
        self.signals(cx)?;
        if self.whole.hard.is_some_and(|at| Instant::now() >= at) {
            return Err(Box::new(Stop::Deadline));
        }
        Ok(())
    }
    async fn check(&mut self) -> Result<(), Failure> {
        poll_fn(|cx| Poll::Ready(self.poll_check(cx))).await
    }
    async fn delay(&mut self, delay: &Delay) -> Result<(), Failure> {
        self.check().await?;
        let (mut canonical, mut native) = match delay {
            Delay::Forever => (None, None),
            Delay::Finite(d) if d.is_zero() => {
                tokio::task::yield_now().await;
                return self.check().await;
            }
            Delay::Finite(d) => {
                let native = Instant::now()
                    .checked_add(*d)
                    .ok_or("proof inter-round native delay overflow")?;
                let now = self.whole.clock.sample()?.now;
                let at = now
                    .as_micros()
                    .checked_add(u64::try_from(d.as_micros())?)
                    .map(AbsoluteTime::from_micros)
                    .ok_or("proof inter-round canonical delay overflow")?;
                self.whole.check()?;
                (
                    Some(Deadline::at(self.whole.clock.clone(), at)?),
                    Some(Box::pin(tokio::time::sleep_until(native))),
                )
            }
        };
        // Each delay has its own fixed pair. Wakes/signals do not restart it;
        // the original whole pair independently caps every such wait.
        poll_fn(|cx| {
            self.poll_check(cx)?;
            let mut ready = false;
            if let Some(wait) = &mut canonical {
                match Pin::new(wait).poll(cx) {
                    Poll::Ready(Ok(())) => ready = true,
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(Box::new(Stop::Clock(e)) as Failure));
                    }
                    Poll::Pending => {}
                }
            }
            if let Some(wait) = &mut native {
                ready |= wait.as_mut().poll(cx).is_ready();
            }
            if ready {
                Poll::Ready(self.poll_check(cx))
            } else {
                Poll::Pending
            }
        })
        .await
    }
}
fn checkpoint(store: &mut Store, facts: &mut Facts, dirty: &mut bool) -> Result<(), Failure> {
    facts.checkpoint_attempts += 1;
    match store.commit(facts.next_counter.to_ne_bytes()) {
        Ok(()) => {
            facts.checkpoints += 1;
            facts.last_committed = Some(facts.next_counter);
            *dirty = false;
            Ok(())
        }
        Err(e) => {
            facts.persistence_failed = true;
            facts.persistence_outcome = Some(e.outcome);
            // Unknown is never counter zero, a retry, or a different value.
            Err(Box::new(e))
        }
    }
}
async fn mine(
    settings: &Settings,
    public: &[u8; 32],
    store: &mut Store,
    guard: &mut Guard,
    facts: &mut Facts,
    dirty: &mut bool,
) -> Result<(), Failure> {
    guard.check().await?;
    let mut memory = Vec::new();
    memory.try_reserve_exact(pow::MEMORY_BLOCKS)?;
    for _ in 0..pow::MEMORY_BLOCKS {
        memory.push(pow::Block::default());
    }
    guard.check().await?;
    let mut round = 0;
    loop {
        guard.check().await?;
        if settings
            .max_hashes
            .is_some_and(|max| facts.hashes >= u128::from(max))
        {
            return Err(Box::new(Stop::HashLimit));
        }
        let bytes = facts.next_counter.to_ne_bytes();
        let valid = crypto::valid_proof(settings.bits, public, &bytes, &mut memory)?;
        facts.hashes += 1;
        *dirty = true;
        if valid {
            facts.found = Some(facts.next_counter);
        } else if let Some(next) = facts.next_counter.checked_add(1) {
            facts.next_counter = next;
        } else {
            facts.exhausted = true;
        }
        // Every actual hash, including valid/MAX, cooperatively yields before
        // the post-hash stop check. A yield is not an IO-driver barrier.
        tokio::task::yield_now().await;
        guard.check().await?;
        if valid {
            checkpoint(store, facts, dirty)?;
            guard.check().await?;
            let line = format!("Proof of work found: {}!\n", facts.next_counter);
            let mut stdout = io::stdout().lock();
            let mut written = 0;
            while written < line.len() {
                guard.check().await?;
                match stdout.write(&line.as_bytes()[written..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "original proof stdout write made no progress",
                        )
                        .into());
                    }
                    Ok(n) => {
                        written += n;
                        facts.stdout_bytes += n as u64;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
                guard.check().await?;
            }
            stdout.flush()?;
            return guard.check().await;
        }
        if facts.exhausted {
            return Err(Box::new(Stop::Exhausted));
        }
        if facts.hashes.is_multiple_of(CHECKPOINT) {
            checkpoint(store, facts, dirty)?;
            guard.check().await?;
        }
        round += 1;
        if round == ROUND {
            facts.rounds += 1;
            round = 0;
            guard.whole.reporter.message(
                Level::INFO,
                "scrypt.progress",
                format_args!("Current: {} [hashes: {}]", facts.next_counter, facts.hashes),
            );
            guard.check().await?;
            guard.delay(&settings.delay).await?;
        }
    }
}
pub(super) async fn run(prepared: Prepared, parent: Option<ParentControl>) -> Result<(), Failure> {
    let Prepared {
        settings,
        whole,
        public,
        mut store,
        counter,
    } = prepared;
    let reporter = whole.reporter.clone();
    let mut guard = Guard::new(whole, parent)?;
    let mut facts = Facts {
        next_counter: counter,
        ..Facts::default()
    };
    let mut dirty = false;
    let mut result = if settings.bits.get() == 0 {
        // Exact C configuration branch: disabled mining is not a found proof.
        guard.check().await
    } else {
        mine(
            &settings, &public, &mut store, &mut guard, &mut facts, &mut dirty,
        )
        .await
    };
    // Stop cannot suppress the original progress checkpoint. One actual commit
    // attempt is made; a prior failed/Unknown attempt is never blindly retried.
    let final_checkpoint = if dirty && !facts.persistence_failed {
        checkpoint(&mut store, &mut facts, &mut dirty).err()
    } else {
        None
    };
    if result.is_ok() && final_checkpoint.is_none() {
        result = guard.check().await;
    }
    if result.is_err() || final_checkpoint.is_some() {
        return Err(Box::new(Failed {
            original: result.err(),
            checkpoint: final_checkpoint,
            facts,
        }));
    }
    reporter.debug(
        "scrypt.command.complete",
        format_args!("actual public mining/persistence facts: {facts:?}"),
    );
    Ok(())
}
