use crate::{Cause, Problem, descriptors::Descriptor, spool::Spool};
use gnunet_gnsrecord::{decode_base32, encode_base32};
use std::{
    fmt,
    future::poll_fn,
    io,
    task::{Context, Poll},
};
use tokio::signal::unix::{Signal, SignalKind, signal};
const INPUT: usize = 4096;
const RETAINED: usize = INPUT + 8;
const OUTPUT: usize = RETAINED * 8 / 5 + 8;
#[derive(Debug, Default)]
struct Facts {
    input_bytes: u64,
    stdout_bytes: u64,
    spool_bytes: u64,
    input_eof: bool,
    validated: bool,
    output_complete: bool,
    spool_created: bool,
    spool_removed: bool,
    cancelled: Option<i32>,
}
#[derive(Debug)]
struct Failure {
    original: Option<Problem>,
    input_restore: Option<io::Error>,
    output_restore: Option<io::Error>,
    spool_cleanup: Option<io::Error>,
    retained_spool_directory: Option<std::path::PathBuf>,
    facts: Facts,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original={:?}; input restore={:?}; output restore={:?}; spool cleanup={:?}; retained directory={:?}; actual facts={:?}",
            self.original,
            self.input_restore,
            self.output_restore,
            self.spool_cleanup,
            self.retained_spool_directory,
            self.facts
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_ref()
            .map(|p| p as _)
            .or_else(|| self.spool_cleanup.as_ref().map(|p| p as _))
            .or_else(|| self.output_restore.as_ref().map(|p| p as _))
            .or_else(|| self.input_restore.as_ref().map(|p| p as _))
    }
}
#[derive(Debug)]
struct Cancelled(i32);
impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original conversion cancelled by signal {}", self.0)
    }
}
impl std::error::Error for Cancelled {}
struct Signals {
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }
    fn check(&mut self, cx: &mut Context<'_>, facts: &mut Facts) -> Result<(), Problem> {
        for (port, number) in [
            (&mut self.interrupt, SignalKind::interrupt().as_raw_value()),
            (&mut self.terminate, SignalKind::terminate().as_raw_value()),
        ] {
            match port.poll_recv(cx) {
                Poll::Ready(Some(())) => {
                    facts.cancelled = Some(number);
                    return Err(Problem::new(
                        u8::try_from(128 + number).unwrap_or(1),
                        Cancelled(number),
                    ));
                }
                Poll::Ready(None) => return Err(Problem::message(1, "original signal port ended")),
                Poll::Pending => {}
            }
        }
        Ok(())
    }
}
fn count(counter: &mut u64, n: usize) -> Result<(), Problem> {
    *counter = counter
        .checked_add(u64::try_from(n).map_err(|e| Problem::new(1, e))?)
        .ok_or_else(|| Problem::message(1, "byte observation overflow"))?;
    Ok(())
}
async fn read(
    input: &mut Descriptor,
    signals: &mut Signals,
    facts: &mut Facts,
    bytes: &mut [u8],
) -> Result<usize, Problem> {
    poll_fn(|cx| {
        signals.check(cx, facts)?;
        match input.read(cx, bytes) {
            Poll::Ready(Ok(n)) => {
                count(&mut facts.input_bytes, n)?;
                facts.input_eof |= n == 0;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(Problem::new(2, e))),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
async fn output(
    output: &mut Descriptor,
    signals: &mut Signals,
    facts: &mut Facts,
    bytes: &[u8],
) -> Result<(), Problem> {
    let mut at = 0;
    while at < bytes.len() {
        let n = poll_fn(|cx| {
            signals.check(cx, facts)?;
            match output.write(cx, &bytes[at..]) {
                Poll::Ready(Ok(0)) => Poll::Ready(Err(Problem::message(4, "zero stdout write"))),
                Poll::Ready(Ok(n)) => {
                    count(&mut facts.stdout_bytes, n)?;
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(Problem::new(4, e))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        at += n;
        tokio::task::yield_now().await;
    }
    Ok(())
}
async fn spooled(
    owner: &mut Option<Spool>,
    signals: &mut Signals,
    facts: &mut Facts,
    bytes: &[u8],
) -> Result<(), Problem> {
    if bytes.is_empty() {
        return Ok(());
    }
    if owner.is_none() {
        poll_fn(|cx| {
            signals.check(cx, facts)?;
            let result = Spool::create(owner);
            facts.spool_created |= owner.is_some();
            Poll::Ready(result.map_err(|e| Problem::new(5, e)))
        })
        .await?;
    }
    let spool = owner
        .as_mut()
        .ok_or_else(|| Problem::message(5, "spool owner absent"))?;
    let mut at = 0;
    while at < bytes.len() {
        let n = poll_fn(|cx| {
            signals.check(cx, facts)?;
            match spool.write(&bytes[at..]) {
                Ok(0) => Poll::Ready(Err(Problem::message(5, "zero private spool write"))),
                Ok(n) => {
                    count(&mut facts.spool_bytes, n)?;
                    Poll::Ready(Ok(n))
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(Problem::new(5, e))),
            }
        })
        .await?;
        at += n;
        tokio::task::yield_now().await;
    }
    Ok(())
}
async fn convert(
    decode: bool,
    input: &mut Descriptor,
    out: &mut Descriptor,
    signals: &mut Signals,
    spool: &mut Option<Spool>,
    facts: &mut Facts,
) -> Result<(), Problem> {
    let mut incoming = [0u8; RETAINED];
    let mut outgoing = [0u8; OUTPUT];
    let mut retained = 0;
    loop {
        let n = read(
            input,
            signals,
            facts,
            &mut incoming[retained..retained + INPUT],
        )
        .await?;
        let total = retained + n;
        if n == 0 {
            if retained != 0 {
                let produced = if decode {
                    decode_base32(&incoming[..retained], &mut outgoing)
                        .map_err(|e| Problem::new(3, e))?
                } else {
                    encode_base32(&incoming[..retained], &mut outgoing)
                        .map_err(|e| Problem::new(1, e))?
                };
                if decode {
                    spooled(spool, signals, facts, &outgoing[..produced]).await?;
                } else {
                    output(out, signals, facts, &outgoing[..produced]).await?;
                }
            }
            facts.validated = true;
            break;
        }
        let unit = if decode { 8 } else { 5 };
        let complete = total / unit * unit;
        if complete != 0 {
            let produced = if decode {
                decode_base32(&incoming[..complete], &mut outgoing)
                    .map_err(|e| Problem::new(3, e))?
            } else {
                encode_base32(&incoming[..complete], &mut outgoing)
                    .map_err(|e| Problem::new(1, e))?
            };
            if decode {
                spooled(spool, signals, facts, &outgoing[..produced]).await?;
            } else {
                output(out, signals, facts, &outgoing[..produced]).await?;
            }
        }
        incoming.copy_within(complete..total, 0);
        retained = total - complete;
        tokio::task::yield_now().await;
    }
    if decode && let Some(spool) = spool.as_mut() {
        poll_fn(|cx| {
            signals.check(cx, facts)?;
            Poll::Ready(spool.rewind().map_err(|e| Problem::new(5, e)))
        })
        .await?;
        let mut delivered = 0u64;
        loop {
            let n = poll_fn(|cx| {
                signals.check(cx, facts)?;
                match spool.read(&mut incoming[..INPUT]) {
                    Ok(n) => Poll::Ready(Ok(n)),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(Problem::new(5, e))),
                }
            })
            .await?;
            if n == 0 {
                break;
            }
            count(&mut delivered, n)?;
            output(out, signals, facts, &incoming[..n]).await?;
            tokio::task::yield_now().await;
        }
        if delivered != facts.spool_bytes {
            return Err(Problem::message(5, "private spool extent changed"));
        }
    }
    facts.output_complete = true;
    Ok(())
}
pub(super) async fn run(decode: bool) -> Result<(), Problem> {
    let mut signals = Signals::new().map_err(|e| Problem::new(1, e))?;
    let (mut input, mut output) = Descriptor::pair().map_err(|e| Problem::new(1, e))?;
    let mut spool = None;
    let mut facts = Facts::default();
    let original = convert(
        decode,
        &mut input,
        &mut output,
        &mut signals,
        &mut spool,
        &mut facts,
    )
    .await
    .err();
    facts.spool_created |= spool.is_some();
    let mut retained_spool_directory = None;
    let spool_cleanup = if let Some(spool) = spool.as_mut() {
        match spool.close() {
            Ok(()) => {
                facts.spool_removed = true;
                None
            }
            Err(error) => {
                retained_spool_directory = Some(spool.path());
                Some(error)
            }
        }
    } else {
        None
    };
    let output_restore = output.close();
    let input_restore = input.close();
    if original.is_some()
        || spool_cleanup.is_some()
        || output_restore.is_some()
        || input_restore.is_some()
    {
        let code = original.as_ref().map_or(6, |e| e.code);
        let cause: Cause = Box::new(Failure {
            original,
            input_restore,
            output_restore,
            spool_cleanup,
            retained_spool_directory,
            facts,
        });
        Err(Problem { code, cause })
    } else {
        Ok(())
    }
}
