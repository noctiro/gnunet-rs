//! Real CLI consumers of the existing standard HPKE envelope helper.
use super::{Result, SecretKey, crypt, keys};
use gnunet::{
    clients::identity::clock::RuntimeClock, crypto::Entropy, gnsrecord::ZoneKey,
    types::Error as Fault,
};
use std::{
    cell::Cell,
    error::Error,
    ffi::OsString,
    fmt,
    fs::File,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

// The helper's explicit local profile, not an additional HPKE wire header.
const MESSAGE_BYTES: usize = 1024 * 1024;
const ENCODED_BYTES: usize =
    ((MESSAGE_BYTES + 1 + gnunet::session_crypto::hpke::ONESHOT_OVERHEAD) * 8).div_ceil(5);

pub(super) fn take(args: &mut [OsString], at: usize) -> Result<Zeroizing<Vec<u8>>> {
    let value = args
        .get_mut(at)
        .ok_or("missing explicit IDENTITY message")?;
    Ok(Zeroizing::new(std::mem::take(value).into_encoded_bytes()))
}
/// Validate only after all explicit private argv has moved to erased owners.
pub(super) fn validate(bytes: &[u8], encrypted: bool) -> Result<()> {
    if bytes.len()
        > if encrypted {
            ENCODED_BYTES
        } else {
            MESSAGE_BYTES
        }
    {
        return Err("IDENTITY message exceeds the bounded CLI profile".into());
    }
    Ok(())
}

struct Guard<'a, F> {
    hard: Instant,
    logical: Option<(Arc<dyn RuntimeClock>, u64)>,
    signal: Pin<&'a mut F>,
    stopped: &'a Cell<bool>,
    error: Option<io::Error>,
}
impl<F: Future<Output = io::Result<()>>> Guard<'_, F> {
    fn check(&mut self, cx: &mut Context<'_>) -> std::result::Result<(), Fault> {
        if Instant::now() >= self.hard {
            return Err(Fault::Deadline);
        }
        if self.stopped.get() {
            return Err(Fault::Cancelled);
        }
        match self.signal.as_mut().poll(cx) {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                self.stopped.set(true);
                return Err(Fault::Cancelled);
            }
            Poll::Ready(Err(error)) => {
                self.stopped.set(true);
                self.error = Some(error);
                return Err(Fault::Io);
            }
        }
        if let Some((clock, until)) = &self.logical {
            let now = clock.sample()?.now.as_micros();
            if Instant::now() >= self.hard || now >= *until {
                return Err(Fault::Deadline);
            }
        }
        Ok(())
    }
    async fn checkpoint(&mut self) -> std::result::Result<(), Fault> {
        poll_fn(|cx| Poll::Ready(self.check(cx))).await
    }
}
struct Random<'a> {
    file: File,
    hard: Instant,
    stopped: &'a Cell<bool>,
    error: Option<io::Error>,
}
impl Entropy for Random<'_> {
    fn fill(&mut self, output: &mut [u8]) -> std::result::Result<(), Fault> {
        if Instant::now() >= self.hard || self.stopped.get() {
            output.zeroize();
            return Err(if self.stopped.get() {
                Fault::Cancelled
            } else {
                Fault::Deadline
            });
        }
        if let Err(error) = self.file.read_exact(output) {
            output.zeroize();
            self.error = Some(error);
            return Err(Fault::Entropy);
        }
        if Instant::now() >= self.hard || self.stopped.get() {
            output.zeroize();
            return Err(if self.stopped.get() {
                Fault::Cancelled
            } else {
                Fault::Deadline
            });
        }
        Ok(())
    }
}
#[derive(Debug)]
struct Failed {
    operation: Option<Box<dyn Error>>,
    output: Option<io::Error>,
    guard: Option<Fault>,
    signal: Option<io::Error>,
    entropy: Option<io::Error>,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IDENTITY message failed: {self:?}")
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.operation
            .as_deref()
            .or_else(|| self.output.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.signal.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.entropy.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.guard.as_ref().map(|error| error as &dyn Error))
    }
}
fn failed(
    operation: Option<Box<dyn Error>>,
    output: Option<io::Error>,
    guard: Option<Fault>,
    signal: Option<io::Error>,
    entropy: Option<io::Error>,
) -> Box<dyn Error> {
    Box::new(Failed {
        operation,
        output,
        guard,
        signal,
        entropy,
    })
}
// Stdio and synchronous crypto are explicit synchronous boundaries. The same
// hard/signal is checked around them, not advertised as a way to preempt a
// blocked syscall or interrupt a primitive halfway through its execution.
async fn emit<F: Future<Output = io::Result<()>>>(
    out: &mut impl Write,
    bytes: &[u8],
    guard: &mut Guard<'_, F>,
) -> Result<()> {
    if let Err(error) = guard.checkpoint().await {
        return Err(failed(None, None, Some(error), guard.error.take(), None));
    }
    let output = (|| -> io::Result<()> {
        out.write_all(bytes)?;
        out.write_all(b"\n")?;
        out.flush()
    })();
    let after = guard.checkpoint().await;
    if output.is_err() || after.is_err() || guard.error.is_some() {
        return Err(failed(
            None,
            output.err(),
            after.err(),
            guard.error.take(),
            None,
        ));
    }
    Ok(())
}
fn timeout(args: &[OsString]) -> Result<Duration> {
    let mut milliseconds = 30_000u64;
    let mut at = 0;
    while at < args.len() {
        if args[at] != "--timeout-ms" {
            return Err("unknown or inapplicable IDENTITY message option".into());
        }
        milliseconds = args
            .get(at + 1)
            .and_then(|value| value.to_str())
            .ok_or("missing IDENTITY timeout")?
            .parse()?;
        at += 2;
    }
    if milliseconds == 0 || milliseconds.checked_mul(1000).is_none() {
        return Err("invalid finite IDENTITY message bound".into());
    }
    let duration = Duration::from_millis(milliseconds);
    if Instant::now().checked_add(duration).is_none() {
        return Err("IDENTITY native bound is not representable".into());
    }
    Ok(duration)
}
/// Encrypt is local: no identity service, new secret identity, Resolver or worker.
/// Message ownership is taken before ordinary validation can return an error.
pub(super) fn encrypt(args: &mut [OsString], out: &mut impl Write) -> Result<()> {
    let message = take(args, 2)?;
    if keys::extract(args)?.is_some() {
        return Err("IDENTITY encryption takes a public recipient, not private key import".into());
    }
    validate(&message, false)?;
    let recipient = args
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or("missing standard typed recipient public key")?;
    let recipient = ZoneKey::from_ztld(recipient)?;
    let timeout = timeout(args.get(3..).ok_or("missing IDENTITY message")?)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let hard = Instant::now()
                .checked_add(timeout)
                .ok_or("IDENTITY native bound overflow")?;
            let signal = tokio::signal::ctrl_c();
            tokio::pin!(signal);
            let stopped = Cell::new(false);
            let mut guard = Guard {
                hard,
                logical: None,
                signal: signal.as_mut(),
                stopped: &stopped,
                error: None,
            };
            if let Err(error) = guard.checkpoint().await {
                return Err(failed(None, None, Some(error), guard.error.take(), None));
            }
            let mut entropy = Random {
                file: File::open("/dev/urandom")?,
                hard,
                stopped: &stopped,
                error: None,
            };
            let encrypted = poll_fn(|cx| {
                let mut original = || guard.check(cx);
                Poll::Ready(crypt::encrypt(
                    &recipient,
                    &message,
                    &mut entropy,
                    &mut original,
                ))
            })
            .await;
            let after = guard.checkpoint().await;
            if encrypted.is_err()
                || after.is_err()
                || guard.error.is_some()
                || entropy.error.is_some()
            {
                return Err(failed(
                    encrypted
                        .err()
                        .map(|error| Box::new(error) as Box<dyn Error>),
                    None,
                    after.err(),
                    guard.error.take(),
                    entropy.error.take(),
                ));
            }
            let encrypted = encrypted?;
            emit(out, &encrypted, &mut guard).await
        })
}
/// Called only with the actual original lookup's opaque secret. Ciphertext and
/// plaintext stay erased; no UTF-8 conversion or JSON String owns their bytes.
pub(super) async fn decrypt<F: Future<Output = io::Result<()>>>(
    secret: &SecretKey,
    encoded: &[u8],
    hard: Instant,
    logical: (Arc<dyn RuntimeClock>, u64),
    signal: Pin<&mut F>,
    out: &mut impl Write,
) -> Result<()> {
    let stopped = Cell::new(false);
    let mut guard = Guard {
        hard,
        logical: Some(logical),
        signal,
        stopped: &stopped,
        error: None,
    };
    let plaintext = poll_fn(|cx| {
        let mut original = || guard.check(cx);
        Poll::Ready(crypt::decrypt(secret, encoded, &mut original))
    })
    .await;
    let after = guard.checkpoint().await;
    if plaintext.is_err() || after.is_err() || guard.error.is_some() {
        return Err(failed(
            plaintext
                .err()
                .map(|error| Box::new(error) as Box<dyn Error>),
            None,
            after.err(),
            guard.error.take(),
            None,
        ));
    }
    let plaintext = plaintext?;
    emit(out, &plaintext, &mut guard).await
}
