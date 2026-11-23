//! One original nonblocking byte stream driven by a bounded TCP session turn.
use crate::session::{Effect, Phase, ResultKind, Session, Ticket, Time, WriteResult};
use core::{fmt, num::NonZeroUsize};
use gnunet_crypto::Entropy;
use gnunet_types::Error;

/// Observation from one nonblocking native read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Read {
    /// These leading bytes were filled in the supplied buffer.
    Bytes(NonZeroUsize),
    /// No bytes were read. Re-arm readiness after would-block or interruption.
    WouldBlock,
    /// The original peer closed its send direction.
    Eof,
}

/// Observation from one nonblocking native write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Write {
    /// This leading portion of the offered ciphertext was accepted.
    Bytes(NonZeroUsize),
    /// No bytes were written. Re-arm readiness after would-block or interruption.
    WouldBlock,
    /// An actual native zero-length write observation for nonempty input.
    Zero,
}

/// Exclusive connected socket ownership with synchronous, nonblocking I/O.
///
/// Dropping an implementation must retire its original socket if it is still
/// live. This also covers failed construction by its caller and a dropped
/// pump. [`Self::close`] consumes the same authority and reports its result.
pub trait Stream {
    /// A terminal native failure, carrying the board's original error.
    type Error;

    /// Fill the given nonempty scratch prefix once without retaining it.
    fn read(&mut self, scratch: &mut [u8]) -> Result<Read, Self::Error>;

    /// Attempt one write of these bytes without retaining a pending borrow.
    fn write(&mut self, bytes: &[u8]) -> Result<Write, Self::Error>;

    /// Consume close authority even when the native close reports failure.
    fn close(self) -> Result<(), Self::Error>;
}

/// Optional bounded readiness wait on the same stream the pump owns.
pub trait WaitStream: Stream {
    /// The platform's actual ready or terminal event observation.
    type Events;

    /// Watch `interest` for at most the supplied milliseconds. Zero polls
    /// immediately. None of these observations acknowledge socket I/O.
    fn wait_ready(&mut self, interest: Ready, timeout_ms: u32)
    -> Result<Self::Events, Self::Error>;
}

/// Caller-owned storage for native ciphertext that the parser has not consumed.
pub struct Scratch<'a>(&'a mut [u8]);

impl<'a> Scratch<'a> {
    /// Take one nonempty buffer. Its size bounds the native read per turn.
    ///
    /// # Errors
    /// Refuses empty scratch, which cannot distinguish a read from EOF.
    pub fn new(bytes: &'a mut [u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::Capacity);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Scratch<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scratch")
            .field("capacity", &self.0.len())
            .finish()
    }
}

/// Native readiness observed for the original stream by its host.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ready {
    /// Permit a nonblocking read attempt this turn.
    pub readable: bool,
    /// Permit a nonblocking write attempt this turn.
    pub writable: bool,
}

/// Work the host may schedule for the original session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interest {
    /// Watch read readiness for new native input.
    pub readable: bool,
    /// Watch write readiness for the session's original ciphertext.
    pub writable: bool,
    /// The parser can consume retained bytes without a native readiness event.
    pub buffered_input: bool,
    /// The session's current logical deadline, if armed.
    pub deadline: Option<u64>,
}

/// Actual progress made in one bounded turn.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Turn {
    /// Ciphertext read from the native stream.
    pub read: usize,
    /// Retained ciphertext accepted by the session parser.
    pub ingested: usize,
    /// Ciphertext accepted by the native stream.
    pub written: usize,
    /// Native EOF triggered the original session's cleanup.
    pub eof: bool,
}

/// Failure from the protocol/port contract or the original native operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PumpError<E> {
    /// Session failure or impossible native byte count.
    Session(Error),
    /// Original error from the native read, write or close.
    Native(E),
}

impl<E> From<Error> for PumpError<E> {
    fn from(error: Error) -> Self {
        Self::Session(error)
    }
}

#[derive(Clone, Copy)]
enum Ingress {
    Empty,
    Buffered { start: usize, end: usize },
    Fenced,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Direction {
    Read,
    Write,
}

/// Couples one native stream and its retained ciphertext to one TCP session.
/// Dropping the pump retires its socket through the stream's drop contract.
/// Drive the session's explicit close effect to observe its native result.
pub struct Pump<'scope, 'scratch, S> {
    session: Session<'scope>,
    stream: Option<S>,
    scratch: Scratch<'scratch>,
    ingress: Ingress,
    preferred: Direction,
}

impl<'scope, 'scratch, S: Stream> Pump<'scope, 'scratch, S> {
    /// Bind one connected nonblocking stream to its original protocol owner.
    pub const fn new(session: Session<'scope>, stream: S, scratch: Scratch<'scratch>) -> Self {
        Self {
            session,
            stream: Some(stream),
            scratch,
            ingress: Ingress::Empty,
            preferred: Direction::Read,
        }
    }

    /// Inspect the session without issuing a native operation.
    pub const fn session(&self) -> &Session<'scope> {
        &self.session
    }

    /// Drive service effects and graceful retirement on the original session.
    /// The caller operates Replay and TRANSPORT effects here and routes an
    /// original `Effect::Close` ticket through [`Self::close`].
    /// Keep this session associated with its original stream and leave native
    /// I/O progress reporting to the pump.
    pub fn session_mut(&mut self) -> &mut Session<'scope> {
        &mut self.session
    }

    /// Query socket readiness and independently schedulable retained input.
    #[must_use]
    pub fn interest(&self) -> Interest {
        let receiving = self.stream.is_some() && self.session.read_interest();
        Interest {
            readable: receiving && matches!(self.ingress, Ingress::Empty),
            writable: self.stream.is_some() && self.session.write_interest(),
            buffered_input: receiving && matches!(self.ingress, Ingress::Buffered { .. }),
            deadline: self.session.deadline(),
        }
    }

    /// Wait on the original socket after outstanding local work has drained.
    /// The caller caps the wait at its earliest protocol or application timer.
    ///
    /// # Errors
    /// An ended stream or a turn without socket interests is refused.
    /// Buffered input returns `WouldBlock` to request an immediate local turn.
    pub fn wait_ready(&mut self, timeout_ms: u32) -> Result<S::Events, PumpError<S::Error>>
    where
        S: WaitStream,
    {
        let interest = self.interest();
        if interest.buffered_input {
            return Err(Error::WouldBlock.into());
        }
        let stream = self.stream.as_mut().ok_or(Error::Closed)?;
        if !interest.readable && !interest.writable {
            return Err(Error::NotReady.into());
        }
        stream
            .wait_ready(
                Ready {
                    readable: interest.readable,
                    writable: interest.writable,
                },
                timeout_ms,
            )
            .map_err(PumpError::Native)
    }

    /// Perform one receive or write turn, alternating when both can proceed.
    /// A receive makes at most one native read and one ingestion. A retained
    /// suffix is fed before any new read. The host settles session effects
    /// from that ingestion before attempting another native operation.
    ///
    /// # Errors
    /// A native failure initiates cleanup. An ingestion error can follow input
    /// consumption, so it fences input and begins the original session's FINISH.
    pub fn turn(
        &mut self,
        ready: Ready,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<Turn, PumpError<S::Error>> {
        if matches!(self.session.phase(), Phase::Initial | Phase::Finishing) {
            self.session.tick(time.now);
        }
        let mut progress = Turn::default();
        let interest = self.interest();
        let read = ready.readable && interest.readable;
        let receive = read || interest.buffered_input;
        let write = ready.writable && interest.writable;
        if receive && (!write || self.preferred == Direction::Read) {
            self.preferred = Direction::Write;
            self.receive(read, time, entropy, &mut progress)?;
        } else if write {
            self.preferred = Direction::Read;
            progress.written = self.write(time, entropy)?;
        }
        self.session.tick(time.now);
        Ok(progress)
    }

    fn receive(
        &mut self,
        read: bool,
        time: Time,
        entropy: &mut impl Entropy,
        progress: &mut Turn,
    ) -> Result<(), PumpError<S::Error>> {
        if read {
            let stream = self.stream.as_mut().ok_or(Error::Conflict)?;
            match stream.read(self.scratch.0) {
                Ok(Read::Bytes(count)) if count.get() <= self.scratch.0.len() => {
                    progress.read = count.get();
                    self.ingress = Ingress::Buffered {
                        start: 0,
                        end: count.get(),
                    };
                    self.session.native_read_progress(time.now);
                }
                Ok(Read::WouldBlock) => return Ok(()),
                Ok(Read::Eof) => {
                    self.lose_stream();
                    progress.eof = true;
                    return Ok(());
                }
                Ok(Read::Bytes(_)) => {
                    self.lose_stream();
                    return Err(Error::InvalidInput.into());
                }
                Err(error) => {
                    self.lose_stream();
                    return Err(PumpError::Native(error));
                }
            }
        }

        if let Ingress::Buffered { start, end } = self.ingress {
            match self
                .session
                .ingest(&self.scratch.0[start..end], time, entropy)
            {
                Ok(consumed) => {
                    progress.ingested = consumed;
                    let start = start + consumed;
                    self.ingress = if start == end {
                        Ingress::Empty
                    } else {
                        Ingress::Buffered { start, end }
                    };
                }
                Err(error) => {
                    self.ingress = Ingress::Fenced;
                    self.session.finish(time)?;
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }

    fn write(
        &mut self,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<usize, PumpError<S::Error>> {
        let Some(ticket) = self.session.write_ready(time, entropy)? else {
            return Ok(0);
        };
        let bytes = self.session.write_bytes(ticket)?;
        let stream = self.stream.as_mut().ok_or(Error::Conflict)?;
        let (result, count) = match stream.write(bytes) {
            Ok(Write::Bytes(n)) if n.get() <= bytes.len() => (WriteResult::Bytes(n.get()), n.get()),
            Ok(Write::WouldBlock) => (WriteResult::Retry, 0),
            Ok(Write::Zero) => (WriteResult::Zero, 0),
            Ok(Write::Bytes(_)) => {
                self.session
                    .written(ticket, WriteResult::Fatal, time, entropy)?;
                return Err(Error::InvalidInput.into());
            }
            Err(error) => {
                self.session
                    .written(ticket, WriteResult::Fatal, time, entropy)?;
                return Err(PumpError::Native(error));
            }
        };
        self.session.written(ticket, result, time, entropy)?;
        Ok(count)
    }

    fn lose_stream(&mut self) {
        self.ingress = Ingress::Fenced;
        self.session.native_lost();
    }

    /// Consume the original stream under its outstanding session close ticket.
    ///
    /// # Errors
    /// An invalid ticket leaves the stream untouched. A native close failure
    /// is reported to both the session and caller with no repeated close.
    pub fn close(
        &mut self,
        ticket: Ticket<'_>,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<(), PumpError<S::Error>> {
        if !matches!(self.session.effect(ticket)?, Effect::Close) {
            return Err(Error::InvalidInput.into());
        }
        let stream = self.stream.take().ok_or(Error::Conflict)?;
        self.ingress = Ingress::Fenced;
        let closed = stream.close();
        let status = if closed.is_ok() {
            ResultKind::Success
        } else {
            ResultKind::Failed
        };
        self.session.acknowledge(ticket, status, time, entropy)?;
        closed.map_err(PumpError::Native)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        session::{Buffers, CIPHERTEXT_CAPACITY, CompletionSlot, Identity, Policy, Scope},
        wire,
    };
    use core::cell::{Cell, RefCell};
    use gnunet_crypto::EddsaPrivateKey;
    use gnunet_session_crypto::exchange::EcdheSecret;
    use std::{vec, vec::Vec};

    #[derive(Default)]
    struct Calls {
        reads: Cell<usize>,
        writes: RefCell<Vec<Vec<u8>>>,
        closes: Cell<usize>,
    }

    struct Socket<'a> {
        received: &'a [u8],
        calls: &'a Calls,
    }

    impl Stream for Socket<'_> {
        type Error = Error;

        fn read(&mut self, scratch: &mut [u8]) -> Result<Read, Error> {
            self.calls.reads.set(self.calls.reads.get() + 1);
            let Some(count) = NonZeroUsize::new(self.received.len()) else {
                return Ok(Read::Eof);
            };
            scratch
                .get_mut(..count.get())
                .ok_or(Error::Capacity)?
                .copy_from_slice(self.received);
            self.received = &[];
            Ok(Read::Bytes(count))
        }

        fn write(&mut self, bytes: &[u8]) -> Result<Write, Error> {
            let mut writes = self.calls.writes.borrow_mut();
            writes.push(bytes.to_vec());
            match writes.len() {
                1 => Ok(Write::WouldBlock),
                2 => Ok(Write::Bytes(
                    NonZeroUsize::new(7).ok_or(Error::InvalidInput)?,
                )),
                _ => Ok(Write::Bytes(
                    NonZeroUsize::new(bytes.len()).ok_or(Error::InvalidInput)?,
                )),
            }
        }

        fn close(self) -> Result<(), Error> {
            self.calls.closes.set(self.calls.closes.get() + 1);
            Ok(())
        }
    }

    struct Random(u64);
    impl Entropy for Random {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
            for byte in out {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *byte = self.0 as u8;
            }
            Ok(())
        }
    }

    struct BuffersOwner {
        receive: Vec<u8>,
        transmit: Vec<u8>,
        plaintext: Vec<u8>,
        completions: [CompletionSlot; 1],
    }

    impl BuffersOwner {
        fn new() -> Self {
            Self {
                receive: vec![0; wire::MAX_RECORD],
                transmit: vec![0; CIPHERTEXT_CAPACITY],
                plaintext: vec![0; wire::MAX_RECORD],
                completions: [CompletionSlot::default()],
            }
        }

        fn buffers(&mut self) -> Buffers<'_> {
            Buffers {
                receive: &mut self.receive,
                transmit: &mut self.transmit,
                plaintext: &mut self.plaintext,
                completions: &mut self.completions,
            }
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert original session and native observations"
    )]
    fn preserves_a_replay_blocked_suffix_and_partial_ciphertext() -> Result<(), PumpError<Error>> {
        let mut random = Random(7);
        let mut peer_scope = Scope::new();
        let mut scope = Scope::new();
        let time = Time {
            now: 1,
            signed: 101,
        };
        let mut policy = Policy::reference(NonZeroUsize::new(128).ok_or(Error::InvalidInput)?);
        policy.max_backpressure = 1;
        let key = EddsaPrivateKey::from_seed([1; 32]);
        let exchange = EcdheSecret::from_eddsa_seed([1; 32]);
        let peer_key = EddsaPrivateKey::from_seed([2; 32]);
        let peer_exchange = EcdheSecret::from_eddsa_seed([2; 32]);
        let mut sender_buffers = BuffersOwner::new();
        let mut sender = Session::new(
            &mut peer_scope,
            Identity::new(&peer_key, &peer_exchange)?,
            Some(key.public_key()),
            sender_buffers.buffers(),
            policy,
            time,
            &mut random,
        )?;
        let initial = sender
            .write_ready(time, &mut random)?
            .ok_or(Error::NotReady)?;
        let mut input = sender.write_bytes(initial)?.to_vec();
        input.push(42);

        let mut buffers = BuffersOwner::new();
        let session = Session::new(
            &mut scope,
            Identity::new(&key, &exchange)?,
            None,
            buffers.buffers(),
            policy,
            time,
            &mut random,
        )?;
        let calls = Calls::default();
        let socket = Socket {
            received: &input,
            calls: &calls,
        };
        let mut scratch = [0; wire::INITIAL_KX + 1];
        let mut pump = Pump::new(session, socket, Scratch::new(&mut scratch)?);
        let ready = Ready {
            readable: true,
            writable: true,
        };

        let first = pump.turn(ready, time, &mut random)?;
        assert_eq!(
            (first.read, first.ingested, first.written),
            (input.len(), wire::INITIAL_KX, 0)
        );
        assert!(!pump.interest().buffered_input);
        assert_eq!(pump.turn(ready, time, &mut random)?, Turn::default());
        assert_eq!(calls.reads.get(), 1);

        let replay = pump.session_mut().next_effect()?.ok_or(Error::NotReady)?;
        assert!(matches!(
            pump.session().effect(replay)?,
            Effect::ReplayStart { .. }
        ));
        pump.session_mut()
            .acknowledge(replay, ResultKind::Success, time, &mut random)?;
        assert!(pump.interest().buffered_input);
        assert_eq!(pump.turn(ready, time, &mut random)?, Turn::default());
        let suffix = pump.turn(ready, time, &mut random)?;
        assert_eq!((suffix.read, suffix.ingested, suffix.written), (0, 1, 0));
        assert_eq!(calls.reads.get(), 1);

        let writable = Ready {
            readable: false,
            writable: true,
        };
        assert_eq!(pump.turn(writable, time, &mut random)?.written, 7);
        assert_eq!(
            pump.turn(writable, time, &mut random)?.written,
            wire::INITIAL_KX - 7
        );
        let writes = calls.writes.borrow();
        assert_eq!(writes[0], writes[1]);
        assert_eq!(writes[2], writes[1][7..]);

        assert!(pump.turn(ready, time, &mut random)?.eof);
        let cancel = pump.session_mut().next_effect()?.ok_or(Error::NotReady)?;
        assert!(matches!(
            pump.session().effect(cancel)?,
            Effect::ReplayCancel(..)
        ));
        pump.session_mut()
            .acknowledge(cancel, ResultKind::Success, time, &mut random)?;
        let close = pump.session_mut().next_effect()?.ok_or(Error::NotReady)?;
        pump.close(close, time, &mut random)?;
        assert_eq!(pump.session().phase(), Phase::Closed);
        assert_eq!(calls.closes.get(), 1);
        assert_eq!(
            pump.close(close, time, &mut random),
            Err(PumpError::Session(Error::Stale))
        );
        assert_eq!(calls.closes.get(), 1);
        Ok(())
    }
}
