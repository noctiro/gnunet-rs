use super::*;
use crate::{
    replay_store::{Commit, CommitFailure},
    session::{CIPHERTEXT_CAPACITY, CompletionSlot, KeyRing, ReplayKind},
    stream::{Read, Write},
    wire,
};
use core::{
    cell::{Cell, RefCell},
    num::NonZeroUsize,
};
use std::{collections::VecDeque, rc::Rc};

const PAYLOAD: [u8; 6] = [0, 6, 0, 42, 7, 9];

#[derive(Default)]
struct Link {
    inbound: RefCell<[VecDeque<u8>; 2]>,
    closed: [Cell<bool>; 2],
    write_limit: [Cell<Option<usize>>; 2],
}

struct Socket {
    link: Rc<Link>,
    end: usize,
}

impl Stream for Socket {
    type Error = Error;

    fn read(&mut self, scratch: &mut [u8]) -> Result<Read, Error> {
        let mut input = self.link.inbound.borrow_mut();
        let input = &mut input[self.end];
        let count = scratch.len().min(input.len()).min(53);
        if let Some(count) = NonZeroUsize::new(count) {
            for (slot, next) in scratch.iter_mut().zip(input.drain(..count.get())) {
                *slot = next;
            }
            Ok(Read::Bytes(count))
        } else if self.link.closed[1 - self.end].get() {
            Ok(Read::Eof)
        } else {
            Ok(Read::WouldBlock)
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<Write, Error> {
        let limit = self.link.write_limit[self.end].get().unwrap_or(37);
        let Some(count) = NonZeroUsize::new(bytes.len().min(limit)) else {
            return Ok(Write::WouldBlock);
        };
        self.link.inbound.borrow_mut()[1 - self.end].extend(&bytes[..count.get()]);
        Ok(Write::Bytes(count))
    }

    fn close(self) -> Result<(), Error> {
        Ok(())
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.link.closed[self.end].set(true);
    }
}

struct Board {
    random: u32,
    elapsed: u64,
    high_water: u64,
}

impl Entropy for Board {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        for byte in bytes {
            self.random ^= self.random << 13;
            self.random ^= self.random >> 17;
            self.random ^= self.random << 5;
            *byte = self.random as u8;
        }
        Ok(())
    }
}

impl Clock for Board {
    fn sample(&mut self) -> Result<Sample, Error> {
        self.elapsed += 1;
        Ok(Sample {
            absolute: AbsoluteTime::from_micros(1000),
            elapsed: MonoInstant(self.elapsed),
        })
    }

    fn signed_high_water(&mut self) -> Result<u64, Error> {
        Ok(self.high_water)
    }

    fn reserve_signed(&mut self, first: NonZeroU64) -> Result<(u64, u64), Error> {
        if first.get() <= self.high_water {
            return Err(Error::Conflict);
        }
        self.high_water = first.get() + 255;
        Ok((first.get(), self.high_water))
    }
}

type Written = (NonZeroU64, Result<(), Error>, MonoInstant);

#[derive(Default)]
struct Evidence {
    replay_accessed: Cell<bool>,
    acknowledgement: Cell<bool>,
    delivery: Cell<bool>,
    queue_registered: Cell<bool>,
    sent: Cell<Option<Result<(), Error>>>,
    written: Cell<Option<Written>>,
    write_callbacks: Cell<usize>,
}

struct History(Rc<Evidence>);

impl Backend for History {
    type Error = Error;

    fn load_max(&mut self, _: EddsaPublicKey, _: ReplayKind) -> Result<Option<u64>, Error> {
        self.0.replay_accessed.set(true);
        Ok(None)
    }

    fn commit_max(
        &mut self,
        _: EddsaPublicKey,
        kind: ReplayKind,
        _: u64,
    ) -> Result<Commit, CommitFailure<Error>> {
        self.0.replay_accessed.set(true);
        if kind == ReplayKind::Acknowledgement {
            self.0.acknowledgement.set(true);
        }
        Ok(Commit::Advanced)
    }
}

struct Local {
    evidence: Rc<Evidence>,
    output: Option<[u8; PAYLOAD.len()]>,
    observe: Option<NonZeroU64>,
}

impl Transport for Local {
    fn add_queue(&mut self, _: EddsaPublicKey, _: EddsaPublicKey, _: Role) -> Result<(), Error> {
        if !self.evidence.acknowledgement.get() {
            return Err(Error::Replay);
        }
        self.evidence.queue_registered.set(true);
        Ok(())
    }

    fn remove_queue(&mut self) {
        self.evidence.queue_registered.set(false);
    }

    fn receive(
        &mut self,
        _: EddsaPublicKey,
        message: &[u8],
        _: &mut TransportContext<'_, impl Entropy>,
    ) -> Result<Delivery, Error> {
        self.evidence.delivery.set(message == PAYLOAD);
        Ok(Delivery::Consumed)
    }

    fn poll_send(
        &mut self,
        _: &mut TransportContext<'_, impl Entropy>,
        admit: impl FnOnce(Outgoing<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if let Some(message) = &self.output {
            admit(match self.observe {
                Some(id) => Outgoing::ObserveNative { message, id },
                None => Outgoing::Buffered(message),
            })?;
        }
        Ok(())
    }

    fn outgoing_complete(&mut self, result: Result<(), Error>) {
        self.output = None;
        self.evidence.sent.set(Some(result));
    }

    fn outgoing_written(
        &mut self,
        id: NonZeroU64,
        result: Result<(), Error>,
        elapsed: MonoInstant,
    ) {
        self.evidence.written.set(Some((id, result, elapsed)));
        self.evidence
            .write_callbacks
            .set(self.evidence.write_callbacks.get() + 1);
    }

    fn deadlines(&self) -> Result<TransportDeadlines, Error> {
        Ok(TransportDeadlines::default())
    }
}

struct Storage {
    scope: Scope,
    receive: std::vec::Vec<u8>,
    transmit: std::vec::Vec<u8>,
    plaintext: std::vec::Vec<u8>,
    completions: [CompletionSlot; 1],
    scratch: [u8; 128],
}

impl Storage {
    fn new() -> Self {
        Self {
            scope: Scope::new(),
            receive: std::vec![0; wire::MAX_RECORD],
            transmit: std::vec![0; CIPHERTEXT_CAPACITY],
            plaintext: std::vec![0; wire::MAX_RECORD],
            completions: [CompletionSlot::default()],
            scratch: [0; 128],
        }
    }

    fn connection<'a>(
        &'a mut self,
        key: &'a KeyRing,
        handshake: Handshake,
    ) -> Result<Connection<'a>, Error> {
        let mut policy = Policy::reference(NonZeroUsize::new(128).ok_or(Error::InvalidInput)?);
        policy.max_backpressure = self.completions.len();
        policy.max_replay_operations = REPLAY_OPERATIONS;
        Ok(Connection {
            scope: &mut self.scope,
            identity: Identity::from_keys(key),
            handshake,
            buffers: Buffers {
                receive: &mut self.receive,
                transmit: &mut self.transmit,
                plaintext: &mut self.plaintext,
                completions: &mut self.completions,
            },
            policy,
            scratch: Scratch::new(&mut self.scratch)?,
        })
    }
}

fn ports(
    link: &Rc<Link>,
    evidence: &Rc<Evidence>,
    end: usize,
) -> Ports<Socket, History, Board, Local> {
    Ports {
        stream: Socket {
            link: Rc::clone(link),
            end,
        },
        replay: History(Rc::clone(evidence)),
        clock: Board {
            random: 17 + end as u32,
            elapsed: 0,
            high_water: 0,
        },
        transport: Local {
            evidence: Rc::clone(evidence),
            output: (end == 0).then_some(PAYLOAD),
            observe: None,
        },
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert against an observed native owner"
)]
fn rejected_firmware_policy_returns_the_original_stream() -> Result<(), Error> {
    let evidence = Rc::new(Evidence::default());
    let mut storage = Storage::new();
    let key = KeyRing::from_seed([41; 32]);
    for (replay_operations, backpressure, error) in [
        (REPLAY_OPERATIONS + 1, 1, Error::InvalidInput),
        (REPLAY_OPERATIONS, 0, Error::Capacity),
    ] {
        let link = Rc::new(Link::default());
        let mut connection = storage.connection(&key, Handshake::Accept { expected: None })?;
        connection.policy.max_replay_operations = replay_operations;
        connection.policy.max_backpressure = backpressure;
        let rejected = Driver::new(connection, ports(&link, &evidence, 0))
            .err()
            .ok_or(Error::Conflict)?;
        assert_eq!(rejected.reason, error);
        assert!(!link.closed[0].get());
        rejected.value.close()?;
        assert!(link.closed[0].get());
    }
    Ok(())
}

#[test]
fn authenticates_and_settles_replay_before_queue_delivery() -> Result<(), Fault<Error, Error>> {
    let link = Rc::new(Link::default());
    let a = Rc::new(Evidence::default());
    let b = Rc::new(Evidence::default());
    let mut a_storage = Storage::new();
    let mut b_storage = Storage::new();
    let a_key = KeyRing::from_seed([41; 32]);
    let b_key = KeyRing::from_seed([7; 32]);
    let a_connection = a_storage
        .connection(&a_key, Handshake::Initiate(b_key.public()))
        .map_err(Fault::Session)?;
    let b_connection = b_storage
        .connection(
            &b_key,
            Handshake::Accept {
                expected: Some(a_key.public()),
            },
        )
        .map_err(Fault::Session)?;
    let mut outgoing = Driver::new(a_connection, ports(&link, &a, 0))
        .map_err(|error| Fault::Session(error.reason))?;
    let mut incoming = Driver::new(b_connection, ports(&link, &b, 1))
        .map_err(|error| Fault::Session(error.reason))?;
    let ready = Ready {
        readable: true,
        writable: true,
    };
    for _ in 0..768 {
        outgoing.turn(ready)?;
        incoming.turn(ready)?;
        if b.delivery.get() && a.sent.get() == Some(Ok(())) {
            break;
        }
    }
    if !b.delivery.get() || a.sent.get() != Some(Ok(())) {
        return Err(Fault::Session(Error::NotReady));
    }
    outgoing.stop().map_err(Fault::Session)?;
    for _ in 0..128 {
        outgoing.turn(ready)?;
        incoming.turn(ready)?;
        if link.closed[0].get() && link.closed[1].get() {
            break;
        }
    }
    if link.closed.iter().all(Cell::get) && !a.queue_registered.get() && !b.queue_registered.get() {
        Ok(())
    } else {
        Err(Fault::Session(Error::Conflict))
    }
}

#[test]
fn unexpected_authenticated_peer_is_rejected_before_replay() -> Result<(), Fault<Error, Error>> {
    let link = Rc::new(Link::default());
    let a = Rc::new(Evidence::default());
    let b = Rc::new(Evidence::default());
    let mut a_storage = Storage::new();
    let mut b_storage = Storage::new();
    let a_key = KeyRing::from_seed([41; 32]);
    let b_key = KeyRing::from_seed([7; 32]);
    let expected = KeyRing::from_seed([13; 32]).public();
    let a_connection = a_storage
        .connection(&a_key, Handshake::Initiate(b_key.public()))
        .map_err(Fault::Session)?;
    let b_connection = b_storage
        .connection(
            &b_key,
            Handshake::Accept {
                expected: Some(expected),
            },
        )
        .map_err(Fault::Session)?;
    let mut outgoing = Driver::new(a_connection, ports(&link, &a, 0))
        .map_err(|error| Fault::Session(error.reason))?;
    let mut incoming = Driver::new(b_connection, ports(&link, &b, 1))
        .map_err(|error| Fault::Session(error.reason))?;
    let ready = Ready {
        readable: true,
        writable: true,
    };
    for _ in 0..wire::INITIAL_KX {
        outgoing.turn(ready)?;
        match incoming.turn(ready) {
            Err(Fault::PeerRejected) => {
                let closed = incoming.turn(Ready::default())?;
                if matches!(closed, Turn::Closed)
                    && link.closed[1].get()
                    && !b.replay_accessed.get()
                    && !b.queue_registered.get()
                    && link.inbound.borrow()[0].is_empty()
                {
                    return Ok(());
                }
                return Err(Fault::Session(Error::Conflict));
            }
            Err(error) => return Err(error),
            Ok(_) => {}
        }
    }
    Err(Fault::Session(Error::NotReady))
}

type TestDriver<'a> = Driver<'a, Socket, History, Board, Local>;

const WRITE_READY: Ready = Ready {
    readable: false,
    writable: true,
};
const BOX_LEN: usize = wire::BOX_PREFIX + PAYLOAD.len();

fn buffer_frame(
    driver: &mut TestDriver<'_>,
    id: Option<NonZeroU64>,
) -> Result<(), Fault<Error, Error>> {
    driver.transport.output = Some(PAYLOAD);
    driver.transport.observe = id;
    driver.transport.evidence.sent.set(None);
    for _ in 0..16 {
        driver.turn(WRITE_READY)?;
        if let Some(outcome) = driver.transport.evidence.sent.get() {
            return outcome.map_err(Fault::Session);
        }
    }
    Err(Fault::Session(Error::NotReady))
}

#[test]
fn observes_only_the_original_native_prefix_and_fences_partial_close()
-> Result<(), Fault<Error, Error>> {
    let link = Rc::new(Link::default());
    let a = Rc::new(Evidence::default());
    let b = Rc::new(Evidence::default());
    let mut a_storage = Storage::new();
    let mut b_storage = Storage::new();
    let a_key = KeyRing::from_seed([41; 32]);
    let b_key = KeyRing::from_seed([7; 32]);
    let a_connection = a_storage
        .connection(&a_key, Handshake::Initiate(b_key.public()))
        .map_err(Fault::Session)?;
    let b_connection = b_storage
        .connection(
            &b_key,
            Handshake::Accept {
                expected: Some(a_key.public()),
            },
        )
        .map_err(Fault::Session)?;
    let mut a_ports = ports(&link, &a, 0);
    a_ports.transport.output = None;
    let mut outgoing =
        Driver::new(a_connection, a_ports).map_err(|error| Fault::Session(error.reason))?;
    let mut incoming = Driver::new(b_connection, ports(&link, &b, 1))
        .map_err(|error| Fault::Session(error.reason))?;
    let ready = Ready {
        readable: true,
        writable: true,
    };
    for _ in 0..768 {
        outgoing.turn(ready)?;
        incoming.turn(ready)?;
        if a.queue_registered.get()
            && b.queue_registered.get()
            && !outgoing.interest().writable
            && !outgoing.interest().buffered_input
        {
            break;
        }
    }
    if !a.queue_registered.get()
        || !b.queue_registered.get()
        || outgoing.interest().writable
        || outgoing.interest().buffered_input
    {
        return Err(Fault::Session(Error::NotReady));
    }

    let first = NonZeroU64::new(80).ok_or(Fault::Session(Error::InvalidInput))?;
    let second = NonZeroU64::new(81).ok_or(Fault::Session(Error::InvalidInput))?;
    link.write_limit[0].set(Some(0));
    buffer_frame(&mut outgoing, None)?;
    buffer_frame(&mut outgoing, Some(first))?;
    buffer_frame(&mut outgoing, None)?;
    if a.written.get().is_some() || outgoing.pump.session().pending_transmit() != 3 * BOX_LEN {
        return Err(Fault::Session(Error::Conflict));
    }

    // The leading ordinary BOX, retry, and all but one byte of the observed
    // BOX are insufficient. Later ordinary ciphertext must not delay it.
    for count in [BOX_LEN, 0, BOX_LEN - 1] {
        link.write_limit[0].set(Some(count));
        if !matches!(outgoing.turn(WRITE_READY)?, Turn::Stream(progress) if progress.written == count)
            || a.written.get().is_some()
        {
            return Err(Fault::Session(Error::Conflict));
        }
    }
    link.write_limit[0].set(Some(1));
    if !matches!(outgoing.turn(WRITE_READY)?, Turn::Stream(progress) if progress.written == 1)
        || a.written.get() != Some((first, Ok(()), outgoing.last_elapsed))
        || a.write_callbacks.get() != 1
        || outgoing.pump.session().pending_transmit() != BOX_LEN
    {
        return Err(Fault::Session(Error::Conflict));
    }

    link.write_limit[0].set(Some(0));
    buffer_frame(&mut outgoing, Some(second))?;
    link.write_limit[0].set(Some(BOX_LEN + 1));
    if !matches!(outgoing.turn(WRITE_READY)?, Turn::Stream(progress) if progress.written == BOX_LEN + 1)
        || a.write_callbacks.get() != 1
    {
        return Err(Fault::Session(Error::Conflict));
    }
    outgoing.abort();
    if a.written.get() != Some((second, Err(Error::Closed), outgoing.last_elapsed)) {
        return Err(Fault::Session(Error::Conflict));
    }
    drop(outgoing);
    if a.write_callbacks.get() != 2 || a.queue_registered.get() {
        return Err(Fault::Session(Error::Conflict));
    }
    Ok(())
}
