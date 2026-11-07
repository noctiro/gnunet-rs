use crate::support::{self, Clock, Kind, Outbox};
use crate::{
    Binding, BobSums, Error, Frame, Instance, Limits, MatchedVector, OutputId, RejectedFrame,
    Terminal, bob_left, bob_right,
};
use alloc::vec::Vec;
use core::mem::size_of;
use gnunet_paillier::{Ciphertext, EncryptJob, Entropy, Progress, PublicKey};
use gnunet_types::Error as CoreError;
use gnunet_wire::official::scalarproduct::PeerMessage;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Waiting,
    Masks,
    PermP,
    PermQ,
    Sums,
    Sum,
    Prime,
    Pairs,
    Complete,
    Failed,
}

/// The real Paillier responder. Original SETI completion and actual received
/// Alice ciphertext count are separate prerequisites, in either arrival order.
/// It never exposes private coefficients or a fabricated computation ACK.
pub struct Bob<'id> {
    limits: Limits,
    clock: Clock,
    session: [u8; 64],
    vector: MatchedVector,
    public: Option<PublicKey>,
    state: State,
    activated: bool,
    alice: Vec<Ciphertext>,
    masks: Vec<i32>,
    p: Vec<usize>,
    q: Vec<usize>,
    permutation: usize,
    rejections: u32,
    sums: Option<BobSums>,
    sum_cursor: usize,
    encrypt: Vec<EncryptJob>,
    body: Vec<[u8; 516]>,
    computed: usize,
    right: bool,
    first: bool,
    sent: usize,
    handed_off: bool,
    out: Outbox<'id>,
    failure: Option<Error>,
    peer_failure: Option<Error>,
    local_retired: bool,
    external: usize,
}
impl<'id> Bob<'id> {
    /// Admit a real local responder vector and original session port/hash.
    /// Actual peer identity and channel remain bound by the native owner.
    pub fn new(
        instance: &'id Instance,
        session: [u8; 64],
        vector: MatchedVector,
        limits: Limits,
        now: u64,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if vector.is_sealed() || vector.initial_rows() > limits.max_rows {
            return Err(CoreError::InvalidInput.into());
        }
        let rows = vector.initial_rows();
        let reply_values = rows
            .checked_mul(2)
            .and_then(|count| count.checked_add(2))
            .ok_or(CoreError::Overflow)?;
        let mut value = Self {
            limits,
            clock: Clock::new(now, limits.lifetime_micros)?,
            session,
            vector,
            public: None,
            state: State::Waiting,
            activated: false,
            alice: Vec::new(),
            masks: Vec::new(),
            p: Vec::new(),
            q: Vec::new(),
            permutation: 0,
            rejections: 0,
            sums: None,
            sum_cursor: 0,
            encrypt: Vec::new(),
            body: Vec::new(),
            computed: 0,
            right: false,
            first: true,
            sent: 0,
            handed_off: false,
            out: Outbox::new(instance)?,
            failure: None,
            peer_failure: None,
            local_retired: false,
            external: 0,
        };
        value.alice = support::reserve(rows, value.available()?)?;
        value.masks = support::reserve(rows, value.available()?)?;
        value.p = support::reserve(rows, value.available()?)?;
        value.q = support::reserve(rows, value.available()?)?;
        value.encrypt = support::reserve(1, value.available()?)?;
        value.body = support::reserve(reply_values.min(limits.ciphers()), value.available()?)?;
        value.available()?;
        Ok(value)
    }
    /// The actual accepted original CADET channel is usable, not a remote
    /// mathematical result. Opening the listener alone is insufficient.
    pub fn activate(&mut self, binding: Binding<'id>) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        if self.activated || self.state != State::Waiting {
            return Err(Error::Phase);
        }
        self.activated = true;
        Ok(())
    }
    /// Whether the real original Session frame has arrived and SETI may begin.
    #[must_use]
    pub fn intersection_required(&self) -> bool {
        self.activated
            && self.public.is_some()
            && !self.vector.is_sealed()
            && self.failure.is_none()
    }
    /// Original nonzero keys for this original SETI operation only.
    pub fn intersection_keys(&self) -> impl Iterator<Item = &[u8; 64]> {
        self.vector.keys()
    }
    /// Borrow the original SETI population key in O(1), before real DONE.
    #[must_use]
    pub fn intersection_key(&self, index: usize) -> Option<&[u8; 64]> {
        self.vector.intersection_key(index)
    }
    /// Original opaque callback identity for this native and SETI operation.
    #[must_use]
    pub fn binding(&self) -> Binding<'id> {
        self.out.binding()
    }
    /// Apply an actual original DEL_LOCAL callback, without mutating coefficients.
    pub fn intersection_removed(
        &mut self,
        binding: Binding<'id>,
        key: &[u8; 64],
        now: u64,
    ) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        self.live(now)?;
        if self.public.is_none() {
            return self.record(Err(Error::Phase));
        }
        let result = self.vector.remove(key);
        self.record(result)
    }
    /// The real original SETI DONE. Alice's native cryptodata count is never
    /// replaced by the local client count or by a comment about its completion.
    pub fn intersection_done(
        &mut self,
        binding: Binding<'id>,
        size: u64,
        now: u64,
    ) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        self.live(now)?;
        if self.public.is_none() {
            return self.record(Err(Error::Phase));
        }
        let result = (|| {
            self.vector.seal(size)?;
            self.sums = Some(BobSums::new(self.vector.len()?)?);
            Ok(())
        })();
        self.record(result)
    }
    /// Adopt only an actual original-channel frame. On WouldBlock the caller
    /// keeps the exact original delivery and receive_done debt for later retry.
    pub fn receive(
        &mut self,
        binding: Binding<'id>,
        message: PeerMessage<'_>,
        now: u64,
    ) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        self.live(now)?;
        if !self.activated || self.state != State::Waiting {
            return self.record(Err(Error::Phase));
        }
        let result = self.receive_inner(message);
        if matches!(result, Err(Error::Core(CoreError::WouldBlock))) {
            return result;
        }
        self.record(result)
    }
    fn receive_inner(&mut self, message: PeerMessage<'_>) -> Result<(), Error> {
        if message.encoded_len()? > self.limits.frame_bytes {
            return Err(CoreError::Capacity.into());
        }
        match message {
            PeerMessage::PaillierSession {
                session,
                public_key,
                ..
            } => {
                if session != &self.session || self.public.is_some() {
                    return Err(CoreError::Conflict.into());
                }
                let public = PublicKey::from_bytes(public_key)?;
                self.public = Some(public);
            }
            PeerMessage::PaillierAlice { values } => {
                if self.public.is_none() {
                    return Err(Error::Phase);
                }
                if !self.vector.is_sealed() {
                    return Err(CoreError::WouldBlock.into());
                }
                let count = self
                    .alice
                    .len()
                    .checked_add(values.len())
                    .ok_or(CoreError::Overflow)?;
                if values.is_empty() || count > self.vector.len()? {
                    return Err(CoreError::InvalidInput.into());
                }
                // Shape/count/capacity have all been checked. Admission itself
                // preserves the exact public fields; real arithmetic later
                // validates each ciphertext/unit against the original modulus.
                for value in values {
                    self.alice.push(Ciphertext::from_wire(*value));
                }
            }
            _ => return Err(Error::Phase),
        }
        Ok(())
    }
    /// Original official output ready for an actual native admission.
    #[must_use]
    pub fn output(&self) -> Option<OutputId<'id>> {
        self.out.output()
    }
    /// Transfer exactly this retained original frame allocation.
    pub fn admit_output(&mut self, id: OutputId<'id>) -> Result<Frame<'id>, Error> {
        self.out.admit(id)
    }
    /// Settle the actual original MQ disposition once, without allocation.
    /// The final Written means only Bob's local reply handoff, as in the public
    /// C client contract; it grants no proof that Alice computed a product.
    pub fn complete_output(
        &mut self,
        frame: Frame<'id>,
        terminal: Terminal,
    ) -> Result<(), RejectedFrame<'id>> {
        let preflight = (|| {
            let kind = self.out.check(frame.id())?;
            let mut sent = self.sent;
            if self.failure.is_none() && matches!(terminal, Terminal::Written) {
                let Kind::Bob { first, count, last } = kind else {
                    return Err(Error::Phase);
                };
                if first != self.first {
                    return Err(Error::Phase);
                }
                sent = sent.checked_add(count).ok_or(CoreError::Overflow)?;
                let rows = self.vector.len()?;
                if sent > rows || (last && sent != rows) {
                    return Err(Error::Phase);
                }
            }
            Ok((kind, sent))
        })();
        let (kind, sent) = match preflight {
            Ok(value) => value,
            Err(error) => return Err(RejectedFrame::new(error, frame)),
        };
        if let Err(error) = self.out.complete(frame.id()) {
            return Err(RejectedFrame::new(error, frame));
        }
        drop(frame);
        // Preserve the real original last whole-write even when cancellation
        // was observed first. Existing failure still blocks a new success.
        if matches!(terminal, Terminal::Written) && matches!(kind, Kind::Bob { last: true, .. }) {
            self.handed_off = true;
        }
        if self.failure.is_some() {
            return Ok(());
        }
        match terminal {
            Terminal::Unsent(error) | Terminal::Lost(error) => self.fail(error),
            Terminal::Written => {
                self.sent = sent;
                self.first = false;
                if matches!(kind, Kind::Bob { last: true, .. }) {
                    self.erase();
                    self.state = State::Complete;
                }
            }
        }
        Ok(())
    }
    /// Perform at most the configured finite number of primitive/cursor units.
    /// Independent uniform Fisher-Yates permutations and fresh signed32 masks
    /// use only this explicit caller entropy, with finite rejection bounds.
    pub fn progress(
        &mut self,
        now: u64,
        entropy: &mut impl Entropy,
        units: u16,
    ) -> Result<bool, Error> {
        if self.state == State::Complete {
            return Ok(false);
        }
        self.live(now)?;
        let units = self.limits.units(units)?;
        let mut progressed = false;
        for _ in 0..units {
            match self.step(entropy) {
                Ok(true) => progressed = true,
                Ok(false) => break,
                Err(error) => {
                    self.fail(error);
                    return Err(error);
                }
            }
        }
        Ok(progressed)
    }
    fn step(&mut self, entropy: &mut impl Entropy) -> Result<bool, Error> {
        if self.out.busy() {
            return Ok(false);
        }
        if self.state == State::Waiting {
            if !self.activated
                || self.public.is_none()
                || !self.vector.is_sealed()
                || self.alice.len() != self.vector.len()?
            {
                return Ok(false);
            }
            self.state = State::Masks;
            return Ok(true);
        }
        let count = self.vector.len()?;
        if self.state == State::Masks {
            let index = self.masks.len();
            if index == count {
                self.permutation = count;
                self.state = State::PermP;
                return Ok(true);
            }
            let mut bytes = Zeroizing::new([0; 4]);
            entropy
                .fill(bytes.as_mut())
                .map_err(gnunet_paillier::Error::Entropy)?;
            self.masks.push(i32::from_be_bytes(*bytes));
            self.p.push(index);
            self.q.push(index);
            return Ok(true);
        }
        if matches!(self.state, State::PermP | State::PermQ) {
            if self.permutation <= 1 {
                if self.state == State::PermP {
                    self.state = State::PermQ;
                    self.permutation = count;
                } else {
                    self.state = State::Sums;
                }
                return Ok(true);
            }
            let bound = u32::try_from(self.permutation).map_err(|_| CoreError::Overflow)?;
            let mut bytes = Zeroizing::new([0; 4]);
            entropy
                .fill(bytes.as_mut())
                .map_err(gnunet_paillier::Error::Entropy)?;
            let value = Zeroizing::new(u32::from_be_bytes(*bytes));
            let threshold = bound.wrapping_neg() % bound;
            if *value < threshold {
                self.rejections = self.rejections.checked_add(1).ok_or(CoreError::Overflow)?;
                if self.rejections >= self.limits.primitive.rejections {
                    return Err(CoreError::Capacity.into());
                }
                return Ok(true);
            }
            self.rejections = 0;
            let index =
                Zeroizing::new(usize::try_from(*value % bound).map_err(|_| CoreError::Overflow)?);
            let list = if self.state == State::PermP {
                &mut self.p
            } else {
                &mut self.q
            };
            list.swap(self.permutation - 1, *index);
            self.permutation -= 1;
            return Ok(true);
        }
        if self.state == State::Sums {
            if self.sum_cursor == count {
                self.state = State::Sum;
                return Ok(true);
            }
            let index = self.sum_cursor;
            self.sums
                .as_mut()
                .ok_or(Error::Phase)?
                .push(self.vector.coefficient(index)?, self.masks[index])?;
            self.sum_cursor += 1;
            return Ok(true);
        }
        if self.state == State::Pairs {
            let capacity = self.limits.bob_pairs(self.first);
            let in_frame = (self.body.len() - if self.first { 2 } else { 0 }) / 2;
            if !self.right && (in_frame == capacity || self.computed == count) {
                let budget = self.available()?;
                let message = if self.first {
                    PeerMessage::PaillierBob { values: &self.body }
                } else {
                    PeerMessage::PaillierBobPart { values: &self.body }
                };
                self.out.queue(
                    message,
                    Kind::Bob {
                        first: self.first,
                        count: in_frame,
                        last: self.computed == count,
                    },
                    budget,
                    self.limits.frame_bytes,
                )?;
                self.body.zeroize();
                self.body.clear();
                return Ok(true);
            }
        }
        if self.encrypt.is_empty() {
            let public = self.public.as_ref().ok_or(Error::Phase)?;
            let (plain, operations) = match self.state {
                State::Sum => (self.sums.as_ref().ok_or(Error::Phase)?.sum(public)?, 1),
                State::Prime => (self.sums.as_ref().ok_or(Error::Phase)?.prime(public)?, 1),
                State::Pairs => {
                    let index = if self.right {
                        self.q[self.computed]
                    } else {
                        self.p[self.computed]
                    };
                    (
                        if self.right {
                            bob_right(public, self.masks[index])?
                        } else {
                            bob_left(public, self.vector.coefficient(index)?, self.masks[index])?
                        },
                        2,
                    )
                }
                _ => return Ok(false),
            };
            self.encrypt
                .push(public.encrypt(plain, operations, self.limits.primitive)?);
            return Ok(true);
        }
        if self.encrypt[0].advance(entropy, 1)? != Progress::Ready {
            return Ok(true);
        }
        let cipher = self.encrypt[0].take_result()?;
        self.encrypt.clear();
        match self.state {
            State::Sum => {
                self.body.push(cipher.to_wire());
                self.state = State::Prime;
            }
            State::Prime => {
                self.body.push(cipher.to_wire());
                self.state = State::Pairs;
            }
            State::Pairs => {
                let index = if self.right {
                    self.q[self.computed]
                } else {
                    self.p[self.computed]
                };
                let combined = self
                    .public
                    .as_ref()
                    .ok_or(Error::Phase)?
                    .homomorphic_add(&cipher, &self.alice[index])?;
                self.body.push(combined.to_wire());
                if self.right {
                    self.computed += 1;
                }
                self.right = !self.right;
            }
            _ => return Err(Error::Phase),
        }
        Ok(true)
    }
    /// Actual final original reply whole-write fact, not Alice's computation.
    #[must_use]
    pub fn reply_handed_off(&self) -> bool {
        self.handed_off
    }
    /// The actual last original complete local reply write is already known.
    /// This capability never treats peer/source closure as that write or ACK.
    #[must_use]
    pub fn can_finish_locally(&self) -> bool {
        self.failure.is_none()
            && self.handed_off
            && !self.out.busy()
            && self.state == State::Complete
    }
    /// Record actual original source retirement after the real local handoff.
    /// Caller has physically retired old IO and settled its original receipts;
    /// the source cause remains independent of Bob's local handoff fact.
    pub fn retire_peer_for_local_work(
        &mut self,
        binding: Binding<'id>,
        cause: Error,
    ) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        if self.local_retired {
            return Err(Error::Finished);
        }
        if !self.can_finish_locally() {
            return Err(Error::Phase);
        }
        if self.peer_failure.is_none() {
            self.peer_failure = Some(cause);
        }
        self.local_retired = true;
        Ok(())
    }
    /// A real original peer source loss. Already known local handoff remains a
    /// separate local fact; original loss is retained independently.
    pub fn peer_lost(&mut self, binding: Binding<'id>, error: Error) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        if self.peer_failure.is_none() {
            self.peer_failure = Some(error);
        }
        if self.local_retired {
            return Ok(());
        }
        if self.state != State::Complete {
            self.fail(error);
        }
        Ok(())
    }
    /// Cancel original work; actual admitted frame debts still require terminals.
    pub fn cancel(&mut self) {
        self.fail(Error::Cancelled);
    }
    /// Original lifetime, without renewal across retries or changed public keys.
    #[must_use]
    pub fn deadline(&self) -> Option<u64> {
        if matches!(self.state, State::Complete | State::Failed) {
            None
        } else {
            Some(self.clock.deadline())
        }
    }
    /// First original computation/IO-class failure.
    #[must_use]
    pub const fn failure(&self) -> Option<Error> {
        self.failure
    }
    /// First actual original source retirement, also after a known local handoff.
    #[must_use]
    pub const fn peer_failure(&self) -> Option<Error> {
        self.peer_failure
    }
    /// Actual original admitted frame obligations have all been settled.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        !self.out.admitted() && matches!(self.state, State::Complete | State::Failed)
    }
    /// Actual allocation capacities and reported native retained bytes.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        support::sum(&[
            size_of::<Self>(),
            self.vector.retained_bytes(),
            support::bytes(&self.alice)?,
            support::bytes(&self.masks)?,
            support::bytes(&self.p)?,
            support::bytes(&self.q)?,
            support::bytes(&self.encrypt)?,
            support::bytes(&self.body)?,
            self.out.bytes(),
            self.external,
        ])
    }
    /// Charge actual additional native buffers before admitting them; reduction
    /// of a prior valid charge never requires an allocation or a new quota.
    pub fn set_external_retained_bytes(&mut self, bytes: usize) -> Result<(), Error> {
        let base = self
            .retained_bytes()?
            .checked_sub(self.external)
            .ok_or(CoreError::Overflow)?;
        if support::sum(&[base, bytes])? > self.limits.max_retained_bytes {
            return Err(CoreError::Capacity.into());
        }
        self.external = bytes;
        Ok(())
    }
    fn available(&self) -> Result<usize, Error> {
        support::available(self.retained_bytes()?, self.limits.max_retained_bytes)
    }
    fn live(&mut self, now: u64) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        match self.clock.observe(now) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.fail(error);
                Err(error)
            }
        }
    }
    fn record(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        if let Err(error) = result {
            self.fail(error);
        }
        result
    }
    fn erase(&mut self) {
        for job in &mut self.encrypt {
            job.cancel();
        }
        self.encrypt.clear();
        self.vector.clear();
        self.alice.zeroize();
        self.alice.clear();
        self.masks.zeroize();
        self.masks.clear();
        self.p.zeroize();
        self.p.clear();
        self.q.zeroize();
        self.q.clear();
        self.body.zeroize();
        self.body.clear();
        self.sums = None;
        self.public = None;
    }
    fn fail(&mut self, error: Error) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        self.erase();
        self.out.clear_unadmitted();
        self.state = State::Failed;
    }
}
impl Drop for Bob<'_> {
    fn drop(&mut self) {
        self.masks.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.body.zeroize();
        self.alice.zeroize();
    }
}
