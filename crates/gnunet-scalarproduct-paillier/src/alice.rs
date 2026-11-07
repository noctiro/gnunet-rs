use crate::support::{self, Clock, Kind, Outbox};
use crate::{
    AliceMath, Binding, Error, Frame, Instance, Limits, MatchedVector, OutputId, Product,
    RejectedFrame, Terminal, alice_value,
};
use alloc::{rc::Rc, vec::Vec};
use core::mem::size_of;
use gnunet_paillier::{Ciphertext, DecryptJob, EncryptJob, Entropy, KeyPair, Progress};
use gnunet_types::Error as CoreError;
use gnunet_wire::official::scalarproduct::PeerMessage;
use zeroize::Zeroize;

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Setup,
    Encrypt,
    Reply,
    Decrypt,
    Complete,
    Consumed,
    Failed,
}

/// The real Paillier initiator. Its original shared key snapshot, SETI vector,
/// wire-session identifier, domain, deadline and output leases never rebind.
pub struct Alice<'id> {
    limits: Limits,
    clock: Clock,
    session: [u8; 64],
    key: Option<Rc<KeyPair>>,
    vector: MatchedVector,
    state: State,
    activated: bool,
    introduced: bool,
    cursor: usize,
    sent: usize,
    body: Vec<[u8; 516]>,
    encrypt: Vec<EncryptJob>,
    decrypt: Vec<DecryptJob>,
    out: Outbox<'id>,
    input: Vec<[u8; 516]>,
    input_first: bool,
    input_cursor: usize,
    reply_started: bool,
    received: usize,
    math: Option<AliceMath>,
    product: Option<Product>,
    computed: bool,
    failure: Option<Error>,
    peer_failure: Option<Error>,
    local_retired: bool,
    external: usize,
}
impl<'id> Alice<'id> {
    /// Admit this original operation. The Rc retains the actual original key;
    /// global key rotation or another session cannot replace its n/lambda/mu.
    /// Actual channel/SETI acquisition remains the native owner's responsibility.
    pub fn new(
        instance: &'id Instance,
        session: [u8; 64],
        key: Rc<KeyPair>,
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
            key: Some(key),
            vector,
            state: State::Setup,
            activated: false,
            introduced: false,
            cursor: 0,
            sent: 0,
            body: Vec::new(),
            encrypt: Vec::new(),
            decrypt: Vec::new(),
            out: Outbox::new(instance)?,
            input: Vec::new(),
            input_first: false,
            input_cursor: 0,
            reply_started: false,
            received: 0,
            math: None,
            product: None,
            computed: false,
            failure: None,
            peer_failure: None,
            local_retired: false,
            external: 0,
        };
        value.body = support::reserve(rows.min(limits.ciphers()), value.available()?)?;
        value.input = support::reserve(reply_values.min(limits.ciphers()), value.available()?)?;
        value.encrypt = support::reserve(usize::from(rows != 0), value.available()?)?;
        value.decrypt = support::reserve(1, value.available()?)?;
        value.available()?;
        Ok(value)
    }
    /// Initial keys, supplied only to the original SETI listener/operation.
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
    /// Original actual DEL_LOCAL callback, before original DONE only.
    pub fn intersection_removed(
        &mut self,
        binding: Binding<'id>,
        key: &[u8; 64],
        now: u64,
    ) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        self.live(now)?;
        let result = self.vector.remove(key);
        self.record(result)
    }
    /// Original real SETI DONE. It does not imply a CADET write, reply or result.
    pub fn intersection_done(
        &mut self,
        binding: Binding<'id>,
        size: u64,
        now: u64,
    ) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        self.live(now)?;
        let result = (|| {
            self.vector.seal(size)?;
            self.math = Some(AliceMath::new(self.vector.len()?)?);
            Ok(())
        })();
        self.record(result)
    }
    /// The actual original CADET channel is usable. A local create/write can
    /// permit sending, but this method grants no peer-online or result proof.
    pub fn activate(&mut self, binding: Binding<'id>) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        if self.state != State::Setup || self.activated {
            return Err(Error::Phase);
        }
        self.activated = true;
        Ok(())
    }
    /// Immutable original official output identity ready for native admission.
    #[must_use]
    pub fn output(&self) -> Option<OutputId<'id>> {
        self.out.output()
    }
    /// Transfer exactly one prepared official allocation to its original owner.
    pub fn admit_output(&mut self, id: OutputId<'id>) -> Result<Frame<'id>, Error> {
        self.out.admit(id)
    }
    /// Apply the real original write disposition once, even after cancellation.
    /// This path allocates nothing and never fabricates a reply or peer ACK.
    pub fn complete_output(
        &mut self,
        frame: Frame<'id>,
        terminal: Terminal,
    ) -> Result<(), RejectedFrame<'id>> {
        let preflight = (|| {
            let kind = self.out.check(frame.id())?;
            let mut sent = self.sent;
            let mut last = false;
            if self.failure.is_none() && matches!(terminal, Terminal::Written) {
                match kind {
                    Kind::Introduction => {}
                    Kind::Alice(count) => {
                        sent = sent.checked_add(count).ok_or(CoreError::Overflow)?;
                        let rows = self.vector.len()?;
                        if sent > rows {
                            return Err(Error::Phase);
                        }
                        last = sent == rows;
                    }
                    Kind::Bob { .. } => return Err(Error::Phase),
                }
            }
            Ok((kind, sent, last))
        })();
        let (kind, sent, last) = match preflight {
            Ok(value) => value,
            Err(error) => return Err(RejectedFrame::new(error, frame)),
        };
        if let Err(error) = self.out.complete(frame.id()) {
            return Err(RejectedFrame::new(error, frame));
        }
        drop(frame);
        if self.failure.is_some() {
            return Ok(());
        }
        match terminal {
            Terminal::Unsent(error) | Terminal::Lost(error) => self.fail(error),
            Terminal::Written => match kind {
                Kind::Introduction => self.introduced = true,
                Kind::Alice(_) => {
                    self.sent = sent;
                    if last {
                        self.state = State::Reply;
                    }
                }
                Kind::Bob { .. } => {} // rejected before application above
            },
        }
        Ok(())
    }
    /// Adopt only a real message delivered on this original authenticated
    /// peer/channel. Caller must retain the original delivery while WouldBlock.
    /// A successful copy is local input admission, not arithmetic completion.
    pub fn receive(
        &mut self,
        binding: Binding<'id>,
        message: PeerMessage<'_>,
        now: u64,
    ) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        self.live(now)?;
        if !self.input.is_empty() {
            return Err(CoreError::WouldBlock.into());
        }
        if !matches!(self.state, State::Reply | State::Decrypt) {
            return Err(Error::Phase);
        }
        let (values, first) = match message {
            PeerMessage::PaillierBob { values } if !self.reply_started => (values, true),
            PeerMessage::PaillierBobPart { values } if self.reply_started => (values, false),
            _ => return self.record(Err(Error::Phase)),
        };
        let base = if first { 2 } else { 0 };
        let encoded_len = match message.encoded_len() {
            Ok(length) => length,
            Err(error) => return self.record(Err(error.into())),
        };
        if values.len() < base
            || !(values.len() - base).is_multiple_of(2)
            || (!first && values.is_empty())
            || values.len() > self.limits.ciphers()
            || values.len() > self.input.capacity()
            || encoded_len > self.limits.frame_bytes
        {
            return self.record(Err(CoreError::InvalidInput.into()));
        }
        let pairs = (values.len() - base) / 2;
        let received = self
            .received
            .checked_add(pairs)
            .ok_or(CoreError::Overflow)?;
        if received > self.vector.len()? {
            return self.record(Err(CoreError::InvalidInput.into()));
        }
        self.input.extend_from_slice(values);
        self.input_first = first;
        self.input_cursor = 0;
        self.received = received;
        self.reply_started = true;
        self.state = State::Decrypt;
        Ok(())
    }
    /// Advance at most the selected finite number of original work units.
    /// Fixed-width validation/division boundaries are finite, not OS-preemptible.
    pub fn progress(
        &mut self,
        now: u64,
        entropy: &mut impl Entropy,
        units: u16,
    ) -> Result<bool, Error> {
        if matches!(self.state, State::Complete | State::Consumed) {
            return Ok(false);
        }
        self.live(now)?;
        let units = self.limits.units(units)?;
        let mut progressed = false;
        for _ in 0..units {
            let result = self.step(entropy);
            match result {
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
        if self.state == State::Setup {
            if !self.activated {
                return Ok(false);
            }
            if !self.introduced {
                let public = self
                    .key
                    .as_ref()
                    .ok_or(Error::Finished)?
                    .public_key()
                    .to_bytes();
                let budget = self.available()?;
                self.out.queue(
                    PeerMessage::PaillierSession {
                        reserved: 0,
                        session: &self.session,
                        public_key: &public,
                    },
                    Kind::Introduction,
                    budget,
                    self.limits.frame_bytes,
                )?;
                return Ok(true);
            }
            if !self.vector.is_sealed() {
                return Ok(false);
            }
            if self.vector.is_empty()? {
                self.state = State::Reply;
            } else {
                self.state = State::Encrypt;
            }
            return Ok(true);
        }
        if self.state == State::Encrypt {
            if self.encrypt.is_empty() {
                let public = self.key.as_ref().ok_or(Error::Finished)?.public_key();
                let value = alice_value(public, self.vector.coefficient(self.cursor)?)?;
                self.encrypt
                    .push(public.encrypt(value, 3, self.limits.primitive)?);
                return Ok(true);
            }
            if self.encrypt[0].advance(entropy, 1)? != Progress::Ready {
                return Ok(true);
            }
            let cipher = self.encrypt[0].take_result()?;
            self.encrypt.clear();
            self.body.push(cipher.to_wire());
            self.cursor += 1;
            if self.body.len() == self.limits.ciphers() || self.cursor == self.vector.len()? {
                let count = self.body.len();
                let budget = self.available()?;
                self.out.queue(
                    PeerMessage::PaillierAlice { values: &self.body },
                    Kind::Alice(count),
                    budget,
                    self.limits.frame_bytes,
                )?;
                self.body.zeroize();
                self.body.clear();
            }
            return Ok(true);
        }
        if self.state != State::Decrypt {
            return Ok(false);
        }
        if self.decrypt.is_empty() {
            let cipher = Ciphertext::from_wire(self.input[self.input_cursor]);
            let key = self.key.as_ref().ok_or(Error::Finished)?;
            self.decrypt.push(key.private_key().decrypt(
                key.public_key(),
                &cipher,
                self.limits.primitive,
            )?);
            return Ok(true);
        }
        if self.decrypt[0].advance(1)? != Progress::Ready {
            return Ok(true);
        }
        let plain = self.decrypt[0].take_result()?;
        self.decrypt.clear();
        let bytes = plain.to_bytes();
        let math = self.math.as_mut().ok_or(Error::Phase)?;
        if self.input_first && self.input_cursor == 0 {
            math.sum(&bytes)?;
        } else if self.input_first && self.input_cursor == 1 {
            math.prime(&bytes)?;
        } else if self.input_cursor.is_multiple_of(2) {
            math.left(&bytes)?;
        } else {
            math.right(&bytes)?;
        }
        self.input_cursor += 1;
        if self.input_cursor == self.input.len() {
            self.input.zeroize();
            self.input.clear();
            self.input_cursor = 0;
            if self.received == self.vector.len()? {
                self.product = Some(math.finish()?);
                self.computed = true;
                self.math = None;
                self.vector.clear();
                self.key = None;
                self.state = State::Complete;
            } else {
                self.state = State::Reply;
            }
        }
        Ok(true)
    }
    /// Consume the actual computed result once. Native client output and source
    /// retirement are still real separate owner obligations.
    pub fn take_product(&mut self) -> Result<Product, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.state != State::Complete {
            return Err(Error::Phase);
        }
        let product = self.product.take().ok_or(Error::Finished)?;
        self.state = State::Consumed;
        Ok(product)
    }
    /// Whether the original arithmetic really completed, even if its private
    /// result was later erased by caller cancellation before client output.
    #[must_use]
    pub const fn product_computed(&self) -> bool {
        self.computed
    }
    /// All required original reply bytes were copied after the real original
    /// SETI DONE, or the real arithmetic already completed. This is a phase
    /// capability only: it does not prove a peer close, ACK or valid product.
    #[must_use]
    pub fn can_finish_locally(&self) -> bool {
        self.failure.is_none()
            && !self.out.busy()
            && (matches!(self.state, State::Complete | State::Consumed)
                || (self.state == State::Decrypt
                    && self.math.is_some()
                    && self.reply_started
                    && self.vector.is_sealed()
                    && self.vector.len().is_ok_and(|rows| self.received == rows)))
    }
    /// Only an already held original reply continuation can unblock after an
    /// earlier chunk's cooperative decryption. No peer output is still owed.
    /// The native owner must retain the exact source, packet and original time
    /// bounds, validate every tail through receive, and admit no new peer IO.
    /// This is not complete transcript ownership or product/result authority.
    #[must_use]
    pub fn can_drain_peer_input(&self) -> bool {
        self.failure.is_none()
            && !self.local_retired
            && self.activated
            && self.introduced
            && self.reply_started
            && self.math.is_some()
            && self.vector.is_sealed()
            && self.vector.len().is_ok_and(|rows| self.received < rows)
            && !self.out.busy()
            && matches!(self.state, State::Reply | State::Decrypt)
    }
    /// Record actual original source retirement while preserving only complete
    /// already-owned local work. Caller must first validate all outer packet
    /// tails, physically detach every old source and settle all original native
    /// receipts. No further old IO/receive_done may follow this boundary.
    /// The original clock/deadline and actual decrypt/range/evenness checks stay.
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
    /// Real original peer loss. A completed product remains a computed fact;
    /// the independent source error is retained and never called an ACK.
    pub fn peer_lost(&mut self, binding: Binding<'id>, error: Error) -> Result<(), Error> {
        self.out.validate_binding(binding)?;
        if self.peer_failure.is_none() {
            self.peer_failure = Some(error);
        }
        if self.local_retired {
            return Ok(());
        }
        if !matches!(self.state, State::Complete | State::Consumed) {
            self.fail(error);
        }
        Ok(())
    }
    /// Explicit original cancellation erases jobs/plaintexts/results and keeps
    /// an already admitted frame debt until its actual original terminal.
    pub fn cancel(&mut self) {
        self.fail(Error::Cancelled);
    }
    /// Original finite deadline, never renewed by retries or a different key.
    #[must_use]
    pub fn deadline(&self) -> Option<u64> {
        if matches!(
            self.state,
            State::Complete | State::Consumed | State::Failed
        ) {
            None
        } else {
            Some(self.clock.deadline())
        }
    }
    /// First original computation failure, distinct from later source retirement.
    #[must_use]
    pub const fn failure(&self) -> Option<Error> {
        self.failure
    }
    /// First real peer source failure, even when a result was already computed.
    #[must_use]
    pub const fn peer_failure(&self) -> Option<Error> {
        self.peer_failure
    }
    /// All original admitted frame obligations have actually been settled.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        !self.out.admitted()
            && matches!(
                self.state,
                State::Complete | State::Consumed | State::Failed
            )
    }
    /// Actual retained capacities including native buffers reported by caller.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        support::sum(&[
            size_of::<Self>(),
            self.vector.retained_bytes(),
            support::bytes(&self.body)?,
            support::bytes(&self.input)?,
            support::bytes(&self.encrypt)?,
            support::bytes(&self.decrypt)?,
            self.out.bytes(),
            self.external,
            if self.key.is_some() {
                size_of::<KeyPair>() + 2 * size_of::<usize>()
            } else {
                0
            },
        ])
    }
    /// Charge actual additional native copies before admission. Shrinking a
    /// prior valid charge cannot fail; growth fails without changing the charge.
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
    fn fail(&mut self, error: Error) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        for job in &mut self.encrypt {
            job.cancel();
        }
        for job in &mut self.decrypt {
            job.cancel();
        }
        self.encrypt.clear();
        self.decrypt.clear();
        self.vector.clear();
        self.key = None;
        self.body.zeroize();
        self.body.clear();
        self.input.zeroize();
        self.input.clear();
        self.math = None;
        self.product = None;
        self.out.clear_unadmitted();
        self.state = State::Failed;
    }
}
impl Drop for Alice<'_> {
    fn drop(&mut self) {
        self.body.zeroize();
        self.input.zeroize();
    }
}

// No key, ciphertext validity or arithmetic outcome is manufactured by this
// cfg(test) helper. It models only a copied-input phase for retirement gates;
// the cases never attempt decryption and grant no cryptographic/runtime credit.
#[cfg(test)]
pub(crate) fn local_retirement_metadata_case(
    instance: &Instance,
    received: usize,
) -> Result<Alice<'_>, Error> {
    let mut second = [0; 64];
    second[0] = 1;
    let mut vector = MatchedVector::new(
        alloc::vec![crate::Value::new([0; 64], 1), crate::Value::new(second, 2)],
        crate::HashOrder::Little,
        2,
        4096,
    )?;
    vector.seal(2)?;
    Ok(Alice {
        limits: Limits {
            lifetime_micros: 100,
            ..Limits::default()
        },
        clock: Clock::new(10, 100)?,
        session: [0; 64],
        key: None,
        vector,
        state: State::Decrypt,
        activated: true,
        introduced: true,
        cursor: 2,
        sent: 2,
        body: Vec::new(),
        encrypt: Vec::new(),
        decrypt: Vec::new(),
        out: Outbox::new(instance)?,
        input: alloc::vec![[0;516];2 + 2 * received],
        input_first: true,
        input_cursor: 0,
        reply_started: true,
        received,
        math: Some(AliceMath::new(2)?),
        product: None,
        computed: false,
        failure: None,
        peer_failure: None,
        local_retired: false,
        external: 0,
    })
}
