//! Caller-driven original-MQ subscription to official NSE estimates.
//! This owner has no runtime, task, allocation or peer-estimation algorithm.
//! A host owns partial I/O and must retire the original physical connection
//! before reporting its loss and attaching another one.
use gnunet_types::Error;
pub use gnunet_wire::official::nse::{Double, ESTIMATE_LEN, Estimate, START_LEN};
use gnunet_wire::official::{Frame, message_type};

/// Non-zero-sized identity storage, borrowed exclusively while tokens exist.
///
/// ```compile_fail
/// use gnunet_client::nse::{Client, Instance};
/// let mut instance = Instance::new();
/// let mut first = Client::new(&mut instance);
/// let old_epoch = first.begin_connection().unwrap();
/// first.close();
/// drop(first);
/// let mut replacement = Client::new(&mut instance);
/// let _ = replacement.receive(old_epoch, &[]);
/// ```
#[derive(Debug)]
pub struct Instance {
    _private: u8,
}
impl Instance {
    /// Fresh local owner storage; no global counter or wire extension is used.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: 0 }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}

/// Original physical MQ identity. Its serial alone grants no authority.
#[derive(Clone, Copy, Debug)]
pub struct Epoch<'a> {
    owner: &'a Instance,
    serial: u64,
}
impl PartialEq for Epoch<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.owner, other.owner) && self.serial == other.serial
    }
}
impl Eq for Epoch<'_> {}
impl Epoch<'_> {
    /// Diagnostic generation; not a request or connection field on the wire.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}

/// Immutable original subscription bytes, retained through partial/canceled I/O.
/// Dropping this value does not authorize regenerating START on the same MQ.
#[must_use = "retain the original START through full write or retire its MQ"]
pub struct Start<'a> {
    epoch: Epoch<'a>,
    bytes: [u8; START_LEN],
}
impl<'a> Start<'a> {
    /// Original local MQ identity.
    #[must_use]
    pub const fn epoch(&self) -> Epoch<'a> {
        self.epoch
    }
    /// Exact official bytes, without an owner/epoch wire extension.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; START_LEN] {
        &self.bytes
    }
}

/// Copyable public observation. Keeping this old data does not make its epoch
/// current after an MQ loss; consult the original client for current state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation<'a> {
    /// Original local service MQ, not network authentication.
    pub epoch: Epoch<'a>,
    /// Source-service statistical observation.
    pub estimate: Estimate,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    NeedConnection,
    NeedStart,
    StartLeased,
    Listening,
    Poisoned,
    Closed,
}

/// Allocation-free subscription with one original START lease per physical MQ.
/// Retry scheduling belongs to the host; valid repeated or older timestamps are
/// delivered unchanged rather than interpreted as authenticated freshness.
pub struct Client<'a> {
    owner: &'a Instance,
    serial: u64,
    epoch: Option<Epoch<'a>>,
    state: State,
    latest: Option<Observation<'a>>,
}
impl<'a> Client<'a> {
    /// Construct without connecting, scheduling, encoding or receiving anything.
    #[must_use]
    pub fn new(instance: &'a mut Instance) -> Self {
        Self {
            owner: instance,
            serial: 0,
            epoch: None,
            state: State::NeedConnection,
            latest: None,
        }
    }
    /// Whether an enclosing host may attempt another original MQ.
    #[must_use]
    pub fn connection_needed(&self) -> bool {
        self.state == State::NeedConnection
    }
    /// Attach one new physical MQ after any old one has actually been retired.
    pub fn begin_connection(&mut self) -> Result<Epoch<'a>, Error> {
        if self.state == State::Closed {
            return Err(Error::Closed);
        }
        if !self.connection_needed() {
            return Err(Error::NotReady);
        }
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let epoch = Epoch {
            owner: self.owner,
            serial,
        };
        self.serial = serial;
        self.epoch = Some(epoch);
        self.state = State::NeedStart;
        Ok(epoch)
    }
    fn check_epoch(&self, epoch: Epoch<'a>) -> Result<(), Error> {
        if self.state == State::Closed {
            return Err(Error::Closed);
        }
        if self.epoch != Some(epoch) {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Prepare the single original immutable START. Native hosts should reserve
    /// output resources first; this state is not repeatable after a canceled wait.
    pub fn prepare_start(&mut self, epoch: Epoch<'a>) -> Result<Start<'a>, Error> {
        self.check_epoch(epoch)?;
        if self.state != State::NeedStart {
            return Err(Error::NotReady);
        }
        let mut bytes = [0; START_LEN];
        gnunet_wire::official::nse::encode_start(&mut bytes)?;
        self.state = State::StartLeased;
        Ok(Start { epoch, bytes })
    }
    /// Report the exact original lease after its full physical write. This is
    /// local stream progress and does not acknowledge service processing.
    /// A foreign rejection borrows the lease so its real owner can still use it.
    pub fn written(&mut self, start: &Start<'a>) -> Result<(), Error> {
        self.check_epoch(start.epoch)?;
        if self.state != State::StartLeased {
            return Err(Error::Stale);
        }
        self.state = State::Listening;
        Ok(())
    }
    /// Consume one complete original-MQ frame. Well-framed unhandled types are
    /// ignored like the reference MQ. Malformed known input poisons this owner
    /// until the host closes its original physical MQ and calls `retire`.
    pub fn receive(
        &mut self,
        epoch: Epoch<'a>,
        input: &[u8],
    ) -> Result<Option<Observation<'a>>, Error> {
        self.check_epoch(epoch)?;
        if self.state != State::Listening {
            return Err(Error::NotReady);
        }
        let result = Frame::decode(input).and_then(|frame| {
            if frame.header().message_type() == message_type::NSE_ESTIMATE {
                Estimate::decode(input).map(Some)
            } else {
                Ok(None)
            }
        });
        match result {
            Ok(Some(estimate)) => {
                let observed = Observation { epoch, estimate };
                self.latest = Some(observed);
                Ok(Some(observed))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                self.state = State::Poisoned;
                self.latest = None;
                Err(error)
            }
        }
    }
    /// Last observation from this currently valid listening MQ, if any.
    #[must_use]
    pub const fn latest(&self) -> Option<Observation<'a>> {
        self.latest
    }
    /// Report original physical MQ retirement, invalidating its live observation
    /// and pending START authority before another epoch can be attached.
    pub fn retire(&mut self, epoch: Epoch<'a>) -> Result<(), Error> {
        self.check_epoch(epoch)?;
        self.epoch = None;
        self.latest = None;
        self.state = State::NeedConnection;
        Ok(())
    }
    /// Permanently close this owner. A new owner needs a fresh exclusive borrow;
    /// this one never wraps generations or restarts after closure.
    pub fn close(&mut self) {
        self.epoch = None;
        self.latest = None;
        self.state = State::Closed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_exhaustion_keeps_the_original_disconnected_state() {
        let mut instance = Instance::new();
        let mut owner = Client::new(&mut instance);
        owner.serial = u64::MAX;
        assert_eq!(owner.begin_connection(), Err(Error::Overflow));
        assert!(owner.connection_needed());
        assert!(owner.epoch.is_none());
        assert!(owner.latest().is_none());
    }
}
