//! Bounded original room, operation and output state.
use super::*;
#[derive(Clone, Copy)]
pub(super) enum Purpose {
    Input,
    Setup,
    History,
}
#[derive(Clone, Copy)]
pub(super) struct Original<'id> {
    pub(super) operation: Operation<'id>,
    pub(super) purpose: Purpose,
}
pub(super) struct Pending<'id> {
    pub(super) length: usize,
    pub(super) deadline: Deadline,
    pub(super) recipients: Vec<MemberSession<'id>>,
    pub(super) next: usize,
}
pub(super) struct Fetch {
    pub(super) hash: Hash,
    pub(super) deadline: Deadline,
}
pub(super) struct State<'id> {
    pub(super) room: Option<Room<'id>>,
    pub(super) output: output::Writer,
    pub(super) opening: Option<Deadline>,
    pub(super) setup: Option<Deadline>,
    pub(super) setup_step: u8,
    pub(super) monitor_started: bool,
    pub(super) joined: bool,
    pub(super) eof: bool,
    pub(super) pending: Option<Pending<'id>>,
    pub(super) payload: Zeroizing<Vec<u8>>,
    pub(super) originals: Vec<Original<'id>>,
    pub(super) seen: Vec<Hash>,
    pub(super) requested: Vec<Hash>,
    pub(super) fetch: VecDeque<Fetch>,
    pub(super) history: messenger::HistoryWorkspace<'static>,
    pub(super) walked: bool,
    pub(super) close: Option<Deadline>,
    pub(super) leave: bool,
    pub(super) room_closed: bool,
    pub(super) destroy: bool,
    pub(super) stop_requested: bool,
    pub(super) recovering: bool,
    pub(super) ever_joined: bool,
    // Admission only: API owns confirmation, original Span and recovery.
    pub(super) talk_admitted: bool,
    pub(super) recovery_input_warned: bool,
}
impl<'id> State<'id> {
    pub(super) fn new(settings: &Settings) -> Result<Self, Failure> {
        let mut payload = Zeroizing::new(Vec::new());
        payload.try_reserve_exact(INPUT_BYTES)?;
        payload.resize(INPUT_BYTES, 0);
        let mut originals = Vec::new();
        originals.try_reserve_exact(settings.limits.operations)?;
        let mut seen = Vec::new();
        seen.try_reserve_exact(settings.limits.core.messages_per_room)?;
        let mut requested = Vec::new();
        requested.try_reserve_exact(settings.limits.core.messages_per_room)?;
        let mut fetch = VecDeque::new();
        fetch.try_reserve_exact(settings.limits.core.missing_per_room)?;
        Ok(Self {
            room: None,
            output: output::Writer::new(
                settings.output_bytes,
                settings.limits.core.messages_per_room,
                settings.timeout,
            ),
            opening: None,
            setup: None,
            setup_step: 0,
            monitor_started: false,
            joined: false,
            eof: false,
            pending: None,
            payload,
            originals,
            seen,
            requested,
            fetch,
            history: messenger::HistoryWorkspace::new(settings.limits.core.messages_per_room)?,
            walked: false,
            close: None,
            leave: false,
            room_closed: false,
            destroy: false,
            stop_requested: false,
            recovering: false,
            ever_joined: false,
            talk_admitted: false,
            recovery_input_warned: false,
        })
    }
    pub(super) fn retain(
        &mut self,
        operation: Operation<'id>,
        purpose: Purpose,
    ) -> Result<(), Fault> {
        if self.originals.iter().any(|o| o.operation == operation) {
            return Err(Fault::Replay);
        }
        if self.originals.len() == self.originals.capacity() {
            return Err(Fault::Capacity);
        }
        self.originals.push(Original { operation, purpose });
        Ok(())
    }
    pub(super) fn budgets(&self) -> impl Iterator<Item = Deadline> + '_ {
        self.opening
            .into_iter()
            .chain(self.setup)
            .chain(self.pending.as_ref().map(|p| p.deadline))
            .chain(self.fetch.iter().map(|f| f.deadline))
            .chain(self.close)
    }
    pub(super) fn fetch(
        &mut self,
        api: &mut Api<'id, OsEntropy>,
        hash: Hash,
        timeout: Duration,
    ) -> Result<(), Failure> {
        if hash == [0; 64]
            || self.requested.contains(&hash)
            || self.fetch.iter().any(|f| f.hash == hash)
        {
            return Ok(());
        }
        if self.fetch.len() == self.fetch.capacity()
            || self.requested.len() == self.requested.capacity()
        {
            return Err("bounded Messenger history request capacity exhausted".into());
        }
        self.fetch.push_back(Fetch {
            hash,
            deadline: api.deadline(timeout)?,
        });
        Ok(())
    }
}
pub(super) fn retry(error: &messenger::Error) -> bool {
    matches!(
        error,
        messenger::Error::Local(Fault::NotReady | Fault::WouldBlock)
            | messenger::Error::Domain(domain::Error::Protocol(
                Fault::NotReady | Fault::WouldBlock
            ))
    )
}
pub(super) fn room_key(settings: &Settings) -> Result<Hash, Failure> {
    let mut key = match &settings.room {
        Some(name) => gnunet_crypto::hash512(name),
        None => {
            let mut key = [0; 64];
            let mut entropy = OsEntropy::new();
            if let Err(error) = entropy.fill(&mut key) {
                return Err(match entropy.take_error() {
                    Some(original) => Box::new(output::EntropyFailure(original)) as Failure,
                    None => Box::new(error) as Failure,
                });
            }
            key
        }
    };
    let bits = if settings.public { 3u8 } else { 2u8 };
    key[0] = match settings.profile.endian {
        Endian::Little => bits,
        Endian::Big => bits.reverse_bits(),
    };
    Ok(key)
}
