//! Strict private task fields. They never construct a native observation.
use super::*;
const MAGIC: &[u8; 8] = b"FSPRB001";
const MAX_FRAME: usize = gnunet_wire::official::fs::CLIENT_PUT_PREFIX + BLOCK_BYTES + TAG_BYTES;

pub(super) struct Terminal {
    pub task: [u8; 32],
    pub manifest: [u8; 64],
    pub observation: Observation,
    pub transport_loss: bool,
    pub diagnostic: Vec<u8>,
    pub last_response: Vec<u8>,
    pub frames: Vec<Vec<u8>>,
}
impl Terminal {
    pub fn native(
        manifest: &Manifest,
        scope: ([u8; 32], [u8; 64]),
        attempt: Attempt,
        result: &Result<probe::Observed, probe::Failure>,
        frames: &[Vec<u8>],
        wanted: Control,
    ) -> Result<Self, Cause> {
        if frames.len() > 8 || frames.iter().any(|frame| frame.len() > MAX_FRAME) {
            return Err(Cause::Format);
        }
        let content = manifest.content()?;
        let (
            kind,
            progress,
            queries_written,
            started,
            last_checked,
            retired,
            loss,
            diagnostic,
            last_response,
            policy,
            actual_content,
            leaf,
        ) = match result {
            Ok(actual) => (
                Kind::Success,
                actual.progress(),
                actual.queries_written(),
                Some(actual.started()),
                Some(actual.finished()),
                actual.retired(),
                false,
                Vec::new(),
                Vec::new(),
                actual.policy(),
                actual.verified().content(),
                actual.leaf(),
            ),
            Err(failure) => {
                let (kind, loss) = classify(failure.cause(), failure.queries_written());
                let diagnostic = diagnostic(failure.cause())?;
                (
                    kind,
                    failure.progress(),
                    failure.queries_written(),
                    failure.started(),
                    failure.last_checked(),
                    failure.retired(),
                    loss,
                    diagnostic,
                    copy(failure.last_response())?,
                    failure.policy(),
                    failure.content(),
                    failure.leaf(),
                )
            }
        };
        let expected = manifest.options.transfer;
        if actual_content != content
            || leaf != attempt.leaf
            || policy.deadline != attempt.deadline
            || policy.target != expected.target
            || policy.anonymity != expected.anonymity
            || policy.local_only != expected.local_only
            || policy.queries_per_connection != expected.queries_per_connection
            || policy.io_slice_bytes != expected.io_slice_bytes
            || policy.limits.max_file_bytes != expected.limits.max_file_bytes
            || policy.limits.max_encoded_bytes != expected.limits.max_encoded_bytes
        {
            return Err(ProtocolError::Conflict.into());
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(frames.len())
            .map_err(|_| ProtocolError::Capacity)?;
        for frame in frames {
            owned.push(copy(frame)?);
        }
        Ok(Self {
            task: scope.0,
            manifest: scope.1,
            observation: Observation {
                attempt,
                kind,
                progress,
                queries_written,
                started,
                last_checked,
                retired,
                wanted,
            },
            transport_loss: loss,
            diagnostic,
            last_response,
            frames: owned,
        })
    }
}
fn classify(error: &network::Error, written: u64) -> (Kind, bool) {
    match error {
        network::Error::Deadline { first_io } => (
            if written > 0 {
                Kind::Inconclusive
            } else {
                Kind::SetupDeadline
            },
            first_io.is_some(),
        ),
        network::Error::Cancelled(_) | network::Error::Local(crate::Error::Cancelled) => {
            (Kind::Cancelled, false)
        }
        network::Error::Protocol(error)
        | network::Error::Local(crate::Error::Protocol(error))
        | network::Error::Client(gnunet_client_host::ConnectError::Protocol(error)) => (
            match error {
                ProtocolError::Authentication => Kind::Authentication,
                ProtocolError::TimeUncertain => Kind::Clock,
                ProtocolError::Capacity | ProtocolError::Overflow | ProtocolError::TooLarge => {
                    Kind::Resource
                }
                ProtocolError::InvalidInput
                | ProtocolError::Unsupported
                | ProtocolError::NotReady => Kind::Setup,
                _ => Kind::Protocol,
            },
            false,
        ),
        network::Error::Client(gnunet_client_host::ConnectError::Configuration(_)) => {
            (Kind::Setup, false)
        }
        network::Error::Client(gnunet_client_host::ConnectError::Io(_))
        | network::Error::Local(crate::Error::Io(_)) => (Kind::Transport, false),
        network::Error::Local(crate::Error::Limit) => (Kind::Resource, false),
        network::Error::Local(crate::Error::Corrupt) => (Kind::Authentication, false),
        network::Error::Local(_) => (Kind::Local, false),
        #[cfg(feature = "network")]
        network::Error::Store(_) => (Kind::Other, false),
    }
}
fn diagnostic(error: &network::Error) -> Result<Vec<u8>, Cause> {
    use std::fmt::Write;
    struct Bounded(String);
    impl std::fmt::Write for Bounded {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            let available = 4096 - self.0.len();
            let mut used = available.min(value.len());
            while !value.is_char_boundary(used) {
                used -= 1;
            }
            self.0.push_str(&value[..used]);
            if used < value.len() {
                Err(std::fmt::Error)
            } else {
                Ok(())
            }
        }
    }
    let mut value = String::new();
    value
        .try_reserve_exact(4096)
        .map_err(|_| ProtocolError::Capacity)?;
    let mut bounded = Bounded(value);
    // Formatting stops at the explicit diagnostic bound; the original complete
    // typed error remains independently in Recorded.result().
    match write!(&mut bounded, "{error}") {
        Ok(()) | Err(_) => {}
    }
    Ok(bounded.0.into_bytes())
}
fn copy(raw: &[u8]) -> Result<Vec<u8>, Cause> {
    let mut out = Vec::new();
    out.try_reserve_exact(raw.len())
        .map_err(|_| ProtocolError::Capacity)?;
    out.extend_from_slice(raw);
    Ok(out)
}
struct Writer(Vec<u8>);
impl Writer {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn raw(&mut self, raw: &[u8]) -> Result<(), Cause> {
        self.0
            .try_reserve(raw.len())
            .map_err(|_| ProtocolError::Capacity)?;
        self.0.extend_from_slice(raw);
        Ok(())
    }
    fn u8(&mut self, v: u8) -> Result<(), Cause> {
        self.raw(&[v])
    }
    fn bool(&mut self, v: bool) -> Result<(), Cause> {
        self.u8(u8::from(v))
    }
    fn u32(&mut self, v: u32) -> Result<(), Cause> {
        self.raw(&v.to_be_bytes())
    }
    fn u64(&mut self, v: u64) -> Result<(), Cause> {
        self.raw(&v.to_be_bytes())
    }
    fn u128(&mut self, v: u128) -> Result<(), Cause> {
        self.raw(&v.to_be_bytes())
    }
    fn bytes(&mut self, v: &[u8]) -> Result<(), Cause> {
        self.u32(u32::try_from(v.len()).map_err(|_| ProtocolError::Overflow)?)?;
        self.raw(v)
    }
    fn instant(&mut self, v: Option<AbsoluteTime>) -> Result<(), Cause> {
        self.bool(v.is_some())?;
        if let Some(v) = v {
            self.u64(v.as_micros())?;
        }
        Ok(())
    }
    fn attempt(&mut self, a: Attempt) -> Result<(), Cause> {
        self.u32(a.ordinal)?;
        self.u64(a.intent_record)?;
        self.u64(a.leaf)?;
        self.u64(a.admitted.as_micros())?;
        self.u64(a.deadline.as_micros())
    }
}
struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Cause> {
        let end = self.at.checked_add(n).ok_or(Cause::Format)?;
        let raw = self.raw.get(self.at..end).ok_or(Cause::Format)?;
        self.at = end;
        Ok(raw)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Cause> {
        self.take(N)?.try_into().map_err(|_| Cause::Format)
    }
    fn u8(&mut self) -> Result<u8, Cause> {
        Ok(self.array::<1>()?[0])
    }
    fn bool(&mut self) -> Result<bool, Cause> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Cause::Format),
        }
    }
    fn u32(&mut self) -> Result<u32, Cause> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Cause> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn u128(&mut self) -> Result<u128, Cause> {
        Ok(u128::from_be_bytes(self.array()?))
    }
    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, Cause> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(Cause::Format);
        }
        copy(self.take(len)?)
    }
    fn instant(&mut self) -> Result<Option<AbsoluteTime>, Cause> {
        if self.bool()? {
            Ok(Some(AbsoluteTime::from_micros(self.u64()?)))
        } else {
            Ok(None)
        }
    }
    fn attempt(&mut self) -> Result<Attempt, Cause> {
        Ok(Attempt {
            ordinal: self.u32()?,
            intent_record: self.u64()?,
            leaf: self.u64()?,
            admitted: AbsoluteTime::from_micros(self.u64()?),
            deadline: AbsoluteTime::from_micros(self.u64()?),
        })
    }
    fn end(self) -> Result<(), Cause> {
        if self.at == self.raw.len() {
            Ok(())
        } else {
            Err(Cause::Format)
        }
    }
}
pub(super) fn encode_manifest(m: &Manifest) -> Result<Vec<u8>, Cause> {
    let mut w = Writer::new();
    w.raw(MAGIC)?;
    w.bytes(&m.uri)?;
    w.bool(m.origin.is_some())?;
    if let Some(origin) = m.origin {
        w.raw(&origin)?;
    }
    let o = m.options;
    let t = o.transfer;
    w.u64(t.limits.max_file_bytes)?;
    w.u128(t.limits.max_encoded_bytes)?;
    w.u32(t.anonymity)?;
    w.raw(&t.target)?;
    w.bool(t.local_only)?;
    w.u32(t.queries_per_connection)?;
    w.u64(u64::try_from(t.io_slice_bytes).map_err(|_| ProtocolError::Overflow)?)?;
    w.u64(o.max_file_bytes)?;
    w.u64(o.max_path_blocks)?;
    w.u128(o.max_encoded_bytes)?;
    w.u32(m.max_attempts)?;
    w.u32(m.max_trials)?;
    w.u64(m.max_history_bytes)?;
    Ok(w.0)
}
pub(super) fn decode_manifest(raw: &[u8]) -> Result<Manifest, Cause> {
    let mut r = Reader::new(raw);
    if r.take(8)? != MAGIC {
        return Err(Cause::Format);
    }
    let uri = r.bytes(4096)?;
    let origin = if r.bool()? { Some(r.array()?) } else { None };
    let transfer = network::DownloadOptions {
        limits: crate::Limits {
            max_file_bytes: r.u64()?,
            max_encoded_bytes: r.u128()?,
        },
        deadline: AbsoluteTime::from_micros(0),
        anonymity: r.u32()?,
        target: r.array()?,
        local_only: r.bool()?,
        queries_per_connection: r.u32()?,
        io_slice_bytes: usize::try_from(r.u64()?).map_err(|_| ProtocolError::Overflow)?,
    };
    let options = probe::Options {
        transfer,
        max_file_bytes: r.u64()?,
        max_path_blocks: r.u64()?,
        max_encoded_bytes: r.u128()?,
    };
    let m = Manifest {
        uri,
        options,
        origin,
        max_attempts: r.u32()?,
        max_trials: r.u32()?,
        max_history_bytes: r.u64()?,
    };
    r.end()?;
    Ok(m)
}
pub(super) fn encode_attempt(a: Attempt) -> Result<Vec<u8>, Cause> {
    let mut w = Writer::new();
    w.attempt(a)?;
    Ok(w.0)
}
pub(super) fn decode_attempt(raw: &[u8]) -> Result<Attempt, Cause> {
    let mut r = Reader::new(raw);
    let a = r.attempt()?;
    r.end()?;
    Ok(a)
}
pub(super) fn encode_terminal(t: &Terminal) -> Result<Vec<u8>, Cause> {
    let mut w = Writer::new();
    let o = t.observation;
    w.raw(&t.task)?;
    w.raw(&t.manifest)?;
    w.attempt(o.attempt)?;
    w.u8(o.kind as u8)?;
    w.bool(t.transport_loss)?;
    w.u8(match o.wanted {
        Control::Continue => 0,
        Control::Pause => 1,
        Control::Cancel => 2,
    })?;
    w.u64(o.progress.plaintext_bytes)?;
    w.u64(o.progress.blocks)?;
    w.u128(o.progress.encoded_bytes)?;
    w.u64(o.queries_written)?;
    w.instant(o.started)?;
    w.instant(o.last_checked)?;
    w.bool(o.retired)?;
    w.bytes(&t.diagnostic)?;
    w.bytes(&t.last_response)?;
    w.u32(u32::try_from(t.frames.len()).map_err(|_| ProtocolError::Overflow)?)?;
    for frame in &t.frames {
        w.bytes(frame)?;
    }
    Ok(w.0)
}
pub(super) fn decode_terminal(raw: &[u8]) -> Result<Terminal, Cause> {
    let mut r = Reader::new(raw);
    let task = r.array()?;
    let manifest = r.array()?;
    let attempt = r.attempt()?;
    let kind = match r.u8()? {
        0 => Kind::Success,
        1 => Kind::Inconclusive,
        2 => Kind::SetupDeadline,
        3 => Kind::Cancelled,
        4 => Kind::Authentication,
        5 => Kind::Protocol,
        6 => Kind::Clock,
        7 => Kind::Resource,
        8 => Kind::Transport,
        9 => Kind::Setup,
        10 => Kind::Local,
        11 => Kind::Other,
        _ => return Err(Cause::Format),
    };
    let transport_loss = r.bool()?;
    let wanted = match r.u8()? {
        0 => Control::Continue,
        1 => Control::Pause,
        2 => Control::Cancel,
        _ => return Err(Cause::Format),
    };
    let progress = Progress {
        plaintext_bytes: r.u64()?,
        blocks: r.u64()?,
        encoded_bytes: r.u128()?,
    };
    let queries_written = r.u64()?;
    let started = r.instant()?;
    let last_checked = r.instant()?;
    let retired = r.bool()?;
    let diagnostic = r.bytes(4096)?;
    let last_response = r.bytes(MAX_FRAME)?;
    let count = r.u32()? as usize;
    if count > 8 {
        return Err(Cause::Format);
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(count)
        .map_err(|_| ProtocolError::Capacity)?;
    for _ in 0..count {
        frames.push(r.bytes(MAX_FRAME)?);
    }
    r.end()?;
    Ok(Terminal {
        task,
        manifest,
        observation: Observation {
            attempt,
            kind,
            progress,
            queries_written,
            started,
            last_checked,
            retired,
            wanted,
        },
        transport_loss,
        diagnostic,
        last_response,
        frames,
    })
}
