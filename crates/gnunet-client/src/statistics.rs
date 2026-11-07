//! Official STATISTICS IPC, GNUnet v0.29.1.
//!
//! Sources: `src/service/statistics/statistics.h`, `statistics_api.c`, and
//! `gnunet-service-statistics.c:321-455`. Names are two NUL-terminated byte
//! strings. GET has no request ID, so one connection has one outstanding GET.
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader, MessageType, message_type};

/// Persistence flag in VALUE's UID; different from SET's persistence flag.
pub const PERSIST_BIT: u32 = 1 << 31;
/// SET changes the value by a signed delta when this bit is present.
pub const SET_RELATIVE: u32 = 1;
/// SET requests persistence when this bit is present.
pub const SET_PERSISTENT: u32 = 2;

/// A GET or WATCH selector. Empty subsystem/name means a wildcard for GET.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selector<'a> {
    /// Original subsystem bytes, without a terminator.
    pub subsystem: &'a [u8],
    /// Original statistic name bytes, without a terminator.
    pub name: &'a [u8],
}
impl Selector<'_> {
    fn payload_len(self) -> Result<usize, Error> {
        if self.subsystem.contains(&0) || self.name.contains(&0) {
            return Err(Error::InvalidInput);
        }
        self.subsystem
            .len()
            .checked_add(self.name.len())
            .and_then(|n| n.checked_add(2))
            .ok_or(Error::Overflow)
    }
    fn encode_as(self, kind: MessageType, output: &mut [u8]) -> Result<usize, Error> {
        let header = MessageHeader::new(kind, self.payload_len()?)?;
        if output.len() < header.size() {
            return Err(Error::Capacity);
        }
        header.encode(output)?;
        write_names(self, &mut output[4..header.size()]);
        Ok(header.size())
    }
    /// Encode an official GET, preserving the destination on rejected input.
    pub fn encode_get(self, output: &mut [u8]) -> Result<usize, Error> {
        self.encode_as(message_type::STATISTICS_GET, output)
    }
    /// Encode an official WATCH request; watch IDs follow connection request order.
    pub fn encode_watch(self, output: &mut [u8]) -> Result<usize, Error> {
        self.encode_as(message_type::STATISTICS_WATCH, output)
    }
}
fn write_names(selector: Selector<'_>, output: &mut [u8]) {
    let first = selector.subsystem.len();
    output[..first].copy_from_slice(selector.subsystem);
    output[first] = 0;
    output[first + 1..first + 1 + selector.name.len()].copy_from_slice(selector.name);
    output[first + 1 + selector.name.len()] = 0;
}
fn read_names(bytes: &[u8]) -> Result<Selector<'_>, Error> {
    let first = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or(Error::InvalidInput)?;
    let rest = bytes.get(first + 1..).ok_or(Error::Truncated)?;
    let second = rest
        .iter()
        .position(|b| *b == 0)
        .ok_or(Error::InvalidInput)?;
    if second + 1 != rest.len() {
        return Err(Error::InvalidInput);
    }
    Ok(Selector {
        subsystem: &bytes[..first],
        name: &rest[..second],
    })
}

/// One official VALUE response, borrowing its two names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Statistic<'a> {
    /// UID including its persistence bit, as sent by the service.
    pub raw_uid: u32,
    /// Unsigned stored value. Relative SET deltas use two's-complement encoding.
    pub value: u64,
    /// Subsystem/name owned by the input frame.
    pub selector: Selector<'a>,
}
impl Statistic<'_> {
    /// Stable connection-local UID without the persistence marker.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.raw_uid & !PERSIST_BIT
    }
    /// Whether this value is marked persistent.
    #[must_use]
    pub const fn persistent(self) -> bool {
        self.raw_uid & PERSIST_BIT != 0
    }
}

/// A GET response; END is the only successful completion indication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// One selected statistic.
    Value(Statistic<'a>),
    /// Exact, header-only STATISTICS_END.
    End,
}
impl<'a> Response<'a> {
    /// Decode one complete frame, rejecting invalid strings, trailing bytes and foreign types.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        let body = frame.payload();
        match frame.header().message_type() {
            message_type::STATISTICS_END if body.is_empty() => Ok(Self::End),
            message_type::STATISTICS_VALUE => {
                let fixed = body.get(..12).ok_or(Error::Truncated)?;
                Ok(Self::Value(Statistic {
                    raw_uid: u32::from_be_bytes(
                        fixed[..4].try_into().map_err(|_| Error::Truncated)?,
                    ),
                    value: u64::from_be_bytes(fixed[4..].try_into().map_err(|_| Error::Truncated)?),
                    selector: read_names(&body[12..])?,
                }))
            }
            message_type::STATISTICS_END => Err(Error::InvalidInput),
            _ => Err(Error::Unsupported),
        }
    }
}

/// Official SET message. Unknown flag bits are preserved as upstream does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Set<'a> {
    /// Statistic to change; SET does not use GET wildcard semantics.
    pub selector: Selector<'a>,
    /// SET_RELATIVE and/or SET_PERSISTENT.
    pub flags: u32,
    /// Absolute value or the two's-complement bit pattern of a signed delta.
    pub value: u64,
}
impl Set<'_> {
    /// Encode the exact upstream SET layout, with preflight capacity validation.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let body_len = self
            .selector
            .payload_len()?
            .checked_add(12)
            .ok_or(Error::Overflow)?;
        let header = MessageHeader::new(message_type::STATISTICS_SET, body_len)?;
        if output.len() < header.size() {
            return Err(Error::Capacity);
        }
        header.encode(output)?;
        output[4..8].copy_from_slice(&self.flags.to_be_bytes());
        output[8..16].copy_from_slice(&self.value.to_be_bytes());
        write_names(self.selector, &mut output[16..header.size()]);
        Ok(header.size())
    }
}

/// Encode the official disconnect/flush request. Its confirmation is a separate frame.
pub fn encode_disconnect(output: &mut [u8]) -> Result<usize, Error> {
    Frame::new(message_type::STATISTICS_DISCONNECT, &[])?.encode(output)
}
/// Validate the exact, header-only official disconnect confirmation.
pub fn confirm_disconnect(input: &[u8]) -> Result<(), Error> {
    let frame = Frame::decode(input)?;
    if frame.header().message_type() != message_type::STATISTICS_DISCONNECT_CONFIRM
        || !frame.payload().is_empty()
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// Connection-local WATCH token with a borrowed owner brand. Its numeric wire
/// WID is diagnostic data and cannot authorize operations on another session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchId<'a>(u32, crate::statistics_owner::Brand<'a>);
impl WatchId<'_> {
    /// Numeric wire ID, starting at zero; it is not sufficient authority.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}
/// Stable caller storage shared by the short and long-lived STATISTICS owners.
pub use crate::statistics_owner::Instance;

/// Exact official WATCH_VALUE fields; no names or terminators follow this frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchValue {
    /// Raw server flags, including unknown future bits.
    pub flags: u32,
    /// Watch request number in this connection.
    pub wid: u32,
    /// Reserved upstream field. Normally zero; preserved on decode as the C
    /// client only diagnoses, rather than rejects, a nonzero value.
    pub reserved: u32,
    /// Current absolute unsigned statistic value.
    pub value: u64,
}
impl WatchValue {
    /// Decode exactly the 24-byte WATCH_VALUE frame. This does not establish
    /// that its WID belongs to this client; [`WatchSession::receive`] does that.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        if frame.header().message_type() != message_type::STATISTICS_WATCH_VALUE {
            return Err(Error::Unsupported);
        }
        let body = frame.payload();
        if body.len() != 20 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            flags: u32::from_be_bytes(body[..4].try_into().map_err(|_| Error::Truncated)?),
            wid: u32::from_be_bytes(body[4..8].try_into().map_err(|_| Error::Truncated)?),
            reserved: u32::from_be_bytes(body[8..12].try_into().map_err(|_| Error::Truncated)?),
            value: u64::from_be_bytes(body[12..].try_into().map_err(|_| Error::Truncated)?),
        })
    }
    /// Persistence according to the pinned service's `notify_change`: bit 2.
    ///
    /// The v0.29.1 C client checks VALUE's high UID bit here instead, a source
    /// discrepancy. This method follows the bytes actually emitted by the
    /// official service, retaining raw flags for callers needing either view.
    #[must_use]
    pub const fn persistent(self) -> bool {
        self.flags & SET_PERSISTENT != 0
    }
}

/// A WATCH notification bound to the original selector and connection WID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchUpdate<'a> {
    /// Original caller-owned selector, never taken from notification bytes.
    pub selector: Selector<'a>,
    /// Original connection-local watch number.
    pub id: WatchId<'a>,
    /// Server's exact fields.
    pub notification: WatchValue,
}

/// Fixed-capacity WATCH ownership. Selectors borrow caller-owned bytes. Local
/// cancellation suppresses callbacks but does not remove the service's watch;
/// the upstream protocol frees service watches when the connection closes.
pub struct WatchSession<'a, const N: usize> {
    instance: crate::statistics_owner::Brand<'a>,
    watches: [Option<Selector<'a>>; N],
    issued: usize,
    closed: bool,
}
impl<'a, const N: usize> WatchSession<'a, N> {
    /// Create a connection session accepting at most N WATCH requests in total.
    #[must_use]
    pub const fn new(instance: &'a mut Instance) -> Self {
        Self {
            instance: crate::statistics_owner::Brand::new(instance),
            watches: [None; N],
            issued: 0,
            closed: false,
        }
    }
    /// Encode and admit one request atomically. Empty names are literal for
    /// WATCH, unlike GET's wildcard behavior. Capacity/input refusal consumes
    /// neither a slot nor a WID and leaves the destination unchanged.
    pub fn start(
        &mut self,
        selector: Selector<'a>,
        output: &mut [u8],
    ) -> Result<(WatchId<'a>, usize), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.issued >= N {
            return Err(Error::Capacity);
        }
        let id = WatchId(
            u32::try_from(self.issued).map_err(|_| Error::Capacity)?,
            self.instance,
        );
        let size = selector.encode_watch(output)?;
        self.watches[self.issued] = Some(selector);
        self.issued += 1;
        Ok((id, size))
    }
    /// Cancel only the local callback. Its WID is retained as a tombstone and
    /// cannot be reassigned to another watch on this connection.
    /// `id` must have been issued by this same `WatchSession` instance; a WID
    /// from another session cannot identify a watch owned by this one.
    pub fn cancel(&mut self, id: WatchId<'a>) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if id.1 != self.instance {
            return Err(Error::Stale);
        }
        let slot = self
            .watches
            .get_mut(id.0 as usize)
            .filter(|_| (id.0 as usize) < self.issued)
            .ok_or(Error::NotFound)?;
        if slot.take().is_none() {
            return Err(Error::NotFound);
        }
        Ok(())
    }
    /// Bind one notification to its original selector. A cancelled watch is
    /// ignored (`None`). Malformed data or an unknown WID closes the session;
    /// the I/O owner must also retire that connection before starting another.
    pub fn receive(&mut self, input: &[u8]) -> Result<Option<WatchUpdate<'a>>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let result = (|| {
            let notification = WatchValue::decode(input)?;
            let index = usize::try_from(notification.wid).map_err(|_| Error::Malformed)?;
            if index >= self.issued {
                return Err(Error::Malformed);
            }
            Ok(self.watches[index].map(|selector| WatchUpdate {
                selector,
                id: WatchId(notification.wid, self.instance),
                notification,
            }))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Retire every original watch, including any future callback authority.
    pub fn close(&mut self) {
        self.watches.fill(None);
        self.closed = true;
    }
    /// Whether this connection session has been retired.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }
}
/// One bounded GET operation. A rejected response poisons the original operation.
#[derive(Debug)]
pub struct GetSession {
    remaining: usize,
    state: State,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Idle,
    Receiving,
    Complete,
    Failed,
}
impl GetSession {
    /// Supply an explicit maximum number of VALUE responses.
    #[must_use]
    pub const fn new(maximum_values: usize) -> Self {
        Self {
            remaining: maximum_values,
            state: State::Idle,
        }
    }
    /// Encode/admit this request once. Capacity rejection leaves it idle.
    pub fn start(&mut self, selector: Selector<'_>, output: &mut [u8]) -> Result<usize, Error> {
        if self.state != State::Idle {
            return Err(Error::Stale);
        }
        let size = selector.encode_get(output)?;
        self.state = State::Receiving;
        Ok(size)
    }
    /// Consume a complete reply. No reply after completion can revive the operation.
    pub fn receive<'a>(&mut self, input: &'a [u8]) -> Result<Response<'a>, Error> {
        if self.state != State::Receiving {
            return Err(Error::Stale);
        }
        let response = match Response::decode(input) {
            Ok(response) => response,
            Err(error) => {
                self.state = State::Failed;
                return Err(error);
            }
        };
        match response {
            Response::End => self.state = State::Complete,
            Response::Value(_) if self.remaining == 0 => {
                self.state = State::Failed;
                return Err(Error::Capacity);
            }
            Response::Value(_) => self.remaining -= 1,
        }
        Ok(response)
    }
    /// Only the exact official END completes a GET; local socket authority is external.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Fallible tests assert independent official bytes and original operation boundaries"
    )]
    use super::*;
    #[test]
    fn independent_get_and_value_bytes() -> Result<(), Error> {
        let selector = Selector {
            subsystem: b"core",
            name: b"peers",
        };
        let mut out = [0; 32];
        let len = selector.encode_get(&mut out)?;
        assert_eq!(&out[..len], b"\x00\x0f\x00\xa9core\0peers\0");
        let value =
            b"\x00\x1b\x00\xaa\x80\x00\x00\x07\x01\x02\x03\x04\x05\x06\x07\x08core\0peers\0";
        let Response::Value(statistic) = Response::decode(value)? else {
            return Err(Error::InvalidInput);
        };
        assert_eq!(statistic.uid(), 7);
        assert!(statistic.persistent());
        assert_eq!(statistic.value, 0x0102_0304_0506_0708);
        assert_eq!(statistic.selector, selector);
        Ok(())
    }
    #[test]
    fn one_original_get_requires_end_and_enforces_its_limit() -> Result<(), Error> {
        let mut session = GetSession::new(1);
        let selector = Selector {
            subsystem: b"",
            name: b"",
        };
        assert_eq!(session.start(selector, &mut [0; 5]), Err(Error::Capacity));
        let mut out = [0; 6];
        session.start(selector, &mut out)?;
        let value = b"\x00\x12\x00\xaa\0\0\0\x01\0\0\0\0\0\0\0\x09\0\0";
        assert!(matches!(session.receive(value)?, Response::Value(_)));
        assert!(!session.is_complete());
        assert_eq!(session.receive(value), Err(Error::Capacity));
        assert_eq!(session.receive(b"\0\x04\0\xab"), Err(Error::Stale));
        let mut session = GetSession::new(0);
        session.start(selector, &mut out)?;
        assert_eq!(session.receive(b"\0\x04\0\xab")?, Response::End);
        assert!(session.is_complete());
        assert_eq!(session.receive(value), Err(Error::Stale));
        Ok(())
    }
    #[test]
    fn malformed_strings_and_eof_are_not_completion() -> Result<(), Error> {
        assert_eq!(
            Response::decode(b"\0\x05\0\xab\0"),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            Response::decode(b"\0\x04\0\xabextra"),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            Response::decode(b"\0\x12\0\xaa\0\0\0\0\0\0\0\0\0\0\0\0xx"),
            Err(Error::InvalidInput)
        );
        let mut out = [0xa5; 32];
        assert_eq!(
            Selector {
                subsystem: b"a\0b",
                name: b"x"
            }
            .encode_get(&mut out),
            Err(Error::InvalidInput)
        );
        assert_eq!(out, [0xa5; 32]);
        let set = Set {
            selector: Selector {
                subsystem: b"a",
                name: b"b",
            },
            flags: 3,
            value: u64::MAX,
        };
        let len = set.encode(&mut out)?;
        assert_eq!(
            &out[..len],
            b"\0\x14\0\xa8\0\0\0\x03\xff\xff\xff\xff\xff\xff\xff\xffa\0b\0"
        );
        assert_eq!(encode_disconnect(&mut out)?, 4);
        assert_eq!(&out[..4], b"\0\x04\0\xae");
        confirm_disconnect(b"\0\x04\0\xaf")?;
        Ok(())
    }
}
