//! Incoming admission policy belongs to the actual refusing stage. These
//! helpers keep only error metadata; they own no source, frame or native debt.
use super::*;

pub(super) struct Failure {
    error: Error,
    disposition: InputRefusalDisposition,
}
impl Failure {
    pub(super) fn deferred(error: impl Into<Error>) -> Self {
        Self {
            error: error.into(),
            disposition: InputRefusalDisposition::Deferred,
        }
    }
    pub(super) fn rejected(error: Protocol) -> Self {
        Self {
            error: error.into(),
            disposition: InputRefusalDisposition::Rejected,
        }
    }
    pub(super) fn expired() -> Self {
        Self {
            error: Error::InputBudgetExpired,
            disposition: InputRefusalDisposition::Expired,
        }
    }
    pub(super) fn source(error: impl Into<Error>) -> Self {
        Self {
            error: error.into(),
            disposition: InputRefusalDisposition::Source,
        }
    }
    pub(super) fn with_origin<J>(self, origin: J) -> InputRefused<J> {
        InputRefused {
            origin,
            error: self.error,
            disposition: self.disposition,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Shape {
    Learn,
    Box,
}
/// The real complete official frame/source/recipient checks before any crypto
/// or provider work. A structural shape asserts no signature/AEAD authority.
pub(super) fn inspect(bytes: &[u8], local: PeerId, neighbour: PeerId) -> Result<Shape, Failure> {
    let checked = (|| {
        let frame = Frame::decode(bytes)?;
        match frame.header().message_type().value() {
            dv::LEARN_TYPE => {
                dv::Learn::decode(bytes)?.check_source(local, neighbour)?;
                Ok(Shape::Learn)
            }
            dv::BOX_TYPE => {
                dv::BoxPacket::decode(bytes)?.check_recipient(local)?;
                Ok(Shape::Box)
            }
            _ => Err(Protocol::Unsupported),
        }
    })();
    checked.map_err(Failure::rejected)
}
pub(super) fn check_bounds(
    bounds: &Bound,
    original: Option<Budget>,
    now: u64,
) -> Result<(), Failure> {
    bounds.check(now).map_err(|error| {
        if original.is_some_and(|original| {
            original.check_native().is_err() || now >= original.until.as_micros()
        }) {
            Failure::expired()
        } else {
            Failure::source(error)
        }
    })
}

#[cfg(test)]
#[path = "admission/tests.rs"]
mod tests;
