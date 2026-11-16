//! One-time reply preparation and synchronous ownership transfer to the original MQ.
use super::{Error, Reply};
use gnunet_client::gns;
use gnunet_gns::{Failure, QueryId, Record};
use gnunet_service_runtime::framing::{Class, Framed, OwnedFrame};
use gnunet_types::Error as Fault;

pub(super) struct ReplyPlan {
    records: Vec<Record>,
    encoded_len: usize,
    failure: Option<Failure>,
}

pub(super) struct Queued {
    pub(super) records: usize,
    pub(super) failure: Option<Failure>,
}

pub(super) enum CallState<'query> {
    Resolving(QueryId<'query>),
    Ready(ReplyPlan),
    Queued,
}

impl<'query> CallState<'query> {
    pub(super) fn query(&self) -> Option<QueryId<'query>> {
        match self {
            Self::Resolving(query) => Some(*query),
            Self::Ready(_) | Self::Queued => None,
        }
    }

    pub(super) fn try_queue<'peer>(
        &mut self,
        io: &mut Framed<Reply<'peer>>,
        origin: Reply<'peer>,
    ) -> Result<Option<Queued>, Error> {
        let Self::Ready(plan) = self else {
            return Ok(None);
        };
        let Some(queued) = plan.try_queue(io, origin)? else {
            return Ok(None);
        };
        // No fallible work follows ownership transfer into the immutable FIFO.
        *self = Self::Queued;
        Ok(Some(queued))
    }
}

impl ReplyPlan {
    pub(super) fn new(outcome: Result<Vec<Record>, Failure>) -> Self {
        let records = match outcome {
            Ok(records) => records,
            Err(failure) => return Self::empty(Some(failure)),
        };
        let encoded_len = gnunet_gnsrecord::serialized_len(records.iter().map(Record::as_data))
            .and_then(|body| {
                body.checked_add(gns::RESULT_HEADER_LEN)
                    .ok_or(Fault::Overflow)
            });
        match encoded_len {
            Ok(encoded_len) if encoded_len <= usize::from(u16::MAX) => Self {
                records,
                encoded_len,
                failure: None,
            },
            _ => Self::empty(Some(Failure::Fault(Fault::TooLarge))),
        }
    }

    fn empty(failure: Option<Failure>) -> Self {
        Self {
            records: Vec::new(),
            encoded_len: gns::RESULT_HEADER_LEN,
            failure,
        }
    }

    /// Backpressure leaves this original plan untouched and performs no allocation.
    /// Encoding and queue transfer happen synchronously after physical preflight.
    fn try_queue<'peer>(
        &self,
        io: &mut Framed<Reply<'peer>>,
        origin: Reply<'peer>,
    ) -> Result<Option<Queued>, Error> {
        if !io.capacity(self.encoded_len, Class::Ordinary) {
            return Ok(None);
        }
        io.reserve(self.encoded_len, Class::Ordinary)?;
        let mut views = Vec::new();
        views
            .try_reserve_exact(self.records.len())
            .map_err(Error::Allocation)?;
        views.extend(self.records.iter().map(Record::as_data));
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.encoded_len)
            .map_err(Error::Allocation)?;
        bytes.resize(self.encoded_len, 0);
        gns::encode_result(origin.wire, &views, &mut bytes)?;
        io.enqueue_owned(OwnedFrame::new(bytes), origin, Class::Ordinary)
            .map_err(|rejected| Error::Protocol(rejected.reason))?;
        Ok(Some(Queued {
            records: self.records.len(),
            failure: self.failure,
        }))
    }
}

#[cfg(test)]
mod tests;
