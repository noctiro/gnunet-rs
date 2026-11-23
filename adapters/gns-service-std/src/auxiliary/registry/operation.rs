//! One original BOX/SBOX lookup and its eventual retirement observation.
use super::{Error, LookupResult, Outcome, worker::Query};
use crate::{
    Bounds, Close, Value,
    native::{Error as NativeError, Report},
};
use gnunet_gns::BoxSelector;
use gnunet_types::Error as Fault;
use std::{
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::time::Instant;

enum Work {
    Prepared(Option<BoxSelector>),
    Native(Query),
}

impl Work {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<LookupResult> {
        match self {
            Self::Prepared(value) => Poll::Ready(Ok(*value)),
            Self::Native(query) => query.poll(cx),
        }
    }
}

enum State {
    Active(Work),
    Stopping(Work),
    Settled(Outcome),
    Retired,
}

pub(in crate::auxiliary) struct Lookup {
    bounds: Bounds,
    state: State,
}

impl Lookup {
    pub(super) fn prepared(mapping: Option<BoxSelector>, bounds: Bounds) -> Self {
        Self {
            bounds,
            state: State::Active(Work::Prepared(mapping)),
        }
    }

    pub(super) fn native(query: Query, bounds: Bounds) -> Self {
        Self {
            bounds,
            state: State::Active(Work::Native(query)),
        }
    }

    pub(in crate::auxiliary) fn check_deadline(&mut self) -> Option<Fault> {
        // The manager registers the original native alarm for this request.
        if matches!(self.state, State::Active(_)) && Instant::now() >= self.bounds.hard() {
            self.begin_close();
            return Some(Fault::Timeout);
        }
        None
    }

    pub(in crate::auxiliary) fn begin_close(&mut self) {
        if let State::Active(Work::Native(query)) = &mut self.state {
            query.begin_close();
        }
        let state = std::mem::replace(&mut self.state, State::Retired);
        self.state = match state {
            State::Active(work) => State::Stopping(work),
            other => other,
        };
    }

    pub(in crate::auxiliary) fn poll<'id>(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Value, NativeError<'id>>> {
        let State::Active(work) = &mut self.state else {
            return Poll::Pending;
        };
        let result = ready!(work.poll(cx));
        self.state = State::Settled(outcome(&result));
        if result.is_ok() && Instant::now() >= self.bounds.hard() {
            return Poll::Ready(Err(Fault::Timeout.into()));
        }
        Poll::Ready(result.map(Value::Service).map_err(native_error))
    }

    pub(in crate::auxiliary) fn poll_close<'id>(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Close<Report<'id>, NativeError<'id>>> {
        let outcome = match &mut self.state {
            State::Stopping(work) => match ready!(work.poll(cx)) {
                Ok(value) => Outcome::Resolved(value),
                Err(Error::Protocol(Fault::Cancelled | Fault::Timeout)) => Outcome::Cancelled,
                Err(error) => {
                    self.state = State::Settled(Outcome::Failed);
                    return Poll::Ready(Close::Failed(native_error(error)));
                }
            },
            State::Settled(outcome) => *outcome,
            State::Active(_) | State::Retired => return Poll::Pending,
        };
        self.state = State::Retired;
        Poll::Ready(Close::Closed(Report::Registry { outcome }))
    }
}

fn outcome(result: &LookupResult) -> Outcome {
    match result {
        Ok(value) => Outcome::Resolved(*value),
        Err(Error::Protocol(Fault::Cancelled | Fault::Timeout)) => Outcome::Cancelled,
        Err(_) => Outcome::Failed,
    }
}

fn native_error<'id>(error: Error) -> NativeError<'id> {
    NativeError::Registry(Arc::new(error))
}
