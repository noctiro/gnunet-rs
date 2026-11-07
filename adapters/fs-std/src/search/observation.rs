//! Staged actual advertisements and strictly source-bound historical replay.
//!
//! Public observation fields are local journal inputs, not authentication tokens.
//! Only live staging or replay through the original Session verifies their block.
//! Expiration/time fields are retained local facts, not signed UBLOCK fields.
use super::{Error, Incoming, QueryId, Session, Step, retryable};
use crate::ipc;
use gnunet_fs::{client::Event as ClientEvent, ublock::Kind};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::fs::CLIENT_PUT_PREFIX;

/// Borrowed original observation fields. A deserialized value grants no result
/// rights; replay checks the actual reconstructed query and authenticates again.
#[derive(Clone, Copy, Debug)]
pub struct Observation<'a> {
    /// Original local graph position, validated against every actual query field.
    pub query_id: usize,
    /// Original keyword or namespace query interpretation.
    pub kind: Kind,
    /// Original effective public namespace; anonymous for keyword queries.
    pub namespace: &'a [u8; 32],
    /// Exact decoded label, excluding a terminator or keyword mandatory marker.
    pub label: &'a [u8],
    /// Actual lookup key derived by the reconstructed original query context.
    pub lookup_key: &'a [u8; 64],
    /// Original complete signed/encrypted UBLOCK, borrowed without a second copy.
    pub wire: &'a [u8],
    /// Native expiration claim observed on the original accepted FS frame.
    pub expiration: AbsoluteTime,
    /// Original source UTC microsecond observation used by native expiry filtering.
    pub observed_at: AbsoluteTime,
}
/// Native/search progress or an authenticated block awaiting aggregate admission.
#[expect(
    clippy::large_enum_variant,
    reason = "Retaining original inline native progress avoids a fallible allocation after an actual event"
)]
pub enum Staged {
    /// `Session::observation` borrows the original authenticated pending frame.
    /// No aggregate result/update graph changes until explicit acceptance.
    Advertisement,
    /// Actual native/search progress; this does not assert search completion.
    Step(Step),
}
pub(super) struct Pending {
    pub(super) query: QueryId,
    pub(super) received: ipc::Received,
    pub(super) observed_at: AbsoluteTime,
    pub(super) incoming: Option<Incoming>,
}
impl<'id, F, const KNOWN: usize> Session<'id, F, KNOWN>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    /// Borrow the one original staged, decoded advertisement. Ordinary pending
    /// resource refusals which have not been authenticated expose no observation.
    #[must_use]
    pub fn observation(&self) -> Option<Observation<'_>> {
        let pending = self.pending.as_ref()?;
        pending.incoming.as_ref()?;
        let query = self.queries.get(pending.query.0)?;
        let ClientEvent::Block(block) = pending.received.event() else {
            return None;
        };
        Some(Observation {
            query_id: pending.query.0,
            kind: query.opener.kind(),
            namespace: query.opener.namespace_key(),
            label: &query.spec.label,
            lookup_key: query.opener.query(),
            wire: block.block,
            expiration: block.expiration,
            observed_at: pending.observed_at,
        })
    }
    pub(super) fn stage_pending(&mut self) -> Result<Staged, Error> {
        let mut pending = self.pending.take().ok_or(ProtocolError::NotReady)?;
        let prepared = (|| -> Result<(), Error> {
            if pending.incoming.is_none() {
                let ClientEvent::Block(block) = pending.received.event() else {
                    return Err(ProtocolError::Malformed.into());
                };
                pending.incoming = Some(self.decode_block(pending.query, block.block)?);
            }
            Ok(())
        })();
        if let Err(cause) = prepared {
            if retryable(&cause) || matches!(cause, Error::Transport(_)) {
                self.pending = Some(pending);
                return Err(cause);
            }
            return Ok(Staged::Step(Step::Rejected {
                query: pending.query,
                cause,
            }));
        }
        // Use the same semantic URI identity lookup as actual acceptance. Old
        // native replies after restart cannot force duplicate journal records.
        let incoming = pending.incoming.as_ref().ok_or(ProtocolError::NotReady)?;
        let matched = self.match_incoming(pending.query, incoming);
        match matched {
            Ok((_, Some(index))) if self.results[index].matched.contains(&pending.query) => {
                Ok(Staged::Step(Step::Ignored))
            }
            Ok(_) => {
                self.pending = Some(pending);
                Ok(Staged::Advertisement)
            }
            Err(cause) => {
                if retryable(&cause) || matches!(cause, Error::Transport(_)) {
                    self.pending = Some(pending);
                    Err(cause)
                } else {
                    Ok(Staged::Step(Step::Rejected {
                        query: pending.query,
                        cause,
                    }))
                }
            }
        }
    }
    /// Admit the exact staged advertisement through the original aggregation and
    /// update-query creation owner. Resource/port refusal retains the same original
    /// native frame for an explicit retry; no service resend is requested.
    pub fn accept_staged(&mut self) -> Result<Step, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        let mut pending = self.pending.take().ok_or(ProtocolError::NotReady)?;
        let Some(incoming) = pending.incoming.take() else {
            self.pending = Some(pending);
            return Err(ProtocolError::NotReady.into());
        };
        let accepted = (|| -> Result<Step, Error> {
            let ClientEvent::Block(block) = pending.received.event() else {
                return Err(ProtocolError::Malformed.into());
            };
            self.accept(
                pending.query,
                incoming,
                block.block,
                block.expiration,
                pending.observed_at,
            )
        })();
        match accepted {
            Ok(step) => Ok(step),
            Err(cause) if retryable(&cause) || matches!(cause, Error::Transport(_)) => {
                self.pending = Some(pending);
                Err(cause)
            }
            Err(cause) => Ok(Step::Rejected {
                query: pending.query,
                cause,
            }),
        }
    }
    /// Rebuild historical results and update queries before any live driving.
    /// Every record is rebound to the actual fresh query and authenticated through
    /// the same decoder/aggregator. Child construction opens no network socket.
    /// Historical expiration is checked at the original observation, not now;
    /// equality is valid exactly as in the native `< observed` expiry filter.
    pub fn replay(&mut self, observation: Observation<'_>) -> Result<Step, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if self.live_started || self.pending.is_some() {
            return Err(ProtocolError::NotReady.into());
        }
        let query = self
            .queries
            .get(observation.query_id)
            .ok_or(ProtocolError::Stale)?;
        if query.opener.kind() != observation.kind
            || query.opener.namespace_key() != observation.namespace
            || query.opener.query() != observation.lookup_key
            || query.spec.label != observation.label
        {
            return Err(ProtocolError::Conflict.into());
        }
        let frame = observation
            .wire
            .len()
            .checked_add(CLIENT_PUT_PREFIX)
            .ok_or(ProtocolError::Overflow)?;
        if observation.wire.len() > self.options.protocol.max_block_bytes
            || frame > self.options.native.frame_bytes
            || frame > usize::from(u16::MAX)
        {
            return Err(Error::Limit);
        }
        if !observation.expiration.is_never()
            && observation.expiration.as_micros() < observation.observed_at.as_micros()
        {
            return Err(ProtocolError::Authentication.into());
        }
        if self
            .last_replayed
            .is_some_and(|last| observation.observed_at < last)
        {
            return Err(ProtocolError::TimeUncertain.into());
        }
        let id = QueryId(observation.query_id);
        let incoming = self.decode_block(id, observation.wire)?;
        let accepted = match self.accept(
            id,
            incoming,
            observation.wire,
            observation.expiration,
            observation.observed_at,
        ) {
            Ok(step) => step,
            Err(cause) if retryable(&cause) || matches!(cause, Error::Transport(_)) => {
                return Err(cause);
            }
            // The durable record witnesses authenticated observation, not a
            // promised aggregate success. Preserve the exact live rejection
            // semantics for a valid artifact with an unusable continuation.
            Err(cause) => Step::Rejected { query: id, cause },
        };
        self.last_replayed = Some(observation.observed_at);
        // Historical verification does not read the current clock. The first
        // live poll must nevertheless preserve the same UTC lower bound.
        self.last_now = Some(observation.observed_at);
        Ok(accepted)
    }
}
