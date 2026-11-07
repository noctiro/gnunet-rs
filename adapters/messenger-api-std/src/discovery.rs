//! Actual original GNS room-entry/details lookup. This is a native client of
//! the selected resolver, not a GNS service or a block-authentication substitute.
use crate::{
    clock::{DriverClock, Span},
    *,
};
use gnunet_gns_client_host as gns;
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
/// Explicit actual GNS query and independent record producer layout. This is
/// local provider configuration, not an assertion of resolver/signature success.
pub struct RoomQuery {
    /// Original actual lookup options, zone and record type.
    pub parameters: gns::Parameters,
    /// Original publisher's Messenger record scalar producer, not local IPC.
    pub profile: wire::profile::Profile,
}
impl std::fmt::Debug for RoomQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessengerRoomQuery([REDACTED])")
            .field("record_profile", &self.profile)
            .finish_non_exhaustive()
    }
}
/// Actual advertised room entry. Its authority is the selected GNS resolver's
/// original answer; no native Messenger membership is claimed by these bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RoomEntry {
    door: [u8; 32],
    key: Hash,
}
impl RoomEntry {
    /// Original advertised CADET door peer.
    pub const fn door(&self) -> &[u8; 32] {
        &self.door
    }
    /// Original advertised room key.
    pub const fn key(&self) -> &Hash {
        &self.key
    }
}
impl std::fmt::Debug for RoomEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomEntry([REDACTED])")
    }
}
/// Exact original GNS answer, retaining its query/source and immutable records.
/// The resolver service owns GNS validation; this wrapper checks Messenger
/// record structure and does not claim it performed zone signature validation.
pub struct RoomAnswer<'a> {
    original: gns::Answer<'a>,
    profile: wire::profile::Profile,
}
impl<'a> RoomAnswer<'a> {
    /// Actual original native reply/query/source.
    pub const fn native(&self) -> &gns::Answer<'a> {
        &self.original
    }
    /// Borrow every actual entry. Bad payloads are reported, not invented doors.
    pub fn entries(&self) -> Result<impl Iterator<Item = Result<RoomEntry, Fault>> + '_, Fault> {
        let records = self.original.result()?.records();
        let profile = self.profile;
        Ok(records.iter().filter_map(move |record| match record {
            Err(error) => Some(Err(error)),
            Ok(record) if record.record_type == gns::RecordType::MESSENGER_ROOM_ENTRY => Some(
                wire::records::Record::decode(record.record_type, record.data, profile).and_then(
                    |record| match record {
                        wire::records::Record::RoomEntry { door, room_key } => Ok(RoomEntry {
                            door: *door,
                            key: *room_key,
                        }),
                        _ => Err(Fault::Malformed),
                    },
                ),
            ),
            Ok(_) => None,
        }))
    }
    /// Borrow original details data through the shared exact payload codec.
    pub fn details(
        &self,
    ) -> Result<impl Iterator<Item = Result<wire::records::Record<'_>, Fault>> + '_, Fault> {
        let records = self.original.result()?.records();
        let profile = self.profile;
        Ok(records.iter().filter_map(move |record| match record {
            Err(error) => Some(Err(error)),
            Ok(record) if record.record_type == gns::RecordType::MESSENGER_ROOM_DETAILS => Some(
                wire::records::Record::decode(record.record_type, record.data, profile),
            ),
            Ok(_) => None,
        }))
    }
}
impl std::fmt::Debug for RoomAnswer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomAnswer([REDACTED])")
    }
}
/// One real discovery observation. No empty answer is manufactured on loss,
/// clock failure or timeout, and no query is replayed on another native epoch.
pub enum DiscoveryProgress<'a> {
    /// Actual pre-result native progress.
    Native(gns::Progress<'a>),
    /// Actual matching original query reply; the source is closed afterwards.
    Answer(RoomAnswer<'a>),
    /// Actual physical stop, retaining the originating native observation.
    Stopped {
        /// Actual local/clock/ownership cause.
        cause: Fault,
        /// Actual independently observed native cause/close fact.
        original: Option<gns::Progress<'a>>,
    },
}
impl std::fmt::Debug for DiscoveryProgress<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MessengerDiscovery([REDACTED])")
    }
}
/// One finite caller-driven room-name lookup, over its original independent GNS
/// MQ. Dropped wait futures preserve the original query/hard deadline. Explicit
/// close is physical; no retry/replay is admitted by this owner after any loss.
pub struct Discovery<'a> {
    client: gns::BoundedClient<'a, 1, 252>,
    query: gns::QueryId<'a>,
    epoch: Option<gns::Epoch<'a>>,
    clock: DriverClock,
    span: Span,
    profile: wire::profile::Profile,
    stopped: bool,
}
impl<'a> Discovery<'a> {
    /// Original lookup token, never an invented Messenger wire field.
    pub const fn query(&self) -> gns::QueryId<'a> {
        self.query
    }
    /// Physically close without sampling clock or treating it as empty result.
    pub fn close(&mut self) -> DiscoveryProgress<'a> {
        self.stopped = true;
        self.clock.clear_alarms();
        DiscoveryProgress::Stopped {
            cause: Fault::Closed,
            original: self.client.close(),
        }
    }
    fn stop(&mut self, cause: Fault, original: Option<gns::Progress<'a>>) -> DiscoveryProgress<'a> {
        self.stopped = true;
        self.clock.clear_alarms();
        let closed = self.client.close();
        DiscoveryProgress::Stopped {
            cause,
            original: original.or(closed),
        }
    }
    /// Register/check original native hard bound before either canonical clock
    /// subscription. GNS source retries are never allowed to rebind this query.
    pub fn poll_progress(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<DiscoveryProgress<'a>, Error>> {
        if self.stopped {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        self.clock.poll_native(cx, Some(self.span.hard));
        if self.span.expired(None) {
            return Poll::Ready(Ok(self.stop(Fault::Timeout, None)));
        }
        let now = match self.clock.poll_now(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Ok(self.stop(e, None))),
            Poll::Ready(Ok(n)) => n,
        };
        if self.span.expired(Some(now)) {
            return Poll::Ready(Ok(self.stop(Fault::Deadline, None)));
        }
        self.clock
            .poll_logical(cx, Some(self.span.logical))
            .map_err(Error::Clock)?;
        let event = {
            let future = self.client.drive(Some(self.span.hard));
            let mut future = std::pin::pin!(future);
            future.as_mut().poll(cx)
        };
        let event = match event {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.stop(Fault::Io, None);
                return Poll::Ready(Err(e.into()));
            }
            Poll::Ready(Ok(v)) => v,
        };
        if self.span.expired(None) {
            return Poll::Ready(Ok(self.stop(Fault::Timeout, Some(event))));
        }
        match event {
            gns::Progress::Connected(epoch) => {
                if self.epoch.is_some() {
                    return Poll::Ready(Ok(self.stop(
                        Fault::StaleGeneration,
                        Some(gns::Progress::Connected(epoch)),
                    )));
                }
                self.epoch = Some(epoch);
                Poll::Ready(Ok(DiscoveryProgress::Native(gns::Progress::Connected(
                    epoch,
                ))))
            }
            gns::Progress::Answer(answer) => {
                if answer.query() != self.query || self.epoch != Some(answer.epoch()) {
                    return Poll::Ready(Ok(
                        self.stop(Fault::StaleGeneration, Some(gns::Progress::Answer(answer)))
                    ));
                }
                self.stopped = true;
                self.client.close();
                self.clock.clear_alarms();
                Poll::Ready(Ok(DiscoveryProgress::Answer(RoomAnswer {
                    original: answer,
                    profile: self.profile,
                })))
            }
            event @ (gns::Progress::Lost { .. }
            | gns::Progress::ConnectRetry { .. }
            | gns::Progress::Unavailable(_)
            | gns::Progress::Refused { .. }
            | gns::Progress::WaitDeadline
            | gns::Progress::Closed) => Poll::Ready(Ok(self.stop(Fault::Unavailable, Some(event)))),
            other => Poll::Ready(Ok(DiscoveryProgress::Native(other))),
        }
    }
    /// Caller-driven wait; starts no actor or resolver service.
    pub async fn progress(&mut self) -> Result<DiscoveryProgress<'a>, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
impl Drop for Discovery<'_> {
    fn drop(&mut self) {
        self.client.close();
    }
}
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    /// Start a real finite room-entry/details lookup against an explicitly
    /// selected native GNS service. Caller policy supplies original zone/options;
    /// this method rejects unrelated types and enforces the same process clock.
    pub fn discover_room<'id>(
        &mut self,
        instance: &'id mut gns::Instance,
        endpoint: EndpointSource,
        parameters: gns::Parameters,
        name: &[u8],
        timeout: Duration,
        limits: gns::Limits,
    ) -> Result<Discovery<'id>, Error> {
        self.discover_room_profiled(
            instance,
            endpoint,
            RoomQuery {
                parameters,
                profile: self
                    .profiles
                    .common_record_profile()
                    .ok_or(Fault::Unavailable)?,
            },
            name,
            timeout,
            limits,
        )
    }
    /// Actually query the explicit GNS endpoint using independent record
    /// producer facts; this never enters a resolver/recovery implementation.
    pub fn discover_room_profiled<'id>(
        &mut self,
        instance: &'id mut gns::Instance,
        endpoint: EndpointSource,
        query: RoomQuery,
        name: &[u8],
        timeout: Duration,
        limits: gns::Limits,
    ) -> Result<Discovery<'id>, Error> {
        let RoomQuery {
            parameters,
            profile,
        } = query;
        profile.validate()?;
        if !matches!(
            parameters.record_type,
            gns::RecordType::MESSENGER_ROOM_ENTRY | gns::RecordType::MESSENGER_ROOM_DETAILS
        ) {
            return Err(Fault::InvalidInput.into());
        }
        if !Arc::ptr_eq(&endpoint.clock(), &self.clock.source) {
            return Err(Fault::Conflict.into());
        }
        let clock = DriverClock::new(endpoint.clock()).map_err(Error::Clock)?;
        let span = Span::new(clock.sample().map_err(Error::Clock)?, timeout)?;
        let mut client = gns::BoundedClient::new(instance, endpoint, limits)?;
        let query = client.lookup(parameters, name)?;
        Ok(Discovery {
            client,
            query,
            epoch: None,
            clock,
            span,
            profile,
            stopped: false,
        })
    }
    /// Actually prepare official ENTRY from an actual resolver answer entry.
    /// Resolve bytes themselves grant no member/session authority.
    pub fn enter_advertised(
        &mut self,
        entry: RoomEntry,
        timeout: Duration,
    ) -> Result<(Room<'a>, Operation<'a>), Error> {
        self.enter_room(entry.key, entry.door, timeout)
    }
}
