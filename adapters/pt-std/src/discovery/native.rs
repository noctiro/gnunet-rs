//! One real DHT GET, bounded by the original PT discovery operation.
use super::{Event, Port, Query};
use crate::{Failure, owner::Failures};
use gnunet_dht_client_host as dht;
use gnunet_pt::{Error as Fault, core::Discovery};
use gnunet_service_runtime::{clock::RuntimeClock, framing::OwnedFrame};
use std::{
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

struct Row<'client, 'pt> {
    query: Query<'pt>,
    get: dht::GetId<'client>,
}
/// Caller-driven DNS-exit GET on the actual DHT service. The separate lifetimes
/// bind real DHT capabilities and PT discovery tokens to their original instances.
/// Construction starts no IO. One GET/output slot, the existing client's bounded
/// input/owned-received frames and one 112-byte copied advertisement are owned.
/// Readonly reconnect retains the same original GET and fixed deadlines.
pub struct Native<'client, 'pt> {
    client: dht::Client<'client>,
    clock: Arc<dyn RuntimeClock>,
    row: Option<Row<'client, 'pt>>,
    alarm: Option<Pin<Box<Sleep>>>,
}
#[derive(Debug)]
struct SourceLoss(dht::LossCause);
impl fmt::Display for SourceLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original PT DHT source retired: {:?}", self.0)
    }
}
impl Error for SourceLoss {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.0 {
            dht::LossCause::Io(error) => Some(error),
            dht::LossCause::Protocol(error) | dht::LossCause::Resource(error) => Some(error),
            _ => None,
        }
    }
}
impl<'client, 'pt> Native<'client, 'pt> {
    /// Reserve the actual single-query DHT client on an already selected source.
    /// The source supplies the same process clock and Resolver as the PT owner.
    pub fn new(
        instance: &'client mut dht::Instance,
        source: dht::EndpointSource,
    ) -> Result<Self, Failure> {
        let clock = source.clock();
        let mut limits = dht::Limits::default();
        limits.protocol.gets = 1;
        limits.protocol.monitors = 0;
        limits.protocol.hellos = 0;
        limits.protocol.operations = 0;
        limits.protocol.attempts = 1;
        limits.protocol.source_bytes = 65535;
        // PT deduplicates signed advertisements by peer/expiration itself.
        limits.protocol.known_per_get = 0;
        limits.protocol.frame_bytes = 65535;
        limits.output.frames = 1;
        limits.output.bytes = 65535;
        limits.hello.maximum_address_bytes = 0;
        limits.hello.maximum_addresses = 0;
        Ok(Self {
            client: dht::Client::new(instance, source, limits)?,
            clock,
            row: None,
            alarm: None,
        })
    }
    fn retire(&mut self, get: dht::GetId<'client>) -> Result<(), Failure> {
        let stopped = self.client.stop(get).err();
        // This closes the real stream OR pending native connection attempt.
        // No epoch/BeforeIssue does not prove that no attempt was present.
        let detached = self.client.retire_io().err();
        if detached.is_some() {
            let _physical = self.client.close();
        }
        match (stopped, detached) {
            (None, None) => Ok(()),
            (Some(error), None) | (None, Some(error)) => Err(Box::new(error)),
            (Some(original), Some(cleanup)) => Err(Box::new(Failures {
                original: Some(Box::new(original)),
                cleanup: vec![Box::new(cleanup)],
            })),
        }
    }
    fn ended(&mut self, original: Option<Failure>) -> Result<Event<'pt>, Failure> {
        let row = self.row.take().ok_or(Fault::Stale)?;
        self.alarm = None;
        let cleanup = self.retire(row.get).err();
        let error = match (original, cleanup) {
            (None, None) => None,
            (Some(error), None) | (None, Some(error)) => Some(error),
            (Some(original), Some(cleanup)) => Some(Box::new(Failures {
                original: Some(original),
                cleanup: vec![cleanup],
            }) as Failure),
        };
        Ok(Event::Ended {
            original: row.query.original,
            error,
        })
    }
    fn fatal(&mut self, original: Failure) -> Failure {
        // Keep the original logical row for its caller's explicit stop, but
        // relinquish physical IO before exposing an unrecoverable port error.
        match self.client.retire_io() {
            Ok(_) => original,
            Err(error) => {
                let _physical = self.client.close();
                Box::new(Failures {
                    original: Some(original),
                    cleanup: vec![Box::new(error)],
                })
            }
        }
    }
    fn observation(original: Discovery<'pt>, error: Failure) -> Event<'pt> {
        Event::SourceFailure { original, error }
    }
    fn poll_one(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<'pt>, Failure>> {
        let Some(row) = &self.row else {
            // No idle connection attempt is authorized outside an actual GET.
            return Poll::Pending;
        };
        let query = row.query;
        let get = row.get;
        if Instant::now() >= query.hard
            || self
                .alarm
                .as_mut()
                .is_some_and(|a| a.as_mut().poll(cx).is_ready())
        {
            return Poll::Ready(self.ended(Some(Fault::Deadline.into())));
        }
        let now = match self.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => return Poll::Ready(Err(self.fatal(Box::new(error)))),
        };
        if now >= query.expires {
            return Poll::Ready(self.ended(Some(Fault::Deadline.into())));
        }
        let progress = match self.client.poll_with_input(cx, Some(query.hard), true) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(progress)) => progress,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(self.fatal(Box::new(error)))),
        };
        let event = match progress {
            dht::Progress::Inbound(received) => {
                if !matches!(received.event(), dht::Event::Result { get: current, .. } if *current == get)
                {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                match received.result() {
                    Ok(result)
                        if *result.key == query.key
                            && result.block_type == 10
                            && result.payload.len() == 112 =>
                    {
                        let mut block = Vec::new();
                        if block.try_reserve_exact(112).is_err() {
                            Self::observation(query.original, Fault::Capacity.into())
                        } else {
                            block.extend_from_slice(result.payload);
                            Event::Result {
                                original: query.original,
                                query: *result.key,
                                block_type: result.block_type,
                                block: OwnedFrame::new(block),
                            }
                        }
                    }
                    Ok(_) => Self::observation(query.original, Fault::Malformed.into()),
                    Err(error) => Self::observation(query.original, Box::new(error)),
                }
            }
            dht::Progress::Lost { cause, .. } => {
                Self::observation(query.original, Box::new(SourceLoss(cause)))
            }
            dht::Progress::ConnectRetry { error, .. } => {
                Self::observation(query.original, Box::new(error))
            }
            dht::Progress::Unavailable(error) => Self::observation(query.original, Box::new(error)),
            dht::Progress::Capacity(_) => Self::observation(query.original, Fault::Capacity.into()),
            dht::Progress::Closed => return Poll::Ready(self.ended(Some(Fault::Closed.into()))),
            _ => {
                // Exactly one native action per poll. The same task is woken to
                // resume its fair provider loop; no detached work is created.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        Poll::Ready(Ok(event))
    }
}
impl<'client, 'pt> Port<'pt> for Native<'client, 'pt> {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    fn start(&mut self, query: Query<'pt>) -> Result<(), Failure> {
        if self.row.is_some() {
            return Err(Fault::Conflict.into());
        }
        if query.key != gnunet_pt::exit::discovery_key()
            || query.block_type != 10
            || query.replication != 1
            || query.options != 1
            || query.expires == u64::MAX
        {
            return Err(Fault::Malformed.into());
        }
        if Instant::now() >= query.hard || self.clock.sample()?.now.as_micros() >= query.expires {
            return Err(Fault::Deadline.into());
        }
        let get = self.client.get(dht::Get {
            key: &query.key,
            block_type: query.block_type,
            options: query.options,
            replication: query.replication,
            extended_query: &[],
        })?;
        self.row = Some(Row { query, get });
        self.alarm = Some(Box::pin(tokio::time::sleep_until(query.hard)));
        if Instant::now() >= query.hard {
            let cleanup = self.stop(query.original).err().into_iter().collect();
            return Err(Box::new(Failures {
                original: Some(Fault::Deadline.into()),
                cleanup,
            }));
        }
        Ok(())
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<'pt>, Failure>> {
        self.poll_one(cx)
    }
    fn stop(&mut self, original: Discovery<'pt>) -> Result<(), Failure> {
        if self
            .row
            .as_ref()
            .is_none_or(|r| r.query.original != original)
        {
            return Err(Fault::Stale.into());
        }
        let row = self.row.take().ok_or(Fault::Stale)?;
        self.alarm = None;
        self.retire(row.get)
    }
}
