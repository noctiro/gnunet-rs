//! Live owner names from the original configured IDENTITY MQ.
use super::{Owner, Result, TIMEOUT, identity};
use crate::{
    control::Control,
    namestore::{EndpointSource, Progress as NameStoreProgress, SecretKey, Stream},
};
use gnunet::wire::identity::SecretKeyView;
use std::{
    future::{Future, poll_fn},
    task::{Context, Poll},
};
use tokio::time::Instant;

#[cfg(all(test, unix))]
mod tests;

pub(super) enum Names<'a, 'id> {
    Zone(&'a Owner),
    Snapshot(&'a [Owner]),
    Live(&'a mut Inventory<'id>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Observation {
    Idle,
    Pending,
    Activity,
}

impl Names<'_, '_> {
    pub(super) fn zone(&self) -> Option<&SecretKey> {
        match self {
            Self::Zone(owner) => Some(&owner.key),
            Self::Snapshot(_) | Self::Live(_) => None,
        }
    }

    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        hard: Option<Instant>,
    ) -> Result<Observation> {
        match self {
            Self::Live(inventory) => inventory.poll(cx, hard),
            Self::Zone(_) | Self::Snapshot(_) => Ok(Observation::Idle),
        }
    }

    pub(super) fn with_name(
        &self,
        zone: SecretKeyView<'_>,
        output: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let key = SecretKey::from_serialized(zone.expose_serialized())?;
        match self {
            Self::Zone(owner) if owner.key.constant_time_eq(&key) => output(&owner.name)?,
            Self::Zone(_) => return Err("NAMESTORE returned a record from another zone".into()),
            Self::Snapshot(owners) => {
                if let Some(owner) = owners.iter().find(|owner| owner.key.constant_time_eq(&key)) {
                    output(&owner.name)?;
                }
            }
            Self::Live(inventory) => {
                if let Some(ego) = inventory
                    .client
                    .egos()
                    .find(|ego| ego.secret().constant_time_eq(&key))
                {
                    output(ego.name())?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn close(&mut self) {
        if let Self::Live(inventory) = self {
            let _closed = inventory.client.close();
        }
    }
}

pub(super) struct Inventory<'id> {
    client: identity::Client<'id>,
    epoch: identity::Epoch<'id>,
}

impl<'id> Inventory<'id> {
    pub(super) async fn open(
        instance: &'id identity::Instance,
        source: EndpointSource,
        control: &mut Control,
    ) -> Result<Self> {
        let mut client = identity::Client::monitor(
            instance,
            source,
            identity::Limits {
                reconnect: false,
                initialization_timeout: TIMEOUT,
                ..Default::default()
            },
        )?;
        let hard = Some(control.hard());
        loop {
            match control.drive(client.drive(hard)).await? {
                identity::Progress::Initialized(epoch)
                    if client.initialized() && client.epoch() == Some(epoch) =>
                {
                    return Ok(Self { client, epoch });
                }
                identity::Progress::Connected(_)
                | identity::Progress::StartQueued(_)
                | identity::Progress::StartWritten(_)
                | identity::Progress::Ego { initial: true, .. }
                | identity::Progress::Deleted { .. }
                | identity::Progress::Activity { .. }
                | identity::Progress::ConnectRetry { .. } => {}
                event => return Err(unexpected(event)),
            }
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>, hard: Option<Instant>) -> Result<Observation> {
        use identity::{InventoryProgress, Progress};
        match self.client.poll_inventory(cx, hard) {
            Poll::Pending => Ok(Observation::Pending),
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Ready(Ok(InventoryProgress::Idle(epoch))) => {
                if epoch != self.epoch || !self.client.initialized() {
                    return Err("IDENTITY monitor changed source".into());
                }
                Ok(Observation::Idle)
            }
            Poll::Ready(Ok(InventoryProgress::Source(event))) => match event {
                Progress::Ego { initial: false, .. }
                | Progress::Deleted { .. }
                | Progress::Activity { .. } => {
                    if self.client.epoch() != Some(self.epoch) || !self.client.initialized() {
                        return Err("IDENTITY monitor changed source".into());
                    }
                    Ok(Observation::Activity)
                }
                event => Err(unexpected(event)),
            },
        }
    }
}

fn unexpected(event: identity::Progress<'_>) -> Box<dyn std::error::Error> {
    match event {
        identity::Progress::Lost { cause, .. } => {
            format!("IDENTITY monitor source lost: {cause:?}").into()
        }
        identity::Progress::Unavailable(error) => error.into(),
        identity::Progress::WaitDeadline => "IDENTITY monitor initial inventory deadline".into(),
        identity::Progress::Closed => "IDENTITY monitor closed".into(),
        _ => "unexpected IDENTITY inventory event".into(),
    }
}

pub(super) async fn step<'id>(
    names: &mut Names<'_, '_>,
    stream: &mut Stream<'id>,
    control: &mut Control,
    hard: Option<Instant>,
) -> Result<NameStoreProgress<'id>> {
    // Only one original NAMESTORE record can be delayed. Give its co-ready
    // IDENTITY changes time to settle without requiring an atomic cross-service
    // snapshot or letting an active IDENTITY sender starve the record stream.
    const IDENTITY_TURNS: usize = 8;
    let mut turns = IDENTITY_TURNS;
    let mut held = None;
    let mut next = std::pin::pin!(stream.drive(hard));
    poll_fn(|cx| {
        control.check(cx)?;
        let observed = names.poll(cx, hard)?;
        if let Some(record) = held.take() {
            if observed == Observation::Idle || turns == 0 {
                return Poll::Ready(Ok(record));
            }
            turns -= 1;
            held = Some(record);
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        match next.as_mut().poll(cx) {
            Poll::Ready(Ok(record @ NameStoreProgress::Record { .. }))
                if observed != Observation::Idle =>
            {
                held = Some(record);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending if observed == Observation::Activity => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            result => result.map_err(Into::into),
        }
    })
    .await
}
