//! Original route evidence for sending a locally sealed DV BOX.
use super::{NeighbourId, Router, Selected};
use crate::{
    PeerId,
    dv::{self, BoxPacket, routes},
};
use gnunet_types::{Error, MonoInstant};

/// Exact route generation and native first hop for a locally originated BOX.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginRoute<'id> {
    id: routes::RouteId<'id>,
    target: PeerId,
    first: NeighbourId<'id>,
    distance: u32,
    until: MonoInstant,
    policy: routes::SendPolicy,
}

impl<'id> OriginRoute<'id> {
    /// Original virtual destination authenticated by this route.
    pub const fn target(self) -> PeerId {
        self.target
    }

    /// The exact existing direct carrier for later mailbox admission.
    pub const fn first_hop(self) -> NeighbourId<'id> {
        self.first
    }

    /// Official DV distance: the intermediates after the native first hop.
    pub const fn distance(self) -> u32 {
        self.distance
    }

    /// Deadline of the original route, shortened by its first carrier lease.
    pub const fn deadline(self) -> MonoInstant {
        self.until
    }
}

impl<'id> Router<'id, '_> {
    /// Select a live indirect route only when no direct carrier owns the target.
    pub fn select_origin(
        &mut self,
        target: PeerId,
        policy: routes::SendPolicy,
        now: MonoInstant,
    ) -> Result<Option<OriginRoute<'id>>, Error> {
        if target == self.local_peer() || self.direct(target, now)?.is_some() {
            return Ok(None);
        }
        let Some(selected) = self.select(target, policy, now)? else {
            return Ok(None);
        };
        if selected.route.path.len() < 2 {
            return Err(Error::Conflict);
        }
        let id = selected.route.id;
        let first = selected.next;
        let distance = u32::try_from(selected.route.path.len() - 2).map_err(|_| Error::Overflow)?;
        let until = selected.route.until;
        Ok(Some(OriginRoute {
            id,
            target,
            first,
            distance,
            until: until.min(self.neighbour(first)?.until),
            policy,
        }))
    }

    /// Check that this exact original route and first carrier remain eligible.
    pub fn check_origin(&mut self, route: OriginRoute<'id>, now: MonoInstant) -> Result<(), Error> {
        self.origin_selection(route, now).map(|_| ())
    }

    /// Copy the official wire route into caller storage. The native first
    /// recipient is excluded and the final encrypted destination is included.
    pub fn copy_origin_path(
        &mut self,
        route: OriginRoute<'id>,
        now: MonoInstant,
        output: &mut [PeerId],
    ) -> Result<usize, Error> {
        let selected = self.origin_selection(route, now)?;
        let path = &selected.route.path[1..];
        output
            .get_mut(..path.len())
            .ok_or(Error::Capacity)?
            .copy_from_slice(path);
        Ok(path.len())
    }

    /// Require an unforwarded BOX whose original size and path match this
    /// selected route. The caller remains responsible for actual sealing.
    pub fn check_origin_box(
        &mut self,
        route: OriginRoute<'id>,
        now: MonoInstant,
        packet: BoxPacket<'_>,
    ) -> Result<(), Error> {
        let selected = self.origin_selection(route, now)?;
        let path = &selected.route.path[1..];
        if packet.traversed() != 0
            || usize::from(packet.original_size()?) != packet.bytes().len()
            || packet.hop_count() != path.len()
            || packet.without_fc()? > 1
            || packet.ciphertext().len() < dv::PAYLOAD_PREFIX + 4
        {
            return Err(Error::Malformed);
        }
        for (index, peer) in path.iter().enumerate() {
            if packet.hop(index)? != *peer {
                return Err(Error::Authentication);
            }
        }
        Ok(())
    }

    fn origin_selection(
        &mut self,
        route: OriginRoute<'id>,
        now: MonoInstant,
    ) -> Result<Selected<'id, '_>, Error> {
        if now >= route.until {
            return Err(Error::Deadline);
        }
        if self.direct(route.target, now)?.is_some() {
            return Err(Error::NotReady);
        }
        let selected = self.select_id(route.id, route.target, route.policy, now)?;
        if selected.next != route.first || selected.route.path.len() < 2 {
            return Err(Error::StaleGeneration);
        }
        Ok(selected)
    }
}
