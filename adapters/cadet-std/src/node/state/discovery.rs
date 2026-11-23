//! Bounded route searches owned by an original open or established tunnel.
use super::*;
use crate::node::{Discovery, DiscoveryStatus};

#[derive(Clone, Copy)]
pub(super) struct Repair<'book> {
    serial: u64,
    pub(super) expires: MonoInstant,
    pub(super) hard: Instant,
    pub(super) route: Option<connection::Route<'book>>,
}

impl<'node, 'book, 'app, E: Entropy> State<'node, 'book, '_, 'app, '_, '_, '_, '_, E> {
    fn open_at(&self, index: usize) -> Option<(Discovery<'node, 'app>, Instant)> {
        let channel = self.channels.get(index)?;
        let (open, expires) = channel.open?;
        if channel.closing
            || !self
                .server
                .channel_info(open.channel())
                .is_ok_and(|info| info.phase == app::Phase::Opening)
        {
            return None;
        }
        Some((
            Discovery {
                owner: DiscoveryOwner::Open(open),
                peer: channel.owner.as_ref()?.address().remote_peer,
                expires,
            },
            channel.open_hard?,
        ))
    }

    fn repair_at(&self, index: usize) -> Option<(Discovery<'node, 'app>, Instant)> {
        let tunnel = self.tunnels.get(index)?;
        let repair = tunnel.repair?;
        let scope = tunnel.owner.as_ref()?.scope();
        if !self.can_repair(index) {
            return None;
        }
        Some((
            Discovery {
                owner: DiscoveryOwner::Repair {
                    scope,
                    serial: repair.serial,
                },
                peer: scope.peer(),
                expires: repair.expires,
            },
            repair.hard,
        ))
    }

    fn can_repair(&self, index: usize) -> bool {
        let tunnel = &self.tunnels[index];
        !tunnel.closing
            && tunnel.owner.as_ref().is_some_and(|owner| {
                let snapshot = owner.snapshot();
                !snapshot.closed && snapshot.confirmed.is_some()
            })
            && self.channels.iter().any(|channel| {
                channel.tunnel == index
                    && !channel.closing
                    && channel.binding.is_some_and(|binding| {
                        self.server
                            .channel_info(binding.channel())
                            .is_ok_and(|info| info.phase == app::Phase::Ready)
                    })
            })
    }

    fn wants_path<const P: usize>(book: &Book<'book, '_, '_, P>, peer: [u8; 32]) -> bool {
        !book.has_endpoint_path(peer) && book.current_neighbor(peer).is_none()
    }

    fn locate(&self, wanted: Discovery<'node, 'app>) -> Option<(usize, Instant)> {
        if self.closing {
            return None;
        }
        match wanted.owner {
            DiscoveryOwner::Open(_) => (0..self.channels.len()).find_map(|index| {
                let (current, hard) = self.open_at(index)?;
                (current == wanted).then_some((self.channels[index].tunnel, hard))
            }),
            DiscoveryOwner::Repair { scope, .. } => {
                let index = self.tunnel_index(scope.peer())?;
                let (current, hard) = self.repair_at(index)?;
                (current == wanted).then_some((index, hard))
            }
        }
    }

    fn search_status<const P: usize>(
        &self,
        book: &Book<'book, '_, '_, P>,
        wanted: Discovery<'node, 'app>,
        tunnel: usize,
    ) -> DiscoveryStatus {
        if book.has_ready_endpoint_path(wanted.peer) {
            return DiscoveryStatus::Finished;
        }
        if !Self::wants_path(book, wanted.peer)
            || matches!(wanted.owner, DiscoveryOwner::Repair { .. })
                && self.tunnels[tunnel]
                    .repair
                    .is_some_and(|repair| repair.route.is_some())
        {
            return DiscoveryStatus::Opening;
        }
        DiscoveryStatus::Searching
    }

    pub(in crate::node) fn discovery_status<const P: usize>(
        &self,
        book: &Book<'book, '_, '_, P>,
        wanted: Discovery<'node, 'app>,
    ) -> DiscoveryStatus {
        self.locate(wanted)
            .map_or(DiscoveryStatus::Finished, |(tunnel, _)| {
                self.search_status(book, wanted, tunnel)
            })
    }

    pub(in crate::node) fn discovery_after<const P: usize>(
        &self,
        book: &Book<'book, '_, '_, P>,
        cursor: usize,
    ) -> Option<(usize, Discovery<'node, 'app>)> {
        if self.closing {
            return None;
        }
        let channels = self.channels.len();
        for index in cursor..channels {
            if let Some((wanted, _)) = self.open_at(index)
                && Self::wants_path(book, wanted.peer)
                && self.repair_at(self.channels[index].tunnel).is_none()
            {
                return Some((index + 1, wanted));
            }
        }
        for index in cursor.saturating_sub(channels)..self.tunnels.len() {
            if let Some((wanted, _)) = self.repair_at(index)
                && self.search_status(book, wanted, index) == DiscoveryStatus::Searching
            {
                return Some((channels + index + 1, wanted));
            }
        }
        None
    }

    pub(in crate::node) fn discovery_hard<const P: usize>(
        &self,
        book: &Book<'book, '_, '_, P>,
        wanted: Discovery<'node, 'app>,
    ) -> Option<Instant> {
        let (tunnel, hard) = self.locate(wanted)?;
        (self.search_status(book, wanted, tunnel) != DiscoveryStatus::Finished).then_some(hard)
    }

    pub(in crate::node) fn expire_discovery<const P: usize>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        wanted: Discovery<'node, 'app>,
    ) -> Result<(), ProtocolError> {
        let (tunnel, _) = self.locate(wanted).ok_or(ProtocolError::StaleGeneration)?;
        match wanted.owner {
            DiscoveryOwner::Open(open) => {
                let channel = self
                    .channels
                    .iter_mut()
                    .find(|channel| channel.open == Some((open, wanted.expires)))
                    .ok_or(ProtocolError::StaleGeneration)?;
                channel.closing = true;
                self.fail(wanted.peer, None, ProtocolError::Deadline);
            }
            DiscoveryOwner::Repair { .. } => {
                if let Some(route) = self.tunnels[tunnel].repair.and_then(|repair| repair.route) {
                    match book.route_info(route) {
                        Ok(info)
                            if matches!(
                                info.phase,
                                connection::Phase::Ready | connection::Phase::Retired
                            ) => {}
                        Ok(_) => book.close_route(route)?,
                        Err(ProtocolError::StaleGeneration) => {}
                        Err(error) => return Err(error),
                    }
                }
                self.end_repair(tunnel, wanted.expires);
            }
        }
        Ok(())
    }

    pub(in crate::node) fn admit_discovery<const P: usize>(
        &mut self,
        wanted: Discovery<'node, 'app>,
        path: &[[u8; 32]],
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
        attempt_until: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        let (tunnel, hard) = self.locate(wanted).ok_or(ProtocolError::StaleGeneration)?;
        let deadline = attempt_until.min(wanted.expires);
        if now >= deadline || Instant::now() >= hard {
            return Err(ProtocolError::Deadline);
        }
        match self.search_status(book, wanted, tunnel) {
            DiscoveryStatus::Searching => {}
            DiscoveryStatus::Opening => return Err(ProtocolError::NotReady),
            DiscoveryStatus::Finished => return Err(ProtocolError::StaleGeneration),
        }
        if path.len() < 2
            || path.len() > P
            || path.first() != Some(&self.server.local_peer())
            || path.last() != Some(&wanted.peer)
            || path.iter().enumerate().any(|(i, p)| path[..i].contains(p))
        {
            return Err(ProtocolError::InvalidInput);
        }
        if book.current_neighbor(path[1]).is_none() {
            return Err(ProtocolError::NotReady);
        }
        let previous = self.tunnels[tunnel].route;
        self.ensure_path(tunnel, book, path, now, Some(deadline))?;
        let Some(route) = self.tunnels[tunnel]
            .route
            .filter(|route| Some(*route) != previous)
        else {
            return Ok(false);
        };
        if let DiscoveryOwner::Repair { .. } = wanted.owner {
            let repair = self.tunnels[tunnel]
                .repair
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?;
            repair.route = Some(route);
        }
        self.drive_initial(tunnel, now)?;
        Ok(true)
    }

    fn end_repair(&mut self, index: usize, now: MonoInstant) {
        let tunnel = &mut self.tunnels[index];
        tunnel.repair = None;
        tunnel.repair_after = MonoInstant(now.0.saturating_add(self.limits.route_tick_micros));
    }

    pub(in crate::node) fn fence_repair_paths<const P: usize>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        let native_now = Instant::now();
        for (index, tunnel) in self.tunnels.iter().enumerate() {
            if let Some(repair) = tunnel.repair.filter(|repair| repair.route.is_some())
                && (now >= repair.expires || native_now >= repair.hard || !self.can_repair(index))
            {
                return self.drive_repair(index, book, now);
            }
        }
        Ok(false)
    }

    pub(super) fn drive_repair<const P: usize>(
        &mut self,
        index: usize,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        if let Some(repair) = self.tunnels[index].repair {
            let eligible = self.can_repair(index);
            let expired = now >= repair.expires || Instant::now() >= repair.hard;
            if let Some(route) = repair.route {
                match book.route_info(route).map(|info| info.phase) {
                    Ok(connection::Phase::Ready) => {
                        self.tunnels[index].repair = None;
                        return Ok(true);
                    }
                    Ok(connection::Phase::Retired) | Err(ProtocolError::StaleGeneration) => {
                        if eligible && !expired {
                            let mut retry = repair;
                            retry.route = None;
                            self.tunnels[index].repair = Some(retry);
                        } else {
                            self.end_repair(index, now);
                        }
                        return Ok(true);
                    }
                    Ok(_) if expired || !eligible => {
                        book.close_route(route)?;
                        self.end_repair(index, now);
                        return Ok(true);
                    }
                    Ok(_) => return Ok(false),
                    Err(error) => return Err(error),
                }
            }
            if expired || !eligible {
                self.end_repair(index, now);
                return Ok(true);
            }
            let peer = self.tunnels[index]
                .peer
                .ok_or(ProtocolError::StaleGeneration)?;
            if book.has_ready_endpoint_path(peer) {
                self.tunnels[index].repair = None;
                return Ok(true);
            }
            return Ok(false);
        }
        if now < self.tunnels[index].repair_after || !self.can_repair(index) {
            return Ok(false);
        }
        let peer = self.tunnels[index]
            .peer
            .ok_or(ProtocolError::StaleGeneration)?;
        if !Self::wants_path(book, peer) {
            return Ok(false);
        }
        let serial = self.next_repair;
        self.next_repair = serial.checked_add(1).ok_or(ProtocolError::Overflow)?;
        let expires = MonoInstant(
            now.0
                .checked_add(self.limits.opening_micros)
                .ok_or(ProtocolError::Overflow)?,
        );
        let hard = Instant::now()
            .checked_add(Duration::from_micros(self.limits.opening_micros))
            .ok_or(ProtocolError::Overflow)?;
        self.tunnels[index].repair = Some(Repair {
            serial,
            expires,
            hard,
            route: None,
        });
        Ok(true)
    }
}
