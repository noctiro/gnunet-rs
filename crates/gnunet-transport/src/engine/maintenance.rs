//! Bounded physical communicator progress while domain output remains blocked.
use super::*;

// Reliable forbids another reliable/fragment envelope inside it. Inspect its
// one legal wrapper without copying a body or changing codec error ownership.
fn requires_dv_source(bytes: &[u8]) -> bool {
    let Ok(frame) = Frame::decode(bytes) else {
        return false;
    };
    match frame.header().message_type().value() {
        crate::dv::LEARN_TYPE | crate::dv::BOX_TYPE => true,
        1216 => p2p::Reliable::decode(bytes).is_ok_and(|boxed| {
            Frame::decode(boxed.message).is_ok_and(|inner| {
                matches!(
                    inner.header().message_type().value(),
                    crate::dv::LEARN_TYPE | crate::dv::BOX_TYPE
                )
            })
        }),
        _ => false,
    }
}

impl Engine {
    /// Process only an already registered physical communicator's maintenance
    /// input, without pumping transmission Jobs. `None` leaves the complete
    /// original frame and every Engine owner unchanged; native callers retain
    /// it under its existing first-byte/source bound. CORE/app/monitor business
    /// and new communicator registration stay behind the domain barrier.
    pub fn receive_maintenance_at(
        &mut self,
        owner: &ClientId,
        bytes: &[u8],
        times: Times,
        signer: &mut impl Signer,
        entropy: &mut impl Entropy,
    ) -> Result<Option<ReceiveOutcome>, Error> {
        self.validate_times(times)?;
        let client = self.client(owner)?;
        if self.clients[client].role != Role::Communicator {
            return Ok(None);
        }
        let kind = Frame::decode(bytes)?.header().message_type().value();
        if !matches!(
            kind,
            1200 | 1201 | 1202 | 1204 | 1205 | 1207 | 1208 | 1210 | 1222 | 1254
        ) {
            return Ok(None);
        }
        let request = communicator::Request::decode(bytes)?;
        if let communicator::Request::Incoming { message, .. } = request
            && self.dv_source_active()
            && requires_dv_source(message)
        {
            // Raw DV requires the original explicit source and both captured
            // targets. Never downgrade it to the legacy scheduling-only path.
            return Ok(None);
        }
        if !self.maintenance_fits(owner, request, times)? {
            return Ok(None);
        }
        self.receive_inner(
            owner,
            bytes,
            times,
            signer,
            entropy,
            ReceiveMode::Maintenance(None),
        )
        .map(Some)
    }

    /// Same maintenance path for one actual raw DV envelope. Its original
    /// Source, mono/canonical targets and physical FC debt survive all staging.
    pub fn receive_dv_maintenance_at(
        &mut self,
        input: dv_bridge::NativeInput<'_>,
        times: Times,
        signer: &mut impl Signer,
        entropy: &mut impl Entropy,
    ) -> Result<Option<ReceiveOutcome>, Error> {
        self.validate_times(times)?;
        let client = self.client(input.owner)?;
        if self.clients[client].role != Role::Communicator {
            return Ok(None);
        }
        self.check_native_input(&input, times)?;
        let request = communicator::Request::decode(input.bytes)?;
        if !self.maintenance_fits(input.owner, request, times)? {
            return Ok(None);
        }
        self.receive_inner(
            input.owner,
            input.bytes,
            times,
            signer,
            entropy,
            ReceiveMode::Maintenance(Some(input)),
        )
        .map(Some)
    }

    fn maintenance_fits(
        &self,
        owner: &ClientId,
        request: communicator::Request<'_>,
        times: Times,
    ) -> Result<bool, Error> {
        let (needed, limit) = match request {
            communicator::Request::Register { .. } | communicator::Request::Backchannel { .. } => {
                return Ok(false);
            }
            communicator::Request::QueueSetup { queue, .. } => {
                if self.routes.len() == self.limits.queues
                    || self.routes.iter().any(|q| {
                        q.owner == *owner
                            && q.description.peer == queue.peer
                            && q.description.id == queue.id
                    })
                    || (!self.peers.iter().any(|p| p.id == queue.peer)
                        && self.peers.len() == self.limits.peers)
                    || (queue.mtu >= 48 && queue.length > 0 && !self.control_room(48))
                {
                    return Ok(false);
                }
                (0, self.limits.messages + self.limits.control_messages)
            }
            communicator::Request::QueueDown { peer, id } => (
                self.retirement_outputs(owner, peer, id, times.monotonic().0)?,
                self.limits.messages + self.limits.control_messages,
            ),
            communicator::Request::Sent {
                peer,
                queue,
                message_id,
                status,
            } if status != 1
                && self.attempts.iter().any(|a| {
                    a.owner == *owner
                        && a.peer == peer
                        && a.queue == queue
                        && a.message_id == message_id
                        && !a.retired
                }) =>
            {
                (
                    self.retirement_outputs(owner, peer, queue, times.monotonic().0)?,
                    self.limits.messages + self.limits.control_messages,
                )
            }
            communicator::Request::Incoming {
                flow_control,
                message,
                ..
            } => {
                let (needed, ordinary) = self.incoming_outputs(message)?;
                (
                    needed
                        .checked_add(usize::from(flow_control))
                        .ok_or(Error::Overflow)?,
                    if ordinary {
                        self.limits.messages
                    } else {
                        self.limits.messages + self.limits.control_messages
                    },
                )
            }
            _ => (0, self.limits.messages + self.limits.control_messages),
        };
        Ok(self
            .output
            .len()
            .checked_add(needed)
            .is_some_and(|n| n <= limit))
    }

    /// Upper bound for one decoded network envelope. Reassembly may expose a
    /// validation or CORE payload, so reserve both possibilities before its
    /// original assembly/FC ownership can change. No space means no mutation.
    fn incoming_outputs(&self, bytes: &[u8]) -> Result<(usize, bool), Error> {
        let cores = || self.clients.iter().filter(|c| c.role == Role::Core).count();
        let Ok(frame) = Frame::decode(bytes) else {
            // A malformed remote body belongs to the original network drop
            // path, not the physical communicator's local protocol errors.
            return Ok((0, false));
        };
        Ok(match frame.header().message_type().value() {
            1303 | 1221 | 1217 | 1218 | 1219 => (0, false),
            1304 | 1214 => (cores().checked_add(1).ok_or(Error::Overflow)?, true),
            1213 => (1, false),
            1216 => {
                match p2p::Reliable::decode(bytes) {
                    Ok(boxed)
                        if Frame::decode(boxed.message).is_ok_and(|inner| {
                            !matches!(inner.header().message_type().value(), 1214 | 1216)
                        }) =>
                    {
                        self.incoming_outputs(boxed.message)?
                    }
                    // The real network handler records the exact decode or
                    // nesting refusal and emits only the original FC response.
                    Ok(_) | Err(_) => (0, false),
                }
            }
            _ => (
                self.clients
                    .iter()
                    .filter(|c| c.role == Role::Core && c.payload)
                    .count(),
                false,
            ),
        })
    }

    /// Mirror only refresh's possible output count after this exact original
    /// queue disappears. Keeping already-consumed FC/CORE debts is essential
    /// when a full domain FIFO temporarily prevents their real responses.
    fn retirement_outputs(
        &self,
        owner: &ClientId,
        peer: PeerId,
        queue: u32,
        now: u64,
    ) -> Result<usize, Error> {
        let remaining = |q: &Route| {
            q.description.peer == peer && !(q.owner == *owner && q.description.id == queue)
        };
        let virtual_live = self.dv_bridge.has_peer(peer, now);
        let routes = virtual_live || self.routes.iter().any(remaining);
        let live = virtual_live
            || self
                .routes
                .iter()
                .any(|q| remaining(q) && q.valid_until > now);
        self.refresh_outputs(peer, routes, live)
    }
}

#[cfg(test)]
mod tests;
