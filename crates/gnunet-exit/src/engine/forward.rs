//! Actual VPN skeleton→IP forwarding. Endpoint TCP state remains at endpoints.
use super::*;
use gnunet_vpn::packet::icmp_error;
impl Engine<'_> {
    fn service(&self, target: Target, protocol: Option<Protocol>) -> Result<Service, Error> {
        let Target::Service(port) = target else {
            return Err(Error::PermissionDenied);
        };
        let mut services =
            self.config.services.iter().filter(|s| {
                s.port == port && protocol.is_none_or(|protocol| s.protocol == protocol)
            });
        let service = services.next().copied().ok_or(Error::NotFound)?;
        // ICMP has no TCP/UDP selector on wire. Before a transport tuple is
        // established, a shared hash with two targets is genuinely ambiguous.
        if services.next().is_some() {
            return Err(Error::Conflict);
        }
        Ok(service)
    }
    fn pool(&self, family: Family) -> Result<Pool, Error> {
        match family {
            Family::V4 => self.config.ipv4,
            Family::V6 => self.config.ipv6,
        }
        .ok_or(Error::Unavailable)
    }
    fn tuple(
        &self,
        index: usize,
        remote: Endpoint,
        protocol: Protocol,
        requested: u16,
        entropy: &mut impl Entropy,
    ) -> Result<Tuple, Error> {
        let record = self.flows[index].as_ref().ok_or(Error::Stale)?;
        if let Some(tuple) = record.tuple {
            if tuple.remote != remote
                || tuple.protocol != protocol
                || (requested != 0 && requested != tuple.local.port)
            {
                return Err(Error::Conflict);
            }
            return Ok(tuple);
        }
        if let Target::Internet(family) = record.target
            && (family != remote.address.family() || !self.config.policy.allows(remote, protocol))
        {
            return Err(Error::PermissionDenied);
        }
        let pool = self.pool(remote.address.family())?;
        for _ in 0..self.limits.entropy_draws {
            let local = pool.candidate(protocol, requested, entropy, self.limits.entropy_draws)?;
            let tuple = Tuple {
                remote,
                local,
                protocol,
            };
            tuple.validate()?;
            if !self.flows.iter().flatten().any(|r| r.tuple == Some(tuple)) {
                return Ok(tuple);
            }
        }
        Err(Error::Capacity)
    }
    fn select_tuple(
        &self,
        index: usize,
        message: PeerMessage<'_>,
        profile: AfProfile,
        entropy: &mut impl Entropy,
    ) -> Result<Tuple, Error> {
        let r = self.flows[index].as_ref().ok_or(Error::Stale)?;
        let target = r.target;
        match message {
            PeerMessage::TcpInternet {
                destination,
                header,
                ..
            } => {
                if !matches!(target, Target::Internet(_)) || r.tuple.is_some() {
                    return Err(Error::Conflict);
                }
                let remote = Endpoint {
                    address: destination,
                    port: u16::from_be_bytes([header[2], header[3]]),
                };
                self.tuple(index, remote, Protocol::Tcp, 0, entropy)
            }
            PeerMessage::TcpService { .. } => {
                let service = self.service(target, Some(Protocol::Tcp))?;
                if r.tuple.is_some() {
                    return Err(Error::Conflict);
                }
                self.tuple(index, service.target, Protocol::Tcp, 0, entropy)
            }
            PeerMessage::Tcp { to_exit: true, .. } => r.tuple.ok_or(Error::NotReady),
            PeerMessage::UdpInternet {
                address,
                source,
                destination,
                ..
            } => {
                if !matches!(target, Target::Internet(_)) {
                    return Err(Error::PermissionDenied);
                }
                self.tuple(
                    index,
                    Endpoint {
                        address,
                        port: destination,
                    },
                    Protocol::Udp,
                    source,
                    entropy,
                )
            }
            PeerMessage::UdpService { source, .. } => {
                let service = self.service(target, Some(Protocol::Udp))?;
                self.tuple(index, service.target, Protocol::Udp, source, entropy)
            }
            PeerMessage::IcmpInternet { destination, .. } => {
                if !matches!(target, Target::Internet(_)) {
                    return Err(Error::PermissionDenied);
                }
                let protocol = r.tuple.map_or(
                    if destination.family() == Family::V4 {
                        Protocol::Icmp
                    } else {
                        Protocol::Icmp6
                    },
                    |t| t.protocol,
                );
                let remote = r.tuple.map_or(
                    Endpoint {
                        address: destination,
                        port: 0,
                    },
                    |t| t.remote,
                );
                if remote.address != destination {
                    return Err(Error::Conflict);
                }
                self.tuple(index, remote, protocol, 0, entropy)
            }
            PeerMessage::IcmpService { af, header, .. } => {
                // Existing TCP/UDP tuples select their original endpoint.
                // A first standalone ICMP request can select only a unique
                // configured target; never use whichever shared hash came first.
                let transport = r
                    .tuple
                    .filter(|tuple| !tuple.protocol.is_icmp())
                    .map(|tuple| tuple.protocol);
                let service = self.service(target, transport)?;
                let from = profile.family(af)?;
                let protocol = r.tuple.map_or(
                    if icmp_error(from, header[0]) {
                        service.protocol
                    } else if service.target.address.family() == Family::V4 {
                        Protocol::Icmp
                    } else {
                        Protocol::Icmp6
                    },
                    |t| t.protocol,
                );
                let mut remote = service.target;
                if protocol.is_icmp() {
                    remote.port = 0
                }
                self.tuple(index, remote, protocol, 0, entropy)
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Admit one exact original complete VPN application frame. WouldBlock leaves
    /// the input and flow unchanged; other failures request real channel closure.
    /// Host retains the original outer CADET Delivery while this receipt is live.
    pub fn receive(
        &mut self,
        flow: &Flow,
        bytes: &[u8],
        now: MonoInstant,
        entropy: &mut impl Entropy,
    ) -> Result<Input, Error> {
        let index = self.index(flow)?;
        let now = self.time(now)?;
        let r = self.flows[index].as_ref().ok_or(Error::Stale)?;
        self.valid_source(&r.source)?;
        if r.closing {
            return Err(Error::Closed);
        }
        if r.receipt.is_some() {
            return Err(Error::WouldBlock);
        }
        let mut af = r.af;
        let result = (|| {
            if bytes.len() > self.limits.peer_bytes {
                return Err(Error::TooLarge);
            }
            let profile = af.receive(bytes)?;
            let message = PeerMessage::decode_with_profile(bytes, profile)?;
            if let PeerMessage::Dns {
                reply: false,
                packet,
            } = message
            {
                return self.dns_start(index, packet, now, entropy);
            }
            self.tun.as_ref().ok_or(Error::NotReady)?;
            let tuple = self.select_tuple(index, message, profile, entropy)?;
            let forward = Forward::from_peer(tuple, message, profile)?;
            let n = forward.packet_len();
            if n > self.limits.packet_bytes {
                return Err(Error::TooLarge);
            }
            self.capacity(n)?;
            let mut packet = zero(n)?;
            forward.encode(&mut packet)?;
            let input = Input {
                owner: self.stamp.clone(),
                serial: self.serial()?,
            };
            let expires = now
                .checked_add(self.limits.input_lifetime)
                .ok_or(Error::Overflow)?;
            let idle = now.checked_add(self.limits.idle).ok_or(Error::Overflow)?;
            self.queue(Side::Tun, flow, packet, Some(input.clone()))?;
            let r = self.flows[index].as_mut().ok_or(Error::Stale)?;
            r.af = af;
            r.tuple = Some(tuple);
            r.last = now;
            r.idle = idle;
            r.receipt = Some(Receipt {
                id: input.clone(),
                ready: false,
                issued: false,
                expires,
            });
            if let Some((header, payload_len)) = forward.tcp() {
                let flags = header[13];
                r.tcp.syn |= flags & 2 != 0;
                if r.syn_end.is_none() && flags & 0x12 == 2 {
                    let seq = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
                    r.syn_end = Some(seq.wrapping_add(payload_len as u32).wrapping_add(1));
                }
                r.tcp.vpn_fin |= flags & 1 != 0;
                r.tcp.reset |= flags & 4 != 0;
            }
            Ok(input)
        })();
        if let Err(e) = result
            && e != Error::WouldBlock
        {
            self.close_index(index, Some(e));
        }
        result
    }
}
