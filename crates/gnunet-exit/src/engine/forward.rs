//! Actual VPN skeleton→IP forwarding. Endpoint TCP state remains at endpoints.
use super::*;
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
    fn packet(&self, tuple: Tuple, protocol: Protocol, segment: &[u8]) -> Result<Vec<u8>, Error> {
        let h = match tuple.local.address.family() {
            Family::V4 => 20,
            Family::V6 => 40,
        };
        let n = h + segment.len();
        if n > self.limits.packet_bytes {
            return Err(Error::TooLarge);
        }
        let mut out = zero(n)?;
        let n = packet::build(
            tuple.local.address,
            tuple.remote.address,
            protocol.number(),
            segment,
            &mut out,
        )?;
        out.truncate(n);
        Ok(out)
    }
    fn tcp(&self, tuple: Tuple, header: [u8; 20], tail: &[u8]) -> Result<Vec<u8>, Error> {
        let mut segment = zero(20usize.checked_add(tail.len()).ok_or(Error::Overflow)?)?;
        segment[..20].copy_from_slice(&header);
        segment[20..].copy_from_slice(tail);
        let offset = usize::from(header[12] >> 4) * 4;
        if offset < 20 || offset > segment.len() {
            return Err(Error::Malformed);
        }
        segment[..2].copy_from_slice(&tuple.local.port.to_be_bytes());
        segment[2..4].copy_from_slice(&tuple.remote.port.to_be_bytes());
        self.packet(tuple, Protocol::Tcp, &segment)
    }
    fn udp(&self, tuple: Tuple, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut segment = zero(8usize.checked_add(payload.len()).ok_or(Error::Overflow)?)?;
        segment[..2].copy_from_slice(&tuple.local.port.to_be_bytes());
        segment[2..4].copy_from_slice(&tuple.remote.port.to_be_bytes());
        segment[8..].copy_from_slice(payload);
        self.packet(tuple, Protocol::Udp, &segment)
    }
    fn icmp(
        &self,
        tuple: Tuple,
        from: Family,
        header: [u8; 8],
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let to = tuple.remote.address.family();
        let header = packet::translate_icmp_header(from, to, header)?;
        if !allowed(to, header[0]) {
            return Err(Error::Unsupported);
        }
        let mut quote = [0; 48];
        let payload = if packet::icmp_error(to, header[0]) {
            if !payload.is_empty() {
                return Err(Error::Malformed);
            }
            let ports =
                (!tuple.protocol.is_icmp()).then_some((tuple.remote.port, tuple.local.port));
            let n = packet::quote(
                tuple.remote.address,
                tuple.local.address,
                tuple.protocol.number(),
                ports,
                &mut quote,
            )?;
            &quote[..n]
        } else {
            payload
        };
        let mut segment = zero(8usize.checked_add(payload.len()).ok_or(Error::Overflow)?)?;
        segment[..8].copy_from_slice(&header);
        segment[8..].copy_from_slice(payload);
        self.packet(
            tuple,
            if to == Family::V4 {
                Protocol::Icmp
            } else {
                Protocol::Icmp6
            },
            &segment,
        )
    }
    fn forward(
        &mut self,
        index: usize,
        message: PeerMessage<'_>,
        entropy: &mut impl Entropy,
    ) -> Result<(Tuple, Vec<u8>, Option<u8>), Error> {
        let r = self.flows[index].as_ref().ok_or(Error::Stale)?;
        let target = r.target;
        match message {
            PeerMessage::TcpInternet {
                destination,
                header,
                tail,
            } => {
                if !matches!(target, Target::Internet(_)) || r.tuple.is_some() {
                    return Err(Error::Conflict);
                }
                let remote = Endpoint {
                    address: destination,
                    port: u16::from_be_bytes([header[2], header[3]]),
                };
                let tuple = self.tuple(index, remote, Protocol::Tcp, 0, entropy)?;
                let bytes = self.tcp(tuple, header, tail)?;
                Ok((tuple, bytes, Some(header[13])))
            }
            PeerMessage::TcpService { header, tail, .. } => {
                let service = self.service(target, Some(Protocol::Tcp))?;
                if r.tuple.is_some() {
                    return Err(Error::Conflict);
                }
                let tuple = self.tuple(index, service.target, Protocol::Tcp, 0, entropy)?;
                let bytes = self.tcp(tuple, header, tail)?;
                Ok((tuple, bytes, Some(header[13])))
            }
            PeerMessage::Tcp {
                to_exit: true,
                header,
                tail,
                ..
            } => {
                let tuple = r.tuple.ok_or(Error::NotReady)?;
                if tuple.protocol != Protocol::Tcp {
                    return Err(Error::Conflict);
                }
                let bytes = self.tcp(tuple, header, tail)?;
                Ok((tuple, bytes, Some(header[13])))
            }
            PeerMessage::UdpInternet {
                address,
                source,
                destination,
                payload,
            } => {
                if !matches!(target, Target::Internet(_)) {
                    return Err(Error::PermissionDenied);
                }
                let tuple = self.tuple(
                    index,
                    Endpoint {
                        address,
                        port: destination,
                    },
                    Protocol::Udp,
                    source,
                    entropy,
                )?;
                let bytes = self.udp(tuple, payload)?;
                Ok((tuple, bytes, None))
            }
            PeerMessage::UdpService {
                source, payload, ..
            } => {
                let service = self.service(target, Some(Protocol::Udp))?;
                let tuple = self.tuple(index, service.target, Protocol::Udp, source, entropy)?;
                let bytes = self.udp(tuple, payload)?;
                Ok((tuple, bytes, None))
            }
            PeerMessage::IcmpInternet {
                destination,
                header,
                payload,
            } => {
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
                let tuple = self.tuple(index, remote, protocol, 0, entropy)?;
                let bytes = self.icmp(tuple, destination.family(), header, payload)?;
                Ok((tuple, bytes, None))
            }
            PeerMessage::IcmpService {
                af,
                header,
                payload,
            } => {
                // Existing TCP/UDP tuples select their original endpoint.
                // A first standalone ICMP request can select only a unique
                // configured target; never use whichever shared hash came first.
                let transport = r
                    .tuple
                    .filter(|tuple| !tuple.protocol.is_icmp())
                    .map(|tuple| tuple.protocol);
                let service = self.service(target, transport)?;
                let from = self.config.af.family(af)?;
                let protocol = r.tuple.map_or(
                    if packet::icmp_error(from, header[0]) {
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
                let tuple = self.tuple(index, remote, protocol, 0, entropy)?;
                let bytes = self.icmp(tuple, from, header, payload)?;
                Ok((tuple, bytes, None))
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
        let result = (|| {
            if bytes.len() > self.limits.peer_bytes {
                return Err(Error::TooLarge);
            }
            let message = PeerMessage::decode_with_profile(bytes, self.config.af)?;
            if let PeerMessage::Dns {
                reply: false,
                packet,
            } = message
            {
                return self.dns_start(index, packet, now, entropy);
            }
            self.tun.as_ref().ok_or(Error::NotReady)?;
            let (tuple, packet, flags) = self.forward(index, message, entropy)?;
            self.capacity(packet.len())?;
            let input = Input {
                owner: self.stamp.clone(),
                serial: self.serial()?,
            };
            let expires = now
                .checked_add(self.limits.input_lifetime)
                .ok_or(Error::Overflow)?;
            let idle = now.checked_add(self.limits.idle).ok_or(Error::Overflow)?;
            let syn_end = if flags.is_some_and(|flags| flags & 0x12 == 2) {
                let p = Packet::parse(&packet)?;
                let segment = p.segment();
                let seq =
                    u32::from_be_bytes(segment[4..8].try_into().map_err(|_| Error::Truncated)?);
                Some(
                    seq.wrapping_add((segment.len() - usize::from(segment[12] >> 4) * 4) as u32)
                        .wrapping_add(1),
                )
            } else {
                None
            };
            self.queue(Side::Tun, flow, packet, Some(input.clone()))?;
            let r = self.flows[index].as_mut().ok_or(Error::Stale)?;
            r.tuple = Some(tuple);
            r.last = now;
            r.idle = idle;
            r.receipt = Some(Receipt {
                id: input.clone(),
                ready: false,
                issued: false,
                expires,
            });
            if let Some(flags) = flags {
                r.tcp.syn |= flags & 2 != 0;
                if r.syn_end.is_none() {
                    r.syn_end = syn_end;
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
pub(super) fn allowed(family: Family, kind: u8) -> bool {
    match family {
        Family::V4 => matches!(kind, 0 | 8 | 3 | 4 | 11),
        Family::V6 => matches!(kind, 128 | 129 | 1 | 2 | 3 | 4),
    }
}
