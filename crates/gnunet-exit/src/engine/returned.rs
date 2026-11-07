//! Actual TUN packets→original VPN channel replies and embedded-quote NAT lookup.
use super::*;
impl Engine<'_> {
    fn lookup(&self, tuple: Tuple) -> Result<usize, Error> {
        self.flows
            .iter()
            .position(|r| {
                r.as_ref()
                    .is_some_and(|r| !r.closing && !r.peer_closed && r.tuple == Some(tuple))
            })
            .ok_or(Error::NotFound)
    }
    /// Process one actual complete normalized raw IP packet read from this exact
    /// original TUN. Checksums and full tuple select the original real flow.
    /// WouldBlock preserves caller input; no result/delivery is fabricated.
    pub fn from_tun(&mut self, tun: &Tun, bytes: &[u8], now: MonoInstant) -> Result<Flow, Error> {
        if self.tun.as_ref() != Some(tun) {
            return Err(Error::Stale);
        }
        let now = self.time(now)?;
        if bytes.len() > self.limits.packet_bytes {
            return Err(Error::TooLarge);
        }
        let packet = Packet::parse(bytes)?;
        packet.validate_checksums()?;
        let family = packet.source().family();
        let protocol = Protocol::from_number(family, packet.protocol())?;
        let segment = packet.segment();
        let (index, kind) = match protocol {
            Protocol::Tcp | Protocol::Udp => {
                if segment.len() < 8 {
                    return Err(Error::Truncated);
                }
                let source = u16::from_be_bytes([segment[0], segment[1]]);
                let destination = u16::from_be_bytes([segment[2], segment[3]]);
                let i = self.lookup(Tuple {
                    remote: Endpoint {
                        address: packet.source(),
                        port: source,
                    },
                    local: Endpoint {
                        address: packet.destination(),
                        port: destination,
                    },
                    protocol,
                })?;
                (i, 0)
            }
            Protocol::Icmp | Protocol::Icmp6 => {
                if segment.len() < 8 {
                    return Err(Error::Truncated);
                }
                if !super::forward::allowed(family, segment[0]) {
                    return Err(Error::Unsupported);
                }
                let i = if packet::icmp_error(family, segment[0]) {
                    let (local, remote, number, ports) = packet::quoted_tuple(&segment[8..])?;
                    if local.family() != family || remote.family() != family {
                        return Err(Error::Malformed);
                    }
                    let protocol = Protocol::from_number(local.family(), number)?;
                    let (local_port, remote_port) = ports.unwrap_or((0, 0));
                    self.lookup(Tuple {
                        remote: Endpoint {
                            address: remote,
                            port: remote_port,
                        },
                        local: Endpoint {
                            address: local,
                            port: local_port,
                        },
                        protocol,
                    })?
                } else {
                    self.lookup(Tuple {
                        remote: Endpoint {
                            address: packet.source(),
                            port: 0,
                        },
                        local: Endpoint {
                            address: packet.destination(),
                            port: 0,
                        },
                        protocol,
                    })?
                };
                (i, 1)
            }
        };
        let r = self.flows[index].as_ref().ok_or(Error::Stale)?;
        self.valid_source(&r.source)?;
        let flow = r.flow.clone();
        if kind == 1 {
            let mut header: [u8; 8] = segment[..8].try_into().map_err(|_| Error::Truncated)?;
            header[2..4].fill(0);
            let payload = if packet::icmp_error(family, header[0]) {
                &[][..]
            } else {
                &segment[8..]
            };
            self.queue_peer(
                &flow,
                PeerMessage::IcmpReply {
                    af: self.config.af.value(family),
                    header,
                    payload,
                },
            )?;
        } else if protocol == Protocol::Udp {
            self.queue_peer(
                &flow,
                PeerMessage::UdpReply {
                    source: 0,
                    destination: 0,
                    payload: &segment[8..],
                },
            )?;
        } else {
            if segment.len() < 20 {
                return Err(Error::Truncated);
            }
            let mut header: [u8; 20] = segment[..20].try_into().map_err(|_| Error::Truncated)?;
            let offset = usize::from(header[12] >> 4) * 4;
            if offset < 20 || offset > segment.len() {
                return Err(Error::Malformed);
            }
            header[..4].fill(0);
            header[16..18].fill(0);
            self.queue_peer(
                &flow,
                PeerMessage::Tcp {
                    to_exit: false,
                    reserved: 0,
                    header,
                    tail: &segment[20..],
                },
            )?;
        }
        let r = self.flows[index].as_mut().ok_or(Error::Stale)?;
        r.last = now;
        r.idle = now.checked_add(self.limits.idle).ok_or(Error::Overflow)?;
        if protocol == Protocol::Tcp && segment.len() >= 20 {
            let flags = segment[13];
            let ack = u32::from_be_bytes(segment[8..12].try_into().map_err(|_| Error::Truncated)?);
            r.tcp.established |= r.tcp.syn && flags & 0x12 == 0x12 && r.syn_end == Some(ack);
            r.tcp.remote_fin |= flags & 1 != 0;
            r.tcp.reset |= flags & 4 != 0;
        }
        Ok(flow)
    }
}
