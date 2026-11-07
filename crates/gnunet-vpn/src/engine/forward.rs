//! Actual raw-IP↔official EXIT conversion; native source/queue effects stay explicit.
use super::*;
use crate::packet::{ICMP, ICMPV6, Packet, TCP, UDP};
use gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE;
fn outgoing<'a>(
    p: Packet<'a>,
    target: Target,
    first: bool,
    af: AfProfile,
) -> Result<PeerMessage<'a>, Error> {
    let b = p.segment();
    let (source, destination) = p.ports()?;
    Ok(match p.protocol() {
        UDP => {
            let source = if source < 32000 { source } else { 0 };
            let payload = &b[8..];
            match target {
                Target::Service { .. } => PeerMessage::UdpService {
                    source,
                    destination,
                    payload,
                },
                Target::Internet(address) => PeerMessage::UdpInternet {
                    address,
                    source,
                    destination,
                    payload,
                },
            }
        }
        TCP => {
            let header = b[..20].try_into().map_err(|_| Error::Truncated)?;
            let tail = &b[20..];
            if first {
                match target {
                    Target::Service { .. } => PeerMessage::TcpService {
                        reserved: 0,
                        header,
                        tail,
                    },
                    Target::Internet(destination) => PeerMessage::TcpInternet {
                        destination,
                        header,
                        tail,
                    },
                }
            } else {
                PeerMessage::Tcp {
                    to_exit: true,
                    reserved: 0,
                    header,
                    tail,
                }
            }
        }
        ICMP | ICMPV6 => {
            let from = p.source().family();
            let to = match target {
                Target::Service { .. } => from,
                Target::Internet(a) => a.family(),
            };
            let header = packet::translate_icmp_header(
                from,
                to,
                b[..8].try_into().map_err(|_| Error::Truncated)?,
            )?;
            let payload = if packet::icmp_error(from, b[0]) {
                &b[8..8]
            } else {
                &b[8..]
            };
            match target {
                Target::Service { .. } => PeerMessage::IcmpService {
                    af: af.value(from),
                    header,
                    payload,
                },
                Target::Internet(destination) => PeerMessage::IcmpInternet {
                    destination,
                    header,
                    payload,
                },
            }
        }
        _ => return Err(Error::Unsupported),
    })
}
impl<'id, 'store, 'bytes> Engine<'id, 'store, 'bytes> {
    /// Retain one actual original raw TUN packet, converting to the complete
    /// official peer message in shared storage. No discovery/open/write occurs.
    /// Existing active tuple targets survive logical lease expiry unchanged.
    /// Absolute lease admission and fixed-epoch native activity are independent.
    pub fn forward_tun(
        &mut self,
        tun: Tun<'id>,
        bytes: &[u8],
        absolute: AbsoluteTime,
        activity: MonoInstant,
    ) -> Result<Ingress<'id>, Error> {
        self.tun_ref(tun, true)?;
        if self.current_tun()? != tun {
            return Err(Error::StaleGeneration);
        }
        self.observe_activity(activity)?;
        if bytes.len() > self.limits.packet_bytes {
            return Err(Error::TooLarge);
        }
        let p = Packet::parse(bytes)?;
        p.validate_checksums()?;
        let (source_port, destination_port) = p.ports()?;
        let tuple = Tuple {
            source: p.source(),
            destination: p.destination(),
            protocol: p.protocol(),
            source_port,
            destination_port,
        };
        let found = self.store.flows.iter().enumerate().find_map(|(row, f)| {
            f.state.filter(|f| f.tuple == tuple).map(|f| Reference {
                row,
                serial: f.serial,
            })
        });
        let (new_flow, row, target, first, profile) = if let Some(r) = found {
            let f = self.store.flows[r.row]
                .state
                .ok_or(Error::StaleGeneration)?;
            if f.peer_ended {
                return Err(Error::Closed);
            }
            if f.phase == Phase::Closing {
                return Err(Error::WouldBlock);
            }
            (false, r.row, f.target, !f.start_encoded, f.af)
        } else {
            let lease = self
                .store
                .leases
                .iter()
                .filter_map(|l| l.state)
                .find(|l| l.address == p.destination() && l.expires > absolute)
                .ok_or(Error::NotFound)?;
            let row = self
                .store
                .flows
                .iter()
                .position(|f| f.state.is_none())
                .ok_or(Error::Capacity)?;
            (true, row, lease.target, true, self.limits.peer_af)
        };
        let message = outgoing(p, target, first, profile)?;
        let len = message.encoded_len()?;
        if len > MAX_APPLICATION_MESSAGE_SIZE {
            return Err(Error::TooLarge);
        }
        let slot = self.packet_slot(len)?;
        self.preflight(if new_flow { 2 } else { 1 })?;
        // All final immutable storage exists before accepting a new flow/packet.
        message.encode_with_profile(self.store.packets[slot].bytes, profile)?;
        let serial = if new_flow {
            self.serial()?
        } else {
            self.store.flows[row]
                .state
                .ok_or(Error::StaleGeneration)?
                .serial
        };
        let flow = Reference { row, serial };
        if new_flow {
            let (peer, phase) = match target {
                Target::Service { peer, .. } => (Some(peer), Phase::NeedOpen),
                Target::Internet(_) => (None, Phase::Discovering),
            };
            self.store.flows[row].state = Some(FlowState {
                serial,
                tuple,
                target,
                phase,
                peer,
                source: None,
                peer_ended: false,
                discovery: None,
                open: None,
                start_encoded: true,
                pending: None,
                receive: None,
                used: activity,
                failure: None,
                af: profile,
            });
        } else {
            let f = self.store.flows[row]
                .state
                .as_mut()
                .ok_or(Error::StaleGeneration)?;
            f.used = activity;
            f.start_encoded = true;
        }
        for l in &mut *self.store.leases {
            if let Some(l) = l.state.as_mut()
                && l.address == tuple.destination
            {
                l.used = absolute;
            }
        }
        let serial = self.serial()?;
        self.store.packets[slot].state = Some(PacketState {
            serial,
            flow,
            kind: PacketKind::Peer,
            len,
            status: Outcome::Buffered,
            attempt: None,
            bound: None,
        });
        Ok(Ingress {
            flow: self.flow(flow),
            buffer: Buffer(self.handle(Reference { row: slot, serial })),
            new_flow,
        })
    }
    /// Offer one genuine Internet-exit discovery operation. The provider must
    /// perform actual policy discovery; this function invents no eligible peer.
    pub fn discovery_request(&mut self, flow: Flow<'id>) -> Result<DiscoveryRequest<'id>, Error> {
        let r = self.flow_ref(flow)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if f.phase != Phase::Discovering {
            return Err(Error::Conflict);
        }
        let Target::Internet(destination) = f.target else {
            return Err(Error::Conflict);
        };
        let w = if let Some(w) = f.discovery {
            if w.queued || w.revoked {
                return Err(Error::WouldBlock);
            }
            w
        } else {
            let w = Work {
                serial: self.serial()?,
                queued: false,
                revoked: false,
            };
            self.store.flows[r.row]
                .state
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .discovery = Some(w);
            w
        };
        Ok(DiscoveryRequest {
            discovery: Discovery {
                flow,
                serial: w.serial,
            },
            destination,
            protocol: f.tuple.protocol,
            port: f.tuple.destination_port,
        })
    }
    fn discovery_ref(&self, d: Discovery<'id>) -> Result<Reference, Error> {
        let r = self.flow_ref(d.flow)?;
        if self.store.flows[r.row]
            .state
            .and_then(|f| f.discovery)
            .is_none_or(|w| w.serial != d.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    /// Preflight original actual-discovery admission before invoking a provider.
    pub fn can_queue_discovery(&self, discovery: Discovery<'id>) -> Result<(), Error> {
        let r = self.discovery_ref(discovery)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        let w = f.discovery.ok_or(Error::StaleGeneration)?;
        if w.queued || w.revoked || f.phase != Phase::Discovering {
            return Err(Error::Closed);
        }
        Ok(())
    }
    /// Actual original discovery job admitted; copies cannot submit it twice.
    pub fn discovery_queued(&mut self, d: Discovery<'id>) -> Result<(), Error> {
        let r = self.discovery_ref(d)?;
        let f = self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        let w = f.discovery.as_mut().ok_or(Error::StaleGeneration)?;
        if w.queued || w.revoked || f.phase != Phase::Discovering {
            return Err(Error::Closed);
        }
        w.queued = true;
        Ok(())
    }
    /// Actual original provider found an eligible exit. The provider must bind
    /// its real original result/policy; a raw untrusted IP/peer field is insufficient.
    /// Selecting it does not mean the original discovery job physically quiesced.
    pub fn select_exit(&mut self, d: Discovery<'id>, peer: [u8; 32]) -> Result<(), Error> {
        let r = self.discovery_ref(d)?;
        let f = self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        let w = f.discovery.ok_or(Error::StaleGeneration)?;
        if !w.queued || w.revoked || f.phase != Phase::Discovering {
            return Err(Error::StaleGeneration);
        }
        f.peer = Some(peer);
        f.phase = Phase::NeedOpen;
        Ok(())
    }
    /// Actual discovery failure/revocation retains its original job until the
    /// separate provider confirms retirement; no placeholder exit is selected.
    pub fn discovery_failed(&mut self, d: Discovery<'id>, reason: Error) -> Result<(), Error> {
        let r = self.discovery_ref(d)?;
        self.close_flow(self.flow(r), reason)
    }
    /// Original discovery job actually settled, even after local cancellation.
    pub fn retire_discovery(&mut self, d: Discovery<'id>) -> Result<(), Error> {
        let r = self.discovery_ref(d)?;
        self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .discovery = None;
        Ok(())
    }
    /// Offer an actual official CADET open. Gateway/service ports remain standard;
    /// no raw CID, queue admission or local write is treated as endpoint binding.
    pub fn open_request(&mut self, flow: Flow<'id>) -> Result<OpenRequest<'id>, Error> {
        let r = self.flow_ref(flow)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if f.peer_ended {
            return Err(Error::Closed);
        }
        if !matches!(f.phase, Phase::NeedOpen | Phase::Opening) {
            return Err(Error::Conflict);
        }
        let w = if let Some(w) = f.open {
            if w.queued || w.revoked {
                return Err(Error::WouldBlock);
            }
            w
        } else {
            let w = Work {
                serial: self.serial()?,
                queued: false,
                revoked: false,
            };
            let f = self.store.flows[r.row]
                .state
                .as_mut()
                .ok_or(Error::StaleGeneration)?;
            f.open = Some(w);
            f.phase = Phase::Opening;
            w
        };
        let port = match f.target {
            Target::Service { descriptor, .. } => {
                service_port(descriptor, f.tuple.destination_port)
            }
            Target::Internet(a) => gateway_port(a.family()),
        };
        Ok(OpenRequest {
            open: Open {
                flow,
                serial: w.serial,
            },
            peer: f.peer.ok_or(Error::NotReady)?,
            port,
        })
    }
    fn open_ref(&self, open: Open<'id>) -> Result<Reference, Error> {
        let r = self.flow_ref(open.flow)?;
        if self.store.flows[r.row]
            .state
            .and_then(|f| f.open)
            .is_none_or(|w| w.serial != open.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    /// Preflight the exact original open before real native CADET admission.
    pub fn can_queue_open(&self, open: Open<'id>) -> Result<(), Error> {
        let r = self.open_ref(open)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        let w = f.open.ok_or(Error::StaleGeneration)?;
        if f.peer_ended || w.queued || w.revoked || f.phase != Phase::Opening {
            return Err(Error::Closed);
        }
        Ok(())
    }
    /// Actual original native CADET create/open admitted, not remote connection.
    pub fn open_queued(&mut self, open: Open<'id>) -> Result<(), Error> {
        let r = self.open_ref(open)?;
        let f = self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        let w = f.open.as_mut().ok_or(Error::StaleGeneration)?;
        if f.peer_ended || w.queued || w.revoked || f.phase != Phase::Opening {
            return Err(Error::Closed);
        }
        w.queued = true;
        Ok(())
    }
    /// Actual original never-admitted open refused. Only the exact original work
    /// is reset; a canceled waiting future is not evidence of native nonadmission.
    pub fn reject_open(&mut self, open: Open<'id>) -> Result<(), Error> {
        let r = self.open_ref(open)?;
        let f = self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if f.open.is_some_and(|w| w.queued) {
            return Err(Error::WouldBlock);
        }
        f.open = None;
        if f.phase != Phase::Closing && !f.peer_ended {
            f.phase = Phase::NeedOpen
        }
        Ok(())
    }
    /// Actual original create/channel job failed or physically retired. This may
    /// retire canceled work and does not silently establish another generation.
    pub fn open_failed(&mut self, open: Open<'id>, reason: Error) -> Result<(), Error> {
        let r = self.open_ref(open)?;
        self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .open = None;
        self.close_flow(self.flow(r), reason)
    }
    /// Bind only the actual expected end-to-end CADET source and its explicit AF
    /// profile. Neither a queued create nor a plaintext source field may call it.
    /// Buffered pre-attempt AF metadata is normalized once before any peer effect.
    pub fn bind_peer(
        &mut self,
        open: Open<'id>,
        actual_peer: [u8; 32],
        af: AfProfile,
    ) -> Result<Peer<'id>, Error> {
        af.validate()?;
        let r = self.open_ref(open)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        let w = f.open.ok_or(Error::StaleGeneration)?;
        if f.peer_ended || f.phase != Phase::Opening || w.revoked || !w.queued {
            return Err(Error::Closed);
        }
        if f.peer != Some(actual_peer) {
            return Err(Error::Authentication);
        }
        // Only buffered, never-prepared bodies exist before first source binding.
        // Preflight all original metadata before changing any AF header bytes.
        for p in &*self.store.packets {
            if let Some(s) = p.state
                && s.flow == r
                && matches!(s.kind, PacketKind::Peer)
            {
                if s.status != Outcome::Buffered {
                    return Err(Error::Conflict);
                }
                PeerMessage::decode_with_profile(&p.bytes[..s.len], f.af)?;
            }
        }
        let serial = self.serial()?;
        for p in &mut *self.store.packets {
            if let Some(s) = p.state
                && s.flow == r
                && matches!(s.kind, PacketKind::Peer)
            {
                let family = match PeerMessage::decode_with_profile(&p.bytes[..s.len], f.af)? {
                    PeerMessage::TcpInternet { destination, .. }
                    | PeerMessage::IcmpInternet { destination, .. } => Some(destination.family()),
                    PeerMessage::UdpInternet { address, .. } => Some(address.family()),
                    PeerMessage::IcmpService { af, .. } => Some(f.af.family(af)?),
                    _ => None,
                };
                if let Some(family) = family {
                    p.bytes[4..8].copy_from_slice(&af.value(family).to_be_bytes())
                }
            }
        }
        let f = self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        f.af = af;
        f.open = None;
        f.source = Some(serial);
        f.phase = Phase::Ready;
        f.failure = None;
        Ok(Peer {
            flow: self.flow(r),
            serial,
            identity: actual_peer,
        })
    }
}

impl<'id, 'store, 'bytes> Engine<'id, 'store, 'bytes> {
    fn receive_inner(
        &mut self,
        peer: Peer<'id>,
        r: Reference,
        bytes: &[u8],
        activity: MonoInstant,
    ) -> Result<Delivery<'id>, Error> {
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if f.phase != Phase::Ready {
            return Err(Error::Closed);
        }
        if f.receive.is_some() {
            return Err(Error::WouldBlock);
        }
        let tun = self.current_tun()?;
        if bytes.len() > MAX_APPLICATION_MESSAGE_SIZE {
            return Err(Error::TooLarge);
        }
        let message = PeerMessage::decode_with_profile(bytes, f.af)?;
        let ip = if f.tuple.source.family() == Family::V4 {
            20
        } else {
            40
        };
        // Original reverse addresses/ports come from the bound flow, never from
        // an untrusted raw message/channel number or a newly reused lease row.
        let source = f.tuple.destination;
        let destination = f.tuple.source;
        let mut header = [0u8; 20];
        let mut quotation = [0u8; 48];
        let (protocol, head, tail) = match message {
            PeerMessage::UdpReply {
                source: source_port,
                destination: destination_port,
                payload,
            } => {
                if f.tuple.protocol != UDP {
                    return Err(Error::Malformed);
                }
                let a = if source_port == 0 {
                    f.tuple.destination_port
                } else {
                    source_port
                };
                let b = if destination_port == 0 {
                    f.tuple.source_port
                } else {
                    destination_port
                };
                header[..2].copy_from_slice(&a.to_be_bytes());
                header[2..4].copy_from_slice(&b.to_be_bytes());
                (UDP, &header[..8], payload)
            }
            PeerMessage::Tcp {
                to_exit: false,
                header: tcp,
                tail,
                ..
            } => {
                if f.tuple.protocol != TCP {
                    return Err(Error::Malformed);
                }
                header = tcp;
                header[..2].copy_from_slice(&f.tuple.destination_port.to_be_bytes());
                header[2..4].copy_from_slice(&f.tuple.source_port.to_be_bytes());
                (TCP, &header[..20], tail)
            }
            PeerMessage::IcmpReply {
                af,
                header: icmp,
                payload,
            } => {
                let family = f.af.family(af)?;
                let error = packet::icmp_error(family, icmp[0]);
                if error && !payload.is_empty() {
                    return Err(Error::Malformed);
                }
                if !error && !matches!(f.tuple.protocol, ICMP | ICMPV6) {
                    return Err(Error::Malformed);
                }
                let translated = packet::translate_icmp_header(family, source.family(), icmp)?;
                header[..8].copy_from_slice(&translated);
                let tail = if error {
                    let ports = matches!(f.tuple.protocol, TCP | UDP)
                        .then_some((f.tuple.source_port, f.tuple.destination_port));
                    let n = packet::quote(
                        f.tuple.source,
                        f.tuple.destination,
                        f.tuple.protocol,
                        ports,
                        &mut quotation,
                    )?;
                    &quotation[..n]
                } else {
                    payload
                };
                (
                    if source.family() == Family::V4 {
                        ICMP
                    } else {
                        ICMPV6
                    },
                    &header[..8],
                    tail,
                )
            }
            _ => return Err(Error::Unsupported),
        };
        let length = ip + head.len() + tail.len();
        if length > self.limits.packet_bytes {
            return Err(Error::TooLarge);
        }
        let row = self.packet_slot(length)?;
        self.preflight(2)?;
        let len = packet::build_parts(
            source,
            destination,
            protocol,
            head,
            tail,
            self.store.packets[row].bytes,
        )?;
        let serial = self.serial()?;
        let delivery = self.serial()?;
        let reference = Reference { row, serial };
        self.store.packets[row].state = Some(PacketState {
            serial,
            flow: r,
            kind: PacketKind::Tun {
                tun: tun.serial,
                delivery,
                credited: false,
            },
            len,
            status: Outcome::Buffered,
            attempt: None,
            bound: Some(peer.serial),
        });
        let f = self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        f.receive = Some((delivery, reference));
        f.used = activity;
        Ok(Delivery {
            peer,
            serial: delivery,
            buffer: Buffer(self.handle(reference)),
        })
    }
    /// Consume one original actual CADET message into bounded shared raw-TUN
    /// output. Capacity/WouldBlock retains caller input with no ACK/state commit.
    /// Permanent malformed/directional failures request real channel retirement.
    /// Activity belongs to the same native epoch as forward_tun and expire.
    pub fn receive_peer(
        &mut self,
        peer: Peer<'id>,
        bytes: &[u8],
        activity: MonoInstant,
    ) -> Result<Delivery<'id>, Error> {
        let r = self.peer_ref(peer)?;
        self.observe_activity(activity)?;
        match self.receive_inner(peer, r, bytes, activity) {
            Ok(d) => Ok(d),
            Err(e) => {
                if !matches!(e, Error::Capacity | Error::WouldBlock | Error::Closed) {
                    self.close_flow(peer.flow, e)?;
                }
                Err(e)
            }
        }
    }
    /// Whether this original processing token may grant real CADET receive_done.
    /// Only actual whole TUN writing qualifies; queueing/exposure is insufficient.
    pub fn delivery_ready(&self, delivery: Delivery<'id>) -> Result<bool, Error> {
        let r = self.peer_ref(delivery.peer)?;
        let b = self.buffer_ref(delivery.buffer)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        let p = self.store.packets[b.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        if f.receive != Some((delivery.serial, b)) || p.flow != r {
            return Err(Error::StaleGeneration);
        }
        Ok(p.status == Outcome::Written
            && matches!(p.kind,PacketKind::Tun{delivery:serial,credited:false,..}if serial==delivery.serial))
    }
    /// Original processing permission eligible after real TUN writing.
    pub fn receive_ready(&self, peer: Peer<'id>) -> Result<Option<Delivery<'id>>, Error> {
        let r = self.peer_ref(peer)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        let Some((serial, b)) = f.receive else {
            return Ok(None);
        };
        let d = Delivery {
            peer,
            serial,
            buffer: Buffer(self.handle(b)),
        };
        Ok(self.delivery_ready(d)?.then_some(d))
    }
    /// Fairly offer one actual discovery job without hidden resolver/network work.
    pub fn next_discovery(&mut self) -> Result<Option<DiscoveryRequest<'id>>, Error> {
        for n in 0..self.store.flows.len() {
            let row = (self.flow_cursor + n) % self.store.flows.len();
            if let Some(f) = self.store.flows[row].state
                && f.phase == Phase::Discovering
                && f.discovery.is_none_or(|w| !w.queued && !w.revoked)
            {
                self.flow_cursor = (row + 1) % self.store.flows.len();
                return self
                    .discovery_request(self.flow(Reference {
                        row,
                        serial: f.serial,
                    }))
                    .map(Some);
            }
        }
        Ok(None)
    }
    /// Fairly offer one original native CADET open after real policy selection.
    pub fn next_open(&mut self) -> Result<Option<OpenRequest<'id>>, Error> {
        for n in 0..self.store.flows.len() {
            let row = (self.flow_cursor + n) % self.store.flows.len();
            if let Some(f) = self.store.flows[row].state
                && !f.peer_ended
                && matches!(f.phase, Phase::NeedOpen | Phase::Opening)
                && f.open.is_none_or(|w| !w.queued && !w.revoked)
            {
                self.flow_cursor = (row + 1) % self.store.flows.len();
                return self
                    .open_request(self.flow(Reference {
                        row,
                        serial: f.serial,
                    }))
                    .map(Some);
            }
        }
        Ok(None)
    }
    /// Retained actual end-to-end sources, including original close/drain debt.
    pub fn peers(&self) -> impl Iterator<Item = Peer<'id>> + '_ {
        self.store.flows.iter().enumerate().filter_map(|(row, f)| {
            f.state.filter(|f| f.source.is_some()).and_then(|f| {
                self.peer(Reference {
                    row,
                    serial: f.serial,
                })
                .ok()
            })
        })
    }
}
