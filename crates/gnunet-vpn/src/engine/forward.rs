//! Actual raw-IP↔official EXIT conversion; native source/queue effects stay explicit.
use super::*;
use crate::packet::{ICMP, ICMPV6, Packet, TCP, UDP};
use gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE;

impl FlowRoute {
    fn from_lease(target: Target, tuple: &Tuple) -> Result<Self, Error> {
        Ok(match target {
            Target::Service { peer, descriptor } => Self::Service { peer, descriptor },
            Target::Internet(destination) => Self::Internet(InternetRoute {
                destination,
                transport: match tuple.protocol {
                    TCP => InternetTransport::Tcp(tuple.destination_port),
                    UDP => InternetTransport::Udp(tuple.destination_port),
                    ICMP | ICMPV6 => InternetTransport::Icmp,
                    _ => return Err(Error::Unsupported),
                },
            }),
        })
    }
}

impl InternetRoute {
    fn discovery_transport(self) -> (u8, u16) {
        match self.transport {
            InternetTransport::Tcp(port) => (TCP, port),
            InternetTransport::Udp(port) => (UDP, port),
            InternetTransport::Icmp => (
                match self.destination.family() {
                    Family::V4 => ICMP,
                    Family::V6 => ICMPV6,
                },
                0,
            ),
        }
    }
}

fn outgoing<'a>(
    p: Packet<'a>,
    tuple: &Tuple,
    route: FlowRoute,
    first: bool,
) -> Result<PeerMessage<'a>, Error> {
    let b = p.segment();
    Ok(match p.protocol() {
        UDP => {
            let source = tuple.source_port;
            let source = if source < 32000 { source } else { 0 };
            let payload = &b[8..];
            match route {
                FlowRoute::Service { .. } => PeerMessage::UdpService {
                    source,
                    destination: tuple.destination_port,
                    payload,
                },
                FlowRoute::Internet(InternetRoute {
                    destination: address,
                    transport: InternetTransport::Udp(destination),
                }) => PeerMessage::UdpInternet {
                    address,
                    source,
                    destination,
                    payload,
                },
                FlowRoute::Internet(_) => return Err(Error::Conflict),
            }
        }
        TCP => {
            let header = b[..20].try_into().map_err(|_| Error::Truncated)?;
            let tail = &b[20..];
            if first {
                match route {
                    FlowRoute::Service { .. } => PeerMessage::TcpService {
                        reserved: 0,
                        header,
                        tail,
                    },
                    FlowRoute::Internet(InternetRoute {
                        destination,
                        transport: InternetTransport::Tcp(_),
                    }) => PeerMessage::TcpInternet {
                        destination,
                        header,
                        tail,
                    },
                    FlowRoute::Internet(_) => return Err(Error::Conflict),
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
            let to = match route {
                FlowRoute::Service { .. } => from,
                FlowRoute::Internet(InternetRoute {
                    destination,
                    transport: InternetTransport::Icmp,
                }) => destination.family(),
                FlowRoute::Internet(_) => return Err(Error::Conflict),
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
            match route {
                FlowRoute::Service { .. } => PeerMessage::IcmpService {
                    af: AfProfile::LINUX.value(from),
                    header,
                    payload,
                },
                FlowRoute::Internet(route) => PeerMessage::IcmpInternet {
                    destination: route.destination,
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
        self.forward_tun_with_policy(tun, bytes, absolute, activity, |_, _, _| Ok(()))
    }

    /// Retain a raw TUN packet only if the caller admits its checked packet,
    /// tuple and original target. The target comes from the existing flow, even after
    /// lease expiry, or from the unexpired lease for a new tuple.
    /// A policy error leaves flow activity, leases and packet storage unchanged;
    /// the owner still observes the supplied native clock sample.
    pub fn forward_tun_with_policy(
        &mut self,
        tun: Tun<'id>,
        bytes: &[u8],
        absolute: AbsoluteTime,
        activity: MonoInstant,
        admit: impl FnOnce(Packet<'_>, &Tuple, Target) -> Result<(), Error>,
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
        let existing = self.store.flows.iter().enumerate().find_map(|(row, slot)| {
            slot.state
                .as_ref()
                .filter(|f| f.tuple == tuple)
                .map(|f| (row, f))
        });
        let (route, first) = if let Some((_, f)) = existing {
            if f.peer_ended {
                return Err(Error::Closed);
            }
            if f.phase == Phase::Closing {
                return Err(Error::WouldBlock);
            }
            (f.route, !f.start_encoded)
        } else {
            let lease = self
                .store
                .leases
                .iter()
                .filter_map(|l| l.state)
                .find(|l| l.address == tuple.destination && l.routable(absolute))
                .ok_or(Error::NotFound)?;
            (FlowRoute::from_lease(lease.target, &tuple)?, true)
        };
        admit(p, &tuple, route.target())?;
        let row = match existing {
            Some((row, _)) => row,
            None => self
                .store
                .flows
                .iter()
                .position(|f| f.state.is_none())
                .ok_or(Error::Capacity)?,
        };
        let message = outgoing(p, &tuple, route, first)?;
        let wire_family = match message {
            PeerMessage::TcpInternet { destination, .. }
            | PeerMessage::IcmpInternet { destination, .. } => Some(destination.family()),
            PeerMessage::UdpInternet { address, .. } => Some(address.family()),
            PeerMessage::IcmpService { af, .. } => Some(AfProfile::LINUX.family(af)?),
            _ => None,
        };
        let len = message.encoded_len()?;
        if len > MAX_APPLICATION_MESSAGE_SIZE {
            return Err(Error::TooLarge);
        }
        let slot = self.packet_slot(len)?;
        let new_flow = existing.is_none();
        self.preflight(if new_flow { 2 } else { 1 })?;
        // The provisional AF word is private. Preparation writes the bound
        // endpoint's representation before any caller can read these bytes.
        message.encode_with_profile(self.store.packets[slot].bytes, AfProfile::LINUX)?;
        let serial = match existing {
            Some((_, f)) => f.serial,
            None => self.serial()?,
        };
        let flow = Reference { row, serial };
        if new_flow {
            let (peer, phase) = match route {
                FlowRoute::Service { peer, .. } => (FlowPeer::Selected(peer), Phase::NeedOpen),
                FlowRoute::Internet(_) => (FlowPeer::Unselected, Phase::Discovering),
            };
            self.store.flows[row].state = Some(FlowState {
                serial,
                tuple,
                route,
                phase,
                peer,
                peer_ended: false,
                discovery: None,
                open: None,
                start_encoded: true,
                pending: None,
                receive: None,
                used: activity,
                failure: None,
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
            kind: PacketKind::Peer { wire_family },
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
        let FlowRoute::Internet(route) = f.route else {
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
        let (protocol, port) = route.discovery_transport();
        Ok(DiscoveryRequest {
            discovery: Discovery {
                flow,
                serial: w.serial,
            },
            destination: route.destination,
            protocol,
            port,
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
        f.peer = FlowPeer::Selected(peer);
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
        let FlowPeer::Selected(peer) = f.peer else {
            return Err(Error::NotReady);
        };
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
        let port = match f.route {
            FlowRoute::Service { descriptor, .. } => {
                service_port(descriptor, f.tuple.destination_port)
            }
            FlowRoute::Internet(route) => gateway_port(route.destination.family()),
        };
        Ok(OpenRequest {
            open: Open {
                flow,
                serial: w.serial,
            },
            peer,
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
    /// The transmit profile belongs to this peer source for its entire lifetime.
    pub fn bind_peer(
        &mut self,
        open: Open<'id>,
        actual_peer: [u8; 32],
        transmit_af: AfProfile,
    ) -> Result<Peer<'id>, Error> {
        transmit_af.validate()?;
        let r = self.open_ref(open)?;
        let f = self.store.flows[r.row]
            .state
            .ok_or(Error::StaleGeneration)?;
        let w = f.open.ok_or(Error::StaleGeneration)?;
        if f.peer_ended || f.phase != Phase::Opening || w.revoked || !w.queued {
            return Err(Error::Closed);
        }
        if !matches!(f.peer, FlowPeer::Selected(expected) if expected == actual_peer) {
            return Err(Error::Authentication);
        }
        let serial = self.serial()?;
        let f = self.store.flows[r.row]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        f.open = None;
        let source = PeerSource {
            identity: actual_peer,
            serial,
            transmit_af,
        };
        f.peer = FlowPeer::Bound(source);
        f.phase = Phase::Ready;
        f.failure = None;
        Ok(self.peer(r, &source))
    }
}

impl<'id, 'store, 'bytes> Engine<'id, 'store, 'bytes> {
    fn receive_inner(
        &mut self,
        peer: Peer<'id>,
        r: Reference,
        bytes: &[u8],
        activity: MonoInstant,
        admit: impl FnOnce(PeerMessage<'_>, &Tuple) -> Result<(), Error>,
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
        // The accepted reply frames have no variable-length IP address field.
        let message = PeerMessage::decode_with_profile(bytes, AfProfile::LINUX)?;
        admit(message, &f.tuple)?;
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
                let family = if let Some(family) = Family::from_official_af(af) {
                    family
                } else {
                    f.peer
                        .bound()
                        .ok_or(Error::NotReady)?
                        .transmit_af
                        .family(af)?
                };
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
        self.receive_peer_with_policy(peer, bytes, activity, |_, _| Ok(()))
    }

    /// Apply a native receive policy to the decoded message and the original
    /// bound tuple before allocating or writing a reply. Policy errors follow
    /// the same retirement and retry rules as other receive failures.
    pub fn receive_peer_with_policy(
        &mut self,
        peer: Peer<'id>,
        bytes: &[u8],
        activity: MonoInstant,
        admit: impl FnOnce(PeerMessage<'_>, &Tuple) -> Result<(), Error>,
    ) -> Result<Delivery<'id>, Error> {
        let r = self.peer_ref(peer)?;
        self.observe_activity(activity)?;
        match self.receive_inner(peer, r, bytes, activity, admit) {
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
            let f = f.state.as_ref()?;
            let source = f.peer.bound()?;
            Some(self.peer(
                Reference {
                    row,
                    serial: f.serial,
                },
                source,
            ))
        })
    }
}
