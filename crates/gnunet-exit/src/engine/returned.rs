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
        let returned = Returned::parse(bytes)?;
        let index = self.lookup(returned.tuple())?;
        let r = self.flows[index].as_ref().ok_or(Error::Stale)?;
        self.valid_source(&r.source)?;
        let flow = r.flow.clone();
        let profile = r.af.reply();
        let message = returned.message(profile);
        self.queue_peer(&flow, profile, message)?;
        let r = self.flows[index].as_mut().ok_or(Error::Stale)?;
        r.last = now;
        r.idle = now.checked_add(self.limits.idle).ok_or(Error::Overflow)?;
        if let PeerMessage::Tcp { header, .. } = message {
            let flags = header[13];
            let ack = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
            r.tcp.established |= r.tcp.syn && flags & 0x12 == 0x12 && r.syn_end == Some(ack);
            r.tcp.remote_fin |= flags & 1 != 0;
            r.tcp.reset |= flags & 4 != 0;
        }
        Ok(flow)
    }
}
