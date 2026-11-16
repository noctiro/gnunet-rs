//! Authentication and an exclusive, cancellable BOX commit plan.
use super::*;
use gnunet_session_crypto::udp::{BoxView, DatagramKey};

/// Fully authenticated BOX and reserved effects, before KID/window admission.
/// Holds the exclusive original receiver borrow: no other receive, key pruning or
/// close can invalidate this plan. Dropping it preserves the original KID and
/// erases owned application bytes and any newly prepared master. Scratch has
/// already been erased; this guard never lends payload or ACKs before commit.
#[must_use = "Commit after external admission succeeds, or drop to refuse without consuming the KID"]
pub struct PreparedBox<'receiver> {
    receiver: &'receiver mut Receiver,
    window: usize,
    slot: usize,
    bytes: u64,
    retire: bool,
    victims: [Option<usize>; 2],
    refill: Option<Refill>,
    rekey: Option<Window>,
    received: Received,
}
impl core::fmt::Debug for PreparedBox<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedBox").finish_non_exhaustive()
    }
}
impl PreparedBox<'_> {
    /// Consume the original KID and publish the already prepared ACK/payload.
    /// All parsing, crypto, allocations and victim/refill planning succeeded
    /// before this guard was returned; commit performs no fallible work.
    #[must_use]
    pub fn commit(self) -> Received {
        let Self {
            receiver,
            window,
            slot,
            bytes,
            retire,
            victims,
            refill,
            rekey,
            mut received,
        } = self;
        receiver.windows[window].keys[slot].used = true;
        receiver.windows[window].bytes = bytes;
        if let Some(refill) = refill {
            receiver.windows[window].refill(refill);
            received.acknowledgements[0] = Some(receiver.windows[window].ack());
        }
        if retire {
            drop(receiver.windows.remove(window));
        } else {
            receiver.remove(victims);
        }
        if let Some(window) = rekey {
            receiver.windows.push_back(window);
        }
        received
    }
}

impl Receiver {
    /// Authenticate an original cached KID before replay/byte/window commit.
    /// Unknown or consumed IDs are explicit; forged tags leave the valid original
    /// KID available. Only exact used plaintext scratch is erased on every path.
    pub fn boxed(
        &mut self,
        identity: &Identity,
        packet: &[u8],
        scratch: &mut [u8],
    ) -> Result<Received, Error> {
        Ok(self.prepare_boxed(identity, packet, scratch)?.commit())
    }
    /// Authenticate and reserve every BOX receive effect without consuming its
    /// KID. An external endpoint/admission provider can refuse after authentication
    /// by dropping the exclusive guard. No plaintext scratch is retained.
    pub fn prepare_boxed<'receiver>(
        &'receiver mut self,
        identity: &Identity,
        packet: &[u8],
        scratch: &mut [u8],
    ) -> Result<PreparedBox<'receiver>, Error> {
        self.check(identity)?;
        if packet.len() > MAX_PACKET_BYTES {
            return Err(Error::TooLarge);
        }
        let view = BoxView::parse(packet)?;
        if scratch.len() < view.ciphertext.len() {
            return Err(Error::Capacity);
        }
        let mut matching = false;
        let mut unused = false;
        let mut selected = None;
        // A public selector is not an authenticator. Try each original unused
        // candidate before rejecting a collision; no candidate is consumed by a
        // bad tag, and a used earlier candidate cannot hide a live later one.
        'windows: for (window_index, window) in self.windows.iter().enumerate() {
            for (slot_index, slot) in window.keys.iter().enumerate() {
                if slot.kid != *view.kid {
                    continue;
                }
                matching = true;
                if slot.used {
                    continue;
                }
                unused = true;
                let key = DatagramKey::derive(&window.master, slot.sequence)?;
                match key.open_box(packet, scratch) {
                    Ok(n) => {
                        selected = Some((window_index, slot_index, n));
                        break 'windows;
                    }
                    Err(Error::Authentication) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        let Some((window, slot, n)) = selected else {
            return Err(if unused {
                Error::Authentication
            } else if matching {
                Error::Replay
            } else {
                Error::NotFound
            });
        };
        // Borrowed scratch is never retained after this closure, even if payload,
        // rekey preflight or subsequent parsing refuses an authenticated packet.
        let prepared = (|| {
            let bytes = self.windows[window]
                .bytes
                .checked_add(packet.len() as u64)
                .ok_or(Error::Overflow)?;
            let retire = bytes >= self.policy.maximum_secret_bytes;
            let body = Body::decode(&scratch[..n])?;
            let message = payload(&body)?;
            let incoming_ack = match body.control {
                Some(Control::Ack(ack)) => Some(ack),
                _ => None,
            };
            let RekeyPlan {
                window: rekey,
                ack: rekey_ack,
                ..
            } = self.rekey(identity, &body)?;
            // A retiring original window itself makes room for at most one
            // newly authenticated rekey. It must not receive fresh KID credit.
            let victims = if retire {
                [None; 2]
            } else {
                self.victims(usize::from(rekey.is_some()), Some(window))?
            };
            let refill = if retire {
                None
            } else {
                self.windows[window].plan_refill(1)?
            };
            let rekey_ack =
                rekey_ack.filter(|ack| !retire || ack.cmac != self.windows[window].cmac);
            Ok::<_, Error>((
                message,
                incoming_ack,
                rekey,
                rekey_ack,
                victims,
                refill,
                bytes,
                retire,
            ))
        })();
        use zeroize::Zeroize as _;
        scratch[..n].zeroize();
        let (message, incoming_ack, rekey, rekey_ack, victims, refill, bytes, retire) = prepared?;
        Ok(PreparedBox {
            receiver: self,
            window,
            slot,
            bytes,
            retire,
            victims,
            refill,
            rekey,
            received: Received {
                message,
                incoming_ack,
                acknowledgements: [None, rekey_ack],
            },
        })
    }
}
