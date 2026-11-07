//! Full Elligator initial packet authentication. Replay/admission remain explicit.
use crate::{
    Identity, PeerId, identity,
    wire::{self, Confirmation},
};
use core::num::NonZeroUsize;
use gnunet_crypto::Entropy;
use gnunet_session_crypto::{
    Prk,
    elligator::{self, Representative},
    exchange::EcdhePublic,
    session,
    udp::{DatagramKey, InitialView},
};
use gnunet_types::Error;
use zeroize::Zeroize;
/// Fresh master retained for a packet; no implicit sequence/window authority.
pub struct InitialSecret {
    pub(crate) master: Prk,
    /// Exact public acknowledgement marker for this master.
    pub cmac: [u8; 64],
    /// Actual Elligator representative in the signed transcript.
    pub encapsulation: [u8; 32],
}
impl InitialSecret {
    /// Transfer the secret owner to an explicit session/admission owner. No key
    /// bytes or remote credit are exported; nonce/replay policy remains required.
    #[must_use]
    pub fn into_master(self) -> Prk {
        self.master
    }
}
/// Encrypt one already framed/padded body at serial0 after the full confirmation.
/// No state is committed by this function. The returned owner must be installed
/// before subsequent ACK input; packet storage/nonce lifecycle belong to sender.
pub fn seal(
    identity: &Identity,
    target: PeerId,
    monotonic: u64,
    body: &[u8],
    out: &mut [u8],
    entropy: &mut impl Entropy,
    attempts: NonZeroUsize,
) -> Result<(usize, InitialSecret), Error> {
    wire::Body::decode(body)?;
    let needed = wire::PREFIX
        .checked_add(wire::CONFIRMATION)
        .and_then(|n| n.checked_add(body.len()))
        .ok_or(Error::Overflow)?;
    if out.len() < needed {
        return Err(Error::Capacity);
    }
    gnunet_session_crypto::gcm::validate_lengths(
        u64::try_from(needed - wire::PREFIX).map_err(|_| Error::Overflow)?,
        0,
    )?;
    let recipient = EcdhePublic::from_edwards(&target)?;
    let (enc, master) = elligator::encapsulate_random(recipient, entropy, attempts)?;
    let region = wire::handshake_region(identity.peer(), target, enc.as_bytes(), monotonic);
    let signature = identity.sign(33, &region)?;
    let cmac = session::udp_cmac(&master)?;
    let key = DatagramKey::derive(&master, 0)?;
    Confirmation {
        sender: identity.peer(),
        signature,
        monotonic,
    }
    .encode(&mut out[wire::PREFIX..])?;
    out[wire::PREFIX + wire::CONFIRMATION..needed].copy_from_slice(body);
    let tag = key.seal_body(&mut out[wire::PREFIX..needed])?;
    out[..32].copy_from_slice(enc.as_bytes());
    out[32..wire::PREFIX].copy_from_slice(&tag);
    Ok((
        needed,
        InitialSecret {
            master,
            cmac,
            encapsulation: *enc.as_bytes(),
        },
    ))
}
/// Valid signature/AEAD plus owned secret, before replay/durable admission.
/// Payload scratch erases on every return/drop path and cannot outlive this guard.
pub struct Opened<'a> {
    /// Diagnostic copy of the authenticated confirmation. Changing this public
    /// copy does not change the immutable sender/receiver/timestamp binding used
    /// by the receive owner for admission.
    pub confirmation: Confirmation,
    authenticated_sender: PeerId,
    authenticated_receiver: PeerId,
    authenticated_monotonic: u64,
    packet_bytes: usize,
    pub(crate) secret: Option<InitialSecret>,
    plaintext: &'a mut [u8],
}
impl Opened<'_> {
    /// Sender from the verified transcript. The public confirmation is only a
    /// diagnostic copy; changing it cannot change this immutable binding.
    #[must_use]
    pub const fn sender(&self) -> PeerId {
        self.authenticated_sender
    }
    /// Receiver bound by both the actual KEM owner and verified signature.
    #[must_use]
    pub const fn receiver(&self) -> PeerId {
        self.authenticated_receiver
    }
    /// Signed original timestamp, before any durable replay admission.
    #[must_use]
    pub const fn monotonic(&self) -> u64 {
        self.authenticated_monotonic
    }
    /// Actual original datagram extent, not a caller-supplied accounting value.
    #[must_use]
    pub const fn packet_bytes(&self) -> usize {
        self.packet_bytes
    }
    /// Exact following payload/control and padding, still before replay admission.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.plaintext[wire::CONFIRMATION..]
    }
    /// Master acknowledgement marker, not proof of durable replay admission.
    #[must_use]
    pub fn cmac(&self) -> Option<&[u8; 64]> {
        self.secret.as_ref().map(|s| &s.cmac)
    }
    /// Transfer the authenticated secret after the caller's replay/durable gate.
    /// Dropping this guard still erases its complete used plaintext range.
    pub fn into_secret(mut self) -> Result<InitialSecret, Error> {
        self.secret.take().ok_or(Error::Stale)
    }
}
impl Drop for Opened<'_> {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}
/// Authenticate the exact receiver/enc/time transcript before exposing sender.
/// Basic length/resource refusals leave scratch unchanged. Authentication or body
/// failure erases only the used plaintext range; unrelated tail is untouched.
pub fn open<'a>(
    identity: &Identity,
    packet: &[u8],
    scratch: &'a mut [u8],
) -> Result<Opened<'a>, Error> {
    let view = InitialView::parse(packet)?;
    let n = view.ciphertext.len();
    if scratch.len() < n {
        return Err(Error::Capacity);
    }
    let master = match identity.initial(Representative::from_bytes(*view.enc)) {
        Ok(m) => m,
        Err(e) => {
            scratch[..n].zeroize();
            return Err(e);
        }
    };
    let cmac = session::udp_cmac(&master)?;
    let key = DatagramKey::derive(&master, 0)?;
    key.open_initial_payload(packet, &mut scratch[..n])?;
    let receiver = identity.peer();
    let checked = (|| {
        let confirmation = Confirmation::decode(&scratch[..n])?;
        let region = wire::handshake_region(
            confirmation.sender,
            receiver,
            view.enc,
            confirmation.monotonic,
        );
        identity::verify(confirmation.sender, 33, &region, confirmation.signature)?;
        wire::Body::decode(&scratch[wire::CONFIRMATION..n])?;
        Ok::<_, Error>(confirmation)
    })();
    match checked {
        Ok(confirmation) => Ok(Opened {
            authenticated_sender: confirmation.sender,
            authenticated_receiver: receiver,
            authenticated_monotonic: confirmation.monotonic,
            packet_bytes: packet.len(),
            confirmation,
            secret: Some(InitialSecret {
                master,
                cmac,
                encapsulation: *view.enc,
            }),
            plaintext: &mut scratch[..n],
        }),
        Err(error) => {
            scratch[..n].zeroize();
            Err(error)
        }
    }
}
