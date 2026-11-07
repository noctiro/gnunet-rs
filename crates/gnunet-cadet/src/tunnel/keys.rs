//! Exact pinned CADET 3-DH and symmetric key schedule; internal erased owners.
use super::{Identity, Role};
use gnunet_crypto::hkdf_gnunet;
use gnunet_session_crypto::{
    exchange::{EcdhePublic, EcdheSecret},
    transcript::hmac512,
};
use gnunet_types::Error;
use zeroize::Zeroizing;

pub(super) type Secret = Zeroizing<[u8; 32]>;

// Cloning is private transactional staging. Every copy owns zeroizing storage;
// no private scalar is cloned or exported, and no public state clone exists.
#[derive(Clone)]
pub(super) struct Keys {
    pub root: Secret,
    pub send_header: Option<Secret>,
    pub receive_header: Option<Secret>,
    pub next_send_header: Secret,
    pub next_receive_header: Secret,
    pub send_chain: Option<Secret>,
    pub receive_chain: Option<Secret>,
}

pub(super) fn copy(key: &Secret) -> Secret {
    Zeroizing::new(**key)
}

fn part(bytes: &[u8], offset: usize) -> Secret {
    let mut output = Zeroizing::new([0; 32]);
    output.copy_from_slice(&bytes[offset..offset + 32]);
    output
}

pub(super) fn initial(
    role: Role,
    identity: &Identity,
    peer: &[u8; 32],
    ephemeral: &EcdheSecret,
    peer_ephemeral: EcdhePublic,
) -> Result<Keys, Error> {
    let identity_dh = identity
        .dh
        .exchange_hashed(peer_ephemeral)?
        .into_secret_bytes();
    initial_with_identity_hash(role, &identity_dh, peer, ephemeral, peer_ephemeral)
}

pub(super) fn initial_with_identity_hash(
    role: Role,
    identity_dh: &[u8; 64],
    peer: &[u8; 32],
    ephemeral: &EcdheSecret,
    peer_ephemeral: EcdhePublic,
) -> Result<Keys, Error> {
    if identity_dh.iter().all(|byte| *byte == 0) {
        return Err(Error::Authentication);
    }
    let ephemeral_identity_dh = ephemeral.exchange_edwards_hashed(peer)?.into_secret_bytes();
    let ephemeral_dh = ephemeral
        .exchange_hashed(peer_ephemeral)?
        .into_secret_bytes();
    let mut material = Zeroizing::new([0; 192]);
    match role {
        Role::Alice => {
            material[..64].copy_from_slice(identity_dh);
            material[64..128].copy_from_slice(ephemeral_identity_dh.as_ref());
        }
        Role::Betty => {
            material[..64].copy_from_slice(ephemeral_identity_dh.as_ref());
            material[64..128].copy_from_slice(identity_dh);
        }
    }
    material[128..].copy_from_slice(ephemeral_dh.as_ref());
    let mut output = Zeroizing::new([0; 160]);
    hkdf_gnunet(
        b"CADET Axolotl salt\0",
        material.as_ref(),
        &[],
        output.as_mut(),
    )?;
    Ok(match role {
        Role::Alice => Keys {
            root: part(output.as_ref(), 0),
            send_header: None,
            receive_header: Some(part(output.as_ref(), 32)),
            next_send_header: part(output.as_ref(), 64),
            next_receive_header: part(output.as_ref(), 96),
            send_chain: None,
            receive_chain: Some(part(output.as_ref(), 128)),
        },
        Role::Betty => Keys {
            root: part(output.as_ref(), 0),
            send_header: Some(part(output.as_ref(), 32)),
            receive_header: None,
            next_send_header: part(output.as_ref(), 96),
            next_receive_header: part(output.as_ref(), 64),
            send_chain: Some(part(output.as_ref(), 128)),
            receive_chain: None,
        },
    })
}

fn hmac_hash(key: &Secret, message: &[u8]) -> Result<Zeroizing<[u8; 64]>, Error> {
    let mut auth = Zeroizing::new([0; 64]);
    hkdf_gnunet(b"axolotl HMAC-HASH\0", key.as_ref(), &[], auth.as_mut())?;
    Ok(Zeroizing::new(hmac512(auth.as_ref(), &[message])))
}

fn derive(key: &Secret, message: &[u8]) -> Result<Secret, Error> {
    let hash = hmac_hash(key, message)?;
    let mut output = Zeroizing::new([0; 32]);
    hkdf_gnunet(b"axolotl derive key\0", hash.as_ref(), &[], output.as_mut())?;
    Ok(output)
}

pub(super) fn chain(key: &Secret) -> Result<(Secret, Secret), Error> {
    Ok((derive(key, b"0")?, derive(key, b"1")?))
}

pub(super) fn ratchet(
    root: &Secret,
    local: &EcdheSecret,
    remote: EcdhePublic,
) -> Result<(Secret, Secret, Secret), Error> {
    let dh = local.exchange_hashed(remote)?.into_secret_bytes();
    let hash = hmac_hash(root, dh.as_ref())?;
    let mut output = Zeroizing::new([0; 96]);
    hkdf_gnunet(b"axolotl ratchet\0", hash.as_ref(), &[], output.as_mut())?;
    Ok((
        part(output.as_ref(), 0),
        part(output.as_ref(), 32),
        part(output.as_ref(), 64),
    ))
}

pub(super) fn nonce(key: &Secret) -> Result<Zeroizing<[u8; 24]>, Error> {
    let mut output = Zeroizing::new([0; 24]);
    hkdf_gnunet(&[], key.as_ref(), &[], output.as_mut())?;
    Ok(output)
}
