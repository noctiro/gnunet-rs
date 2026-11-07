//! Official purpose-6 signed DHT paths, independent of network/session authority.
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, hash512};
use gnunet_types::Error;
use gnunet_wire::official::dht::{PATH_ELEMENT_LEN, Path};
/// Official GNUNET_SIGNATURE_PURPOSE_DHT_HOP.
pub const PURPOSE: u32 = 6;
/// Exact signed bytes, including purpose header.
pub const SIGNED_LEN: usize = 144;
/// Encode the exact original signing region. This does not authorize a signer.
#[must_use]
pub fn region(
    payload_hash: &[u8; 64],
    expiration: u64,
    predecessor: &[u8; 32],
    successor: &[u8; 32],
) -> [u8; SIGNED_LEN] {
    let mut bytes = [0; SIGNED_LEN];
    bytes[..4].copy_from_slice(&(SIGNED_LEN as u32).to_be_bytes());
    bytes[4..8].copy_from_slice(&PURPOSE.to_be_bytes());
    bytes[8..16].copy_from_slice(&expiration.to_be_bytes());
    bytes[16..80].copy_from_slice(payload_hash);
    bytes[80..112].copy_from_slice(predecessor);
    bytes[112..].copy_from_slice(successor);
    bytes
}
/// An entry rejected during strict reverse path verification. The original
/// reason is retained: only Authentication identifies an invalid recorded
/// signature eligible for suffix recovery, never a provider/resource refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Zero-based rejected entry across the original PUT then GET paths.
    pub index: usize,
    /// Actual primitive/region error at that exact entry.
    pub reason: Error,
}
/// Verify recorded entries in reverse order, exactly binding payload hash,
/// expiration, original/truncated predecessor and final recipient. An entry's
/// identity is its signer, despite the legacy C field name `pred`.
/// Empty paths are valid empty evidence; no authenticated origin is implied.
/// This strict API rejects the entire path on any error and retains its reason;
/// it does not apply the routed-message suffix recovery policy.
pub fn verify(
    payload: &[u8],
    expiration: u64,
    truncated: Option<&[u8; 32]>,
    put: Path<'_>,
    get: Path<'_>,
    recipient: &[u8; 32],
) -> Result<(), Failure> {
    verify_recorded(
        &hash512(payload),
        expiration,
        truncated,
        put,
        get,
        recipient,
    )
}
fn verify_recorded(
    hash: &[u8; 64],
    expiration: u64,
    truncated: Option<&[u8; 32]>,
    put: Path<'_>,
    get: Path<'_>,
    recipient: &[u8; 32],
) -> Result<(), Failure> {
    let n = put.len() + get.len();
    for index in (0..n).rev() {
        let (signature, signer) = entry(put, get, index);
        let predecessor = if index == 0 {
            truncated.copied().unwrap_or([0; 32])
        } else {
            entry(put, get, index - 1).1
        };
        let successor = if index + 1 == n {
            *recipient
        } else {
            entry(put, get, index + 1).1
        };
        if let Err(reason) = EddsaPublicKey::from_bytes(signer).verify(
            PURPOSE,
            &region(hash, expiration, &predecessor, &successor),
            &EddsaSignature::from_bytes(signature),
        ) {
            return Err(Failure { index, reason });
        }
    }
    Ok(())
}
/// Verify the separate last-sender signature and every preceding entry before
/// accepting an incoming tracked message. The actual underlay sender, recipient,
/// and expiry must be supplied by the service, not extracted as authority from
/// unsigned metadata. Expiration equal to `now` remains valid in GNUnet.
/// This strict proof API never truncates a path; every original cause propagates.
#[expect(
    clippy::too_many_arguments,
    reason = "Original sender, recipient, clock and each independently borrowed wire component remain explicit verification inputs."
)]
pub fn verify_incoming(
    payload: &[u8],
    expiration: u64,
    now: u64,
    truncated: Option<&[u8; 32]>,
    put: Path<'_>,
    get: Path<'_>,
    sender: &[u8; 32],
    recipient: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), Error> {
    if expiration < now {
        return Err(Error::Stale);
    }
    let hash = hash512(payload);
    verify_sender(
        &hash, expiration, truncated, put, get, sender, recipient, signature,
    )?;
    verify_recorded(&hash, expiration, truncated, put, get, sender)
        .map_err(|failure| failure.reason)
}
#[expect(
    clippy::too_many_arguments,
    reason = "Sender signature verification binds each original independently borrowed path and both actual peer identities"
)]
fn verify_sender(
    hash: &[u8; 64],
    expiration: u64,
    truncated: Option<&[u8; 32]>,
    put: Path<'_>,
    get: Path<'_>,
    sender: &[u8; 32],
    recipient: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), Error> {
    let n = put.len() + get.len();
    let predecessor = if n == 0 {
        truncated.copied().unwrap_or([0; 32])
    } else {
        entry(put, get, n - 1).1
    };
    EddsaPublicKey::from_bytes(*sender).verify(
        PURPOSE,
        &region(hash, expiration, &predecessor, recipient),
        &EddsaSignature::from_bytes(*signature),
    )
}
/// Original routed-message path selection after strict sender verification.
/// These borrowed bytes are metadata for the exact payload/expiry/peer inputs,
/// not reusable signing, source or remote-delivery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedPath<'a> {
    /// Original boundary, or the exact signer of the last removed element.
    pub truncated: Option<[u8; 32]>,
    /// Retained original PUT elements, without re-signing or rewriting them.
    pub put: Path<'a>,
    /// Retained original GET elements; failure here removes every PUT element.
    pub get: Path<'a>,
    /// Number of original recorded elements removed; zero means unchanged.
    pub removed: usize,
}
/// Receive a tracked PUT/RESULT path using the protocol's suffix recovery rule.
/// The separate actual sender signature is verified first and is never salvaged.
/// Only an earlier recorded Authentication failure can discard that element and
/// its prefix. The selected suffix and original sender signature are reverified
/// with the exact new boundary; all other errors propagate unchanged. The caller
/// sets TRUNCATED when `removed != 0` and then appends the original sender's
/// signature/key to its appropriate path, retaining the original peer identity.
#[expect(
    clippy::too_many_arguments,
    reason = "Actual sender/recipient, original time and immutable PUT/GET/payload/signature components must remain explicit"
)]
pub fn receive_incoming<'a>(
    payload: &[u8],
    expiration: u64,
    now: u64,
    truncated: Option<&[u8; 32]>,
    put: Path<'a>,
    get: Path<'a>,
    sender: &[u8; 32],
    recipient: &[u8; 32],
    signature: &[u8; 64],
) -> Result<ReceivedPath<'a>, Error> {
    if expiration < now {
        return Err(Error::Stale);
    }
    let hash = hash512(payload);
    verify_sender(
        &hash, expiration, truncated, put, get, sender, recipient, signature,
    )?;
    let failure = match verify_recorded(&hash, expiration, truncated, put, get, sender) {
        Ok(()) => {
            return Ok(ReceivedPath {
                truncated: truncated.copied(),
                put,
                get,
                removed: 0,
            });
        }
        Err(failure) => failure,
    };
    if failure.reason != Error::Authentication {
        return Err(failure.reason);
    }
    let selected = suffix(put, get, failure)?;
    verify_sender(
        &hash,
        expiration,
        Some(&selected.truncated),
        selected.put,
        selected.get,
        sender,
        recipient,
        signature,
    )?;
    verify_recorded(
        &hash,
        expiration,
        Some(&selected.truncated),
        selected.put,
        selected.get,
        sender,
    )
    .map_err(|failure| failure.reason)?;
    Ok(ReceivedPath {
        truncated: Some(selected.truncated),
        put: selected.put,
        get: selected.get,
        removed: failure.index.checked_add(1).ok_or(Error::Overflow)?,
    })
}
/// Validated suffix metadata following the last invalid recorded entry. Calling
/// this does not erase the failure: the service explicitly chooses salvage and
/// carries the removed signer's identity as the new truncation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Suffix<'a> {
    /// New boundary predecessor identity.
    pub truncated: [u8; 32],
    /// Remaining PUT path.
    pub put: Path<'a>,
    /// Remaining GET path.
    pub get: Path<'a>,
}
/// Retain only the verified suffix after a failure returned for these exact
/// paths. Non-Authentication reasons and out-of-range indexes fail. A Failure
/// value is diagnostic, not proof; the caller must rerun verification before
/// giving the suffix authority. `receive_incoming` performs that whole check.
pub fn suffix<'a>(put: Path<'a>, get: Path<'a>, failure: Failure) -> Result<Suffix<'a>, Error> {
    if failure.reason != Error::Authentication {
        return Err(failure.reason);
    }
    if failure.index >= put.len() + get.len() {
        return Err(Error::InvalidInput);
    }
    let truncated = entry(put, get, failure.index).1;
    let removed = failure.index + 1;
    let (put, get) = if removed <= put.len() {
        (
            Path::new(&put.as_bytes()[removed * PATH_ELEMENT_LEN..])?,
            get,
        )
    } else {
        (
            Path::empty(),
            Path::new(&get.as_bytes()[(removed - put.len()) * PATH_ELEMENT_LEN..])?,
        )
    };
    Ok(Suffix {
        truncated,
        put,
        get,
    })
}
fn entry(put: Path<'_>, get: Path<'_>, index: usize) -> ([u8; 64], [u8; 32]) {
    let (bytes, index) = if index < put.len() {
        (put.as_bytes(), index)
    } else {
        (get.as_bytes(), index - put.len())
    };
    let bytes = &bytes[index * PATH_ELEMENT_LEN..(index + 1) * PATH_ELEMENT_LEN];
    let mut signature = [0; 64];
    signature.copy_from_slice(&bytes[..64]);
    let mut identity = [0; 32];
    identity.copy_from_slice(&bytes[64..]);
    (signature, identity)
}
