use super::{Crypto, Dnskey, Rrset, Scratch, TrustedKeys, name_eq, verify_key};
use crate::{Error, MAX_WIRE_NAME_LENGTH, Name, Type};

/// Original DNSSEC trust anchor RDATA for a zone authenticated by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Anchor<'a> {
    /// DS RDATA matching the canonical owner and complete DNSKEY RDATA.
    Ds(&'a [u8]),
    /// DNSKEY RDATA matching a member of the apex DNSKEY RRset byte for byte.
    Dnskey(&'a [u8]),
}

/// Authenticate the apex DNSKEY RRset using authenticated DS records.
/// The matching key must validate a real signature of the complete RRset.
pub fn trust_dnskeys<'a>(
    zone: Name<'a>,
    ds: &[&[u8]],
    keys: Rrset<'a>,
    signatures: Rrset<'_>,
    now: u32,
    crypto: &impl Crypto,
    scratch: &mut Scratch<'_>,
) -> Result<TrustedKeys<'a>, Error> {
    trust(
        zone,
        ds.iter().copied().map(Anchor::Ds),
        keys,
        signatures,
        now,
        crypto,
        scratch,
    )
}

/// Authenticate the apex DNSKEY RRset using authenticated DS or DNSKEY records.
/// The caller binds every supplied anchor to this exact zone and limits trust
/// to the anchor's lifetime. An exact DNSKEY match and a matching DS digest
/// each authorize a candidate key to validate a signature on the whole RRset.
/// A supported SHA-2 DS suppresses SHA-1 DS selection. An explicitly trusted
/// DNSKEY remains independently eligible in a mixed set.
pub fn trust_dnskeys_with_anchors<'a>(
    zone: Name<'a>,
    anchors: &[Anchor<'_>],
    keys: Rrset<'a>,
    signatures: Rrset<'_>,
    now: u32,
    crypto: &impl Crypto,
    scratch: &mut Scratch<'_>,
) -> Result<TrustedKeys<'a>, Error> {
    trust(
        zone,
        anchors.iter().copied(),
        keys,
        signatures,
        now,
        crypto,
        scratch,
    )
}

fn trust<'a, 'anchor>(
    zone: Name<'a>,
    anchors: impl Iterator<Item = Anchor<'anchor>> + Clone,
    keys: Rrset<'a>,
    signatures: Rrset<'_>,
    now: u32,
    crypto: &impl Crypto,
    scratch: &mut Scratch<'_>,
) -> Result<TrustedKeys<'a>, Error> {
    if keys.kind != Type::DNSKEY.0 || !name_eq(keys.owner, zone) || anchors.clone().next().is_none()
    {
        return Err(Error::Authentication);
    }
    let strong_ds = prefer_strong_ds(anchors.clone(), crypto)?;
    let mut name = [0; MAX_WIRE_NAME_LENGTH];
    let canonical = &mut name[..zone.wire_len()];
    canonical.copy_from_slice(zone.wire());
    canonical.make_ascii_lowercase();
    let mut last = Error::Authentication;
    for raw in keys.records {
        let key = match Dnskey::parse(raw) {
            Ok(key) if key.usable() && crypto.supports_signature(key.algorithm) => key,
            _ => continue,
        };
        let exact = anchors
            .clone()
            .any(|anchor| matches!(anchor, Anchor::Dnskey(pin) if pin == *raw));
        if !exact
            && !matches_ds(
                anchors.clone(),
                key,
                canonical,
                strong_ds,
                crypto,
                &mut last,
            )?
        {
            continue;
        }
        match verify_key(zone, key, keys, signatures, now, crypto, scratch) {
            Ok(validated) => {
                return Ok(TrustedKeys {
                    zone,
                    set: keys,
                    verified_at: now,
                    ttl: validated.ttl(),
                });
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn prefer_strong_ds<'anchor>(
    anchors: impl Iterator<Item = Anchor<'anchor>>,
    crypto: &impl Crypto,
) -> Result<bool, Error> {
    let mut eligible = false;
    let mut last = Error::Unsupported;
    for anchor in anchors {
        match anchor {
            Anchor::Ds(raw) => {
                let Some(header) = raw.first_chunk::<4>() else {
                    last = Error::Truncated;
                    continue;
                };
                if Dnskey::algorithm_usable(header[2])
                    && crypto.supports_signature(header[2])
                    && crypto.supports_digest(header[3])
                {
                    // RFC 6840 excludes unsupported algorithm pairs before
                    // digest preference. A supported SHA-2 DS prevents SHA-1
                    // fallback even if the matching key or signature fails.
                    if matches!(header[3], 2 | 4) {
                        return Ok(true);
                    }
                    eligible = true;
                }
            }
            Anchor::Dnskey(raw) => match Dnskey::parse(raw) {
                Ok(key) if key.usable() && crypto.supports_signature(key.algorithm) => {
                    eligible = true;
                }
                Ok(_) => {}
                Err(error) => last = error,
            },
        }
    }
    if eligible { Ok(false) } else { Err(last) }
}

fn matches_ds<'anchor>(
    anchors: impl Iterator<Item = Anchor<'anchor>>,
    key: Dnskey<'_>,
    owner: &[u8],
    strong: bool,
    crypto: &impl Crypto,
    last: &mut Error,
) -> Result<bool, Error> {
    let tag = key.tag();
    for anchor in anchors {
        let Anchor::Ds(raw) = anchor else { continue };
        let Some((header, digest)) = raw.split_first_chunk::<4>() else {
            *last = Error::Truncated;
            continue;
        };
        if tag != u16::from_be_bytes([header[0], header[1]])
            || key.algorithm != header[2]
            || (strong && header[3] == 1)
            || !crypto.supports_digest(header[3])
        {
            continue;
        }
        let mut hash = [0; 48];
        let n = match crypto.digest(header[3], &[owner, key.rdata], &mut hash) {
            Ok(n) if n <= hash.len() => n,
            Ok(_) => return Err(Error::Malformed),
            Err(error) => {
                *last = error;
                continue;
            }
        };
        if hash[..n] == *digest {
            return Ok(true);
        }
    }
    Ok(false)
}
