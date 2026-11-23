//! Ephemeral-static ECDH recipient selection and key agreement (RFC 5753).

mod kek;
mod montgomery;
mod mqv;

use p256::elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey, SecretKey,
    pkcs8::{
        PrivateKeyInfoRef,
        der::{Decode, oid::AssociatedOid},
    },
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
};
use std::borrow::Cow;
use x509_parser::x509::SubjectPublicKeyInfo;
use zeroize::Zeroizing;

use super::{
    Ber, CONTEXT_0, CONTEXT_1, Item, OCTETS, OID, RecipientId, SEQUENCE, algorithm, key_agreement,
    key_wrap::{MAX_WRAPPED_BYTES, WrappedKey},
    originator::Certificates,
};

pub(super) const EC_PUBLIC_KEY: &[u8] = b"\x2a\x86\x48\xce\x3d\x02\x01";
pub(super) use montgomery::{X448, X25519};
pub(super) const ECDH_PUBLIC_KEY: &[u8] = b"\x2b\x81\x04\x01\x0c";
const P256: &[u8] = b"\x2a\x86\x48\xce\x3d\x03\x01\x07";
const P384: &[u8] = b"\x2b\x81\x04\x00\x22";
const P521: &[u8] = b"\x2b\x81\x04\x00\x23";
const MAX_POINT_BYTES: usize = 136;
pub(super) const ECMQV_PUBLIC_KEY: &[u8] = b"\x2b\x81\x04\x01\x0d";
const NULL: u8 = 0x05;

pub(super) struct Key {
    private: PrivateKey,
    use_for: Usage,
}

enum PrivateKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    Montgomery(montgomery::Key),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Usage {
    Any,
    Ecdh,
    Mqv,
}

impl Usage {
    fn from_oid(oid: &[u8]) -> Option<Self> {
        match oid {
            EC_PUBLIC_KEY => Some(Self::Any),
            ECDH_PUBLIC_KEY => Some(Self::Ecdh),
            ECMQV_PUBLIC_KEY => Some(Self::Mqv),
            _ => None,
        }
    }

    fn merge(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::Any, usage) | (usage, Self::Any) => Some(usage),
            (first, second) => (first == second).then_some(first),
        }
    }
}

impl Key {
    pub(super) fn parse(certificate: &SubjectPublicKeyInfo<'_>, pkcs8: &[u8]) -> Option<Self> {
        let certificate_oid = certificate.algorithm.algorithm.as_bytes();
        if matches!(certificate_oid, X25519 | X448) {
            return Some(Self {
                private: PrivateKey::Montgomery(montgomery::Key::parse(certificate, pkcs8)?),
                use_for: Usage::Ecdh,
            });
        }
        let curve = certificate.algorithm.parameters.as_ref()?.as_oid().ok()?;
        let point = &certificate.subject_public_key.data;
        let pkcs8 = PrivateKeyInfoRef::from_der(pkcs8).ok()?;
        let use_for = Usage::from_oid(certificate_oid)?
            .merge(Usage::from_oid(pkcs8.algorithm.oid.as_bytes())?)?;
        let private = match curve.as_bytes() {
            P256 => PrivateKey::P256(bind(point, pkcs8)?),
            P384 => PrivateKey::P384(bind(point, pkcs8)?),
            P521 => PrivateKey::P521(bind(point, pkcs8)?),
            _ => return None,
        };
        Some(Self { private, use_for })
    }

    fn curve(&self) -> &'static [u8] {
        match &self.private {
            PrivateKey::P256(_) => P256,
            PrivateKey::P384(_) => P384,
            PrivateKey::P521(_) => P521,
            PrivateKey::Montgomery(key) => key.oid(),
        }
    }
}

fn bind<C>(point: &[u8], pkcs8: PrivateKeyInfoRef<'_>) -> Option<SecretKey<C>>
where
    C: AssociatedOid + CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
{
    let certificate = PublicKey::<C>::from_sec1_bytes(point).ok()?;
    if pkcs8.algorithm.parameters_oid().ok()? != C::OID {
        return None;
    }
    let private = SecretKey::<C>::from_sec1_der(pkcs8.private_key.as_bytes()).ok()?;
    if let Some(point) = pkcs8.public_key
        && PublicKey::<C>::from_sec1_bytes(point.as_bytes()?).ok()? != certificate
    {
        return None;
    }
    (private.public_key() == certificate).then_some(private)
}

pub(super) struct Recipient<'a> {
    peer: Peer<'a>,
    ukm: Option<Cow<'a, [u8]>>,
    scheme: kek::Scheme<'a>,
}

enum Peer<'a> {
    Ephemeral(Cow<'a, [u8]>),
    Mqv {
        ephemeral: Cow<'a, [u8]>,
        originator: Cow<'a, [u8]>,
    },
}

impl Recipient<'_> {
    pub(super) fn open(self, key: &Key) -> Option<Zeroizing<Vec<u8>>> {
        match &key.private {
            PrivateKey::P256(key) => self.open_with(key, 128),
            PrivateKey::P384(key) => self.open_with(key, 192),
            PrivateKey::P521(key) => self.open_with(key, 261),
            PrivateKey::Montgomery(key) => {
                let Peer::Ephemeral(point) = &self.peer else {
                    return None;
                };
                key.with_shared(point, |secret| {
                    self.scheme.unwrap(self.ukm.as_deref(), secret)
                })
            }
        }
    }

    fn open_with<C>(self, key: &SecretKey<C>, auxiliary_bits: usize) -> Option<Zeroizing<Vec<u8>>>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    {
        match self.peer {
            Peer::Ephemeral(point) => {
                let point = decode_point::<C>(&point)?;
                let secret = key.diffie_hellman(&point);
                self.scheme
                    .unwrap(self.ukm.as_deref(), secret.raw_secret_bytes())
            }
            Peer::Mqv {
                ephemeral,
                originator,
            } => {
                let ephemeral = decode_point::<C>(&ephemeral)?;
                let originator = decode_point::<C>(&originator)?;
                let secret = mqv::shared(key, &originator, &ephemeral, auxiliary_bits)?;
                self.scheme.unwrap(self.ukm.as_deref(), &secret)
            }
        }
    }
}

fn decode_point<C>(point: &[u8]) -> Option<PublicKey<C>>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
{
    if !matches!(point.first(), Some(2..=4)) {
        return None;
    }
    PublicKey::<C>::from_sec1_bytes(point).ok().or_else(|| {
        // RFC 5753 describes a DER ECPoint. OpenSSL sends SEC1 octets
        // directly in the BIT STRING.
        let wrapped = super::asn1::Der::single(point, OCTETS)?;
        matches!(wrapped.data.first(), Some(2..=4)).then_some(())?;
        PublicKey::<C>::from_sec1_bytes(wrapped.data).ok()
    })
}

pub(super) fn select<'a>(
    key: &Key,
    rid: &RecipientId,
    entry: Item<'a>,
    budget: &mut usize,
    originators: Certificates<'a>,
) -> Option<Option<Recipient<'a>>> {
    let Some(fields) = key_agreement::select(rid, entry, budget)? else {
        return Some(None);
    };
    let (kdf, params) = algorithm(fields.algorithm)?;
    let method = if matches!(key.private, PrivateKey::Montgomery(_)) {
        kek::Method::Montgomery
    } else if kek::Method::is_mqv(kdf) {
        if key.use_for == Usage::Ecdh {
            return None;
        }
        kek::Method::Mqv
    } else {
        if key.use_for == Usage::Mqv {
            return None;
        }
        kek::Method::Ecdh
    };
    let wrapped = fields.encrypted.octets(OCTETS, MAX_WRAPPED_BYTES)?;
    let wrapped = WrappedKey::parse(params?, wrapped)?;
    let scheme = kek::Scheme::parse(kdf, wrapped, method)?;
    let originator = key_agreement::explicit(fields.originator)?;
    let (peer, ukm) = match method {
        kek::Method::Mqv => {
            let originator = mqv_originator(originator, key, originators)?;
            let encoded = key_agreement::explicit(fields.ukm?)?
                .octets(OCTETS, kek::MAX_UKM_BYTES + MAX_POINT_BYTES * 2)?;
            let material = match encoded {
                Cow::Borrowed(bytes) => mqv_material(bytes, key)?,
                Cow::Owned(bytes) => mqv_material(&bytes, key)?.into_owned(),
            };
            (
                Peer::Mqv {
                    ephemeral: material.ephemeral,
                    originator,
                },
                material.added_ukm,
            )
        }
        _ => {
            let point = public_point(originator, key, PointRole::Ephemeral)?;
            let ukm = match fields.ukm {
                Some(field) => {
                    Some(key_agreement::explicit(field)?.octets(OCTETS, kek::MAX_UKM_BYTES)?)
                }
                None => None,
            };
            (Peer::Ephemeral(point), ukm)
        }
    };
    Some(Some(Recipient { peer, ukm, scheme }))
}

struct MqvMaterial<'a> {
    ephemeral: Cow<'a, [u8]>,
    added_ukm: Option<Cow<'a, [u8]>>,
}

impl MqvMaterial<'_> {
    fn into_owned(self) -> MqvMaterial<'static> {
        MqvMaterial {
            ephemeral: Cow::Owned(self.ephemeral.into_owned()),
            added_ukm: self.added_ukm.map(|value| Cow::Owned(value.into_owned())),
        }
    }
}

fn mqv_material<'a>(bytes: &'a [u8], key: &Key) -> Option<MqvMaterial<'a>> {
    let mut value = Ber::sequence(bytes)?;
    let point = public_point(value.take(SEQUENCE)?, key, PointRole::MqvEphemeral)?;
    let added = match value.optional(CONTEXT_0)? {
        Some(field) => Some(key_agreement::explicit(field)?.octets(OCTETS, kek::MAX_UKM_BYTES)?),
        None => None,
    };
    value.finish()?;
    Some(MqvMaterial {
        ephemeral: point,
        added_ukm: added,
    })
}

fn mqv_originator<'a>(
    originator: Item<'a>,
    key: &Key,
    originators: Certificates<'a>,
) -> Option<Cow<'a, [u8]>> {
    if originator.tag == CONTEXT_1 {
        return public_point(originator, key, PointRole::MqvStatic);
    }
    let certificate = originators.find(originator)?;
    if !certificate
        .key_usage()
        .ok()?
        .is_none_or(|usage| usage.value.key_agreement() && !usage.value.decipher_only())
    {
        return None;
    }
    let public_key = certificate.tbs_certificate.subject_pki;
    if !matches!(
        public_key.algorithm.algorithm.as_bytes(),
        EC_PUBLIC_KEY | ECMQV_PUBLIC_KEY
    ) || public_key
        .algorithm
        .parameters
        .as_ref()?
        .as_oid()
        .ok()?
        .as_bytes()
        != key.curve()
        || public_key.subject_public_key.unused_bits != 0
        || !(1..=MAX_POINT_BYTES).contains(&public_key.subject_public_key.data.len())
    {
        return None;
    }
    Some(public_key.subject_public_key.data)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PointRole {
    Ephemeral,
    MqvEphemeral,
    MqvStatic,
}

fn public_point<'a>(item: Item<'a>, key: &Key, role: PointRole) -> Option<Cow<'a, [u8]>> {
    let expected_tag = match role {
        PointRole::MqvEphemeral => SEQUENCE,
        _ => CONTEXT_1,
    };
    if item.tag != expected_tag {
        return None;
    }
    let mut fields = Ber(item.data);
    let (oid, params) = algorithm(fields.take(SEQUENCE)?)?;
    let point_field = fields.read()?;
    fields.finish()?;
    if let PrivateKey::Montgomery(key) = &key.private {
        if oid != key.oid() || params.is_some() {
            return None;
        }
        let size = if oid == X25519 { 32 } else { 56 };
        let point = point_field.byte_aligned_bits(size + 2)?;
        if point.len() == size {
            return Some(point);
        }
        // RFC 8418 also describes OCTET STRING bytes inside OriginatorPublicKey.
        let wrapped = super::asn1::Der::single(&point, OCTETS)?;
        return (wrapped.data.len() == size).then(|| Cow::Owned(wrapped.data.to_vec()));
    }
    if !(oid == EC_PUBLIC_KEY || role == PointRole::MqvStatic && oid == ECMQV_PUBLIC_KEY)
        || params.is_some_and(|p| {
            !(p.tag == NULL && p.data.is_empty() || p.tag == OID && p.data == key.curve())
        })
    {
        return None;
    }
    let point = point_field.byte_aligned_bits(MAX_POINT_BYTES)?;
    // SEC 1 hybrid encodings are explicitly excluded by RFC 5753.
    matches!(point.first(), Some(2..=4)).then_some(point)
}
