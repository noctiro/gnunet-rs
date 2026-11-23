//! Digest and HMAC adapters for the existing rustls key schedules.
use hmac::{Hmac, KeyInit, Mac};
use rustls::crypto::{hash, hmac as tls_hmac, tls12::PrfUsingHmac, tls13::HkdfUsingHmac};
use sha2::{Digest, Sha256, Sha384};
use std::marker::PhantomData;
use zeroize::Zeroizing;

pub(super) static SHA256: DigestAlgorithm<Sha256> =
    DigestAlgorithm::new(hash::HashAlgorithm::SHA256);
pub(super) static SHA384: DigestAlgorithm<Sha384> =
    DigestAlgorithm::new(hash::HashAlgorithm::SHA384);

pub(super) static PRF_SHA256: PrfUsingHmac<'_> = PrfUsingHmac(&HMAC_SHA256);
pub(super) static PRF_SHA384: PrfUsingHmac<'_> = PrfUsingHmac(&HMAC_SHA384);
pub(super) static HKDF_SHA256: HkdfUsingHmac<'_> = HkdfUsingHmac(&HMAC_SHA256);
pub(super) static HKDF_SHA384: HkdfUsingHmac<'_> = HkdfUsingHmac(&HMAC_SHA384);

static HMAC_SHA256: HmacAlgorithm<Hmac<Sha256>> = HmacAlgorithm(PhantomData);
static HMAC_SHA384: HmacAlgorithm<Hmac<Sha384>> = HmacAlgorithm(PhantomData);

pub(super) struct DigestAlgorithm<D>(hash::HashAlgorithm, PhantomData<D>);

impl<D> DigestAlgorithm<D> {
    const fn new(algorithm: hash::HashAlgorithm) -> Self {
        Self(algorithm, PhantomData)
    }
}

impl<D: Digest + Clone + Send + Sync + 'static> hash::Hash for DigestAlgorithm<D> {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(DigestContext(D::new()))
    }

    fn hash(&self, bytes: &[u8]) -> hash::Output {
        hash::Output::new(&D::digest(bytes))
    }

    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        self.0
    }
}

struct DigestContext<D>(D);

impl<D: Digest + Clone + Send + Sync + 'static> hash::Context for DigestContext<D> {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

struct HmacAlgorithm<M>(PhantomData<M>);

impl<M: Mac + KeyInit + Clone + Send + Sync + 'static> tls_hmac::Hmac for HmacAlgorithm<M> {
    #[expect(
        clippy::expect_used,
        reason = "The two RustCrypto HMAC instances accept every key length"
    )]
    fn with_key(&self, key: &[u8]) -> Box<dyn tls_hmac::Key> {
        Box::new(HmacKey(
            M::new_from_slice(key).expect("HMAC accepts any key length"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        M::output_size()
    }
}

struct HmacKey<M>(M);

impl<M: Mac + Clone + Send + Sync> tls_hmac::Key for HmacKey<M> {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> tls_hmac::Tag {
        let mut mac = self.0.clone();
        mac.update(first);
        for part in middle {
            mac.update(part);
        }
        mac.update(last);
        let bytes = Zeroizing::new(mac.finalize().into_bytes());
        tls_hmac::Tag::new(bytes.as_ref())
    }

    fn tag_len(&self) -> usize {
        M::output_size()
    }
}
