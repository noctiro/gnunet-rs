//! Source-only algebra/lifecycle cases. Tiny public integers deliberately bypass
//! only private test construction, never the production2047/2048-bit key gate.
//! They do not prove real keygen, entropy, native interoperability or constant time.
use super::*;
use crypto_bigint::{Odd, modular::FixedMontyParams};
use zeroize::Zeroizing;

mod witness;

fn tiny_pair() -> Result<KeyPair, Error> {
    // Public pedagogical Paillier arithmetic p=3,q=5,n=15,phi=8,mu=2.
    let n = U2048::from(15u8);
    let square = U4096::from(225u16);
    let odd = Odd::new(square).into_option().ok_or(Error::InvalidKey)?;
    Ok(KeyPair {
        public: PublicKey {
            n,
            square,
            params: FixedMontyParams::new(odd),
        },
        private: PrivateKey {
            n,
            lambda: Zeroizing::new(U2048::from(8u8)),
            mu: Zeroizing::new(U2048::from(2u8)),
        },
    })
}
struct AlgebraNonce;
impl Entropy for AlgebraNonce {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), gnunet_types::Error> {
        bytes.fill(0);
        let last = bytes.last_mut().ok_or(gnunet_types::Error::InvalidInput)?;
        *last = 2;
        Ok(())
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit source assertions compare independent algebra/wire/lifecycle expectations; original API errors propagate"
)]
fn bounded_power_and_real_small_paillier_algebra() -> Result<(), Error> {
    let key = tiny_pair()?;
    assert_eq!(
        PublicKey::from_bytes(&key.public.to_bytes()).err(),
        Some(Error::InvalidKey)
    );
    let plaintext = key.public.plaintext(&[7])?;
    let mut encrypt = key.public.encrypt(plaintext, 0, Limits::default())?;
    assert!(matches!(encrypt.take_result(), Err(Error::NotReady)));
    for _ in 0..4096 {
        if encrypt.advance(&mut AlgebraNonce, 1)? == Progress::Ready {
            break;
        }
    }
    let cipher = encrypt.take_result()?;
    assert_eq!(cipher.integer(), U4096::from(83u8));
    assert_eq!(cipher.remaining_ops(), 0);
    assert!(matches!(encrypt.take_result(), Err(Error::Finished)));
    let mut decrypt = key
        .private
        .decrypt(&key.public, &cipher, Limits::default())?;
    for _ in 0..4096 {
        if decrypt.advance(1)? == Progress::Ready {
            break;
        }
    }
    let plain = decrypt.take_result()?.to_bytes();
    assert!(plain[..255].iter().all(|b| *b == 0));
    assert_eq!(plain[255], 7);
    assert!(matches!(decrypt.take_result(), Err(Error::Finished)));
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit source assertions compare independent algebra/wire/lifecycle expectations; original API errors propagate"
)]
fn official_counter_and_modular_homomorphic_product_preserve_original_wire() -> Result<(), Error> {
    let key = tiny_pair()?;
    let a = Ciphertext::from_integer(&U4096::from(83u8), 1);
    let b = Ciphertext::from_integer(&U4096::from(173u8), 1);
    let sum = key.public.homomorphic_add(&a, &b)?;
    assert_eq!(sum.integer(), U4096::from(184u8));
    assert_eq!(sum.remaining_ops(), 0);
    assert!(matches!(
        key.public.homomorphic_add(&sum, &b),
        Err(Error::Range)
    ));
    let mut wire = sum.to_wire();
    wire[..4].copy_from_slice(&(-1i32).to_be_bytes());
    let original = Ciphertext::from_wire(wire);
    assert_eq!(original.remaining_ops(), -1);
    assert_eq!(original.to_wire(), wire);
    assert!(matches!(
        key.public.homomorphic_add(&original, &b),
        Err(Error::Range)
    ));
    let mut decrypt = key.private.decrypt(&key.public, &sum, Limits::default())?;
    for _ in 0..4096 {
        if decrypt.advance(1)? == Progress::Ready {
            break;
        }
    }
    assert_eq!(decrypt.take_result()?.to_bytes()[255], 11);
    Ok(())
}
struct PartialFailure;
impl Entropy for PartialFailure {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), gnunet_types::Error> {
        if let Some(byte) = bytes.first_mut() {
            *byte = 0xa5;
        }
        Err(gnunet_types::Error::Unavailable)
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit source assertions compare independent algebra/wire/lifecycle expectations; original API errors propagate"
)]
fn original_entropy_failure_cancel_and_unfinished_work_never_yield_key_or_cipher()
-> Result<(), Error> {
    let mut keygen = Keygen::new(Limits::default())?;
    assert!(matches!(keygen.take_result(), Err(Error::NotReady)));
    let original = Error::Entropy(gnunet_types::Error::Unavailable);
    assert_eq!(keygen.advance(&mut PartialFailure, 1), Err(original));
    assert!(matches!(keygen.take_result(),Err(error) if error==original));
    keygen.cancel();
    assert_eq!(keygen.advance(&mut PartialFailure, 1), Err(original));
    let mut cancelled = Keygen::new(Limits::default())?;
    cancelled.cancel();
    assert_eq!(
        cancelled.advance(&mut PartialFailure, 1),
        Err(Error::Cancelled)
    );
    let pair = tiny_pair()?;
    let mut encrypt = pair
        .public
        .encrypt(pair.public.plaintext(&[7])?, 0, Limits::default())?;
    assert_eq!(encrypt.advance(&mut PartialFailure, 1), Err(original));
    assert!(matches!(encrypt.take_result(),Err(error) if error==original));
    let mut live = pair
        .public
        .encrypt(pair.public.plaintext(&[7])?, 0, Limits::default())?;
    live.cancel();
    assert!(matches!(live.take_result(), Err(Error::Cancelled)));
    Ok(())
}
