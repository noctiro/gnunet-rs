//! Rejected old/foreign client or signing identity must not move another live owner's clock.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Public API noninterference uses a valid control and rejected authority sequence."
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_transport::{
    Engine, Limits, PeerId, Signer,
    application::{AddressAdmission, Discovery, Preference},
};
use gnunet_types::Error;
struct Key(EddsaPrivateKey);
impl Signer for Key {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.public_key().as_bytes())
    }
    fn sign_validation(&mut self, r: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(35, r)?.as_bytes())
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        b.fill(7);
        Ok(())
    }
}
fn setup() -> Result<(Engine, Discovery), Error> {
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut random = Random;
    let mut e = Engine::new(key.identity(), Limits::default())?;
    let comm = e.accept()?;
    let mut wire = [0; 16];
    wire[..2].copy_from_slice(&16_u16.to_be_bytes());
    wire[2..4].copy_from_slice(&1211_u16.to_be_bytes());
    wire[4..8].copy_from_slice(&1_u32.to_be_bytes());
    wire[12..].copy_from_slice(b"tcp\0");
    e.receive(&comm, &wire, 100, &mut key, &mut random)?;
    let app = e.accept()?;
    let mut wire = [0; 44];
    Preference {
        priority: 0,
        bandwidth: 0,
        peer: PeerId([9; 32]),
    }
    .encode(false, &mut wire)?;
    e.receive(&app, &wire, 100, &mut key, &mut random)?;
    let lease = e.discovery(100)?.ok_or(Error::NotFound)?;
    Ok((e, lease))
}
fn scenario(mode: u8) -> Result<(), Error> {
    let (mut control, valid) = setup()?;
    assert_eq!(
        control.discovered_address(&valid, b"tcp-127.0.0.1:42", 100),
        Ok(AddressAdmission::Issued)
    );
    let (mut victim, current) = setup()?;
    let mut signer = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut rng = Random;
    let mut wire = [0; 44];
    Preference {
        priority: 0,
        bandwidth: 0,
        peer: PeerId([10; 32]),
    }
    .encode(false, &mut wire)?;
    let (mut foreign, _) = setup()?;
    let source = if mode == 1 {
        foreign.accept()?
    } else {
        victim.accept()?
    };
    if mode == 0 {
        victim.close(&source)?;
    }
    let expected = if mode == 2 {
        signer = Key(EddsaPrivateKey::from_seed([2; 32]));
        Error::Authentication
    } else {
        Error::Stale
    };
    assert_eq!(
        victim.receive(&source, &wire, 1000, &mut signer, &mut rng),
        Err(expected)
    );
    assert!(victim.output().is_none());
    assert!(victim.discovery_live(&current));
    assert_eq!(
        victim.discovered_address(&current, b"tcp-127.0.0.1:42", 100),
        Ok(AddressAdmission::Issued),
        "Rejected receive authority advanced shared time for an unrelated live request"
    );
    Ok(())
}
#[test]
fn retired_mq_receive_cannot_poison_current_clock() -> Result<(), Error> {
    scenario(0)
}
#[test]
fn foreign_mq_receive_cannot_poison_current_clock() -> Result<(), Error> {
    scenario(1)
}
#[test]
fn rejected_signer_cannot_poison_current_clock() -> Result<(), Error> {
    scenario(2)
}
