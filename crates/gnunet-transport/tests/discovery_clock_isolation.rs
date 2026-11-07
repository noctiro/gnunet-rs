//! Rejected old/foreign discovery callbacks must not poison a current owner's clock.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Independent public API sequence checks rejected capability noninterference."
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
    fn sign_validation(&mut self, region: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(35, region)?.as_bytes())
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.fill(7);
        Ok(())
    }
}
fn active(replace: bool) -> Result<(Engine, Discovery, Discovery), Error> {
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut random = Random;
    let mut engine = Engine::new(key.identity(), Limits::default())?;
    let communicator = engine.accept()?;
    let mut registration = [0; 16];
    registration[..2].copy_from_slice(&16_u16.to_be_bytes());
    registration[2..4].copy_from_slice(&1211_u16.to_be_bytes());
    registration[4..8].copy_from_slice(&1_u32.to_be_bytes());
    registration[12..].copy_from_slice(b"tcp\0");
    engine.receive(&communicator, &registration, 100, &mut key, &mut random)?;
    let app = engine.accept()?;
    let request = Preference {
        priority: 0,
        bandwidth: 0,
        peer: PeerId([9; 32]),
    };
    let mut wire = [0; 44];
    request.encode(false, &mut wire)?;
    engine.receive(&app, &wire, 100, &mut key, &mut random)?;
    let first = engine.discovery(100)?.ok_or(Error::NotFound)?;
    if !replace {
        return Ok((engine, first.clone(), first));
    }
    request.encode(true, &mut wire)?;
    engine.receive(&app, &wire, 100, &mut key, &mut random)?;
    request.encode(false, &mut wire)?;
    engine.receive(&app, &wire, 100, &mut key, &mut random)?;
    let fresh = engine.discovery(100)?.ok_or(Error::NotFound)?;
    assert_ne!(first, fresh);
    assert!(!engine.discovery_live(&first));
    assert!(engine.discovery_live(&fresh));
    Ok((engine, first, fresh))
}
fn probe(complete: bool, foreign: bool) -> Result<(), Error> {
    let (mut control, _, valid) = active(true)?;
    assert_eq!(
        control.discovered_address(&valid, b"tcp-127.0.0.1:42", 100),
        Ok(AddressAdmission::Issued)
    );
    let (mut victim, old, fresh) = active(true)?;
    let (_other, foreign_id, _) = active(false)?;
    let rejected = if foreign { &foreign_id } else { &old };
    assert_eq!(victim.validate_time(100), Ok(()));
    assert!(victim.discovery_live(&fresh));
    if complete {
        assert_eq!(
            victim.discovery_complete(rejected, 1000, 0, true),
            Err(Error::Stale)
        );
    } else {
        assert_eq!(
            victim.discovered_address(rejected, b"tcp-127.0.0.1:43", 1000),
            Err(Error::Stale)
        );
    }
    assert!(
        victim.output().is_none(),
        "Rejected callback must not mint a communicator CREATE"
    );
    assert!(
        victim.discovery_live(&fresh),
        "Fresh logical request remains live"
    );
    // Replay the identical valid source event at the same caller clock as the control.
    assert_eq!(
        victim.discovered_address(&fresh, b"tcp-127.0.0.1:42", 100),
        Ok(AddressAdmission::Issued),
        "Rejected old/foreign lease moved time for an unrelated current request"
    );
    Ok(())
}
#[test]
fn stale_address_callback_cannot_advance_current_request_clock() -> Result<(), Error> {
    probe(false, false)
}
#[test]
fn stale_completion_cannot_advance_current_request_clock() -> Result<(), Error> {
    probe(true, false)
}
#[test]
fn foreign_address_callback_cannot_advance_current_request_clock() -> Result<(), Error> {
    probe(false, true)
}
#[test]
fn foreign_completion_cannot_advance_current_request_clock() -> Result<(), Error> {
    probe(true, true)
}
