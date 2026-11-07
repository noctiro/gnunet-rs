//! Original communicator address ownership; no actual PILS or Node credit.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Protocol/resource invariants use assertions while setup errors propagate"
)]
use gnunet_crypto::Entropy;
use gnunet_transport::{ClientId, Engine, Limits, PeerId, Signer};
use gnunet_types::Error;
static NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
fn now() -> u64 {
    NOW.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}
struct Identity;
impl Signer for Identity {
    fn identity(&self) -> PeerId {
        PeerId([1; 32])
    }
    fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Error> {
        Err(Error::Unavailable)
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(5);
        Ok(())
    }
}
fn frame(kind: u16, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    b[..2].copy_from_slice(&(n as u16).to_be_bytes());
    b[2..4].copy_from_slice(&kind.to_be_bytes());
    b
}
fn owner(e: &mut Engine) -> Result<ClientId, Error> {
    let c = e.accept()?;
    let mut b = frame(1211, 16);
    b[4..8].copy_from_slice(&1u32.to_be_bytes());
    b[12..].copy_from_slice(b"tcp\0");
    e.receive(&c, &b, now(), &mut Identity, &mut Random)?;
    Ok(c)
}
fn add(
    e: &mut Engine,
    c: &ClientId,
    id: u32,
    a: &[u8],
    validity: u64,
) -> Result<gnunet_transport::ReceiveOutcome, Error> {
    let mut b = frame(1200, 21 + a.len());
    b[4..8].copy_from_slice(&id.to_be_bytes());
    b[8..16].copy_from_slice(&validity.to_be_bytes());
    b[16..20].copy_from_slice(&1u32.to_be_bytes());
    b[20..20 + a.len()].copy_from_slice(a);
    e.receive(c, &b, now(), &mut Identity, &mut Random)
}
fn delete(e: &mut Engine, c: &ClientId, id: u32) -> Result<(), Error> {
    let mut b = frame(1201, 8);
    b[4..8].copy_from_slice(&id.to_be_bytes());
    e.receive(c, &b, now(), &mut Identity, &mut Random)?;
    Ok(())
}
fn engine(limits: Limits) -> Result<Engine, Error> {
    Engine::new(PeerId([1; 32]), limits)
}
#[test]
fn shared_uri_survives_one_original_mq_loss_and_old_full_write_does_not_settle_new_aggregate()
-> Result<(), Error> {
    let mut e = engine(Limits::default())?;
    let a = owner(&mut e)?;
    let b = owner(&mut e)?;
    add(&mut e, &a, 1, b"tcp-127.0.0.1:42", 120)?;
    add(&mut e, &b, 1, b"tcp-127.0.0.1:42", 120)?;
    add(&mut e, &a, 2, b"tcp-127.0.0.1:43", 120)?;
    let p = e.address_publication()?.ok_or(Error::NotReady)?;
    assert_eq!(p.uris().count(), 2);
    assert_eq!(p.records().count(), 3);
    let old = p.id().clone();
    e.claim_address_publication(&old)?;
    e.close(&a)?;
    assert!(e.address_publication()?.is_none());
    e.address_publication_written(&old)?;
    let p = e.address_publication()?.ok_or(Error::NotReady)?;
    assert_eq!(
        p.uris().collect::<Vec<_>>(),
        vec![b"tcp://127.0.0.1:42".as_slice()]
    );
    assert_eq!(p.records().next().ok_or(Error::NotFound)?.owner, &b);
    let current = p.id().clone();
    assert_ne!(old, current);
    e.claim_address_publication(&current)?;
    e.address_publication_written(&current)?;
    assert!(e.address_publication()?.is_none());
    delete(&mut e, &b, 1)?;
    let p = e.address_publication()?.ok_or(Error::NotReady)?;
    assert_eq!(p.uris().count(), 0);
    Ok(())
}
#[test]
fn foreign_and_duplicate_publication_leases_cannot_claim_or_complete_other_originals()
-> Result<(), Error> {
    let mut a = engine(Limits::default())?;
    let mut b = engine(Limits::default())?;
    let ca = owner(&mut a)?;
    let cb = owner(&mut b)?;
    add(&mut a, &ca, 1, b"tcp-127.0.0.1:42", 120)?;
    add(&mut b, &cb, 1, b"tcp-127.0.0.1:42", 120)?;
    let foreign = a
        .address_publication()?
        .ok_or(Error::NotReady)?
        .id()
        .clone();
    let own = b
        .address_publication()?
        .ok_or(Error::NotReady)?
        .id()
        .clone();
    assert_eq!(b.claim_address_publication(&foreign), Err(Error::Stale));
    b.claim_address_publication(&own)?;
    assert_eq!(b.address_publication_written(&foreign), Err(Error::Stale));
    assert_eq!(b.claim_address_publication(&own), Err(Error::Stale));
    b.address_publication_written(&own)?;
    assert_eq!(b.address_publication_written(&own), Err(Error::Stale));
    a.claim_address_publication(&foreign)?;
    Ok(())
}
#[test]
fn actual_zero_wire_ids_are_retained_and_bounded_refusal_is_atomic() -> Result<(), Error> {
    let mut e = engine(Limits {
        control_messages: 2,
        ..Limits::default()
    })?;
    let a = owner(&mut e)?;
    add(&mut e, &a, 0, b"tcp-127.0.0.1:42", 0)?;
    add(&mut e, &a, 0, b"tcp-127.0.0.1:43", 0)?;
    let original = e
        .address_publication()?
        .ok_or(Error::NotReady)?
        .id()
        .clone();
    assert_eq!(
        add(&mut e, &a, 0, b"tcp-127.0.0.1:44", 0),
        Ok(gnunet_transport::ReceiveOutcome::AddressRejected(
            gnunet_transport::addresses::AddressRejection {
                client: a.clone(),
                address_id: 0,
                reason: Error::Capacity
            }
        ))
    );
    assert_eq!(
        e.address_publication()?.ok_or(Error::NotReady)?.id(),
        &original
    );
    delete(&mut e, &a, 77)?;
    assert_eq!(
        e.address_publication()?
            .ok_or(Error::NotReady)?
            .records()
            .count(),
        2
    );
    delete(&mut e, &a, 0)?;
    let p = e.address_publication()?.ok_or(Error::NotReady)?;
    let r = p.records().next().ok_or(Error::NotFound)?;
    assert_eq!(r.address, b"tcp-127.0.0.1:42");
    assert_eq!(r.validity, 0);
    assert_eq!(p.uris().count(), 1);
    Ok(())
}
#[test]
fn immutable_handed_snapshot_and_new_physical_owner_never_gain_old_delete_authority()
-> Result<(), Error> {
    let mut e = engine(Limits::default())?;
    let a = owner(&mut e)?;
    assert_eq!(
        add(&mut e, &a, 1, b"bad?scheme-address", 1),
        Err(Error::Malformed)
    );
    assert!(e.address_publication()?.is_none());
    add(&mut e, &a, 1, b"tcp-127.0.0.1:42", 0)?;
    let p = e.address_publication()?.ok_or(Error::NotReady)?;
    let handed = p.uris().map(|u| u.to_vec()).collect::<Vec<_>>();
    let id = p.id().clone();
    e.claim_address_publication(&id)?;
    e.close(&a)?;
    let b = owner(&mut e)?;
    add(&mut e, &b, 1, b"tcp-127.0.0.1:43", 0)?;
    assert_eq!(delete(&mut e, &a, 1), Err(Error::Stale));
    assert_eq!(handed, vec![b"tcp://127.0.0.1:42".to_vec()]);
    e.address_publication_written(&id)?;
    assert_eq!(
        e.address_publication()?
            .ok_or(Error::NotReady)?
            .uris()
            .collect::<Vec<_>>(),
        vec![b"tcp://127.0.0.1:43".as_slice()]
    );
    Ok(())
}
