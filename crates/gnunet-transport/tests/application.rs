//! Actual official application hint and original communicator-MQ request ownership.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify external protocol and owner boundaries"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_transport::{
    ClientId, Engine, Limits, Output, PeerId, Signer, application::ValidateAddress,
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
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(7);
        Ok(())
    }
}
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut v = vec![0; size];
    v[..2].copy_from_slice(&(size as u16).to_be_bytes());
    v[2..4].copy_from_slice(&kind.to_be_bytes());
    v
}
fn hint(peer: PeerId, address: &[u8]) -> Vec<u8> {
    let mut v = frame(1302, 41 + address.len());
    v[4..8].copy_from_slice(&1_u32.to_be_bytes());
    v[8..40].copy_from_slice(&peer.0);
    v[40..40 + address.len()].copy_from_slice(address);
    v
}
fn registration() -> Vec<u8> {
    let mut v = frame(1211, 16);
    v[4..8].copy_from_slice(&1_u32.to_be_bytes());
    v[12..].copy_from_slice(b"tcp\0");
    v
}
fn result(id: [u8; 4], success: bool) -> Vec<u8> {
    let mut v = frame(if success { 1207 } else { 1208 }, 8);
    v[4..8].copy_from_slice(&id);
    v
}
fn create(engine: &mut Engine, owner: &ClientId) -> Result<Vec<u8>, Error> {
    match engine.output() {
        Some(Output::Frame { client, bytes })
            if client == *owner && bytes[2..4] == 1206_u16.to_be_bytes() =>
        {
            Ok(bytes)
        }
        _ => Err(Error::NotFound),
    }
}
fn setup(engine: &mut Engine, key: &mut Key, rng: &mut Random) -> Result<ClientId, Error> {
    let c = engine.accept()?;
    engine.receive(&c, &registration(), 100, key, rng)?;
    Ok(c)
}
#[test]
fn official_hint_preserves_opaque_address_and_checks_terminator() -> Result<(), Error> {
    let peer = PeerId([9; 32]);
    let original = hint(peer, b"tcp-127.0.0.1:42");
    let parsed = ValidateAddress::decode(&original)?;
    assert_eq!(parsed.peer, peer);
    assert_eq!(parsed.network, 1);
    assert_eq!(parsed.address, b"tcp-127.0.0.1:42");
    let empty = hint(peer, b"");
    assert!(ValidateAddress::decode(&empty)?.address.is_empty());
    let mut missing = original.clone();
    missing.pop();
    let n = missing.len() as u16;
    missing[..2].copy_from_slice(&n.to_be_bytes());
    assert_eq!(ValidateAddress::decode(&missing), Err(Error::Malformed));
    let mut embedded = original.clone();
    embedded[44] = 0;
    assert_eq!(ValidateAddress::decode(&embedded), Err(Error::Malformed));
    // Official1302 checks C-string framing; each communicator interprets its
    // own address. In particular, UNIX paths need not contain UTF-8 bytes.
    let mut opaque = original;
    opaque[44] = 255;
    assert_eq!(
        ValidateAddress::decode(&opaque)?.address,
        &opaque[40..opaque.len() - 1]
    );
    assert!(ValidateAddress::decode(&frame(1302, 40)).is_err());
    Ok(())
}
#[test]
fn positive_create_is_not_authentication_and_original_app_eof_does_not_retract_hint()
-> Result<(), Error> {
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut rng = Random;
    let mut e = Engine::new(key.identity(), Limits::default())?;
    let comm = setup(&mut e, &mut key, &mut rng)?;
    let app = e.accept()?;
    let peer = PeerId([9; 32]);
    let original = hint(peer, b"tcp-127.0.0.1:42");
    e.receive(&app, &original, 100, &mut key, &mut rng)?;
    let sent = create(&mut e, &comm)?;
    assert_eq!(&sent[8..40], &peer.0);
    assert_eq!(&sent[40..], b"tcp-127.0.0.1:42\0");
    let rid = sent[4..8].try_into().map_err(|_| Error::Malformed)?;
    e.receive(&app, &original, 101, &mut key, &mut rng)?;
    assert!(e.output().is_none());
    e.close(&app)?;
    assert_eq!(e.snapshot().pending_address_creates, 1);
    e.receive(&comm, &result(rid, true), 102, &mut key, &mut rng)?;
    assert_eq!(e.snapshot().pending_address_creates, 1);
    assert_eq!(
        (
            e.snapshot().queues,
            e.snapshot().connected,
            e.snapshot().validations
        ),
        (0, 0, 0)
    );
    // An additional contradictory local result cannot end the admitted attempt.
    e.receive(&comm, &result(rid, false), 103, &mut key, &mut rng)?;
    assert_eq!(e.snapshot().pending_address_creates, 1);
    let mut queue = frame(1204, 64 + b"tcp-127.0.0.1:42\0".len());
    queue[4..8].copy_from_slice(&2_u32.to_be_bytes());
    queue[8..40].copy_from_slice(&peer.0);
    queue[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    queue[48..56].copy_from_slice(&8_u64.to_be_bytes());
    queue[64..].copy_from_slice(b"tcp-127.0.0.1:42\0");
    e.receive(&comm, &queue, 104, &mut key, &mut rng)?;
    assert_eq!(e.snapshot().pending_address_creates, 0);
    assert_eq!(e.snapshot().address_create_bytes, 0);
    assert_eq!(e.snapshot().queues, 1);
    assert_eq!(e.snapshot().connected, 0);
    assert_eq!(e.snapshot().validations, 0);
    let again = e.accept()?;
    e.receive(&again, &original, 105, &mut key, &mut rng)?;
    assert_eq!(e.snapshot().address_creates_issued, 1);
    Ok(())
}
#[test]
fn old_communicator_results_cannot_complete_a_new_physical_owners_request() -> Result<(), Error> {
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut rng = Random;
    let mut e = Engine::new(key.identity(), Limits::default())?;
    let old = setup(&mut e, &mut key, &mut rng)?;
    let app = e.accept()?;
    let original = hint(PeerId([9; 32]), b"tcp-127.0.0.1:42");
    e.receive(&app, &original, 100, &mut key, &mut rng)?;
    let first = create(&mut e, &old)?;
    let oldrid = first[4..8].try_into().map_err(|_| Error::Malformed)?;
    e.close(&old)?;
    assert_eq!(e.snapshot().pending_address_creates, 0);
    let new = e.accept()?;
    e.receive(&new, &registration(), 101, &mut key, &mut rng)?;
    e.receive(&app, &original, 102, &mut key, &mut rng)?;
    let second = create(&mut e, &new)?;
    let newrid = second[4..8].try_into().map_err(|_| Error::Malformed)?;
    assert_ne!(oldrid, newrid);
    e.receive(&new, &result(oldrid, false), 103, &mut key, &mut rng)?;
    assert_eq!(e.snapshot().pending_address_creates, 1);
    assert_eq!(
        e.receive(&old, &result(oldrid, true), 103, &mut key, &mut rng),
        Err(Error::Stale)
    );
    e.receive(&new, &result(newrid, false), 104, &mut key, &mut rng)?;
    assert_eq!(e.snapshot().pending_address_creates, 0);
    assert_eq!(e.snapshot().address_create_bytes, 0);
    Ok(())
}
#[test]
fn bounded_pending_admission_and_absolute_expiry_preserve_unique_wire_ids() -> Result<(), Error> {
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut rng = Random;
    let mut e = Engine::new(
        key.identity(),
        Limits {
            control_messages: 1,
            ..Limits::default()
        },
    )?;
    let comm = setup(&mut e, &mut key, &mut rng)?;
    let app = e.accept()?;
    let a = hint(PeerId([9; 32]), b"tcp-127.0.0.1:42");
    let b = hint(PeerId([10; 32]), b"tcp-127.0.0.1:43");
    e.receive(&app, &a, 100, &mut key, &mut rng)?;
    let first = create(&mut e, &comm)?;
    let oldrid = first[4..8].try_into().map_err(|_| Error::Malformed)?;
    e.receive(&app, &b, 101, &mut key, &mut rng)?;
    assert!(e.output().is_none());
    assert_eq!(e.snapshot().pending_address_creates, 1);
    assert_eq!(e.snapshot().address_creates_issued, 1);
    let _ = e.tick(60_000_100, &mut rng)?;
    assert_eq!(e.snapshot().pending_address_creates, 0);
    e.receive(&app, &b, 60_000_101, &mut key, &mut rng)?;
    let second = create(&mut e, &comm)?;
    let newrid = second[4..8].try_into().map_err(|_| Error::Malformed)?;
    assert_ne!(oldrid, newrid);
    e.receive(
        &comm,
        &result(oldrid, false),
        60_000_102,
        &mut key,
        &mut rng,
    )?;
    assert_eq!(e.snapshot().pending_address_creates, 1);
    e.receive(
        &comm,
        &result(newrid, false),
        60_000_103,
        &mut key,
        &mut rng,
    )?;
    assert_eq!(e.snapshot().pending_address_creates, 0);
    Ok(())
}
#[test]
fn unsupported_or_malformed_hint_has_no_create_or_role_escalation() -> Result<(), Error> {
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut rng = Random;
    let mut e = Engine::new(key.identity(), Limits::default())?;
    let _comm = setup(&mut e, &mut key, &mut rng)?;
    let app = e.accept()?;
    let unknown = hint(PeerId([9; 32]), b"udp-127.0.0.1:42");
    e.receive(&app, &unknown, 100, &mut key, &mut rng)?;
    assert!(e.output().is_none());
    assert_eq!(
        e.receive(&app, &registration(), 101, &mut key, &mut rng),
        Err(Error::Malformed)
    );
    let fresh = e.accept()?;
    let mut malformed = hint(PeerId([9; 32]), b"tcp-x");
    malformed[41] = 0;
    assert_eq!(
        e.receive(&fresh, &malformed, 102, &mut key, &mut rng),
        Err(Error::Malformed)
    );
    e.receive(&fresh, &registration(), 103, &mut key, &mut rng)?;
    assert_eq!(e.snapshot().address_creates_issued, 0);
    Ok(())
}

#[test]
fn official1300_keeps_original_application_mq_usable() -> Result<(), Error> {
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut rng = Random;
    let mut e = Engine::new(key.identity(), Limits::default())?;
    let comm = setup(&mut e, &mut key, &mut rng)?;
    let app = e.accept()?;
    let peer = PeerId([9; 32]);
    let mut suggest = frame(1300, 44);
    suggest[8..40].copy_from_slice(&peer.0);
    // Official public API explicitly permits background priority and bandwidth0.
    assert!(e.receive(&app, &suggest, 100, &mut key, &mut rng).is_ok());
    assert!(e.output().is_none());
    e.receive(
        &app,
        &hint(peer, b"tcp-127.0.0.1:42"),
        101,
        &mut key,
        &mut rng,
    )?;
    assert_eq!(&create(&mut e, &comm)?[8..40], &peer.0);
    suggest[2..4].copy_from_slice(&1301_u16.to_be_bytes());
    e.receive(&app, &suggest, 102, &mut key, &mut rng)?;
    Ok(())
}

#[test]
fn suggestion_leases_follow_original_mq_cancel_and_independent_client() -> Result<(), Error> {
    use gnunet_transport::application::{AddressAdmission, Preference};
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut rng = Random;
    let mut e = Engine::new(key.identity(), Limits::default())?;
    let comm = setup(&mut e, &mut key, &mut rng)?;
    let a = e.accept()?;
    let b = e.accept()?;
    let p = Preference {
        priority: 0x800000ff,
        bandwidth: u32::MAX,
        peer: PeerId([9; 32]),
    };
    let mut wire = [0; 44];
    p.encode(false, &mut wire)?;
    e.receive(&a, &wire, 100, &mut key, &mut rng)?;
    e.receive(&b, &wire, 100, &mut key, &mut rng)?;
    assert_eq!(Preference::decode(&wire)?, (p, false));
    assert_eq!(e.snapshot().application_suggestions, 2);
    let first = e.discovery(100)?.ok_or(Error::NotFound)?;
    let second = e.discovery(100)?.ok_or(Error::NotFound)?;
    assert_ne!(first, second);
    p.encode(true, &mut wire)?;
    e.receive(&a, &wire, 101, &mut key, &mut rng)?;
    assert!(!e.discovery_live(&first));
    assert!(e.discovery_live(&second));
    assert_eq!(
        e.discovered_address(&first, b"tcp-127.0.0.1:42", 101),
        Err(Error::Stale)
    );
    assert_eq!(
        e.discovered_address(&second, b"tcp-127.0.0.1:42", 101)?,
        AddressAdmission::Issued
    );
    let original = create(&mut e, &comm)?;
    assert_eq!(&original[8..40], &p.peer.0);
    // Closing the demand does not retract an already admitted service-owned CREATE.
    e.close(&b)?;
    assert_eq!(e.snapshot().application_suggestions, 0);
    assert_eq!(e.snapshot().pending_address_creates, 1);
    assert_eq!(
        e.discovered_address(&second, b"tcp-127.0.0.1:43", 101),
        Err(Error::Stale)
    );
    p.encode(false, &mut wire)?;
    e.receive(&a, &wire, 102, &mut key, &mut rng)?;
    let fresh = e.discovery(102)?.ok_or(Error::NotFound)?;
    assert_ne!(fresh, first);
    assert!(!e.discovery_live(&first));
    assert_eq!(
        e.discovered_address(&fresh, b"tcp-127.0.0.1:42", 102)?,
        AddressAdmission::Existing
    );
    Ok(())
}

#[test]
fn due_retries_preserve_cursor_fairness_and_no_scalar_foreign_authority() -> Result<(), Error> {
    use gnunet_transport::application::Preference;
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut rng = Random;
    let mut e = Engine::new(key.identity(), Limits::default())?;
    let app = e.accept()?;
    let p = Preference {
        priority: 0,
        bandwidth: 0,
        peer: PeerId([9; 32]),
    };
    let mut raw = [0; 44];
    p.encode(false, &mut raw)?;
    e.receive(&app, &raw, 10, &mut key, &mut rng)?;
    let one = e.discovery(10)?.ok_or(Error::NotFound)?;
    assert!(e.discovery(10)?.is_none());
    e.discovery_complete(&one, 10, 37, false)?;
    assert!(e.discovery(1_000_009)?.is_none());
    let two = e.discovery(1_000_010)?.ok_or(Error::NotFound)?;
    assert_eq!(two.cursor(), 37);
    assert_ne!(one, two);
    assert_eq!(
        e.discovery_complete(&one, 1_000_010, 0, true),
        Err(Error::Stale)
    );
    let mut other = Engine::new(key.identity(), Limits::default())?;
    let a2 = other.accept()?;
    other.receive(&a2, &raw, 1_000_010, &mut key, &mut rng)?;
    assert!(!other.discovery_live(&two));
    assert_eq!(
        other.discovered_address(&two, b"tcp-x", 1_000_010),
        Err(Error::Stale)
    );
    e.discovery_complete(&two, 1_000_010, 99, true)?;
    let three = e.discovery(2_000_010)?.ok_or(Error::NotFound)?;
    assert_eq!(three.cursor(), 0);
    Ok(())
}

#[test]
fn full_demand_pool_and_malformed_preferences_are_atomic() -> Result<(), Error> {
    use gnunet_transport::application::Preference;
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut rng = Random;
    let mut e = Engine::new(
        key.identity(),
        Limits {
            peers: 1,
            ..Limits::default()
        },
    )?;
    let app = e.accept()?;
    let p = Preference {
        priority: 0,
        bandwidth: 0,
        peer: PeerId([9; 32]),
    };
    let mut raw = [0; 44];
    p.encode(false, &mut raw)?;
    e.receive(&app, &raw, 10, &mut key, &mut rng)?;
    assert_eq!(
        e.receive(&app, &raw, 10, &mut key, &mut rng),
        Err(Error::Conflict)
    );
    raw[8] = 10;
    assert_eq!(
        e.receive(&app, &raw, 10, &mut key, &mut rng),
        Err(Error::WouldBlock)
    );
    assert_eq!(e.snapshot().application_suggestions, 1);
    let mut too_long = raw.to_vec();
    too_long.push(0);
    too_long[..2].copy_from_slice(&45_u16.to_be_bytes());
    assert_eq!(Preference::decode(&too_long), Err(Error::Malformed));
    let mut output = [0x77; 43];
    assert_eq!(p.encode(false, &mut output), Err(Error::Capacity));
    assert_eq!(output, [0x77; 43]);
    Ok(())
}

#[test]
fn impossible_address_is_declined_so_it_cannot_hold_the_discovery_cursor_forever()
-> Result<(), Error> {
    use gnunet_transport::application::Preference;
    let mut key = Key(EddsaPrivateKey::from_seed([1; 32]));
    let mut rng = Random;
    let mut e = Engine::new(
        key.identity(),
        Limits {
            control_bytes: 120,
            ..Limits::default()
        },
    )?;
    let _comm = setup(&mut e, &mut key, &mut rng)?;
    let app = e.accept()?;
    let p = Preference {
        priority: 0,
        bandwidth: 0,
        peer: PeerId([9; 32]),
    };
    let mut raw = [0; 44];
    p.encode(false, &mut raw)?;
    e.receive(&app, &raw, 100, &mut key, &mut rng)?;
    let original = e.discovery(100)?.ok_or(Error::NotFound)?;
    let mut huge = b"tcp-".to_vec();
    huge.resize(121, b'a');
    assert_ne!(
        format!("{:?}", e.discovered_address(&original, &huge, 100)?),
        "Deferred"
    );
    assert_eq!(e.snapshot().pending_address_creates, 0);
    assert_eq!(
        e.discovered_address(&original, b"tcp-127.0.0.1:42", 100)?,
        gnunet_transport::application::AddressAdmission::Issued
    );
    Ok(())
}
