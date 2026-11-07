//! Unexecuted source cases. GNS source completion is explicitly mocked; none of
//! these cases establishes native transport or official C interoperability.
use super::*;
use alloc::{vec, vec::Vec};
use gnunet_identity::SecretKey;
use gnunet_types::Error;
use gnunet_wire::official::abd::{self, Delegates, Policy, Term};

fn time() -> Time {
    Time {
        monotonic_us: 1,
        utc_earliest_us: 100,
        utc_latest_us: 110,
    }
}
fn principal(seed: u8) -> Result<Principal, Error> {
    let mut bytes = [seed; 36];
    bytes[..4].copy_from_slice(&abd::EDKEY.to_be_bytes());
    Principal::new(SecretKey::new(bytes)?.public_key()?)
}
fn policy(terms: &[(Principal, Option<&[u8]>)]) -> Result<Vec<u8>, Error> {
    let mut payload = Vec::new();
    for (key, attr) in terms {
        let term = Term {
            subject: key.view()?,
            attribute: *attr,
        };
        let mut encoded = vec![0; term.encoded_len()?];
        term.encode(&mut encoded)?;
        payload.extend_from_slice(&encoded);
    }
    let value = Policy::from_terms(
        &payload,
        u32::try_from(terms.len()).map_err(|_| Error::TooLarge)?,
    )?;
    let layout = Limits::default().record_layout;
    let mut record = vec![0; value.encoded_len(layout)?];
    value.encode(&mut record, layout)?;
    Ok(record)
}
fn drive(
    query: &mut Query<'_>,
    mut records: impl FnMut(Principal, &[u8]) -> Result<Option<Vec<u8>>, Error>,
) -> Result<Outcome, Error> {
    let mut source = 1u64;
    for _ in 0..1000 {
        query.advance(time(), 64)?;
        while let Some(effect) = query.effect() {
            let id = effect.id;
            let work = match effect.action {
                Action::Lookup {
                    zone,
                    attribute,
                    record_type,
                } => Some((zone, attribute.to_vec(), record_type)),
                Action::Cancel { source } => {
                    query.finish_lookup(id, source)?;
                    None
                }
            };
            if let Some((zone, attr, record_type)) = work {
                source = source.checked_add(1).ok_or(Error::Overflow)?;
                query.admit(id, source)?;
                if let Some(data) = records(zone, &attr)? {
                    query.record(
                        id,
                        source,
                        Record {
                            record_type,
                            data: &data,
                            expiration_us: 1_000_000,
                        },
                        time(),
                    )?;
                }
                query.finish_lookup(id, source)?;
            }
        }
        if let Some(outcome) = query.outcome(time())? {
            return Ok(outcome);
        }
    }
    Err(Error::NotReady)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "source assertions cover actual signature verification after the C request's distinct non-NUL serialization"
)]
fn real_signed_c_leaf_and_subject_binding() -> Result<(), Error> {
    let mut bytes = [17; 36];
    bytes[..4].copy_from_slice(&abd::EDKEY.to_be_bytes());
    let secret = SecretKey::new(bytes)?;
    let issuer = Principal::new(secret.public_key()?)?;
    let subject = principal(19)?;
    let value = issue(
        &secret,
        subject,
        b"member",
        None,
        1_000_000,
        time(),
        253,
        65536,
    )?;
    let fields = value.view()?.delegate();
    let mut raw = vec![0; fields.ipc_len(false)?];
    fields.encode_ipc(&mut raw, false)?;
    assert!(raw.last() == Some(&b'r'));
    let list = Delegates::new(&raw, 1)?;
    let leaf = list.iter().next().ok_or(Error::NotFound)?;
    let verified = Credential::verify_ipc(leaf, time(), 253, 65536)?;
    assert!(verified.bytes() == value.bytes());
    let brand = Instance::new();
    let mut query = Query::new(
        &brand,
        issuer,
        b"member",
        subject,
        abd::FORWARD,
        Limits::default(),
        1_000_000,
        time(),
    )?;
    query.add_credential(verified, time())?;
    assert!(matches!(
        drive(&mut query, |_, _| Ok(None))?,
        Outcome::Authorized { .. }
    ));
    assert!(query.proof_credentials().count() == 1);
    let other = principal(23)?;
    let verified = Credential::verify_ipc(leaf, time(), 253, 65536)?;
    let mut wrong = Query::new(
        &brand,
        issuer,
        b"member",
        other,
        abd::FORWARD,
        Limits::default(),
        1_000_000,
        time(),
    )?;
    wrong.add_credential(verified, time())?;
    assert!(drive(&mut wrong, |_, _| Ok(None))? == Outcome::Denied);
    let mut bad = value.bytes().to_vec();
    bad[20] ^= 1;
    assert!(matches!(
        Credential::verify_record(&bad, time(), 253, 65536),
        Err(Error::Authentication)
    ));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "source assertions require every AND term for the same requested principal and permit a real direct GNS proof without fake credentials"
)]
fn same_subject_conjunction_and_direct_gns_proof() -> Result<(), Error> {
    let brand = Instance::new();
    let a = principal(1)?;
    let b = principal(2)?;
    let c = principal(3)?;
    let s = principal(4)?;
    let other = principal(5)?;
    for shared in [false, true] {
        let mut query = Query::new(
            &brand,
            a,
            b"root",
            s,
            abd::BACKWARD,
            Limits::default(),
            1_000_000,
            time(),
        )?;
        let outcome = drive(&mut query, |zone, attr| {
            let terms = if zone == a && attr == b"root" {
                vec![(b, Some(&b"left"[..])), (c, Some(&b"right"[..]))]
            } else if zone == b && attr == b"left" {
                vec![(s, None)]
            } else if zone == c && attr == b"right" {
                vec![(if shared { s } else { other }, None)]
            } else {
                return Ok(None);
            };
            Ok(Some(policy(&terms)?))
        })?;
        assert!(matches!(outcome, Outcome::Authorized { .. }) == shared);
        if shared {
            assert!(query.proof_credentials().count() == 0 && query.proof_edges().count() == 4);
        } else {
            assert!(outcome == Outcome::Denied);
        }
        assert!(query.is_quiescent());
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "source assertions reject distributing a linked-role tail across different AND witnesses and retain original cancellation debts"
)]
fn linked_and_requires_one_intermediate_and_original_cancel() -> Result<(), Error> {
    let brand = Instance::new();
    let a = principal(1)?;
    let b = principal(2)?;
    let c = principal(3)?;
    let d = principal(4)?;
    let x = principal(5)?;
    let y = principal(6)?;
    let s = principal(7)?;
    let mut query = Query::new(
        &brand,
        a,
        b"root",
        s,
        abd::BACKWARD,
        Limits::default(),
        1_000_000,
        time(),
    )?;
    let outcome = drive(&mut query, |zone, attr| {
        let terms = if zone == a && attr == b"root" {
            vec![(b, Some(&b"roles.tail"[..]))]
        } else if zone == b && attr == b"roles" {
            vec![(c, Some(&b"left"[..])), (d, Some(&b"right"[..]))]
        } else if zone == c && attr == b"left" {
            vec![(x, None)]
        } else if zone == d && attr == b"right" {
            vec![(y, None)]
        } else if (zone == x || zone == y) && attr == b"tail" {
            vec![(s, None)]
        } else {
            return Ok(None);
        };
        Ok(Some(policy(&terms)?))
    })?;
    assert!(outcome == Outcome::Denied);
    let mut query = Query::new(
        &brand,
        a,
        b"root",
        s,
        abd::BACKWARD,
        Limits::default(),
        1_000_000,
        time(),
    )?;
    let id = query.effect().ok_or(Error::NotReady)?.id;
    query.admit(id, 17)?;
    query.cancel();
    assert!(query.pending_sources() == 1 && !query.is_quiescent());
    assert!(matches!(
        query.effect().ok_or(Error::NotReady)?.action,
        Action::Cancel { source: 17 }
    ));
    assert!(query.finish_lookup(id, 18) == Err(Error::StaleGeneration));
    query.finish_lookup(id, 17)?;
    assert!(query.is_quiescent() && query.outcome(time())? == Some(Outcome::Cancelled));
    Ok(())
}
