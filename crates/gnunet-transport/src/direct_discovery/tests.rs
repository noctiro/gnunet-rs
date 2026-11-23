use super::*;
use gnunet_crypto::EddsaPrivateKey;
use gnunet_hello::{HelloBuilder, MESSAGE_FIXED_LEN};

const LIMITS: Limits = Limits {
    maximum_input_bytes: 256,
    maximum_address_bytes: 96,
    maximum_addresses: 4,
};
const NOW: AbsoluteTime = AbsoluteTime::from_micros(50);
const FIRST: AbsoluteTime = AbsoluteTime::from_micros(100);
const SECOND: AbsoluteTime = AbsoluteTime::from_micros(150);

fn message(
    key: &EddsaPrivateKey,
    addresses: &[&[u8]],
    expiration: AbsoluteTime,
    profile: SignatureProfile,
    output: &mut [u8],
) -> Result<usize, Error> {
    let mut canonical = [0; LIMITS.maximum_address_bytes];
    let mut builder = HelloBuilder::new(&mut canonical, LIMITS);
    for address in addresses {
        builder.add_address(address)?;
    }
    builder
        .sign(key, expiration, profile)?
        .encode_message(output)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact proof and candidate selection after fallible encoding"
)]
fn metadata_only_hello_requires_its_original_authenticated_subject() -> Result<(), Error> {
    let subject = EddsaPrivateKey::from_seed([4; 32]);
    let other = EddsaPrivateKey::from_seed([5; 32]);
    let mut retained = [0; LIMITS.maximum_address_bytes];
    let mut scratch = [0; LIMITS.maximum_address_bytes];
    let mut wire = [0; LIMITS.maximum_input_bytes];
    let mut book = Book::new(subject.public_key(), &mut retained, LIMITS)?;
    let profile = SignatureProfile::Gnunet029;
    let address = b"tcp://192.0.2.1:2086";
    let used = message(&subject, &[address], FIRST, profile, &mut wire)?;
    assert!(is_hello_uri(&wire[..used]));
    assert_eq!(
        book.import_signed(Input::Message(&wire[..used]), NOW, &mut scratch),
        Err(Error::Authentication)
    );
    assert_eq!(
        book.receive_authenticated(
            other.public_key(),
            &wire[..used],
            profile,
            NOW,
            &mut scratch
        ),
        Err(Error::Authentication)
    );
    let used = message(&other, &[address], FIRST, profile, &mut wire)?;
    assert_eq!(
        book.receive_authenticated(
            subject.public_key(),
            &wire[..used],
            profile,
            NOW,
            &mut scratch
        ),
        Err(Error::Authentication)
    );
    assert_eq!(book.current(NOW)?, None);
    let used = message(&subject, &[address], FIRST, profile, &mut wire)?;
    assert_eq!(
        book.receive_authenticated(
            subject.public_key(),
            &wire[..used],
            profile,
            NOW,
            &mut scratch
        ),
        Ok(Update::Published)
    );
    let snapshot = book.current(NOW)?.ok_or(Error::NotFound)?;
    assert_eq!(snapshot.proof(), AddressProof::AuthenticatedCore);

    let profile = SignatureProfile::DeterministicPidDerivation;
    let used = message(&subject, &[address], FIRST, profile, &mut wire)?;
    assert_eq!(
        book.import_signed(Input::Message(&wire[..used]), NOW, &mut scratch),
        Ok(Update::Unchanged)
    );
    let candidate = book.select(NOW, |_| Some(0))?.ok_or(Error::NotFound)?;
    assert_eq!(candidate.proof(), AddressProof::Signature);
    assert_eq!(candidate.address().as_bytes(), address);
    assert_eq!(candidate.peer(), subject.public_key());
    assert_eq!(candidate.expiration(), FIRST);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact expiry, withdrawal and original record preservation"
)]
fn signed_set_replacement_and_expiry_preserve_the_original_floor() -> Result<(), Error> {
    let subject = EddsaPrivateKey::from_seed([6; 32]);
    let mut retained = [0; LIMITS.maximum_address_bytes];
    let mut scratch = [0; LIMITS.maximum_address_bytes];
    let mut wire = [0; LIMITS.maximum_input_bytes];
    let mut book = Book::new(subject.public_key(), &mut retained, LIMITS)?;
    let profile = SignatureProfile::DeterministicPidDerivation;
    let first = b"tcp://192.0.2.1:2086";
    let last = b"tcp://192.0.2.2:2086";
    let used = message(&subject, &[first, last], FIRST, profile, &mut wire)?;
    assert_eq!(
        book.import_signed(Input::Message(&wire[..used]), NOW, &mut scratch),
        Ok(Update::Published)
    );
    let selected = book.select(NOW, |_| Some(0))?.ok_or(Error::NotFound)?;
    assert_eq!(selected.address().as_bytes(), last);
    let selected = book
        .select(NOW, |address| Some(u16::from(address.as_bytes() == first)))?
        .ok_or(Error::NotFound)?;
    assert_eq!(selected.address().as_bytes(), first);

    let used = message(&subject, &[first], SECOND, profile, &mut wire)?;
    wire[MESSAGE_FIXED_LEN + 8] = b'3';
    assert_eq!(
        book.import_signed(Input::Message(&wire[..used]), NOW, &mut scratch),
        Err(Error::Authentication)
    );
    let used = message(&subject, &[last], FIRST, profile, &mut wire)?;
    assert_eq!(
        book.import_signed(Input::Message(&wire[..used]), NOW, &mut scratch),
        Err(Error::Conflict)
    );
    assert_eq!(book.next_expiration(), Some(FIRST));
    assert_eq!(book.current(FIRST)?, None);
    assert_eq!(book.next_expiration(), Some(FIRST));
    assert!(book.expire(FIRST)?);
    assert!(!book.expire(FIRST)?);
    assert_eq!(book.next_expiration(), None);
    assert_eq!(book.current(NOW), Err(Error::TimeUncertain));

    let used = message(&subject, &[], SECOND, profile, &mut wire)?;
    assert_eq!(
        book.import_signed(Input::Message(&wire[..used]), FIRST, &mut scratch),
        Ok(Update::Withdrawn)
    );
    let between = AbsoluteTime::from_micros(120);
    let used = message(&subject, &[first], between, profile, &mut wire)?;
    assert_eq!(
        book.import_signed(Input::Message(&wire[..used]), FIRST, &mut scratch),
        Err(Error::Replay)
    );
    assert_eq!(book.select(FIRST, |_| Some(0))?, None);
    Ok(())
}
