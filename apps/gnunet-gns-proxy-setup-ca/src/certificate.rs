//! Real CA generation uses the existing Rust AWS-LC-backed certificate provider.
use crate::{Cause, budget::Budget};
use base64ct::{Base64, Encoding};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use zeroize::Zeroizing;

pub(super) struct Generated {
    pub certificate: Zeroizing<String>,
    pub private_key: Zeroizing<String>,
}
pub(super) fn generate(budget: &Budget) -> Result<Generated, Cause> {
    budget.check()?;
    let now = time::OffsetDateTime::now_utc();
    let mut name = DistinguishedName::new();
    name.push(DnType::CountryName, "ZZ");
    name.push(DnType::LocalityName, "World");
    name.push(DnType::OrganizationName, "GNU");
    name.push(DnType::OrganizationalUnitName, "GNUnet");
    name.push(DnType::CommonName, "GNS Proxy CA");
    name.push(
        DnType::CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]),
        DnValue::Ia5String("bounce@gnunet.org".try_into()?),
    );
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.not_before = now
        .checked_sub(time::Duration::minutes(5))
        .ok_or("CA not-before overflow")?;
    params.not_after = now
        .checked_add(time::Duration::days(3650))
        .ok_or("CA expiration overflow")?;
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.use_authority_key_identifier_extension = true;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    budget.check()?;
    let certificate = params.self_signed(&key)?;
    budget.check()?;
    let private_der = Zeroizing::new(key.serialize_der());
    let generated = Generated {
        certificate: pem("CERTIFICATE", certificate.der().as_ref())?,
        private_key: pem("PRIVATE KEY", &private_der)?,
    };
    if generated.certificate.len() > 16 * 1024 || generated.private_key.len() > 16 * 1024 {
        return Err("generated CA exceeds the local PEM profile".into());
    }
    budget.check()?;
    Ok(generated)
}

// Encode only bounded DER using the already-admitted Base64 implementation.
// Every private DER/Base64/PEM buffer we create has a zeroizing owner.
fn pem(label: &str, der: &[u8]) -> Result<Zeroizing<String>, Cause> {
    if der.len() > 16 * 1024 {
        return Err("generated CA DER exceeds the local profile".into());
    }
    let encoded = Zeroizing::new(Base64::encode_string(der));
    let capacity = encoded
        .len()
        .checked_add(encoded.len() / 64)
        .and_then(|size| size.checked_add(128))
        .ok_or("CA PEM size overflow")?;
    let mut pem = Zeroizing::new(String::new());
    pem.try_reserve_exact(capacity)?;
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line)?);
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    Ok(pem)
}
