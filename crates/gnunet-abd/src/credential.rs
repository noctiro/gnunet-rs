use alloc::vec::Vec;
use gnunet_crypto::{
    EddsaPrivateKey,
    gns::{PkeySecret, verify_edkey, verify_pkey},
};
use gnunet_identity::SecretKey;
use gnunet_types::Error;
use gnunet_wire::official::abd::{self, Delegate, Key, SignedDelegate};
use zeroize::Zeroizing;

/// Owned public blindable key including its original BE32 curve type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Principal([u8; abd::KEY_BYTES]);
impl Principal {
    /// Validate the supported official key type; authorization is not implied.
    pub fn new(bytes: [u8; abd::KEY_BYTES]) -> Result<Self, Error> {
        Key::new(&bytes)?;
        Ok(Self(bytes))
    }
    /// Copy an already structurally validated public key.
    #[must_use]
    pub fn from_key(key: Key<'_>) -> Self {
        Self(*key.bytes())
    }
    /// Exact official typed public key.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; abd::KEY_BYTES] {
        &self.0
    }
    /// Borrow its validated wire view, without a panic or crypto operation.
    pub fn view(&self) -> Result<Key<'_>, Error> {
        Key::new(&self.0)
    }
}

/// Caller-observed monotonic time and conservative trusted UTC interval.
#[derive(Clone, Copy, Debug)]
pub struct Time {
    /// Monotonic microseconds in the original query's clock domain.
    pub monotonic_us: u64,
    /// Earliest possible actual UTC microseconds.
    pub utc_earliest_us: u64,
    /// Latest possible actual UTC microseconds.
    pub utc_latest_us: u64,
}
impl Time {
    /// Reject incoherent clock intervals; no clock or UTC is manufactured here.
    pub fn validate(self) -> Result<(), Error> {
        if self.utc_earliest_us > self.utc_latest_us {
            Err(Error::InvalidInput)
        } else {
            Ok(())
        }
    }
    /// Establish strict nonexpiration across the entire trusted UTC interval.
    pub fn valid_until(self, expiration_us: u64) -> Result<(), Error> {
        self.validate()?;
        if expiration_us == u64::MAX {
            return Ok(());
        }
        if self.utc_earliest_us >= expiration_us {
            return Err(Error::Timeout);
        }
        if self.utc_latest_us >= expiration_us {
            return Err(Error::TimeUncertain);
        }
        Ok(())
    }
}

/// Canonical original signed DEL owner. Construction actually verifies both
/// purpose28 and the issuer's signature. It contains no private key material.
pub struct Credential {
    bytes: Vec<u8>,
}
impl Credential {
    /// Authenticate an exact singular GNS record and preserve its signed bytes.
    /// Signed attributes remain byte-for-byte original, including case; graph
    /// role normalization is separate and cannot change the signed payload.
    pub fn verify_record(
        input: &[u8],
        time: Time,
        maximum: usize,
        available: usize,
    ) -> Result<Self, Error> {
        let signed = SignedDelegate::decode(input)?;
        let value = signed.delegate();
        check_attributes(value, maximum)?;
        time.valid_until(value.expiration_us)?;
        let public: &[u8; 32] = value
            .issuer
            .material()
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let signature: &[u8; 64] = value.signature[4..]
            .try_into()
            .map_err(|_| Error::Malformed)?;
        match value.issuer.kind() {
            abd::PKEY => verify_pkey(
                public,
                abd::DELEGATE_PURPOSE,
                &[signed.signed_bytes()],
                signature,
            )?,
            abd::EDKEY => verify_edkey(
                public,
                abd::DELEGATE_PURPOSE,
                &[signed.signed_bytes()],
                signature,
            )?,
            _ => return Err(Error::Unsupported),
        }
        Ok(Self {
            bytes: crate::resource::copy(input, available)?,
        })
    }
    /// Restore the C IPC leaf's omitted canonical NUL/length before verifying
    /// its original signature. A raw any-nonzero status never reaches this path.
    pub fn verify_ipc(
        value: Delegate<'_>,
        time: Time,
        maximum: usize,
        available: usize,
    ) -> Result<Self, Error> {
        if value.subject_attribute.is_some() {
            return Err(Error::Unsupported);
        }
        check_attributes(value, maximum)?;
        time.valid_until(value.expiration_us)?;
        let n = value.record_len()?;
        let mut bytes = crate::resource::filled(n, 0u8, available)?;
        value.encode_record(&mut bytes)?;
        // Authenticate in place instead of keeping a second retained allocation.
        let result = Self { bytes };
        result.authenticate(time, maximum)?;
        Ok(result)
    }
    fn authenticate(&self, time: Time, maximum: usize) -> Result<(), Error> {
        let signed = self.view()?;
        let value = signed.delegate();
        check_attributes(value, maximum)?;
        time.valid_until(value.expiration_us)?;
        let public: &[u8; 32] = value
            .issuer
            .material()
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let sig: &[u8; 64] = value.signature[4..]
            .try_into()
            .map_err(|_| Error::Malformed)?;
        match value.issuer.kind() {
            abd::PKEY => verify_pkey(public, abd::DELEGATE_PURPOSE, &[signed.signed_bytes()], sig),
            abd::EDKEY => {
                verify_edkey(public, abd::DELEGATE_PURPOSE, &[signed.signed_bytes()], sig)
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Borrow the immutable canonical signed record.
    pub fn view(&self) -> Result<SignedDelegate<'_>, Error> {
        SignedDelegate::decode(&self.bytes)
    }
    /// Exact canonical record, suitable for an actual GNS/namestore owner.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Actual retained public allocation, including unused spare capacity.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.bytes.capacity()
    }
}
fn check_attributes(value: Delegate<'_>, maximum: usize) -> Result<(), Error> {
    let valid = |s: &[u8]| {
        !s.is_empty() && s.len() <= maximum && !s.contains(&0) && core::str::from_utf8(s).is_ok()
    };
    if !valid(value.issuer_attribute) || value.subject_attribute.is_some_and(|s| !valid(s)) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// Issue a real original-key PKEY/EDKEY purpose28 credential. The secret owner
/// is borrowed, temporary seeds/scalars are erased, and no entropy/FFI or native
/// service is hidden here. Public attributes are signed exactly as supplied.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit original signed fields, trusted time and finite resource profile are independent inputs"
)]
pub fn issue(
    secret: &SecretKey,
    subject: Principal,
    issuer_attribute: &[u8],
    subject_attribute: Option<&[u8]>,
    expiration_us: u64,
    time: Time,
    maximum: usize,
    available: usize,
) -> Result<Credential, Error> {
    time.valid_until(expiration_us)?;
    let issuer = secret.public_key()?;
    let mut signature = [0u8; abd::SIGNATURE_BYTES];
    signature[..4].copy_from_slice(&issuer[..4]);
    let fields = Delegate {
        signature: &signature,
        issuer: Key::new(&issuer)?,
        subject: subject.view()?,
        expiration_us,
        issuer_attribute,
        subject_attribute,
    };
    check_attributes(fields, maximum)?;
    let n = fields.record_len()?;
    let mut bytes = crate::resource::filled(n, 0u8, available)?;
    fields.encode_record(&mut bytes)?;
    let mut material = Zeroizing::new([0u8; 32]);
    material.copy_from_slice(&secret.expose_serialized()[4..]);
    let sig = match u32::from_be_bytes([issuer[0], issuer[1], issuer[2], issuer[3]]) {
        abd::PKEY => {
            PkeySecret::from_bytes(*material)?.sign(abd::DELEGATE_PURPOSE, &[&bytes[68..]])?
        }
        abd::EDKEY => *EddsaPrivateKey::from_seed(*material)
            .sign(abd::DELEGATE_PURPOSE, &bytes[68..])?
            .as_bytes(),
        _ => return Err(Error::Unsupported),
    };
    bytes[4..68].copy_from_slice(&sig);
    Ok(Credential { bytes })
}
