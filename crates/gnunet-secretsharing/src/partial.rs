use crate::{
    Ciphertext, Element, Entropy, Error, Group, Limits, Progress, Scalar, Subgroup,
    field::{G, Pow, Pow1, Q, Sampler, encode, mul},
};
use crypto_bigint::U1024;
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature, hash512};
use gnunet_wire::official::secretsharing::{
    DECRYPT_ELEMENT_BYTES, DECRYPTION_PURPOSE, DecryptionFields, SignedElement,
};

/// Authenticate the exact complete purpose21/22/23 region with the expected
/// original roster peer. Wire shape decoding is separate; signature validity
/// alone does not establish DKG qualification, freshness, threshold or proof.
pub fn authenticate_element(
    element: &SignedElement<'_>,
    expected_peer: &[u8; 32],
    limits: Limits,
) -> Result<(), Error> {
    limits.validate()?;
    if element.bytes().len() > limits.retained_bytes.min(65535) {
        return Err(Error::Capacity);
    }
    if element.peer().map_err(Error::Source)? != expected_peer {
        return Err(Error::Roster);
    }
    EddsaPublicKey::from_bytes(*expected_peer)
        .verify(
            element.purpose(),
            element.signed_bytes(),
            &EddsaSignature::from_bytes(*element.signature().map_err(Error::Source)?),
        )
        .map_err(Error::Source)
}

fn challenge(bytes: &[u8]) -> U1024 {
    let hash = hash512(bytes);
    let mut padded = [0; 128];
    padded[64..].copy_from_slice(&hash);
    U1024::from_be_slice(&padded)
}
/// Completed original public proof awaiting its real original peer signature.
/// It is intentionally not a signed/verified element. This permits a native
/// owner to use its original PILS signing operation without importing a seed.
pub struct UnsignedPartial {
    bytes: [u8; DECRYPT_ELEMENT_BYTES],
    peer: [u8; 32],
}
impl UnsignedPartial {
    /// Exact purpose23 region for the original native signing operation.
    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes[64..]
    }
    /// Exact required original signing identity.
    #[must_use]
    pub const fn peer(&self) -> &[u8; 32] {
        &self.peer
    }
    /// Verify and attach only a real signature for the original region/peer.
    /// A PILS local write, timeout or unrelated key can never substitute for it.
    pub fn accept_signature(
        mut self,
        signature: EddsaSignature,
    ) -> Result<[u8; DECRYPT_ELEMENT_BYTES], Error> {
        EddsaPublicKey::from_bytes(self.peer)
            .verify(DECRYPTION_PURPOSE, self.signed_bytes(), &signature)
            .map_err(Error::Source)?;
        self.bytes[..64].copy_from_slice(signature.as_bytes());
        Ok(self.bytes)
    }
}
/// Original partial decryption and Chaum–Pedersen proof. The caller supplies
/// the actual roster peer/sigma and transfers its original secret share. The
/// job checks sigma=g^share itself before constructing a proof.
pub struct PartialProver {
    group: Group,
    limits: Limits,
    cipher: Ciphertext,
    peer: [u8; 32],
    sigma: Subgroup,
    share: Option<Scalar>,
    beta: Option<Scalar>,
    sampler: Sampler,
    phase: u8,
    pow: Option<Pow1>,
    partial: Option<Subgroup>,
    commit1: Option<Subgroup>,
    commit2: Option<Subgroup>,
    result: Option<[u8; DECRYPT_ELEMENT_BYTES]>,
    failure: Option<Error>,
    taken: bool,
}
impl PartialProver {
    /// Pin original ciphertext, peer, exponentiated share and owned secret.
    pub fn new(
        group: &Group,
        cipher: Ciphertext,
        peer: [u8; 32],
        sigma: Subgroup,
        share: Scalar,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let pow = Some(Pow::new(&G, &share.0, 1024, &group.p)?);
        Ok(Self {
            group: group.clone(),
            limits,
            cipher,
            peer,
            sigma,
            share: Some(share),
            beta: None,
            sampler: Sampler::new(limits),
            phase: 0,
            pow,
            partial: None,
            commit1: None,
            commit2: None,
            result: None,
            failure: None,
            taken: false,
        })
    }
    fn step(&mut self, entropy: &mut impl Entropy) -> Result<(), Error> {
        if self.phase == 2 {
            let Some(beta) = self.sampler.step(entropy)? else {
                return Ok(());
            };
            self.pow = Some(Pow::new(&G, &beta.0, 1024, &self.group.p)?);
            self.beta = Some(beta);
            self.phase = 3;
            return Ok(());
        }
        if self.phase == 5 {
            let partial = self.partial.ok_or(Error::NotReady)?.to_bytes();
            let c1 = self.commit1.ok_or(Error::NotReady)?.to_bytes();
            let c2 = self.commit2.ok_or(Error::NotReady)?.to_bytes();
            let cipher = self.cipher.to_bytes();
            let zero = [0; 128];
            let mut bytes = [0; DECRYPT_ELEMENT_BYTES];
            DecryptionFields {
                signature: &[0; 64],
                ciphertext: &cipher,
                peer: &self.peer,
                partial: &partial,
                commitment1: &c1,
                commitment2: &c2,
                response: &zero,
            }
            .encode(&mut bytes)
            .map_err(Error::Source)?;
            let e = challenge(&bytes[72..744]);
            let share = self.share.take().ok_or(Error::NotReady)?;
            let beta = self.beta.take().ok_or(Error::NotReady)?;
            let product = self.group.mul_q(&e, &share.0);
            let response = self.group.add_q(&product, &beta.0);
            bytes[744..].copy_from_slice(&encode(&response));
            self.result = Some(bytes);
            self.phase = 6;
            return Ok(());
        }
        if !self.pow.as_mut().ok_or(Error::NotReady)?.step() {
            return Ok(());
        }
        let value = self.pow.take().ok_or(Error::NotReady)?.finish()?;
        match self.phase {
            0 => {
                if *value != self.sigma.0 {
                    return Err(Error::InvalidProof);
                }
                let share = self.share.as_ref().ok_or(Error::NotReady)?;
                self.pow = Some(Pow::new(&self.cipher.c1.0, &share.0, 1024, &self.group.p)?);
                self.phase = 1;
            }
            1 => {
                self.partial = Some(Subgroup(*value));
                self.phase = 2;
            }
            3 => {
                self.commit1 = Some(Subgroup(*value));
                let beta = self.beta.as_ref().ok_or(Error::NotReady)?;
                self.pow = Some(Pow::new(&self.cipher.c1.0, &beta.0, 1024, &self.group.p)?);
                self.phase = 4;
            }
            4 => {
                self.commit2 = Some(Subgroup(*value));
                self.phase = 5;
            }
            _ => return Err(Error::NotReady),
        }
        Ok(())
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.share = None;
        self.beta = None;
        self.pow = None;
        self.result = None;
        e
    }
    /// Advance finite original sampling/exponent/response steps. No key,
    /// ciphertext or roster can be rebound between calls.
    pub fn advance(&mut self, entropy: &mut impl Entropy, units: u16) -> Result<Progress, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if self.result.is_some() {
            return Ok(Progress::Ready);
        }
        let count = match self.limits.units(units) {
            Ok(n) => n,
            Err(e) => return Err(self.fail(e)),
        };
        for _ in 0..count {
            if let Err(e) = self.step(entropy) {
                return Err(self.fail(e));
            }
            if self.result.is_some() {
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Sign exactly the completed original purpose23 region with the supplied
    /// real EdDSA peer key. An unrelated/rotated identity does not consume it.
    pub fn take_signed(
        &mut self,
        signer: &EddsaPrivateKey,
    ) -> Result<[u8; DECRYPT_ELEMENT_BYTES], Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if signer.public_key().as_bytes() != &self.peer {
            return Err(Error::Roster);
        }
        let bytes = self.result.as_mut().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        let signature = signer
            .sign(DECRYPTION_PURPOSE, &bytes[64..])
            .map_err(Error::Source)?;
        bytes[..64].copy_from_slice(signature.as_bytes());
        let out = self.result.take().ok_or(Error::NotReady)?;
        self.taken = true;
        Ok(out)
    }
    /// Transfer exactly one completed original unsigned transcript to the
    /// caller's actual signing owner. No IO/signature/peer acceptance is implied.
    pub fn take_unsigned(&mut self) -> Result<UnsignedPartial, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        let bytes = self.result.take().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        self.taken = true;
        Ok(UnsignedPartial {
            bytes,
            peer: self.peer,
        })
    }
    /// Erase all owned original secret work and any not-yet-signed result.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}
/// Actually verified original peer/cipher/sigma/index association. No public
/// constructor, Clone, signature flag or native receipt can fabricate this type.
pub struct VerifiedPartial {
    pub(crate) peer: [u8; 32],
    pub(crate) index: u16,
    pub(crate) sigma: Subgroup,
    pub(crate) cipher: Ciphertext,
    pub(crate) value: Subgroup,
}
impl VerifiedPartial {
    /// Original exact ciphertext whose partial decryption was verified.
    #[must_use]
    pub const fn ciphertext(&self) -> &Ciphertext {
        &self.cipher
    }
    /// Original checked share commitment bound to this authenticated partial.
    #[must_use]
    pub const fn share_commitment(&self) -> Subgroup {
        self.sigma
    }
    /// Actual authenticated original roster peer.
    #[must_use]
    pub const fn peer(&self) -> &[u8; 32] {
        &self.peer
    }
    /// Original DKG polynomial index, never the reduced roster's array offset.
    #[must_use]
    pub const fn original_index(&self) -> u16 {
        self.index
    }
    /// Actually checked partial decryption.
    #[must_use]
    pub const fn value(&self) -> Subgroup {
        self.value
    }
}
/// Real signature, three membership checks and both DLEQ equations for the
/// original signed872-byte decryption element. No full DKG trust is implied.
pub struct PartialVerifier {
    group: Group,
    limits: Limits,
    cipher: Ciphertext,
    peer: [u8; 32],
    index: u16,
    sigma: Subgroup,
    points: [U1024; 3],
    response: U1024,
    challenge: U1024,
    phase: u8,
    pow: Option<Pow1>,
    left: Option<U1024>,
    result: Option<VerifiedPartial>,
    failure: Option<Error>,
    taken: bool,
}
impl PartialVerifier {
    /// The expected peer/index/sigma come from the same original selected share;
    /// cryptographic signature validity cannot choose or replace that roster.
    pub fn new(
        group: &Group,
        cipher: Ciphertext,
        peer: [u8; 32],
        index: u16,
        sigma: Subgroup,
        bytes: &[u8; DECRYPT_ELEMENT_BYTES],
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let element = SignedElement::decryption(bytes).map_err(Error::Source)?;
        if element.peer().map_err(Error::Source)? != &peer
            || element.ciphertext().map_err(Error::Source)? != &cipher.to_bytes()
        {
            return Err(Error::Roster);
        }
        EddsaPublicKey::from_bytes(peer)
            .verify(
                DECRYPTION_PURPOSE,
                element.signed_bytes(),
                &EddsaSignature::from_bytes(*element.signature().map_err(Error::Source)?),
            )
            .map_err(Error::Source)?;
        let mut points = [U1024::ZERO; 3];
        for (i, point) in points.iter_mut().enumerate() {
            let bytes = element
                .decryption_field(i)
                .map_err(Error::Source)?
                .ok_or(Error::InvalidInput)?;
            let value = Element::from_bytes(bytes)?;
            if value.0 == U1024::ZERO {
                return Err(Error::InvalidProof);
            }
            *point = value.0;
        }
        let response = U1024::from_be_slice(
            element
                .decryption_field(3)
                .map_err(Error::Source)?
                .ok_or(Error::InvalidInput)?,
        );
        if response >= Q {
            return Err(Error::InvalidProof);
        }
        let challenge = challenge(
            element
                .decryption_challenge_bytes()
                .map_err(Error::Source)?,
        );
        let pow = Some(Pow::new(&points[0], &Q, 1024, &group.p)?);
        Ok(Self {
            group: group.clone(),
            limits,
            cipher,
            peer,
            index,
            sigma,
            points,
            response,
            challenge,
            phase: 0,
            pow,
            left: None,
            result: None,
            failure: None,
            taken: false,
        })
    }
    fn step(&mut self) -> Result<(), Error> {
        if !self.pow.as_mut().ok_or(Error::NotReady)?.step() {
            return Ok(());
        }
        let value = self.pow.take().ok_or(Error::NotReady)?.finish()?;
        match self.phase {
            0..=2 => {
                if *value != U1024::ONE {
                    return Err(Error::InvalidProof);
                }
                self.phase += 1;
                let (base, exponent) = if self.phase < 3 {
                    (self.points[usize::from(self.phase)], Q)
                } else {
                    (G, self.response)
                };
                self.pow = Some(Pow::new(&base, &exponent, 1024, &self.group.p)?);
            }
            3 => {
                self.left = Some(*value);
                self.pow = Some(Pow::new(
                    &self.sigma.0,
                    &self.challenge,
                    1024,
                    &self.group.p,
                )?);
                self.phase = 4;
            }
            4 => {
                let rhs = mul(&value, &self.points[1], &self.group.p);
                if Some(*rhs) != self.left {
                    return Err(Error::InvalidProof);
                }
                self.left = None;
                self.pow = Some(Pow::new(
                    &self.cipher.c1.0,
                    &self.response,
                    1024,
                    &self.group.p,
                )?);
                self.phase = 5;
            }
            5 => {
                self.left = Some(*value);
                self.pow = Some(Pow::new(
                    &self.points[0],
                    &self.challenge,
                    1024,
                    &self.group.p,
                )?);
                self.phase = 6;
            }
            6 => {
                let rhs = mul(&value, &self.points[2], &self.group.p);
                if Some(*rhs) != self.left {
                    return Err(Error::InvalidProof);
                }
                self.left = None;
                self.result = Some(VerifiedPartial {
                    peer: self.peer,
                    index: self.index,
                    sigma: self.sigma,
                    cipher: self.cipher,
                    value: Subgroup(self.points[0]),
                });
                self.phase = 7;
            }
            _ => return Err(Error::NotReady),
        }
        Ok(())
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.pow = None;
        self.result = None;
        e
    }
    /// One actual exponent bit per unit, with the exact original signature,
    /// transcript challenge and both equations retained across all calls.
    pub fn advance(&mut self, units: u16) -> Result<Progress, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if self.result.is_some() {
            return Ok(Progress::Ready);
        }
        let count = match self.limits.units(units) {
            Ok(n) => n,
            Err(e) => return Err(self.fail(e)),
        };
        for _ in 0..count {
            if let Err(e) = self.step() {
                return Err(self.fail(e));
            }
            if self.result.is_some() {
                return Ok(Progress::Ready);
            }
        }
        Ok(Progress::Advanced)
    }
    /// Consume only the actual authenticated and mathematically checked partial.
    pub fn take_result(&mut self) -> Result<VerifiedPartial, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        let result = self.result.take().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        self.taken = true;
        Ok(result)
    }
    /// Retire the original verification; no proof result is fabricated.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}
