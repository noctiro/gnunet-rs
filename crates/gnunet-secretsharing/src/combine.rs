use crate::{
    Ciphertext, Error, Group, Limits, Plaintext, Progress, Subgroup, VerifiedPartial,
    field::{P, Pow, Pow1, Q, mul},
};
use alloc::vec::Vec;
use crypto_bigint::U1024;
use zeroize::Zeroizing;

/// One original qualified DKG participant. The original index is the point
/// x=index+1, independent of this participant's position after roster reduction.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Participant {
    /// Original authenticated consensus/peer identity.
    pub peer: [u8; 32],
    /// Original polynomial index, before any disqualification/removal.
    pub original_index: u16,
    /// Actual checked exponentiated aggregate share g^s_i.
    pub sigma: Subgroup,
}
/// Fixed original qualified roster, its original threshold and aggregate key.
/// This records the caller's completed DKG decision; it is not DKG itself.
pub struct Roster {
    members: Vec<Participant>,
    threshold: usize,
    public_key: Subgroup,
    limits: Limits,
}
impl Roster {
    /// Begin bounded uniqueness/threshold admission of one original snapshot.
    pub fn check(
        members: Vec<Participant>,
        threshold: usize,
        public_key: Subgroup,
        limits: Limits,
    ) -> Result<RosterCheck, Error> {
        limits.validate()?;
        if threshold == 0 || threshold > members.len() || members.len() > limits.participants {
            return Err(Error::Roster);
        }
        limits.bytes::<Participant>(members.capacity(), 0)?;
        Ok(RosterCheck {
            roster: Some(Self {
                members,
                threshold,
                public_key,
                limits,
            }),
            a: 0,
            b: 1,
            ready: false,
            failure: None,
            taken: false,
        })
    }
    /// Original required number of distinct valid partial decryptions.
    #[must_use]
    pub const fn threshold(&self) -> usize {
        self.threshold
    }
    /// Original qualified count, not a maximum original index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }
    /// A usable roster never contains zero members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
    /// Original aggregate public key.
    #[must_use]
    pub const fn public_key(&self) -> Subgroup {
        self.public_key
    }
    /// Original qualified member at its retained array position.
    #[must_use]
    pub fn get(&self, position: usize) -> Option<Participant> {
        self.members.get(position).copied()
    }
    /// Actual retained allocation capacity for this original roster.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.limits.bytes::<Participant>(self.members.capacity(), 0)
    }
}
/// Original roster admission advances one distinct-pair check per unit. Large
/// legal rosters never trigger an unbounded quadratic constructor loop.
pub struct RosterCheck {
    roster: Option<Roster>,
    a: usize,
    b: usize,
    ready: bool,
    failure: Option<Error>,
    taken: bool,
}
impl RosterCheck {
    /// At most units actual peer/index comparisons; neither column is reordered.
    pub fn advance(&mut self, units: u16) -> Result<Progress, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if self.taken {
            return Err(Error::Finished);
        }
        if self.ready {
            return Ok(Progress::Ready);
        }
        let roster = self.roster.as_ref().ok_or(Error::NotReady)?;
        let count = match roster.limits.units(units) {
            Ok(n) => n,
            Err(e) => return Err(self.fail(e)),
        };
        for _ in 0..count {
            let roster = self.roster.as_ref().ok_or(Error::NotReady)?;
            let n = roster.members.len();
            if self.a + 1 >= n {
                self.ready = true;
                return Ok(Progress::Ready);
            }
            if self.b >= n {
                self.a += 1;
                self.b = self.a + 1;
                continue;
            }
            let a = roster.members[self.a];
            let b = roster.members[self.b];
            if a.peer == b.peer || a.original_index == b.original_index {
                return Err(self.fail(Error::Roster));
            }
            self.b += 1;
        }
        Ok(Progress::Advanced)
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.roster = None;
        e
    }
    /// Consume the actual unique original snapshot once.
    pub fn take_result(&mut self) -> Result<Roster, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        if !self.ready {
            return Err(Error::NotReady);
        }
        let roster = self.roster.take().ok_or(Error::Finished)?;
        self.taken = true;
        Ok(roster)
    }
    /// Cancel original roster admission without accepting a partial snapshot.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
}
/// Original threshold combination over actual signature+DLEQ checked partials.
/// Each interpolation point is the original stored index, never used as an
/// offset into a shortened roster. Native consensus/timeout policy is separate.
enum RosterView<'a> {
    Borrowed(&'a Roster),
    Owned(Roster),
}
impl core::ops::Deref for RosterView<'_> {
    type Target = Roster;
    fn deref(&self) -> &Roster {
        match self {
            Self::Borrowed(roster) => roster,
            Self::Owned(roster) => roster,
        }
    }
}
/// Original verified-partial combination. The roster view is immutable and
/// either borrows its original owner or adopts that exact existing owner.
pub struct CombineJob<'a> {
    group: Group,
    roster: RosterView<'a>,
    cipher: Ciphertext,
    partials: Option<Vec<VerifiedPartial>>,
    limits: Limits,
    phase: u8,
    at: usize,
    other: usize,
    lookup: usize,
    num: Zeroizing<U1024>,
    den: Zeroizing<U1024>,
    coefficient: Option<Zeroizing<U1024>>,
    product: Subgroup,
    public_product: Subgroup,
    pow: Option<Pow1>,
    result: Option<Plaintext>,
    failure: Option<Error>,
    taken: bool,
}
impl<'a> CombineJob<'a> {
    /// Adopt the actual verified values. Roster and partial allocations together
    /// must fit the selected budget, before any original arithmetic begins.
    pub fn new(
        roster: &'a Roster,
        cipher: Ciphertext,
        partials: Vec<VerifiedPartial>,
        group: &Group,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::with_roster(
            RosterView::Borrowed(roster),
            cipher,
            partials,
            group,
            limits,
        )
    }
    fn with_roster(
        roster: RosterView<'a>,
        cipher: Ciphertext,
        partials: Vec<VerifiedPartial>,
        group: &Group,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if partials.len() < roster.threshold
            || partials.len() > roster.members.len()
            || partials.len() > limits.participants
        {
            return Err(Error::Roster);
        }
        limits.bytes::<VerifiedPartial>(partials.capacity(), roster.retained_bytes()?)?;
        Ok(Self {
            group: group.clone(),
            roster,
            cipher,
            partials: Some(partials),
            limits,
            phase: 0,
            at: 0,
            other: 0,
            lookup: 0,
            num: Zeroizing::new(U1024::ONE),
            den: Zeroizing::new(U1024::ONE),
            coefficient: None,
            product: Subgroup::identity(),
            public_product: Subgroup::identity(),
            pow: None,
            result: None,
            failure: None,
            taken: false,
        })
    }
    fn step(&mut self) -> Result<(), Error> {
        let partials = self.partials.as_ref().ok_or(Error::NotReady)?;
        match self.phase {
            0 => {
                // Associate every real proof with the same original roster.
                if self.at == partials.len() {
                    self.phase = 1;
                    self.at = 0;
                    self.other = 1;
                    return Ok(());
                }
                let partial = &partials[self.at];
                if partial.cipher != self.cipher {
                    return Err(Error::Roster);
                }
                let member = self.roster.members.get(self.lookup).ok_or(Error::Roster)?;
                if member.peer == partial.peer {
                    if member.original_index != partial.index || member.sigma != partial.sigma {
                        return Err(Error::Roster);
                    }
                    self.at += 1;
                    self.lookup = 0;
                } else {
                    self.lookup += 1;
                }
                Ok(())
            }
            1 => {
                // Distinct participants; two valid proofs from one peer are one.
                if self.at + 1 >= partials.len() {
                    self.phase = 2;
                    self.at = 0;
                    self.other = 0;
                    return Ok(());
                }
                if self.other >= partials.len() {
                    self.at += 1;
                    self.other = self.at + 1;
                    return Ok(());
                }
                if partials[self.at].peer == partials[self.other].peer
                    || partials[self.at].index == partials[self.other].index
                {
                    return Err(Error::Roster);
                }
                self.other += 1;
                Ok(())
            }
            2 => {
                if self.at == partials.len() {
                    if self.public_product != self.roster.public_key {
                        return Err(Error::InvalidProof);
                    }
                    self.pow = Some(Pow::new(
                        &self.product.0,
                        &P.wrapping_sub(&U1024::from_u32(2)),
                        1024,
                        &self.group.p,
                    )?);
                    self.phase = 6;
                    return Ok(());
                }
                if self.other == partials.len() {
                    if *self.den == U1024::ZERO {
                        return Err(Error::Roster);
                    }
                    self.pow = Some(Pow::new(
                        &self.den,
                        &Q.wrapping_sub(&U1024::from_u32(2)),
                        1024,
                        &self.group.q,
                    )?);
                    self.phase = 3;
                    return Ok(());
                }
                if self.other != self.at {
                    let x = U1024::from_u32(u32::from(partials[self.other].index) + 1);
                    let j = U1024::from_u32(u32::from(partials[self.at].index) + 1);
                    self.num = self.group.mul_q(&self.num, &x);
                    let difference = self.group.sub_q(&x, &j);
                    self.den = self.group.mul_q(&self.den, &difference);
                }
                self.other += 1;
                Ok(())
            }
            3 => {
                if self.pow.as_mut().ok_or(Error::NotReady)?.step() {
                    let inverse = self.pow.take().ok_or(Error::NotReady)?.finish()?;
                    let coefficient = self.group.mul_q(&self.num, &inverse);
                    self.pow = Some(Pow::new(
                        &partials[self.at].sigma.0,
                        &coefficient,
                        1024,
                        &self.group.p,
                    )?);
                    self.coefficient = Some(coefficient);
                    self.phase = 4;
                }
                Ok(())
            }
            4 => {
                if self.pow.as_mut().ok_or(Error::NotReady)?.step() {
                    let public = self.pow.take().ok_or(Error::NotReady)?.finish()?;
                    self.public_product =
                        Subgroup(*mul(&self.public_product.0, &public, &self.group.p));
                    let coefficient = self.coefficient.take().ok_or(Error::NotReady)?;
                    self.pow = Some(Pow::new(
                        &partials[self.at].value.0,
                        &coefficient,
                        1024,
                        &self.group.p,
                    )?);
                    self.phase = 5;
                }
                Ok(())
            }
            5 => {
                if self.pow.as_mut().ok_or(Error::NotReady)?.step() {
                    let partial = self.pow.take().ok_or(Error::NotReady)?.finish()?;
                    self.product = Subgroup(*mul(&self.product.0, &partial, &self.group.p));
                    self.at += 1;
                    self.other = 0;
                    self.num = Zeroizing::new(U1024::ONE);
                    self.den = Zeroizing::new(U1024::ONE);
                    self.phase = 2;
                }
                Ok(())
            }
            6 => {
                if self.pow.as_mut().ok_or(Error::NotReady)?.step() {
                    let inverse = self.pow.take().ok_or(Error::NotReady)?.finish()?;
                    let value = mul(&self.cipher.c2.0, &inverse, &self.group.p);
                    self.result = Some(Plaintext(value));
                    self.partials = None;
                    self.phase = 7;
                }
                Ok(())
            }
            _ => Err(Error::NotReady),
        }
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = *self.failure.get_or_insert(e);
        self.partials = None;
        self.coefficient = None;
        self.pow = None;
        self.num = Zeroizing::new(U1024::ZERO);
        self.den = Zeroizing::new(U1024::ZERO);
        self.result = None;
        e
    }
    /// One original association/comparison/product/exponent bit per unit.
    /// Inversions use cooperative exponentiation under the fixed prime p/q.
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
    /// Consume the actually combined original Zp plaintext once, preserving0.
    pub fn take_result(&mut self) -> Result<Plaintext, Error> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        let out = self.result.take().ok_or(if self.taken {
            Error::Finished
        } else {
            Error::NotReady
        })?;
        self.taken = true;
        Ok(out)
    }
    /// Retire original interpolation work/result without a false success.
    pub fn cancel(&mut self) {
        if !self.taken {
            self.fail(Error::Cancelled);
        }
    }
    /// Actual retained roster and still-owned proof-vector allocation capacities.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.limits.bytes::<VerifiedPartial>(
            self.partials.as_ref().map_or(0, Vec::capacity),
            self.roster.retained_bytes()?,
        )
    }
}

impl CombineJob<'static> {
    /// Adopt the same already checked original roster without cloning,
    /// rebuilding or changing its threshold/indices/sigmas. This permits a
    /// caller-driven native owner to retain the actual job without self-reference.
    /// The same constructor checks, budget and arithmetic as `new` apply;
    /// `retained_bytes` counts this original roster allocation exactly once.
    pub fn new_owned(
        roster: Roster,
        cipher: Ciphertext,
        partials: Vec<VerifiedPartial>,
        group: &Group,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::with_roster(RosterView::Owned(roster), cipher, partials, group, limits)
    }
}
