//! Authenticated NSEC/NSEC3 denial, without allocation or implicit hashing.
//!
//! Evidence must come from the same authoritative response/zone and from the
//! parent's trusted-chain `verify_rrset`, not merely from a parsed RRSIG. This
//! module neither promotes an untrusted signature nor follows a delegation.
//! A successful proof has its own bounded TTL; negative caching must additionally
//! apply the authenticated SOA/negative-cache limits. Missing evidence, malformed
//! data and exhausted work are errors, never an empty secure answer.
use super::{Validated, name_cmp};
use crate::{Error, MAX_WIRE_NAME_LENGTH, Name};
use core::cmp::Ordering;

const NS: u16 = 2;
const CNAME: u16 = 5;
const SOA: u16 = 6;
const DNAME: u16 = 39;
const DS: u16 = 43;
const RRSIG: u16 = 46;
const NSEC: u16 = 47;
const NSEC3: u16 = 50;
const ANY: u16 = 255;

/// SHA-1 port for RFC 5155's explicit hash construction. The caller supplies the
/// real implementation; this trait supplies no authentication or trust itself.
pub trait Sha1 {
    /// Hash the complete input into the exact 20-byte output, or retain failure.
    fn hash(&mut self, input: &[u8], output: &mut [u8; 20]) -> Result<(), Error>;
}

/// Finite structural and iteration policy, independent of a query's work budget.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum validated RRsets admitted as one coherent evidence group.
    pub maximum_rrsets: usize,
    /// Maximum individual denial records across the supplied RRsets.
    pub maximum_records: usize,
    /// Aggregate denial RDATA byte ceiling.
    pub maximum_rdata_bytes: usize,
    /// Extra SHA-1 iterations, excluding the initial hash. Zero follows RFC 9276.
    pub maximum_iterations: u16,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            maximum_rrsets: 64,
            maximum_records: 64,
            maximum_rdata_bytes: 65535,
            maximum_iterations: 0,
        }
    }
}

/// Caller-owned consumable work. Reusing it across attempts does not renew work.
#[derive(Debug)]
pub struct Work {
    steps: usize,
    hashes: usize,
}
impl Work {
    #[must_use]
    /// Start one consumable scan/hash budget for the original query.
    pub const fn new(steps: usize, hashes: usize) -> Self {
        Self { steps, hashes }
    }
    #[must_use]
    /// Remaining structural steps and SHA-1 calls, respectively.
    pub const fn remaining(&self) -> (usize, usize) {
        (self.steps, self.hashes)
    }
    fn steps(&mut self, count: usize) -> Result<(), Failure> {
        let Some(remaining) = self.steps.checked_sub(count) else {
            self.steps = 0;
            return Err(Failure::WorkLimit);
        };
        self.steps = remaining;
        Ok(())
    }
    fn hash(&mut self) -> Result<(), Failure> {
        let Some(remaining) = self.hashes.checked_sub(1) else {
            return Err(Failure::WorkLimit);
        };
        self.hashes = remaining;
        Ok(())
    }
}

/// A failed proof is not an authenticated negative answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// The question class/name/type cannot be proved by this evidence.
    InvalidQuestion,
    /// Evidence signer or owner escapes the authenticated zone.
    WrongZone,
    /// Original NSEC/NSEC3 wire fields are malformed.
    Malformed,
    /// Explicit record/byte capacity was exceeded.
    Capacity,
    /// A required closest/next/wildcard proof is absent.
    MissingProof,
    /// An authenticated existing name/type contradicts the requested proof.
    Exists,
    /// One evidence group mixes NSEC with NSEC3.
    MixedMechanisms,
    /// NSEC3 records do not use the same original hash parameters.
    InconsistentParameters,
    /// Original NSEC3 iterations exceed caller policy.
    IterationLimit,
    /// Original consumable structural or hash work is exhausted.
    WorkLimit,
    /// Denial does not establish an actual unsigned delegation.
    MissingDelegation,
    /// The actual caller hash failure is preserved, without a downgrade.
    Hash(Error),
}
impl core::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "DNSSEC denial: {self:?}")
    }
}
impl core::error::Error for Failure {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Hash(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// Exact original DNS question whose absence or wildcard is being proved.
pub struct Question<'a> {
    /// Complete original queried name.
    pub name: Name<'a>,
    /// Original query type.
    pub kind: u16,
    /// Original query class.
    pub class: u16,
}

/// Opt-Out does not prove that an omitted insecure delegation does not exist.
/// In particular, `InsecureOptOut` must not authorize an AD/secure response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Security {
    /// Complete authenticated denial without an Opt-Out ambiguity.
    Secure,
    /// A proven Opt-Out span cannot rule out an omitted unsigned delegation.
    InsecureOptOut,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Actual statement established by a completed denial proof.
pub enum Kind {
    /// The original type and CNAME are absent at an existing name.
    NoData,
    /// The original name and its applicable wildcard are absent.
    NameError,
    /// The signed expanded wildcard has no closer applicable name.
    PositiveWildcard,
}

/// Only the proof functions construct this result. It describes denial facts;
/// it is not a replacement for the parent chain or a reusable trust anchor.
#[derive(Clone, Copy, Debug)]
pub struct Proof<'a> {
    security: Security,
    kind: Kind,
    closest: Name<'a>,
    ttl: u32,
    delegation: bool,
}
impl<'a> Proof<'a> {
    #[must_use]
    /// Security status of the exact denial, including Opt-Out ambiguity.
    pub const fn security(self) -> Security {
        self.security
    }
    #[must_use]
    /// Actual statement proved.
    pub const fn kind(self) -> Kind {
        self.kind
    }
    #[must_use]
    /// Closest authenticated existing ancestor used by this proof.
    pub const fn closest_encloser(self) -> Name<'a> {
        self.closest
    }
    #[must_use]
    /// Upper-bound lifetime of the authenticated proof records, in seconds.
    pub const fn ttl(self) -> u32 {
        self.ttl
    }
    /// Exact NS/no-DS/no-SOA at a parent-side cut, or a proven Opt-Out span.
    /// A plain DS NODATA proof at a non-delegation name never sets this flag.
    #[must_use]
    pub const fn delegation(self) -> bool {
        self.delegation
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mechanism {
    Nsec,
    Nsec3,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Parameters<'a> {
    iterations: u16,
    salt: &'a [u8],
}

/// One signer, class and denial mechanism. NSEC3 salt/iteration rollovers must be
/// supplied as separate coherent attempts; records from different chains are not
/// mixed into a proof. Unknown NSEC3 algorithms/flags are ignored (RFC 5155 8.1–2).
pub struct Evidence<'a, 'v> {
    zone: Name<'a>,
    class: u16,
    sets: &'v [Validated<'a>],
    mechanism: Mechanism,
    parameters: Option<Parameters<'a>>,
}
impl<'a, 'v> Evidence<'a, 'v> {
    /// Preflight one same-zone/class mechanism within original work limits.
    pub fn new(
        zone: Name<'a>,
        class: u16,
        sets: &'v [Validated<'a>],
        limits: Limits,
        work: &mut Work,
    ) -> Result<Self, Failure> {
        if class == 0 || matches!(class, 254 | 255) {
            return Err(Failure::InvalidQuestion);
        }
        if sets.len() > limits.maximum_rrsets || limits.maximum_rdata_bytes > 65535 {
            return Err(Failure::Capacity);
        }
        let mut count = 0usize;
        let mut rdata_bytes = 0usize;
        let mut mechanism = None;
        let mut parameters = None;
        for validated in sets {
            let set = validated.set();
            work.steps(set.owner.wire_len() + zone.wire_len() + 1)?;
            if set.class != class
                || !same(validated.signer(), zone)
                || !within(set.owner, zone)
                || validated.wildcard()
            {
                return Err(Failure::WrongZone);
            }
            if !matches!(set.kind, NSEC | NSEC3) || set.records.len() != 1 {
                return Err(Failure::Malformed);
            }
            count = count
                .checked_add(set.records.len())
                .ok_or(Failure::Capacity)?;
            rdata_bytes = rdata_bytes
                .checked_add(set.records[0].len())
                .ok_or(Failure::Capacity)?;
            if count > limits.maximum_records || rdata_bytes > limits.maximum_rdata_bytes {
                return Err(Failure::Capacity);
            }
            let selected = if set.kind == NSEC {
                read_nsec(validated, zone, work)?;
                Some(Mechanism::Nsec)
            } else if let Some(record) = read_nsec3(validated, zone, work)? {
                if record.parameters.iterations > limits.maximum_iterations {
                    return Err(Failure::IterationLimit);
                }
                if parameters.is_some_and(|old| old != record.parameters) {
                    return Err(Failure::InconsistentParameters);
                }
                parameters = Some(record.parameters);
                Some(Mechanism::Nsec3)
            } else {
                None
            };
            if let Some(selected) = selected {
                if mechanism.is_some_and(|old| old != selected) {
                    return Err(Failure::MixedMechanisms);
                }
                mechanism = Some(selected);
            }
        }
        Ok(Self {
            zone,
            class,
            sets,
            mechanism: mechanism.ok_or(Failure::MissingProof)?,
            parameters,
        })
    }

    fn question(&self, question: Question<'_>) -> Result<(), Failure> {
        if question.class != self.class
            || question.kind == 0
            || (pseudo(question.kind) && question.kind != ANY)
        {
            return Err(Failure::InvalidQuestion);
        }
        if !within(question.name, self.zone) {
            return Err(Failure::WrongZone);
        }
        Ok(())
    }

    fn nsec_exact(&self, name: Name<'_>, work: &mut Work) -> Result<Option<Nsec<'a>>, Failure> {
        for set in self.sets {
            if set.set().kind == NSEC {
                let record = read_nsec(set, self.zone, work)?;
                if same(record.owner, name) {
                    return Ok(Some(record));
                }
            }
        }
        Ok(None)
    }

    fn nsec_cover(&self, name: Name<'_>, work: &mut Work) -> Result<Nsec<'a>, Failure> {
        let mut covering = None;
        for set in self.sets {
            if set.set().kind == NSEC {
                let record = read_nsec(set, self.zone, work)?;
                if same(record.owner, name) {
                    return Err(Failure::Exists);
                }
                if record.covers(name) {
                    record.below_cut(name, self.zone)?;
                    if covering.is_none() {
                        covering = Some(record);
                    }
                }
            }
        }
        covering.ok_or(Failure::MissingProof)
    }

    fn nsec3_lookup(&self, hash: &[u8; 20], work: &mut Work) -> Result<Lookup<'a>, Failure> {
        let mut found = Lookup {
            exact: None,
            cover: None,
        };
        for set in self.sets {
            if set.set().kind == NSEC3
                && let Some(record) = read_nsec3(set, self.zone, work)?
            {
                if record.owner == *hash {
                    found.exact = Some(record);
                } else if hash_covers(&record.owner, record.next, hash) && found.cover.is_none() {
                    found.cover = Some(record);
                }
            }
        }
        if found.exact.is_some() && found.cover.is_some() {
            return Err(Failure::InconsistentParameters);
        }
        Ok(found)
    }

    fn hash(
        &self,
        name: Name<'_>,
        sha1: &mut impl Sha1,
        work: &mut Work,
    ) -> Result<[u8; 20], Failure> {
        let parameters = self.parameters.ok_or(Failure::MissingProof)?;
        let mut input = [0u8; MAX_WIRE_NAME_LENGTH + 255];
        let length = name.wire_len() + parameters.salt.len();
        for (output, input) in input.iter_mut().zip(name.wire()) {
            *output = input.to_ascii_lowercase();
        }
        input[name.wire_len()..length].copy_from_slice(parameters.salt);
        let mut output = [0u8; 20];
        work.steps(length)?;
        work.hash()?;
        sha1.hash(&input[..length], &mut output)
            .map_err(Failure::Hash)?;
        let length = 20 + parameters.salt.len();
        for _ in 0..parameters.iterations {
            input[..20].copy_from_slice(&output);
            input[20..length].copy_from_slice(parameters.salt);
            work.steps(length)?;
            work.hash()?;
            sha1.hash(&input[..length], &mut output)
                .map_err(Failure::Hash)?;
        }
        Ok(output)
    }

    fn closest_nsec3(
        &self,
        name: Name<'a>,
        sha1: &mut impl Sha1,
        work: &mut Work,
    ) -> Result<Closest<'a>, Failure> {
        let mut current = name;
        let mut child_cover: Option<Nsec3<'a>> = None;
        loop {
            let hash = self.hash(current, sha1, work)?;
            let found = self.nsec3_lookup(&hash, work)?;
            if let Some(exact) = found.exact {
                if same(current, name) {
                    return Err(Failure::Exists);
                }
                let cover = child_cover.ok_or(Failure::MissingProof)?;
                if exact.bitmap.has(DNAME) || exact.bitmap.delegation() {
                    return Err(Failure::WrongZone);
                }
                return Ok(Closest {
                    name: current,
                    ttl: exact.ttl.min(cover.ttl),
                    opt_out: cover.opt_out,
                });
            }
            if same(current, self.zone) {
                return Err(Failure::MissingProof);
            }
            child_cover = found.cover;
            current = parent(current)?;
        }
    }
}

/// Prove an exact-name, empty-nonterminal, wildcard NODATA or DS Opt-Out result.
/// An Opt-Out result is explicitly insecure, not authenticated absence of a name.
pub fn prove_nodata<'a>(
    question: Question<'a>,
    evidence: &Evidence<'a, '_>,
    sha1: &mut impl Sha1,
    work: &mut Work,
) -> Result<Proof<'a>, Failure> {
    evidence.question(question)?;
    if evidence.mechanism == Mechanism::Nsec {
        if let Some(record) = evidence.nsec_exact(question.name, work)? {
            let delegation = absent(question, evidence.zone, record.bitmap, true)?;
            return Ok(proof(
                Kind::NoData,
                question.name,
                record.ttl,
                false,
                delegation,
            ));
        }
        let covering = evidence.nsec_cover(question.name, work)?;
        if strict_child(covering.next, question.name) {
            // A next authoritative descendant proves an empty nonterminal, not
            // NXDOMAIN. No wildcard synthesis occurs at an existing name.
            return Ok(proof(
                Kind::NoData,
                question.name,
                covering.ttl,
                false,
                false,
            ));
        }
        let closest = nsec_closest(question.name, covering, work)?;
        let mut storage = [0; MAX_WIRE_NAME_LENGTH];
        let wildcard = wildcard(closest, &mut storage)?;
        let record = evidence
            .nsec_exact(wildcard, work)?
            .ok_or(Failure::MissingProof)?;
        absent(
            Question {
                name: wildcard,
                ..question
            },
            evidence.zone,
            record.bitmap,
            true,
        )?;
        Ok(proof(
            Kind::NoData,
            closest,
            covering.ttl.min(record.ttl),
            false,
            false,
        ))
    } else {
        let hash = evidence.hash(question.name, sha1, work)?;
        let found = evidence.nsec3_lookup(&hash, work)?;
        if let Some(record) = found.exact {
            let delegation = absent(question, evidence.zone, record.bitmap, false)?;
            return Ok(proof(
                Kind::NoData,
                question.name,
                record.ttl,
                false,
                delegation,
            ));
        }
        let closest = evidence.closest_nsec3(question.name, sha1, work)?;
        if question.kind == DS && closest.opt_out {
            return Ok(proof(Kind::NoData, closest.name, closest.ttl, true, true));
        }
        let mut storage = [0; MAX_WIRE_NAME_LENGTH];
        let wildcard = wildcard(closest.name, &mut storage)?;
        let hash = evidence.hash(wildcard, sha1, work)?;
        let record = evidence
            .nsec3_lookup(&hash, work)?
            .exact
            .ok_or(Failure::MissingProof)?;
        absent(
            Question {
                name: wildcard,
                ..question
            },
            evidence.zone,
            record.bitmap,
            false,
        )?;
        Ok(proof(
            Kind::NoData,
            closest.name,
            closest.ttl.min(record.ttl),
            closest.opt_out,
            false,
        ))
    }
}

/// Prove QNAME and its applicable wildcard absent. A covered empty nonterminal
/// is an existing name and cannot become a secure NXDOMAIN result.
pub fn prove_nxdomain<'a>(
    question: Question<'a>,
    evidence: &Evidence<'a, '_>,
    sha1: &mut impl Sha1,
    work: &mut Work,
) -> Result<Proof<'a>, Failure> {
    evidence.question(question)?;
    if evidence.mechanism == Mechanism::Nsec {
        let covering = evidence.nsec_cover(question.name, work)?;
        covering.name_absent(question.name)?;
        let closest = nsec_closest(question.name, covering, work)?;
        let next = next_closer(question.name, closest)?;
        let next_proof = evidence.nsec_cover(next, work)?;
        next_proof.name_absent(next)?;
        let mut storage = [0; MAX_WIRE_NAME_LENGTH];
        let wildcard = wildcard(closest, &mut storage)?;
        let wildcard_proof = evidence.nsec_cover(wildcard, work)?;
        wildcard_proof.name_absent(wildcard)?;
        Ok(proof(
            Kind::NameError,
            closest,
            covering.ttl.min(next_proof.ttl).min(wildcard_proof.ttl),
            false,
            false,
        ))
    } else {
        let closest = evidence.closest_nsec3(question.name, sha1, work)?;
        let mut storage = [0; MAX_WIRE_NAME_LENGTH];
        let wildcard = wildcard(closest.name, &mut storage)?;
        let hash = evidence.hash(wildcard, sha1, work)?;
        let found = evidence.nsec3_lookup(&hash, work)?;
        if found.exact.is_some() {
            return Err(Failure::Exists);
        }
        let covering = found.cover.ok_or(Failure::MissingProof)?;
        Ok(proof(
            Kind::NameError,
            closest.name,
            closest.ttl.min(covering.ttl),
            closest.opt_out,
            false,
        ))
    }
}

/// Validate the denial part of a parent-verified expanded wildcard answer. Its
/// actual RRSIG Labels field fixes the generating wildcard/closest encloser;
/// callers cannot substitute a different wildcard name or just a boolean.
pub fn positive_wildcard<'a>(
    question: Question<'a>,
    answer: &Validated<'a>,
    evidence: &Evidence<'a, '_>,
    sha1: &mut impl Sha1,
    work: &mut Work,
) -> Result<Proof<'a>, Failure> {
    evidence.question(question)?;
    let set = answer.set();
    if !answer.wildcard()
        || !same(set.owner, question.name)
        || set.class != question.class
        || !same(answer.signer(), evidence.zone)
        || set.records.is_empty()
        || !(set.kind == question.kind || set.kind == CNAME || question.kind == ANY)
    {
        return Err(Failure::InvalidQuestion);
    }
    work.steps(question.name.wire_len() + 1)?;
    let labels = usize::from(answer.labels());
    if labels >= question.name.labels().count() || labels < evidence.zone.labels().count() {
        return Err(Failure::WrongZone);
    }
    let closest = keep_labels(question.name, labels)?;
    let next = next_closer(question.name, closest)?;
    if evidence.mechanism == Mechanism::Nsec {
        let covering = evidence.nsec_cover(next, work)?;
        covering.name_absent(next)?;
        Ok(proof(
            Kind::PositiveWildcard,
            closest,
            answer.ttl().min(covering.ttl),
            false,
            false,
        ))
    } else {
        let hash = evidence.hash(next, sha1, work)?;
        let found = evidence.nsec3_lookup(&hash, work)?;
        if found.exact.is_some() {
            return Err(Failure::Exists);
        }
        let covering = found.cover.ok_or(Failure::MissingProof)?;
        Ok(proof(
            Kind::PositiveWildcard,
            closest,
            answer.ttl().min(covering.ttl),
            covering.opt_out,
            false,
        ))
    }
}

/// Prove an actual parent-side unsigned delegation, not merely absence of DS at
/// a normal authoritative name (RFC 6840 4.4). Opt-Out remains insecure.
pub fn prove_unsigned_delegation<'a>(
    name: Name<'a>,
    evidence: &Evidence<'a, '_>,
    sha1: &mut impl Sha1,
    work: &mut Work,
) -> Result<Proof<'a>, Failure> {
    if same(name, evidence.zone) {
        return Err(Failure::WrongZone);
    }
    let result = prove_nodata(
        Question {
            name,
            kind: DS,
            class: evidence.class,
        },
        evidence,
        sha1,
        work,
    )?;
    if !result.delegation {
        return Err(Failure::MissingDelegation);
    }
    Ok(result)
}

fn proof(kind: Kind, closest: Name<'_>, ttl: u32, opt_out: bool, delegation: bool) -> Proof<'_> {
    Proof {
        security: if opt_out {
            Security::InsecureOptOut
        } else {
            Security::Secure
        },
        kind,
        closest,
        ttl,
        delegation,
    }
}

#[derive(Clone, Copy)]
struct Bitmap<'a>(&'a [u8]);
impl<'a> Bitmap<'a> {
    fn parse(bytes: &'a [u8], allow_empty: bool) -> Result<Self, Failure> {
        if bytes.is_empty() && !allow_empty {
            return Err(Failure::Malformed);
        }
        let mut at = 0;
        let mut last = None;
        while at < bytes.len() {
            let window = *bytes.get(at).ok_or(Failure::Malformed)?;
            let length = usize::from(*bytes.get(at + 1).ok_or(Failure::Malformed)?);
            let end = at.checked_add(2 + length).ok_or(Failure::Malformed)?;
            if !(1..=32).contains(&length)
                || last.is_some_and(|old| old >= window)
                || end > bytes.len()
                || bytes[end - 1] == 0
            {
                return Err(Failure::Malformed);
            }
            last = Some(window);
            at = end;
        }
        Ok(Self(bytes))
    }
    fn has(self, kind: u16) -> bool {
        if kind == 0 || pseudo(kind) {
            return false;
        }
        let mut at = 0;
        while at < self.0.len() {
            let window = u16::from(self.0[at]);
            let length = usize::from(self.0[at + 1]);
            if window == kind >> 8 {
                let low = usize::from(kind & 255);
                return low / 8 < length && self.0[at + 2 + low / 8] & (0x80 >> (low % 8)) != 0;
            }
            at += 2 + length;
        }
        false
    }
    fn any(self) -> bool {
        let mut at = 0;
        while at < self.0.len() {
            let window = u16::from(self.0[at]) << 8;
            let length = usize::from(self.0[at + 1]);
            for index in 0..length {
                let byte = self.0[at + 2 + index];
                for bit in 0..8 {
                    let kind = window | (index * 8 + bit) as u16;
                    if kind != 0 && !pseudo(kind) && byte & (0x80 >> bit) != 0 {
                        return true;
                    }
                }
            }
            at += 2 + length;
        }
        false
    }
    fn delegation(self) -> bool {
        self.has(NS) && !self.has(SOA)
    }
}

fn absent(
    question: Question<'_>,
    zone: Name<'_>,
    bitmap: Bitmap<'_>,
    nsec: bool,
) -> Result<bool, Failure> {
    let delegation = bitmap.delegation() && !same(question.name, zone);
    if delegation && question.kind != DS {
        return Err(Failure::WrongZone);
    }
    // A child's apex cannot prove absence of parent-side DS data.
    if question.kind == DS && bitmap.has(SOA) && same(question.name, zone) {
        return Err(Failure::WrongZone);
    }
    if bitmap.has(CNAME)
        || bitmap.has(question.kind)
        || (nsec && matches!(question.kind, NSEC | RRSIG))
        || (question.kind == ANY && (nsec || bitmap.any()))
    {
        return Err(Failure::Exists);
    }
    Ok(delegation && question.kind == DS)
}

#[derive(Clone, Copy)]
struct Nsec<'a> {
    owner: Name<'a>,
    next: Name<'a>,
    bitmap: Bitmap<'a>,
    ttl: u32,
}
impl Nsec<'_> {
    fn covers(self, name: Name<'_>) -> bool {
        let lower = name_cmp(self.owner, name);
        let upper = name_cmp(name, self.next);
        match name_cmp(self.owner, self.next) {
            Ordering::Less => lower == Ordering::Less && upper == Ordering::Less,
            Ordering::Equal => lower != Ordering::Equal,
            Ordering::Greater => lower == Ordering::Less || upper == Ordering::Less,
        }
    }
    fn below_cut(self, name: Name<'_>, zone: Name<'_>) -> Result<(), Failure> {
        if strict_child(name, self.owner)
            && (self.bitmap.has(DNAME) || (self.bitmap.delegation() && !same(self.owner, zone)))
        {
            return Err(Failure::WrongZone);
        }
        Ok(())
    }
    fn name_absent(self, name: Name<'_>) -> Result<(), Failure> {
        if strict_child(self.next, name) {
            return Err(Failure::Exists);
        }
        Ok(())
    }
}
fn read_nsec<'a>(
    validated: &Validated<'a>,
    zone: Name<'_>,
    work: &mut Work,
) -> Result<Nsec<'a>, Failure> {
    let set = validated.set();
    let bytes = set.records[0];
    work.steps(bytes.len() + 2 * set.owner.wire_len() + 1)?;
    let mut length = 0usize;
    loop {
        let label = usize::from(*bytes.get(length).ok_or(Failure::Malformed)?);
        length += 1;
        if label == 0 {
            break;
        }
        if label > 63 {
            return Err(Failure::Malformed);
        }
        length = length.checked_add(label).ok_or(Failure::Malformed)?;
        if length > bytes.len() || length > MAX_WIRE_NAME_LENGTH {
            return Err(Failure::Malformed);
        }
    }
    let next = Name::from_wire(&bytes[..length]).map_err(|_| Failure::Malformed)?;
    if !within(next, zone) || (name_cmp(set.owner, next) != Ordering::Less && !same(next, zone)) {
        return Err(Failure::WrongZone);
    }
    Ok(Nsec {
        owner: set.owner,
        next,
        bitmap: Bitmap::parse(&bytes[length..], false)?,
        ttl: validated.ttl(),
    })
}

#[derive(Clone, Copy)]
struct Nsec3<'a> {
    owner: [u8; 20],
    next: &'a [u8; 20],
    parameters: Parameters<'a>,
    opt_out: bool,
    bitmap: Bitmap<'a>,
    ttl: u32,
}
struct Lookup<'a> {
    exact: Option<Nsec3<'a>>,
    cover: Option<Nsec3<'a>>,
}
struct Closest<'a> {
    name: Name<'a>,
    ttl: u32,
    opt_out: bool,
}
fn read_nsec3<'a>(
    validated: &Validated<'a>,
    zone: Name<'_>,
    work: &mut Work,
) -> Result<Option<Nsec3<'a>>, Failure> {
    let set = validated.set();
    let bytes = set.records[0];
    work.steps(bytes.len() + 2 * set.owner.wire_len() + 1)?;
    let algorithm = *bytes.first().ok_or(Failure::Malformed)?;
    let flags = *bytes.get(1).ok_or(Failure::Malformed)?;
    if algorithm != 1 || flags > 1 {
        return Ok(None);
    }
    let iterations = u16::from_be_bytes(
        bytes
            .get(2..4)
            .ok_or(Failure::Malformed)?
            .try_into()
            .map_err(|_| Failure::Malformed)?,
    );
    let salt_length = usize::from(*bytes.get(4).ok_or(Failure::Malformed)?);
    let salt_end = 5 + salt_length;
    let salt = bytes.get(5..salt_end).ok_or(Failure::Malformed)?;
    if *bytes.get(salt_end).ok_or(Failure::Malformed)? != 20 {
        return Err(Failure::Malformed);
    }
    let end = salt_end + 1 + 20;
    let next = bytes
        .get(salt_end + 1..end)
        .ok_or(Failure::Malformed)?
        .try_into()
        .map_err(|_| Failure::Malformed)?;
    let mut labels = set.owner.labels();
    let label = labels.next().ok_or(Failure::Malformed)?;
    if !same(parent(set.owner)?, zone) {
        return Err(Failure::WrongZone);
    }
    let owner = decode_hash(label)?;
    Ok(Some(Nsec3 {
        owner,
        next,
        parameters: Parameters { iterations, salt },
        opt_out: flags == 1,
        bitmap: Bitmap::parse(&bytes[end..], true)?,
        ttl: validated.ttl(),
    }))
}
fn decode_hash(bytes: &[u8]) -> Result<[u8; 20], Failure> {
    if bytes.len() != 32 {
        return Err(Failure::Malformed);
    }
    let mut output = [0; 20];
    let mut bits = 0u16;
    let mut width = 0;
    let mut at = 0;
    for byte in bytes {
        let value = match byte.to_ascii_uppercase() {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'V' => byte.to_ascii_uppercase() - b'A' + 10,
            _ => return Err(Failure::Malformed),
        };
        bits = (bits << 5) | u16::from(value);
        width += 5;
        if width >= 8 {
            width -= 8;
            output[at] = (bits >> width) as u8;
            at += 1;
            bits &= (1 << width) - 1;
        }
    }
    Ok(output)
}
fn hash_covers(owner: &[u8; 20], next: &[u8; 20], hash: &[u8; 20]) -> bool {
    match owner.cmp(next) {
        Ordering::Less => owner < hash && hash < next,
        Ordering::Equal => hash != owner,
        Ordering::Greater => owner < hash || hash < next,
    }
}

fn same(left: Name<'_>, right: Name<'_>) -> bool {
    left.wire().eq_ignore_ascii_case(right.wire())
}
fn within(mut name: Name<'_>, zone: Name<'_>) -> bool {
    while name.wire_len() > zone.wire_len() {
        let Ok(ancestor) = parent(name) else {
            return false;
        };
        name = ancestor;
    }
    same(name, zone)
}
fn strict_child(name: Name<'_>, zone: Name<'_>) -> bool {
    !same(name, zone) && within(name, zone)
}
fn parent(name: Name<'_>) -> Result<Name<'_>, Failure> {
    let length = usize::from(name.wire()[0]);
    if length == 0 {
        return Err(Failure::WrongZone);
    }
    Name::from_wire(&name.wire()[1 + length..]).map_err(|_| Failure::Malformed)
}
fn keep_labels(mut name: Name<'_>, count: usize) -> Result<Name<'_>, Failure> {
    let labels = name.labels().count();
    if count > labels {
        return Err(Failure::InvalidQuestion);
    }
    for _ in count..labels {
        name = parent(name)?;
    }
    Ok(name)
}
fn next_closer<'a>(name: Name<'a>, closest: Name<'_>) -> Result<Name<'a>, Failure> {
    if !strict_child(name, closest) {
        return Err(Failure::Exists);
    }
    keep_labels(name, closest.labels().count() + 1)
}
fn wildcard<'a>(
    name: Name<'_>,
    storage: &'a mut [u8; MAX_WIRE_NAME_LENGTH],
) -> Result<Name<'a>, Failure> {
    let end = 2 + name.wire_len();
    if end > storage.len() {
        return Err(Failure::Malformed);
    }
    storage[..2].copy_from_slice(b"\x01*");
    storage[2..end].copy_from_slice(name.wire());
    Name::from_wire(&storage[..end]).map_err(|_| Failure::Malformed)
}
fn common_suffix<'a>(
    name: Name<'a>,
    other: Name<'_>,
    work: &mut Work,
) -> Result<Name<'a>, Failure> {
    let mut candidate = name;
    // Each test scans at most one DNS-width name. Debit before the bounded loop.
    work.steps(name.wire_len().saturating_mul(name.labels().count() + 1))?;
    while !within(other, candidate) {
        candidate = parent(candidate)?;
    }
    Ok(candidate)
}
fn nsec_closest<'a>(
    name: Name<'a>,
    covering: Nsec<'_>,
    work: &mut Work,
) -> Result<Name<'a>, Failure> {
    let owner = common_suffix(name, covering.owner, work)?;
    let next = common_suffix(name, covering.next, work)?;
    let closest = if owner.wire_len() > next.wire_len() {
        owner
    } else {
        next
    };
    if same(closest, name) {
        return Err(Failure::Exists);
    }
    Ok(closest)
}
fn pseudo(kind: u16) -> bool {
    matches!(kind, 41 | 249..=255)
}
