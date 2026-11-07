//! Revocation plugin wire/key/PoW rules from fixed gnsrecord_pow.c.
use crate::{
    Hash, ReturnValue,
    plugins::{Clock, KeyResult, RevocationConfig, be32, be64},
    pow,
};
use gnunet_crypto::{gns, hash512};
use gnunet_types::Error;
/// Exact16-byte Argon2 salt; the C initializer fills its array with no NUL.
pub const SALT: [u8; 16] = *b"GnsRevocationPow";
struct Proof<'a> {
    bytes: &'a [u8],
    kind: u32,
    key: &'a [u8],
}
fn parse(block: &[u8]) -> Result<Option<Proof<'_>>, Error> {
    if block.len() < 280 || u64::from(be32(block, 4)?) + 8 != block.len() as u64 {
        return Ok(None);
    }
    if block.len() < 316 {
        return Ok(None);
    }
    let kind = be32(block, 280)?;
    if ![65536, 65556].contains(&kind) {
        return Ok(None);
    }
    Ok(Some(Proof {
        bytes: &block[8..],
        kind,
        key: &block[280..316],
    }))
}
/// Source get_key hashes serialized type+public-key36 bytes. It does not require
/// a signature, PoW validity, difficulty or expiry. A malformed block writes no key.
pub fn key(block: &[u8]) -> Result<KeyResult, Error> {
    Ok(match parse(block)? {
        Some(proof) => KeyResult {
            status: ReturnValue::Yes,
            key: Some(hash512(proof.key)),
        },
        None => KeyResult {
            status: ReturnValue::No,
            key: None,
        },
    })
}
/// Plugin check_block maps every native non-YES PoW result to NO. The input
/// message header type/size is deliberately not an additional block condition.
/// Short missing signatures are safely rejected; the C helper would read outside
/// such an untrusted buffer, so that case is not executed in the C oracle.
pub fn check(
    block: &[u8],
    config: RevocationConfig,
    memory: &mut [pow::Block],
    clock: &mut (impl Clock + ?Sized),
) -> Result<ReturnValue, Error> {
    let Some(proof) = parse(block)? else {
        return Ok(ReturnValue::No);
    };
    if proof.bytes.len() < 372 {
        return Ok(ReturnValue::No);
    }
    let result = verify(&proof, config, memory, clock)?;
    Ok(if result == ReturnValue::Yes {
        ReturnValue::Yes
    } else {
        ReturnValue::No
    })
}
/// Original signature-purpose region for one typed public key and timestamp.
/// This is public data, not a signature or proof of possession.
#[must_use]
pub fn signing_message(timestamp: u64, public: &[u8; 36]) -> [u8; 52] {
    let mut region = [0; 52];
    region[..4].copy_from_slice(&52u32.to_be_bytes());
    region[4..8].copy_from_slice(&3u32.to_be_bytes());
    region[8..16].copy_from_slice(&timestamp.to_be_bytes());
    region[16..].copy_from_slice(public);
    region
}
fn parse_proof(bytes: &[u8]) -> Result<Option<Proof<'_>>, Error> {
    if bytes.len() < 308 {
        return Ok(None);
    }
    let kind = be32(bytes, 272)?;
    if ![65536, 65556].contains(&kind) {
        return Ok(None);
    }
    Ok(Some(Proof {
        bytes,
        kind,
        key: &bytes[272..308],
    }))
}
/// Check only the actual original certificate signature. TTL and nonce set are
/// not signed; successful signature checking is not valid work or revocation.
pub fn signature_valid(bytes: &[u8]) -> Result<bool, Error> {
    let Some(proof) = parse_proof(bytes)? else {
        return Ok(false);
    };
    if bytes.len() < 372 {
        return Ok(false);
    }
    let public = proof.key[4..36].try_into().map_err(|_| Error::Truncated)?;
    let signature = bytes[308..372].try_into().map_err(|_| Error::Truncated)?;
    let key = proof.key.try_into().map_err(|_| Error::Truncated)?;
    let region = signing_message(be64(bytes, 0)?, key);
    let parts = [&region[..]];
    Ok(match proof.kind {
        65536 => gns::verify_pkey(&public, 3, &parts, &signature),
        65556 => gns::verify_edkey(&public, 3, &parts, &signature),
        _ => return Ok(false),
    }
    .is_ok())
}
/// Allocation-free original proof verification, with one Argon2 hash per step.
/// The immutable borrowed bytes cannot be replaced between signature and work.
/// Caller owns the reusable1MiB scratch and scheduling; there is no hidden task.
pub struct Verification<'a> {
    proof: Proof<'a>,
    config: RevocationConfig,
    next: u8,
    sum: u32,
}
impl<'a> Verification<'a> {
    /// Authenticate the original signature and ordered nonce set before work.
    /// Invalid proofs return None; no PoW hash or clock call occurs here.
    pub fn new(bytes: &'a [u8], config: RevocationConfig) -> Result<Option<Self>, Error> {
        let Some(proof) = parse_proof(bytes)? else {
            return Ok(None);
        };
        if bytes.len() < 372 || !signature_valid(bytes)? {
            return Ok(None);
        }
        for i in 0..31 {
            if be64(bytes, 16 + i * 8)? >= be64(bytes, 24 + i * 8)? {
                return Ok(None);
            }
        }
        Ok(Some(Self {
            proof,
            config,
            next: 0,
            sum: 0,
        }))
    }
    /// Whether all32 original nonce hashes have actually completed.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.next == 32
    }
    /// Actual completed hash count, independent of service admission or IO.
    #[must_use]
    pub const fn completed_hashes(&self) -> u8 {
        self.next
    }
    /// Execute at most one real hash. Completed work cannot silently restart.
    /// On scratch refusal/error, the original counter and score are unchanged.
    pub fn step(&mut self, memory: &mut [pow::Block]) -> Result<bool, Error> {
        if self.complete() {
            return Err(Error::Replay);
        }
        let mut input = [0; 52];
        let offset = 16 + usize::from(self.next) * 8;
        input[..8].copy_from_slice(&self.proof.bytes[offset..offset + 8]);
        input[8..16].copy_from_slice(&self.proof.bytes[..8]);
        input[16..].copy_from_slice(self.proof.key);
        let mut output = [0; 64];
        pow::hash(&SALT, &input, &mut output, memory)?;
        let score = leading_zeros(&output);
        self.sum = self.sum.checked_add(score).ok_or(Error::Overflow)?;
        self.next += 1;
        Ok(self.complete())
    }
    /// Actual average leading-zero score; absent while any work remains.
    #[must_use]
    pub fn score(&self) -> Option<u32> {
        self.complete().then_some(self.sum / 32)
    }
    /// Check current official lifetime after all original work. Keeps the
    /// reference's clock/FOREVER behavior; informational TTL grants no validity.
    pub fn outcome(&self, clock: &mut (impl Clock + ?Sized)) -> Result<ReturnValue, Error> {
        let score = self.score().ok_or(Error::NotReady)?;
        Ok(valid_lifetime(
            score,
            self.config,
            be64(self.proof.bytes, 0)?,
            clock,
        ))
    }
}
/// Count public work-hash leading zero bits, from0 through512.
#[must_use]
pub fn leading_zeros(bytes: &[u8; 64]) -> u32 {
    let mut score = 0;
    for &byte in bytes {
        score += byte.leading_zeros();
        if byte != 0 {
            break;
        }
    }
    score
}
fn verify(
    proof: &Proof<'_>,
    config: RevocationConfig,
    memory: &mut [pow::Block],
    clock: &mut (impl Clock + ?Sized),
) -> Result<ReturnValue, Error> {
    let Some(mut work) = Verification::new(proof.bytes, config)? else {
        return Ok(ReturnValue::No);
    };
    while !work.complete() {
        work.step(memory)?;
    }
    work.outcome(clock)
}
/// Calculate only the original work-score/time policy at a sampled instant.
/// This does not authenticate the supplied score, signature, proof or storage.
/// Actual verified receipts may reuse their fixed score without repeating hashes.
#[must_use]
pub fn valid_at(score: u32, config: RevocationConfig, timestamp: u64, now: u64) -> ReturnValue {
    valid_lifetime(score, config, timestamp, &mut || now)
}
fn valid_lifetime(
    score: u32,
    config: RevocationConfig,
    timestamp: u64,
    clock: &mut (impl Clock + ?Sized),
) -> ReturnValue {
    if score < config.matching_bits {
        return ReturnValue::No;
    }
    let epochs = u64::from(score - config.matching_bits + 1);
    let ttl = config.epoch_duration.saturating_mul(epochs);
    let buffer = if config.epoch_duration == u64::MAX {
        u64::MAX
    } else {
        config.epoch_duration / 10
    };
    let expiration = timestamp.saturating_add(ttl).saturating_add(buffer);
    // get_remaining(NEVER) returns FOREVER without reading the clock, even atMAX.
    if timestamp == u64::MAX || timestamp > clock.now() {
        return ReturnValue::No;
    }
    if expiration != u64::MAX && expiration <= clock.now() {
        return ReturnValue::No;
    }
    ReturnValue::Yes
}

/// Hash bytes are public; a successful key result does not verify revocation.
#[must_use]
pub fn public_key_hash(serialized_key: &[u8; 36]) -> Hash {
    hash512(serialized_key)
}

#[cfg(test)]
mod boundaries {
    use super::*;
    #[test]
    fn exact_lifetime_boundary_and_two_original_clock_reads() {
        let cfg = RevocationConfig {
            matching_bits: 0,
            epoch_duration: 10,
        };
        for (now, result) in [
            (99, ReturnValue::No),
            (100, ReturnValue::Yes),
            (110, ReturnValue::Yes),
            (111, ReturnValue::No),
        ] {
            let mut reads = 0;
            let mut clock = || {
                reads += 1;
                now
            };
            assert_eq!(valid_lifetime(0, cfg, 100, &mut clock), result);
            assert_eq!(reads, if now < 100 { 1 } else { 2 });
        }
    }
    #[test]
    fn never_timestamp_score_failure_and_saturated_expiration_skip_clock_reads() {
        let mut reads = 0;
        let mut clock = || {
            reads += 1;
            u64::MAX
        };
        let cfg = RevocationConfig {
            matching_bits: 1,
            epoch_duration: u64::MAX,
        };
        assert_eq!(valid_lifetime(0, cfg, 100, &mut clock), ReturnValue::No);
        assert_eq!(
            valid_lifetime(1, cfg, u64::MAX, &mut clock),
            ReturnValue::No
        );
        assert_eq!(valid_lifetime(1, cfg, 100, &mut clock), ReturnValue::Yes);
        assert_eq!(reads, 1);
    }
    #[test]
    fn source_epoch_score_and_clock_continuation_are_not_replaced_with_ttl_field() {
        assert_eq!(
            RevocationConfig::from_native_values(u64::MAX, 10).matching_bits,
            u32::MAX
        );
        let cfg = RevocationConfig::from_native_values(u64::from(u32::MAX) + 3, 10);
        let mut seq = [100, 120].into_iter();
        let mut clock = || seq.next().unwrap_or(0);
        assert_eq!(valid_lifetime(3, cfg, 100, &mut clock), ReturnValue::Yes);
        let mut clock = || 121;
        assert_eq!(valid_lifetime(3, cfg, 100, &mut clock), ReturnValue::No);
    }
}
