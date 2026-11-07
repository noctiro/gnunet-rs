use crate::{Certificate, DEFAULT_EPOCH_MICROS, NONCES, Proof, pow};
use gnunet_types::Error;
/// Actual local mining progress, never a service admission/durability result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MiningProgress {
    /// Completed real hash count in this owner, including restored candidates.
    pub hashes: u64,
    /// Current average including unfilled positions as zero.
    pub score: u32,
    /// Whether32 distinct original nonces meet the requested target.
    pub ready: bool,
}
/// Fixed public work state. One step performs at most one existing Argon2 hash
/// in caller-owned1MiB memory. No key, RNG, allocation, thread or storage exists.
pub struct Miner {
    certificate: Certificate,
    nonces: [u64; NONCES],
    scores: [u32; NONCES],
    used: usize,
    next: u64,
    hashes: u64,
    target: u32,
    ready: bool,
    // The original public nonces stay in certificate until restoration ends.
    // Only fresh actual hashes create the private scores above.
    restoring: Option<usize>,
}
impl Miner {
    /// Start fresh work over the original immutable timestamp/public/signature.
    /// The caller explicitly selects a starting counter and requested epochs.
    /// Signature validity is checked separately before any network submission.
    pub fn new(proof: Proof<'_>, start: u64, difficulty: u32, epochs: u32) -> Result<Self, Error> {
        let target = difficulty.checked_add(epochs).ok_or(Error::Overflow)?;
        if epochs == 0 || target > 512 {
            return Err(Error::InvalidInput);
        }
        let mut certificate = Certificate::copy(proof);
        certificate.0[16..272].fill(0);
        certificate.0[8..16].copy_from_slice(
            &DEFAULT_EPOCH_MICROS
                .saturating_mul(u64::from(epochs))
                .to_be_bytes(),
        );
        Ok(Self {
            certificate,
            nonces: [0; NONCES],
            scores: [0; NONCES],
            used: 0,
            next: start,
            hashes: 0,
            target,
            ready: false,
            restoring: None,
        })
    }
    /// Continue the candidates carried by the same standard public proof.
    /// No serialized score or completed-work claim is trusted: subsequent steps
    /// hash each distinct carried nonce once before trying any new counter.
    /// Repeated zero/empty slots contribute only one real nonce0 candidate.
    ///
    /// This public format has no rejected-candidate cursor or historical count.
    /// Fresh search starts above max(start, every carried nonce), and may revisit
    /// rejected historical counters above that floor. Supply the observed prior
    /// search_after as start to avoid that repetition. u64::MAX never wraps.
    pub fn resume(
        proof: Proof<'_>,
        start: u64,
        difficulty: u32,
        epochs: u32,
    ) -> Result<Self, Error> {
        let mut miner = Self::new(proof, start, difficulty, epochs)?;
        miner.certificate.0[16..272].copy_from_slice(&proof.bytes()[16..272]);
        for i in 0..NONCES {
            miner.next = miner.next.max(proof.nonce(i)?);
        }
        miner.restoring = Some(0);
        Ok(miner)
    }
    /// The next fresh candidate is this counter plus1. During restoration the
    /// floor includes unverified carried nonces; it is not a recovered history.
    #[must_use]
    pub const fn search_after(&self) -> u64 {
        self.next
    }
    /// Whether carried candidates still require actual score rechecking.
    #[must_use]
    pub const fn restoring(&self) -> bool {
        self.restoring.is_some()
    }
    fn restored_candidate(&mut self) -> Result<Option<u64>, Error> {
        while let Some(at) = self.restoring {
            if at == NONCES {
                self.restoring = None;
                return Ok(None);
            }
            let nonce = crate::proof::word(&self.certificate.0, 16 + at * 8)?;
            if !self.nonces[..self.used].contains(&nonce) {
                return Ok(Some(nonce));
            }
            self.restoring = Some(at + 1);
        }
        Ok(None)
    }
    fn remember(&mut self, nonce: u64, score: u32) -> Result<(), Error> {
        if self.used < NONCES {
            self.nonces[self.used] = nonce;
            self.scores[self.used] = score;
            self.used += 1;
        } else {
            let (index, lowest) = self
                .scores
                .iter()
                .copied()
                .enumerate()
                .min_by_key(|(_, score)| *score)
                .ok_or(Error::Conflict)?;
            if score > lowest {
                self.nonces[index] = nonce;
                self.scores[index] = score;
            }
        }
        Ok(())
    }
    fn finish_ready(&mut self) {
        if self.restoring.is_none() && self.used == NONCES && self.average() >= self.target {
            let mut sorted = self.nonces;
            sorted.sort_unstable();
            for (slot, nonce) in self.certificate.0[16..272]
                .as_chunks_mut::<8>()
                .0
                .iter_mut()
                .zip(sorted)
            {
                slot.copy_from_slice(&nonce.to_be_bytes());
            }
            self.ready = true;
        }
    }
    /// Perform at most one actual hash, including restoration. Refused scratch
    /// cannot consume a candidate or grant a score; counters never silently wrap.
    pub fn step(&mut self, memory: &mut [pow::Block]) -> Result<MiningProgress, Error> {
        if self.ready {
            return Ok(self.progress());
        }
        let carried = self.restored_candidate()?;
        let nonce = match carried {
            Some(nonce) => nonce,
            None => self.next.checked_add(1).ok_or(Error::Overflow)?,
        };
        let hashes = self.hashes.checked_add(1).ok_or(Error::Overflow)?;
        if self.nonces[..self.used].contains(&nonce) {
            return Err(Error::Conflict);
        }
        let mut input = [0; 52];
        input[..8].copy_from_slice(&nonce.to_be_bytes());
        input[8..16].copy_from_slice(&self.certificate.0[..8]);
        input[16..].copy_from_slice(&self.certificate.0[272..308]);
        let mut output = [0; 64];
        pow::hash(&gnunet_block::revocation::SALT, &input, &mut output, memory)?;
        let score = gnunet_block::revocation::leading_zeros(&output);
        self.remember(nonce, score)?;
        self.hashes = hashes;
        if carried.is_some() {
            self.restoring = self.restoring.map(|at| at + 1);
            // Skip duplicate slots without more hashes. A finished restore can
            // satisfy the target without trying max_carried_nonce+1.
            let _next_carried = self.restored_candidate()?;
        } else {
            self.next = nonce;
        }
        self.finish_ready();
        Ok(self.progress())
    }
    fn average(&self) -> u32 {
        self.scores.iter().sum::<u32>() / NONCES as u32
    }
    /// Current local work counts. No hashing or clock sampling occurs here.
    #[must_use]
    pub fn progress(&self) -> MiningProgress {
        MiningProgress {
            hashes: self.hashes,
            score: self.average(),
            ready: self.ready,
        }
    }
    /// Same372-byte public work artifact, with no saved score/cursor authority.
    /// While restoring, retain every original candidate rather than discarding
    /// not-yet-rehashed work. Afterwards retain the actual best candidate pool.
    /// Incomplete pools repeat one candidate in empty slots, so they cannot pass
    /// the strict32-distinct nonce check by repeating one expensive hash.
    #[must_use]
    pub fn checkpoint(&self) -> Certificate {
        let mut certificate = self.certificate.clone();
        if self.restoring.is_some() || self.ready {
            return certificate;
        }
        let mut nonces = [self.nonces.first().copied().unwrap_or(0); NONCES];
        nonces[..self.used].copy_from_slice(&self.nonces[..self.used]);
        nonces.sort_unstable();
        for (slot, nonce) in certificate.0[16..272]
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(nonces)
        {
            slot.copy_from_slice(&nonce.to_be_bytes());
        }
        certificate
    }
    /// Complete sorted certificate only after all actual work. This still does
    /// not assert signature/current lifetime or any external service outcome.
    pub fn certificate(&self) -> Result<Proof<'_>, Error> {
        if !self.ready {
            return Err(Error::NotReady);
        }
        self.certificate.proof()
    }
}
