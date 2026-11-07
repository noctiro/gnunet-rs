use crate::Error;
use gnunet_paillier as paillier;
use gnunet_secretsharing::{CommitmentJob, Commitments, Polynomial, PolynomialGenerator};
use gnunet_types::Error as Fault;
use gnunet_wire::official::secretsharing as ipc;

/// Unique material retained after real commitment exponentiation. None of these
/// owners is copied when signing, submitting or handing the transcript onward.
pub(super) struct Material {
    pub(super) keypair: paillier::KeyPair,
    pub(super) polynomial: Polynomial,
    pub(super) coefficients: Commitments,
}
impl Material {
    fn retained_bytes(&self) -> Result<usize, Error> {
        let coefficients = self.coefficients.retained_bytes()?;
        self.polynomial
            .retained_bytes()?
            .checked_add(coefficients)
            .ok_or_else(|| Fault::Overflow.into())
    }
}

// These arithmetic jobs never run concurrently. Keep only the active job's
// inline storage and make the materials required by each later stage explicit.
// Stable operation IDs remain in the owner's source history after a transition.
#[expect(
    clippy::large_enum_variant,
    reason = "Mutually exclusive bounded jobs share inline storage without a new heap allocation"
)]
pub(super) enum Work {
    Identity,
    Keygen(paillier::Keygen),
    Polynomial {
        keypair: paillier::KeyPair,
        job: PolynomialGenerator,
    },
    Commitments {
        keypair: paillier::KeyPair,
        job: CommitmentJob<'static>,
    },
    Unsigned(Material),
    Signing {
        material: Material,
        bytes: [u8; ipc::COMMIT_BYTES],
    },
    Insert {
        material: Material,
        bytes: [u8; ipc::COMMIT_BYTES],
        own_validated: bool,
    },
    Receive(Material),
    Closed,
}
impl Work {
    /// Heap owners appear in precisely one active variant. Inline jobs and key
    /// material are already included by the owner's size_of reservation.
    pub(super) fn retained_bytes(&self) -> Result<usize, Error> {
        match self {
            Self::Identity | Self::Keygen(_) | Self::Closed => Ok(0),
            Self::Polynomial { job, .. } => Ok(job.retained_bytes()?),
            Self::Commitments { job, .. } => Ok(job.retained_bytes()?),
            Self::Unsigned(material)
            | Self::Signing { material, .. }
            | Self::Insert { material, .. }
            | Self::Receive(material) => material.retained_bytes(),
        }
    }
    /// Erase the current real cursor before dropping its unique secret owners.
    pub(super) fn cancel(&mut self) {
        match self {
            Self::Keygen(job) => job.cancel(),
            Self::Polynomial { job, .. } => job.cancel(),
            Self::Commitments { job, .. } => job.cancel(),
            _ => {}
        }
        *self = Self::Closed;
    }
    /// Only the submitted/concluded stage can transfer its original material.
    /// The caller still must establish the real whole-write/525/roster gates.
    pub(super) fn take_material(&mut self) -> Result<Material, Error> {
        if !matches!(self, Self::Receive(_)) {
            return Err(Fault::NotReady.into());
        }
        let Self::Receive(material) = core::mem::replace(self, Self::Closed) else {
            return Err(Fault::NotReady.into());
        };
        Ok(material)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::print_stdout,
        reason = "Expose compiler-computed fixed layout for the selected verification, not an RSS or throughput measurement"
    )]
    fn mutually_exclusive_jobs_use_less_fixed_storage() -> Result<(), Error> {
        // Sum only the seven former Option fields. Excluding their surrounding
        // owner padding, phase tag and signing-operation slot is conservative;
        // this is not a reconstructed size_of for the complete former owner.
        let former_option_fields: usize = [
            core::mem::size_of::<Option<paillier::Keygen>>(),
            core::mem::size_of::<Option<paillier::KeyPair>>(),
            core::mem::size_of::<Option<PolynomialGenerator>>(),
            core::mem::size_of::<Option<CommitmentJob<'static>>>(),
            core::mem::size_of::<Option<Polynomial>>(),
            core::mem::size_of::<Option<Commitments>>(),
            core::mem::size_of::<Option<[u8; ipc::COMMIT_BYTES]>>(),
        ]
        .into_iter()
        .sum();
        let work = core::mem::size_of::<Work>();
        println!(
            "Round1 fixed storage: former Option fields sum={former_option_fields}, Work={work} bytes"
        );
        if work >= former_option_fields {
            return Err(Fault::Capacity.into());
        }
        Ok(())
    }

    struct Draws(usize);
    impl paillier::Entropy for Draws {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Fault> {
            bytes.fill(0x41);
            self.0 += 1;
            Ok(())
        }
    }

    #[test]
    fn partial_keygen_cancel_cannot_transfer_or_restart_material() -> Result<(), Error> {
        let mut work = Work::Keygen(paillier::Keygen::new(Default::default())?);
        let mut draws = Draws(0);
        let Work::Keygen(job) = &mut work else {
            return Err(Fault::Stale.into());
        };
        if job.advance(&mut draws, 1)? != paillier::Progress::Advanced || draws.0 != 1 {
            return Err(Fault::Stale.into());
        }
        work.cancel();
        if !matches!(work, Work::Closed)
            || work.retained_bytes()? != 0
            || !matches!(work.take_material(), Err(Error::Protocol(Fault::NotReady)))
        {
            return Err(Fault::Stale.into());
        }
        work.cancel();
        if !matches!(work, Work::Closed) || draws.0 != 1 {
            return Err(Fault::Stale.into());
        }
        Ok(())
    }
}
