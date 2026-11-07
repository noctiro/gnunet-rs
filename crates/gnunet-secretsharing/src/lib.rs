//! Fixed GNUnet threshold arithmetic, explicit original jobs and real proofs.
//!
//! This is a mathematical layer, not a DKG/CONSENSUS/native SERVICE. In
//! particular the fixed C fair-encryption producer is inconsistent; this crate
//! implements its exact transcript's equation checks, not a pretend working
//! general-purpose fair-proof generator. See the package README.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod aggregate;
#[cfg(feature = "alloc")]
mod combine;
mod elgamal;
mod error;
mod fair;
mod fair_prover;
mod field;
mod partial;
#[cfg(feature = "alloc")]
mod polynomial;
mod recovery;

#[cfg(feature = "alloc")]
pub use aggregate::{AggregateContribution, AggregateJob, AggregateMaterial};
#[cfg(feature = "alloc")]
pub use combine::{CombineJob, Participant, Roster, RosterCheck};
pub use elgamal::{Ciphertext, CiphertextCheck, EncryptJob, Plaintext, PlaintextGenerate};
pub use error::{Error, Limits, Progress};
pub use fair::{FairEquationCheck, FairEquationResult};
pub use fair_prover::FairProver;
pub use field::{Element, Group, MembershipJob, Scalar, ShareCheck, Subgroup};
pub use gnunet_crypto::Entropy;
pub use partial::authenticate_element;
pub use partial::{PartialProver, PartialVerifier, UnsignedPartial, VerifiedPartial};
#[cfg(feature = "alloc")]
pub use polynomial::{
    CommitmentJob, Commitments, Evaluation, Polynomial, PolynomialCheck, PolynomialGenerator,
};
pub use recovery::FairRecoveryJob;

/// Exact fixed field/scalar size in the public1024-bit profile.
pub const FIELD_BYTES: usize = 128;
