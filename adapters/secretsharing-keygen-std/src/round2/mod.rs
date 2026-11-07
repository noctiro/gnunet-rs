//! Original Round2 own/remote validation over the continuing actual PILS source.
//! Whole local INSERT, CONCLUDE and real525 retain distinct native evidence.
mod owner;
mod types;
mod validator;
pub use owner::Round2;
pub use types::{
    BuildFailure, ClosedSource, ContributionEvidence, ContributionParts, Limits, LocalContribution,
    LocalTranscript, OwnEvidence, OwnSignature, Progress, Rejection, Report,
};
