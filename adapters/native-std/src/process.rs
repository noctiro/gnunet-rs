//! Windows process creation with explicit resource inheritance and original handles.
mod account;
mod environment;
#[cfg(feature = "process-job")]
mod job;
mod launch;
mod profile;
mod suspended;
mod usage;
mod wait;
pub use crate::stdio::Stdio;
pub use account::PrimaryToken;
pub use environment::Environment;
#[cfg(feature = "process-job")]
pub use job::{JobProcess, JobRetirement, JobStartError};
pub use launch::Console;
pub use launch::ExportedHandle;
pub use launch::LaunchLimits;
pub use launch::Process;
pub use launch::ProcessIdentity;
pub use launch::Spawn;
pub use profile::{AccountProfile, ProfileCleanup, ProfileRetirement};
pub use suspended::{ActivationTarget, ResumeFailure, SuspendedProcess};
pub use usage::{CpuUsage, IoUsage, MemoryUsage, ResourceUsage};
pub use wait::ProcessWait;
