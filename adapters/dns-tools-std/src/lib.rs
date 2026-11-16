//! Official DNS monitoring/answer-redirecting PROGRAM utilities over the actual
//! admitted interception client. No DNS stub, parser or wire protocol is copied.
#![forbid(unsafe_code)]
mod control;
mod execution;
pub mod packet;
mod program;
mod session;
pub use program::run;
/// Actual current utility behavior, independent of upstream Meson's swapped
/// source filenames for its two non-installed command targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Observe requests/responses and always forward the original callback.
    Monitor,
    /// Rewrite configured answer-section A/AAAA addresses after resolution.
    Redirect,
}
#[cfg(test)]
mod model;
