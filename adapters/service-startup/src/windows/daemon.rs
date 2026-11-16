//! Native detached re-exec and supervised original-process console transition.
mod console;
mod launch;
mod retire;
pub use console::ConsoleDetachFailure;
pub use console::DetachedStderr;
pub use console::detach_managed;
pub use launch::LaunchCause;
pub use launch::LaunchFailure;
pub use launch::Parent;
pub use launch::Reexec;
pub use launch::launch;
pub use retire::RetirementFailure;
pub use retire::retire_child;
