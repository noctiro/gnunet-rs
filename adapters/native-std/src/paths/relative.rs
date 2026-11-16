//! Handle-relative ordinary filesystem operations without reconstructed parent paths.
mod directory;
mod leaf;
mod link;
pub(crate) mod open;
mod rename;
pub(crate) mod status;
pub use directory::Directory;
pub(crate) use link::{remove_directory, remove_special};
pub(crate) use rename::publish_directory;
pub use status::StatusError;
#[cfg(test)]
mod tests;
