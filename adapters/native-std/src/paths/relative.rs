//! Handle-relative ordinary filesystem operations without reconstructed parent paths.
mod directory;
mod leaf;
mod link;
pub(crate) mod open;
mod rename;
pub(crate) mod status;
mod sync;
pub use directory::Directory;
pub(crate) use link::{remove_directory, remove_special};
pub use rename::DirectoryClaim;
pub use status::StatusError;
pub(crate) fn validate_name(name: &std::ffi::OsStr) -> std::io::Result<()> {
    leaf::Leaf::new(name).map(|_| ())
}
#[cfg(test)]
mod tests;
