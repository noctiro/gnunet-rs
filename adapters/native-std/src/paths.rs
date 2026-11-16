//! Native Unicode paths, directory access and ACL-preserving file publication.
mod databases;
mod directory;
mod discovery;
mod encoding;
mod file;
pub(crate) mod metadata;
pub(crate) mod relative;

pub use databases::internet_database_directory;
pub use directory::create_directory_all;
pub use directory::open_directory;
pub use discovery::profile_directory;
pub use discovery::system_directory;
pub use encoding::absolute_wide_path;
pub use file::Publication;
pub use file::create_private_file;
pub use file::exists;
pub use file::open_regular_file;
pub use file::publish_file;
pub use file::validate_file_path;
pub use metadata::FileIdentity;
pub use metadata::is_regular_file;
pub use relative::Directory;
pub use relative::StatusError;

#[cfg(test)]
mod tests;
