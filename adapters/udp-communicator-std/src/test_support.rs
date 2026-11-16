//! Native fixtures shared by unit and integration tests.
mod directory;
pub(crate) use directory::private_directory;
#[cfg(feature = "transport")]
mod stream;
#[cfg(feature = "transport")]
pub(crate) use stream::pair;
