//! Native selected-input opening, separate from content encoding and reading.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub(crate) use unix::open;
#[cfg(windows)]
pub(crate) use windows::open;

#[cfg(feature = "network")]
mod source;
#[cfg(feature = "network")]
pub(crate) use source::{
    absolute_normalized, file_info, named_info, open_exact, owned_path, protocol_filename,
};
