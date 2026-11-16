//! Native ownership guards and private service output parent directories.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use gnunet_native::local_path::LocalPath as CreatedPath;
#[cfg(unix)]
pub use unix::CreatedPath;
#[cfg(unix)]
pub use unix::private_parents;
#[cfg(windows)]
pub use windows::private_parents;
