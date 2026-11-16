//! Single fresh-process inheritance capture before unrelated native owners.
mod inherited;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
pub(crate) use inherited::Inherited;
#[cfg(unix)]
pub(crate) use unix::capture;
#[cfg(windows)]
pub(crate) use windows::capture;
