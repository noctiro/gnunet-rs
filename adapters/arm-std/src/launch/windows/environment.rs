//! Synchronous bridge to CONFIGURATION's infallible variable lookup contract.
//! Native lookup/decoding failures are retained and returned after planning;
//! a missing variable cannot hide a failed native comparison.
use super::{EnvironmentSnapshot, LaunchError};
use gnunet_config::Environment;
use gnunet_native::os_bytes;
use std::{
    cell::RefCell,
    io,
    path::{Path, PathBuf},
};
pub(super) struct PlanEnvironment<'snapshot> {
    snapshot: &'snapshot EnvironmentSnapshot,
    failure: RefCell<Option<io::Error>>,
}
impl<'snapshot> PlanEnvironment<'snapshot> {
    pub(super) fn new(snapshot: &'snapshot EnvironmentSnapshot) -> Self {
        Self {
            snapshot,
            failure: RefCell::new(None),
        }
    }
    pub(super) fn finish<T>(self, result: Result<T, LaunchError>) -> Result<T, LaunchError> {
        match self.failure.into_inner() {
            Some(error) => Err(error.into()),
            None => result,
        }
    }
    fn lookup(&self, name: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let name = os_bytes::decode(name)?;
        self.snapshot
            .variable_os(&name)
            .map(|value| value.map(|value| os_bytes::encode(value).into_owned()))
    }
}
impl Environment for PlanEnvironment<'_> {
    fn variable(&self, name: &[u8]) -> Option<Vec<u8>> {
        match self.lookup(name) {
            Ok(value) => value,
            Err(error) => {
                self.failure.borrow_mut().get_or_insert(error);
                None
            }
        }
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        Ok(self.snapshot.current_dir().to_owned())
    }
    fn absolute_path(&self, path: &Path) -> io::Result<PathBuf> {
        self.snapshot.absolute_path(path)
    }
    fn home_dir(&self) -> io::Result<Option<PathBuf>> {
        match self.lookup(b"HOME")? {
            Some(home) => Some(home),
            None => self.lookup(b"USERPROFILE")?,
        }
        .map(|value| os_bytes::decode_owned(value).map(PathBuf::from))
        .transpose()
    }
}
