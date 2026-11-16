//! CADET stdin/stdout roles over the shared original native I/O retirement.
use gnunet_program_host::binary_io::{self, RetiredSet};
use tokio::time::Instant;
#[derive(Debug)]
pub(crate) struct Retired(RetiredSet<2>);
impl Retired {
    pub(crate) fn input_bytes(&self) -> Option<usize> {
        self.0.get(0)?.count()
    }
    pub(crate) fn output_bytes(&self) -> Option<usize> {
        self.0.get(1)?.count()
    }
    pub(crate) fn input_cancelled(&self) -> Option<bool> {
        self.0.get(0).map(binary_io::Retired::read_cancelled)
    }
    pub(crate) fn input_closed(&self) -> Option<bool> {
        self.0
            .get(0)
            .map(|r| r.closed().is_some_and(|v| v.close.is_none()))
    }
    pub(crate) fn output_closed(&self) -> Option<bool> {
        self.0
            .get(1)
            .map(|r| r.closed().is_some_and(|v| v.close.is_none()))
    }
    pub(crate) fn output_flushed(&self) -> Option<bool> {
        self.0
            .get(1)
            .map(|r| r.closed().is_some_and(|v| v.flush.is_none()))
    }
    pub(crate) fn successful(&self) -> bool {
        self.0.successful()
    }
}
impl std::fmt::Display for Retired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for Retired {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
pub(super) async fn retire(
    input: Option<binary_io::Retirement>,
    output: Option<binary_io::Retirement>,
    hard: Instant,
) -> Retired {
    Retired(binary_io::settle([input, output], hard.into_std()).await)
}
