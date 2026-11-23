use crate::Cause;
use std::fmt;

/// The selected Logger has already handled the terminal diagnostic. A caller
/// must not repeat it through fd2 and bypass the selected -L/-l destination.
#[derive(Debug)]
pub(super) struct Reported(pub Cause);
impl fmt::Display for Reported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for Reported {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
