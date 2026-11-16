//! Exact daemon startup status bytes, independent of the native carrier.
/// Startup status implemented by official GNUnet service.c.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadyStatus {
    /// Accept registration succeeded: '.'. Callers may require actual Host-ready
    /// before publishing this stronger startup fact.
    AcceptRegistered,
    /// Initialization failed after detaching: 'I'.
    InitializationFailed,
    /// The server/scheduler did not start before shutdown: 'S'.
    ServerNotStarted,
}
impl ReadyStatus {
    /// One native parent-pipe byte, not a GNUnet IPC frame.
    pub const fn byte(self) -> u8 {
        match self {
            Self::AcceptRegistered => b'.',
            Self::InitializationFailed => b'I',
            Self::ServerNotStarted => b'S',
        }
    }
    /// Decode only an exact official status byte.
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'.' => Some(Self::AcceptRegistered),
            b'I' => Some(Self::InitializationFailed),
            b'S' => Some(Self::ServerNotStarted),
            _ => None,
        }
    }
}
