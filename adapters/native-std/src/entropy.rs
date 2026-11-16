//! Operating-system cryptographic randomness without device-path assumptions.
use std::io;
/// Fill the complete caller-owned buffer from the platform CSPRNG.
///
/// # Errors
/// Retains the OS/provider error and clears all output on failure. No partial
/// random result is published; an empty buffer remains a valid request.
pub fn fill(output: &mut [u8]) -> io::Result<()> {
    match getrandom::fill(output) {
        Ok(()) => Ok(()),
        Err(error) => {
            output.fill(0);
            Err(io::Error::other(error))
        }
    }
}
