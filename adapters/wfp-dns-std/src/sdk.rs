//! Explicit persistent FWPM metadata provisioning under the caller's identity.
#![expect(
    unsafe_code,
    reason = "FWPM calls borrow fixed SDK structures and retain only their documented original engine and allocation owners"
)]
pub(super) mod provision;
use super::NativeFailure;

fn check(operation: &'static str, code: u32) -> Result<(), NativeFailure> {
    if code == 0 {
        Ok(())
    } else {
        Err(NativeFailure { operation, code })
    }
}
