//! Ordinary official Paillier scalarproduct Alice SERVICE executable.
#![deny(unsafe_code)]
#[expect(
    unsafe_code,
    reason = "Fresh single-threaded executable entry before adopting any descriptor or runtime owner"
)]
fn main() -> std::process::ExitCode {
    // SAFETY: first and only call from the fresh executable entrypoint.
    unsafe { gnunet_service_scalarproduct::paillier_alice_main() }
}
