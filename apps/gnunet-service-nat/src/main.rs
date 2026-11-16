//! Normal official gnunet-service-nat PROGRAM entry.
#![deny(unsafe_code)]
#[expect(
    unsafe_code,
    reason = "Fresh single-threaded executable transfers original inherited resources before native initialization"
)]
fn main() -> std::process::ExitCode {
    // SAFETY: first and only initialization in the fresh executable.
    unsafe { gnunet_nat_host::foreground::main(gnunet_nat_host::server::Mode::Nat) }
}
