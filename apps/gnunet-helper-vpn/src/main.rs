//! Actual installed VPN helper over the small shared privileged boundary.
#![deny(unsafe_code)]
#[expect(
    unsafe_code,
    reason = "The standalone fresh helper main transfers original inherited fd0/fd1 exactly once before constructing any competing stream or descriptor owner"
)]
fn main() -> std::process::ExitCode {
    // SAFETY: first operation in this dedicated helper entry, before any stdio
    // or FD owner is constructed. No old handle is used after the transfer.
    match unsafe { gnunet_tun_helper_host::run(gnunet_tun_helper_host::Profile::Vpn) } {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            gnunet_tun_helper_host::diagnostic(&error);
            std::process::ExitCode::from(error.exit_code())
        }
    }
}
