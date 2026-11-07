//! Actual official NAT client helper entry; no input is parsed before raw capture/drop.
#![forbid(unsafe_code)]
fn main() -> std::process::ExitCode {
    match gnunet_nat_helper_host::client() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            gnunet_nat_helper_host::diagnostic(&error);
            std::process::ExitCode::from(error.code)
        }
    }
}
