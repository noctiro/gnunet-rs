//! Containing-application DNS proxy management entry.
#![forbid(unsafe_code)]
fn main() -> std::process::ExitCode {
    gnunet_service_dns::run_control()
}
