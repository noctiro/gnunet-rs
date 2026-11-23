//! Official DNS service executable.
#![forbid(unsafe_code)]
fn main() -> std::process::ExitCode {
    gnunet_service_dns::run()
}
