//! Actual official ARM CLI entrypoint.
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(gnunet_arm_cli::runtime::main_from(std::env::args_os()))
}
