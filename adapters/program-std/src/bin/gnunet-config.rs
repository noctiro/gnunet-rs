//! Ordinary configuration tool using the actual shared selected logging owner.
#![deny(unsafe_code)]
use std::{io, process::ExitCode};
fn main() -> ExitCode {
    #[expect(
        unsafe_code,
        reason = "Fresh main alone establishes global fd2 exclusivity for the shared ProcessStderr capability"
    )]
    // SAFETY: This is the fresh standalone main. No runtime/thread, foreign
    // callback or buffered stderr writer exists, and this owner spans every
    // selected destination change before the process exits.
    let stderr_owner = match unsafe { gnunet_program_host::process_stderr::ProcessStderr::claim() }
    {
        Ok(owner) => owner,
        Err(error) => {
            use std::io::Write;
            drop(writeln!(
                io::stderr().lock(),
                "gnunet-config stderr: {error}"
            ));
            return ExitCode::FAILURE;
        }
    };
    let mut arguments = std::env::args_os();
    let program = arguments.next().unwrap_or_else(|| "gnunet-config".into());
    let arguments: Vec<_> = arguments.collect();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let report = gnunet_program_host::config_command::run_config_command_with_program(
        &program,
        &arguments,
        stderr_owner,
        &mut stdout,
        &mut stderr,
    );
    ExitCode::from(report.exit_code())
}
