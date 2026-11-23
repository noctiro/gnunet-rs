//! Watchdog for the original Windows process and its private job.
use super::{Outcome, REAP_GRACE, diagnostic};
use gnunet_native::process::{Console, JobProcess, JobRetirement, LaunchLimits, Spawn, Stdio};
use gnunet_service_runtime::process::{EnvironmentSnapshot, resolve_executable};
use std::{
    ffi::{OsStr, OsString},
    future::poll_fn,
    io,
    process::ExitCode,
    time::Duration,
};
use tokio::{
    signal::windows::{ctrl_break, ctrl_c},
    time::{sleep, timeout},
};

const CONTROL_EXIT: u32 = 0xc000_013a;

pub(super) async fn run(
    program: &OsStr,
    arguments: &[OsString],
    duration: Duration,
) -> io::Result<Outcome> {
    let mut interrupt = ctrl_c()?;
    let mut break_event = ctrl_break()?;
    let limits = LaunchLimits::default();
    let environment =
        EnvironmentSnapshot::from_values(std::env::vars_os(), std::env::current_dir()?, limits)?;
    let executable = resolve_executable(program, &environment)?;
    let command = Spawn {
        executable: &executable,
        argv0: program,
        arguments,
        environment: environment.values(),
        directory: environment.current_dir(),
        stdio: [Stdio::Inherit; 3],
        exported_handles: &[],
        console: Console::NewProcessGroup,
    };
    let mut job = match JobProcess::launch(command, limits) {
        Ok(job) => job,
        Err(failure) => {
            if let Some(retirement) = failure.retirement {
                retire_failed_start(retirement).await;
            }
            return Err(failure.error);
        }
    };
    let timed_out = tokio::select! {
        biased;
        code = poll_fn(|cx| job.poll_exit(cx)) => {
            let code = code?;
            if let Err(error) = job.release_after_exit() {
                diagnostic(error);
            }
            return Ok(Outcome::Exited(code));
        }
        _ = interrupt.recv() => false,
        _ = break_event.recv() => false,
        _ = sleep(duration) => true,
    };
    let code = if timed_out { 3 } else { CONTROL_EXIT };
    if let Err(error) = job.terminate(code) {
        diagnostic(error);
        // Dropping this unique job handle requests kill-on-close independently.
        return Ok(if timed_out {
            Outcome::Deadline
        } else {
            Outcome::Exited(code)
        });
    }
    match timeout(REAP_GRACE, poll_fn(|cx| job.poll_exit(cx))).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => diagnostic(error),
        Err(_) => diagnostic("original child exit could not be confirmed within the reap deadline"),
    }
    Ok(if timed_out {
        Outcome::Deadline
    } else {
        Outcome::Exited(code)
    })
}

async fn retire_failed_start(mut original: JobRetirement) {
    if let Err(error) = original.request_stop() {
        diagnostic(error);
    }
    let wait = async {
        while original.try_wait()?.is_none() {
            sleep(Duration::from_millis(10)).await;
        }
        Ok::<(), io::Error>(())
    };
    match timeout(REAP_GRACE, wait).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => diagnostic(error),
        Err(_) => {
            diagnostic("failed startup child exit could not be confirmed within the reap deadline")
        }
    }
}

#[expect(
    clippy::exit,
    reason = "Windows native exit statuses span 32 bits and portable ExitCode::from accepts only u8"
)]
pub(super) fn exit(code: u32) -> ExitCode {
    if let Ok(narrowed) = u8::try_from(code) {
        ExitCode::from(narrowed)
    } else {
        std::process::exit(code as i32);
    }
}
