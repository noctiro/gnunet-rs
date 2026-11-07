//! Actual ordinary configuration command with one selected process logger.
//! The leaf configuration crate owns parsing/tool semantics; this upper owner
//! holds the explicit process-stderr capability and the original diagnostic route.
use crate::{
    config_observer::Route,
    logging::{Environment, Logger, Stamp},
    process_stderr::ProcessStderr,
    shared_clock::SharedClock,
};
use gnunet_config::{
    ConfigCommandPreparation, Error as ConfigError, ToolOutput, prepare_config_command_with_program,
};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
};

/// Actual functional output and independent configuration/logging/output causes.
/// Output bytes are retained observations of the attempted writes, not an ACK.
pub struct Report {
    /// Original functional output and source result code, including partial setup.
    pub output: ToolOutput,
    /// Original configuration error, including one folded into exit status1/2.
    pub configuration_error: Option<ConfigError>,
    /// Actual logger/clock/setup or diagnostic-destination failure.
    pub logging_error: Option<io::Error>,
    /// Actual functional output/fallback write or flush failure.
    pub output_error: Option<io::Error>,
    /// True only when the original prepared command was actually executed.
    pub command_started: bool,
}
impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigCommandReport([REDACTED])")
            .field("exit_code", &self.output.exit_code)
            .field("command_started", &self.command_started)
            .field("configuration_error", &self.configuration_error)
            .field("logging_error", &self.logging_error)
            .field("output_error", &self.output_error)
            .finish_non_exhaustive()
    }
}
impl Report {
    fn empty() -> Self {
        Self {
            output: ToolOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
            },
            configuration_error: None,
            logging_error: None,
            output_error: None,
            command_started: false,
        }
    }
    /// Source nonzero statuses survive independently retained errors. Failed
    /// output always fails the process; logger failure cannot become success.
    pub fn exit_code(&self) -> u8 {
        if self.output_error.is_some() {
            return 1;
        }
        if self.output.exit_code != 0 {
            return u8::try_from(self.output.exit_code).unwrap_or(1);
        }
        u8::from(self.configuration_error.is_some() || self.logging_error.is_some())
    }
    fn write(
        &mut self,
        stdout: &mut impl Write,
        stderr: &mut impl Write,
        stdout_from: usize,
        stderr_from: usize,
    ) {
        if self.output_error.is_some() {
            return;
        }
        let result = (|| {
            let out = self
                .output
                .stdout
                .get(stdout_from..)
                .ok_or_else(|| io::Error::other("configuration output prefix changed"))?;
            let err = self
                .output
                .stderr
                .get(stderr_from..)
                .ok_or_else(|| io::Error::other("configuration diagnostic prefix changed"))?;
            stdout.write_all(out)?;
            stdout.flush()?;
            stderr.write_all(err)?;
            stderr.flush()
        })();
        self.output_error = result.err();
    }
    fn config_failure(&mut self, error: ConfigError) {
        self.output.exit_code = 1;
        self.output
            .stderr
            .extend_from_slice(format!("gnunet-config: {error}\n").as_bytes());
        self.configuration_error = Some(error);
    }
    fn logging_fallback(&mut self, stderr: &mut impl Write) {
        if let Some(error) = self.logging_error.as_ref() {
            let result =
                writeln!(stderr, "gnunet-config logging: {error}").and_then(|()| stderr.flush());
            if self.output_error.is_none() {
                self.output_error = result.err();
            }
        }
    }
}

/// Run the actual standalone command with one explicit process-stderr owner.
/// The caller establishes the capability's single-thread/stdio contract. A
/// requested logfile therefore receives ordinary stderr as well as log records.
/// The same caller flushes stdout and keeps stderr unbuffered across setup.
/// No runtime, task, worker, resolver or second logging engine is created.
pub fn run_config_command_with_program(
    program: &OsStr,
    arguments: &[OsString],
    stderr_owner: ProcessStderr,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Report {
    let mut report = Report::empty();
    let prepared = match prepare_config_command_with_program(program, arguments) {
        Ok(ConfigCommandPreparation::Immediate(output)) => {
            report.output = output;
            report.write(stdout, stderr, 0, 0);
            return report;
        }
        Ok(ConfigCommandPreparation::Ready(prepared)) => prepared,
        Err(error) => {
            report.config_failure(error);
            report.write(stdout, stderr, 0, 0);
            return report;
        }
    };
    report.output = prepared.initial_output().clone();
    // GETOPT's already prepared version bytes precede logging and file IO.
    report.write(stdout, stderr, 0, 0);
    if report.output_error.is_some() {
        return report;
    }
    let emitted_stdout = report.output.stdout.len();
    let emitted_stderr = report.output.stderr.len();
    let selected = (|| -> io::Result<_> {
        let clock = SharedClock::native(0).map_err(io::Error::other)?;
        let mut logger = Logger::new(b"gnunet-config", std::process::id(), true)?;
        logger.bind_clock(clock.clone());
        logger.install_process_stderr(stderr_owner)?;
        let selection = prepared.logging();
        logger.setup_routed(
            b"gnunet-config",
            selection.level,
            selection.file.map(|p| p.as_os_str().as_bytes()),
            &Environment::capture(),
            &Stamp::setup_now()?,
            stderr,
        )?;
        Ok((logger, clock))
    })();
    let (mut logger, clock) = match selected {
        Ok(selected) => selected,
        Err(error) => {
            report.logging_error = Some(error);
            report.logging_fallback(stderr);
            return report;
        }
    };
    let route = Route::new(&mut logger, &clock, stderr);
    report.command_started = true;
    let result = {
        let observer = |event: gnunet_config::diagnostic::Diagnostic<'_>| route.event(event);
        prepared.execute_observed(&observer)
    };
    match result {
        Ok(result) => {
            report.output = result.output;
            report.configuration_error = result.error;
        }
        Err(error) => report.config_failure(error),
    }
    report.logging_error = route.finish().err();
    // ProcessStderr remains owned by logger and actual fd2 stays installed.
    // Functional status bytes are written once, not reconstructed as log records.
    report.write(stdout, stderr, emitted_stdout, emitted_stderr);
    report.logging_fallback(stderr);
    report
}
