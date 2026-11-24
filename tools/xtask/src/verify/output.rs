//! Bounded live command output and incremental verification results.
use super::CheckResult;
use serde_json::{Value, json};
use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
struct ReportingFailure {
    original: Box<dyn Error>,
    reporting: Box<dyn Error>,
}
impl fmt::Display for ReportingFailure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "{}; independent output/report failure: {}",
            self.original, self.reporting
        )
    }
}
impl Error for ReportingFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}

pub(super) fn combine<T>(original: CheckResult<T>, reporting: CheckResult<()>) -> CheckResult<T> {
    match (original, reporting) {
        (Err(original), Err(reporting)) => Err(Box::new(ReportingFailure {
            original,
            reporting,
        })),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

pub(super) struct Recorder {
    directory: Option<PathBuf>,
    group: String,
    stage: Option<&'static str>,
    started: Instant,
    steps: Vec<Value>,
}
impl Recorder {
    pub(super) fn new(group: &str, base: Option<&Path>) -> CheckResult<Self> {
        let directory = base.map(run_directory).transpose()?;
        let recorder = Self {
            directory,
            group: group.to_owned(),
            stage: None,
            started: Instant::now(),
            steps: Vec::new(),
        };
        recorder.persist("running", None)?;
        if let Some(directory) = &recorder.directory {
            writeln!(
                io::stdout().lock(),
                "verification logs: {}",
                directory.display()
            )?;
        }
        Ok(recorder)
    }

    pub(super) fn begin_stage(&mut self, stage: &'static str) -> CheckResult<()> {
        self.stage = Some(stage);
        self.persist("running", None)
    }

    pub(super) fn check<T>(
        &mut self,
        name: &str,
        action: impl FnOnce() -> CheckResult<T>,
    ) -> CheckResult<T> {
        let started = Instant::now();
        let result = action();
        self.steps.push(json!({
            "stage": self.stage,
            "kind": "check",
            "name": name,
            "status": if result.is_ok() { "passed" } else { "failed" },
            "seconds": started.elapsed().as_secs_f64(),
            "error": result.as_ref().err().map(ToString::to_string),
        }));
        combine(result, self.persist("running", None))
    }

    pub(super) fn command(&mut self, program: &str, args: &[impl AsRef<OsStr>]) -> CheckResult<()> {
        self.run(Command::new(program).args(args))
    }

    pub(super) fn run(&mut self, command: &mut Command) -> CheckResult<()> {
        self.command_with(command, io::stdout(), io::stderr())
    }

    fn command_with(
        &mut self,
        command: &mut Command,
        stdout: impl Write + Send,
        stderr: impl Write + Send,
    ) -> CheckResult<()> {
        let started = Instant::now();
        let index = self.steps.len() + 1;
        let stdout_name = format!("{index:03}-stdout.log");
        let stderr_name = format!("{index:03}-stderr.log");
        let (exit, result) = if let Some(directory) = &self.directory {
            logged(
                command,
                &directory.join(&stdout_name),
                &directory.join(&stderr_name),
                stdout,
                stderr,
            )
        } else {
            completed(command.status())
        };
        let argv: Vec<_> = std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(OsStr::to_string_lossy)
            .collect();
        self.steps.push(json!({
            "stage": self.stage,
            "kind": "command",
            "argv": argv,
            "status": if result.is_ok() { "passed" } else { "failed" },
            "exit_code": exit.and_then(|status| status.code()),
            "seconds": started.elapsed().as_secs_f64(),
            "error": result.as_ref().err().map(ToString::to_string),
            "stdout": self.directory.as_ref().map(|_| stdout_name),
            "stderr": self.directory.as_ref().map(|_| stderr_name),
        }));
        combine(result, self.persist("running", None))
    }

    pub(super) fn finish(&self, result: &CheckResult<()>) -> CheckResult<()> {
        self.persist(
            if result.is_ok() { "passed" } else { "failed" },
            result.as_ref().err().map(ToString::to_string),
        )
    }

    fn persist(&self, status: &str, error: Option<String>) -> CheckResult<()> {
        let Some(directory) = &self.directory else {
            return Ok(());
        };
        let temporary = directory.join("result.json.tmp");
        let mut file = File::create(&temporary)?;
        serde_json::to_writer_pretty(
            &mut file,
            &json!({
                "schema": 1,
                "group": self.group,
                "status": status,
                "stage": self.stage,
                "seconds": self.started.elapsed().as_secs_f64(),
                "error": error,
                "steps": self.steps,
            }),
        )?;
        writeln!(file)?;
        drop(file);
        fs::rename(temporary, directory.join("result.json"))?;
        Ok(())
    }
}

fn run_directory(base: &Path) -> io::Result<PathBuf> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fs::create_dir_all(base)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    for _ in 0..32 {
        let directory = base.join(format!(
            "run-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "verification log namespace exhausted",
    ))
}

fn completed(status: io::Result<ExitStatus>) -> (Option<ExitStatus>, CheckResult<()>) {
    match status {
        Ok(status) if status.success() => (Some(status), Ok(())),
        Ok(status) => (
            Some(status),
            Err(format!("command failed with {status}").into()),
        ),
        Err(error) => (None, Err(error.into())),
    }
}

fn stop_after_error(child: &mut Child, result: CheckResult<()>) -> CheckResult<()> {
    let result = combine(result, child.kill().map_err(Into::into));
    combine(result, child.wait().map(|_| ()).map_err(Into::into))
}

fn logged(
    command: &mut Command,
    stdout: &Path,
    stderr: &Path,
    stdout_console: impl Write + Send,
    stderr_console: impl Write + Send,
) -> (Option<ExitStatus>, CheckResult<()>) {
    let execute = || -> io::Result<_> {
        let stdout = File::create(stdout)?;
        let stderr = File::create(stderr)?;
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
            return Ok((
                None,
                stop_after_error(
                    &mut child,
                    Err(io::Error::other("child output pipes missing").into()),
                ),
            ));
        };
        let (status, output) = thread::scope(|scope| {
            let out = scope.spawn(|| pump(out, stdout, stdout_console));
            let err = scope.spawn(|| pump(err, stderr, stderr_console));
            let (status, mut result) = completed(child.wait());
            if status.is_none() {
                result = stop_after_error(&mut child, result);
            }
            for worker in [out, err] {
                let drained = worker
                    .join()
                    .unwrap_or_else(|_| Err(io::Error::other("command output worker panicked")));
                result = combine(result, drained.map_err(Into::into));
            }
            (status, result)
        });
        Ok((status, output))
    };
    execute().unwrap_or_else(|error| (None, Err(error.into())))
}

// Drain both child pipes even after a sink fails, so a reporting failure cannot
// deadlock the child. Each worker retains only one fixed-size output chunk.
fn pump(mut source: impl Read, log: File, console: impl Write) -> io::Result<()> {
    let mut log = Some(log);
    let mut console = Some(console);
    let mut failure = None;
    let mut buffer = [0; 16384];
    loop {
        let count = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                if failure.is_none() {
                    failure = Some(error);
                }
                break;
            }
        };
        if let Some(sink) = &mut log
            && let Err(error) = sink.write_all(&buffer[..count])
        {
            log = None;
            if failure.is_none() {
                failure = Some(error);
            }
        }
        if let Some(sink) = &mut console
            && let Err(error) = sink.write_all(&buffer[..count])
        {
            console = None;
            if failure.is_none() {
                failure = Some(error);
            }
        }
    }
    if let Some(mut sink) = console
        && let Err(error) = sink.flush()
        && failure.is_none()
    {
        failure = Some(error);
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> io::Result<Self> {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ci-controls");
            run_directory(&root).map(Self)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    #[ignore = "Failure-injection child invoked only by the output recording regression"]
    fn failed_child() -> CheckResult<()> {
        // More than a native pipe buffer in both directions exercises concurrent
        // draining; the parent must keep the real nonzero child outcome.
        let stdout = vec![b'o'; 131072];
        let stderr = vec![b'e'; 131072];
        io::stdout().lock().write_all(&stdout)?;
        io::stderr().lock().write_all(&stderr)?;
        Err("controlled command failure".into())
    }

    #[test]
    fn failed_command_keeps_complete_logs_and_original_exit_in_report() -> CheckResult<()> {
        let directory = Directory::new()?;
        let mut recorder = Recorder::new("fixture", Some(&directory.0))?;
        recorder.begin_stage("test")?;
        let executable = std::env::current_exe()?;
        let result = recorder.command_with(
            Command::new(executable).args([
                "--exact",
                "verify::output::tests::failed_child",
                "--ignored",
                "--nocapture",
            ]),
            io::sink(),
            io::sink(),
        );
        if result.is_ok() {
            return Err("failed child was reported as successful".into());
        }
        recorder.finish(&result)?;
        let run = recorder.directory.as_ref().ok_or("missing run directory")?;
        let report: Value = serde_json::from_reader(File::open(run.join("result.json"))?)?;
        let step = &report["steps"][0];
        if report["status"] != "failed" || step["status"] != "failed" || step["exit_code"] != 101 {
            return Err(format!("child failure was lost: {report}").into());
        }
        for (key, byte) in [("stdout", b'o'), ("stderr", b'e')] {
            let path = step[key].as_str().ok_or("missing output log")?;
            let bytes = fs::read(run.join(path))?;
            if bytes.iter().filter(|value| **value == byte).count() < 131072 {
                return Err(format!("{key} output was not completely drained").into());
            }
        }
        Ok(())
    }

    #[test]
    fn failed_policy_records_stage_and_actual_error_without_a_child_process() -> CheckResult<()> {
        let directory = Directory::new()?;
        let mut recorder = Recorder::new("source", Some(&directory.0))?;
        recorder.begin_stage("policy")?;
        let result = recorder.check("dependency boundary", || {
            Err("forbidden production edge".into())
        });
        recorder.finish(&result)?;
        let run = recorder.directory.as_ref().ok_or("missing run directory")?;
        let report: Value = serde_json::from_reader(File::open(run.join("result.json"))?)?;
        if report["status"] != "failed"
            || report["stage"] != "policy"
            || report["steps"][0]["error"] != "forbidden production edge"
        {
            return Err(format!("source policy failure was not recorded: {report}").into());
        }
        Ok(())
    }

    #[test]
    fn reporting_failure_never_replaces_the_original_check_error() -> CheckResult<()> {
        let directory = Directory::new()?;
        let mut recorder = Recorder::new("source", Some(&directory.0))?;
        recorder.begin_stage("policy")?;
        let run = recorder.directory.as_ref().ok_or("missing run directory")?;
        let destination = run.join("result.json");
        fs::remove_file(&destination)?;
        fs::create_dir(&destination)?;
        let result = recorder.check("boundary", || {
            Err::<(), _>("original boundary refusal".into())
        });
        let error = result.err().ok_or("reporting fault returned success")?;
        if !error.to_string().contains("original boundary refusal")
            || error
                .source()
                .is_none_or(|source| source.to_string() != "original boundary refusal")
        {
            return Err(format!("reporting fault replaced the primary error: {error}").into());
        }
        Ok(())
    }
}
