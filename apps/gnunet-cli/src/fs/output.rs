//! FS command output context; native blocking work belongs to PROGRAM/native.
use gnunet_program_host::output::{BoundedOutput, Control, Failure, Snapshot};
use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    io::{self, Write},
    time::{Duration, Instant},
};
pub(super) const GRACE: Duration = Duration::from_secs(5);
pub(super) struct Output<'a, W> {
    sink: &'a mut W,
    control: Control,
}
impl<'a, W: Write> Output<'a, W> {
    pub(super) fn new(sink: &'a mut W, control: Control) -> Self {
        Self { sink, control }
    }
    pub(super) fn deadline(&self, hard: impl Into<Instant>) {
        self.control.deadline(hard.into());
    }
    pub(super) fn interval(&self, micros: u64) -> io::Result<()> {
        let hard = Instant::now()
            .checked_add(Duration::from_micros(micros))
            .ok_or(io::ErrorKind::InvalidInput)?;
        self.deadline(hard);
        Ok(())
    }
    pub(super) fn cleanup(&self) -> io::Result<()> {
        self.control.cleanup(GRACE)
    }
}
impl<W: Write> Write for Output<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.sink.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}
type Cause = Box<dyn Error>;
#[derive(Debug)]
struct Report {
    binary: &'static str,
    operation: Option<Cause>,
    stdout: Option<Result<Snapshot, Failure>>,
    diagnostic: Option<Cause>,
}
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = &self.operation {
            write!(f, "{error}; ")?;
        }
        if let Some(output) = &self.stdout {
            write!(f, "stdout={output:?}; ")?;
        }
        if let Some(error) = &self.diagnostic {
            write!(f, "diagnostic={error}")?;
        }
        Ok(())
    }
}
impl Error for Report {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.operation.as_deref().or_else(|| {
            self.stdout
                .as_ref()
                .and_then(|out| out.as_ref().err().map(|error| error as &dyn Error))
        })
    }
}
pub(crate) fn selected(error: &(dyn Error + 'static)) -> bool {
    error.is::<Report>()
}

// Domain Display implementations remain on the command thread. Bound retained
// diagnostics independently from arbitrary namespace/source error contents.
struct Diagnostic {
    text: String,
    truncated: bool,
}
impl fmt::Write for Diagnostic {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let remaining = 16 * 1024 - self.text.len();
        let count = text.floor_char_boundary(remaining.min(text.len()));
        self.text.push_str(&text[..count]);
        self.truncated |= count != text.len();
        Ok(())
    }
}
fn report(mut failure: Report) -> Result<(), Cause> {
    use fmt::Write as _;
    let mut diagnostic = Diagnostic {
        text: String::new(),
        truncated: false,
    };
    let _format = write!(diagnostic, "{}: {failure}", failure.binary);
    if diagnostic.truncated {
        diagnostic.text.push_str(" [truncated]");
    }
    diagnostic.text.push('\n');
    let emitted = (|| -> Result<(), Cause> {
        let mut stderr = BoundedOutput::stderr(GRACE)?;
        stderr.control().cleanup(GRACE)?;
        let write = stderr.write_all(diagnostic.text.as_bytes());
        if write.is_err() {
            stderr.discard_buffer();
        }
        let settled = stderr.finish();
        match (write, settled) {
            (_, Err(error)) => Err(Box::new(error)),
            (Err(error), _) => Err(Box::new(error)),
            (Ok(()), Ok(_)) => Ok(()),
        }
    })();
    failure.diagnostic = emitted.err();
    Err(Box::new(failure))
}
pub(crate) fn native(args: &[impl AsRef<OsStr>]) -> Result<(), Cause> {
    let bytes = args
        .first()
        .is_some_and(|value| value.as_ref() == OsStr::new("cat"));
    with_stdout("gnunet-cli", bytes, |out| super::execute(args, out))
}

pub(super) fn with_stdout(
    binary: &'static str,
    bytes: bool,
    operation: impl FnOnce(&mut Output<'_, BoundedOutput>) -> Result<(), Cause>,
) -> Result<(), Cause> {
    let output = if bytes {
        BoundedOutput::stdout_bytes(GRACE)
    } else {
        BoundedOutput::stdout(GRACE)
    };
    let mut stdout = match output {
        Ok(output) => output,
        Err(error) => {
            return report(Report {
                binary,
                operation: Some(Box::new(error)),
                stdout: None,
                diagnostic: None,
            });
        }
    };
    let control = stdout.control();
    let operation = operation(&mut Output::new(&mut stdout, control.clone()));
    if operation.is_err() {
        stdout.discard_buffer();
    }
    // Final flush has one explicit cleanup grace, never a renewed work bound.
    let cleanup = control.cleanup(GRACE);
    let settled = stdout.finish();
    if operation.is_ok() && cleanup.is_ok() && settled.is_ok() {
        return Ok(());
    }
    report(Report {
        binary,
        operation: operation
            .err()
            .or_else(|| cleanup.err().map(|error| Box::new(error) as Cause)),
        stdout: Some(settled),
        diagnostic: None,
    })
}
