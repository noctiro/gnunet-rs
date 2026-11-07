//! Bounded status summary; no private key or certificate bytes are formatted.
use std::{
    fmt,
    io::{self, Write},
};

pub(super) struct Output {
    pub verbose: bool,
    summary: Option<Vec<String>>,
}
impl Output {
    pub(super) fn new(verbose: bool, summary: bool) -> Self {
        Self {
            verbose,
            summary: summary.then(Vec::new),
        }
    }
    pub(super) fn status(&mut self, message: fmt::Arguments<'_>) -> io::Result<()> {
        let message = message.to_string();
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{message}")?;
        stdout.flush()?;
        if let Some(summary) = &mut self.summary {
            if summary.len() == 272 || message.len() > 8192 {
                return Err(io::Error::other("CA preparation summary limit reached"));
            }
            summary.try_reserve(1).map_err(io::Error::other)?;
            summary.push(message);
        }
        Ok(())
    }
    pub(super) fn info(&mut self, message: fmt::Arguments<'_>) -> io::Result<()> {
        if self.verbose {
            self.status(message)
        } else {
            Ok(())
        }
    }
    pub(super) fn finish(&self) -> io::Result<()> {
        if let Some(summary) = &self.summary {
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "===> Summary of results:")?;
            for line in summary {
                writeln!(stdout, "  {line}")?;
            }
            writeln!(stdout, "===> .")?;
            stdout.flush()?;
        }
        Ok(())
    }
}
