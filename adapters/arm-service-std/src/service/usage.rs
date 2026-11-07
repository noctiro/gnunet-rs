//! Optional official resource file receives ONLY real original wait4 receipts.
use super::Failure;
use gnunet_service_runtime::process::{Reaped, ResourceUsage};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
};
pub(super) struct Usage {
    file: Option<File>,
    failed: bool,
}
impl Usage {
    pub(super) fn disabled() -> Self {
        Self {
            file: None,
            failed: false,
        }
    }
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            file: Some(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)?,
            ),
            failed: false,
        })
    }
    pub(super) fn enabled(&self) -> bool {
        self.file.is_some() && !self.failed
    }
    pub(super) fn write(
        &mut self,
        binary: &[u8],
        event: &Reaped,
        usage: ResourceUsage,
    ) -> Result<(), Failure> {
        let Some(file) = &mut self.file else {
            return Ok(());
        };
        if self.failed {
            return Err("ARM resource file already failed".into());
        }
        let actual = (|| -> io::Result<()> {
            file.write_all(binary)?;
            write!(file, "({}) ", event.pid)?;
            cpu(file, usage.user_micros)?;
            file.write_all(b" ")?;
            cpu(file, usage.system_micros)?;
            writeln!(
                file,
                " {} {} {} {} {}",
                usage.max_rss,
                usage.in_blocks,
                usage.out_blocks,
                usage.voluntary_switches,
                usage.involuntary_switches
            )?;
            file.flush()
        })();
        if let Err(error) = actual {
            self.failed = true;
            return Err(Box::new(error));
        }
        Ok(())
    }
    pub(super) fn finish(&mut self) -> io::Result<()> {
        if let Some(file) = &mut self.file {
            file.flush()?
        }
        Ok(())
    }
}

fn cpu(file: &mut File, micros: u64) -> io::Result<()> {
    let millis = micros / 1000 + u64::from(micros % 1000 >= 500);
    write!(file, "{}.{:03}", millis / 1000, millis % 1000)
}
