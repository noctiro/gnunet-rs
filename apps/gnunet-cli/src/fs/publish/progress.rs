//! Bounded foreground delivery of real publication preparation events.
use super::Gate;
use gnunet::fs_host::{Control, publication::plan::tree::Event};
use std::{
    future::poll_fn,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::Duration,
};
use tokio::sync::mpsc;

pub(super) struct Producer {
    level: u32,
    sender: mpsc::Sender<Update>,
}

pub(in crate::fs) enum Update {
    Scanning(PathBuf, bool),
    ScanComplete,
    Extracted(PathBuf),
    MetadataComplete,
    Encoding {
        relative: PathBuf,
        completed: u64,
        total: u64,
        elapsed: Duration,
    },
}

pub(super) fn channel(level: u32) -> (Option<Producer>, Option<mpsc::Receiver<Update>>) {
    if level == 0 {
        return (None, None);
    }
    let (sender, receiver) = mpsc::channel(4);
    (Some(Producer { level, sender }), Some(receiver))
}

impl Producer {
    pub(super) fn report(&self, event: Event<'_>) -> Control {
        let Some(update) = select(self.level, event) else {
            return Control::Continue;
        };
        if self.sender.blocking_send(update).is_ok() {
            Control::Continue
        } else {
            Control::Cancel
        }
    }
}

pub(in crate::fs) fn select(level: u32, event: Event<'_>) -> Option<Update> {
    if level == 0 {
        return None;
    }
    let update = match event {
        Event::Scanning {
            relative,
            directory,
        } if level > 1 => Update::Scanning(relative.to_path_buf(), directory),
        Event::ScanComplete => Update::ScanComplete,
        Event::Extracted(relative) if level > 2 => Update::Extracted(relative.to_path_buf()),
        Event::MetadataComplete if level > 1 => Update::MetadataComplete,
        Event::Encoding {
            relative,
            completed,
            total,
            elapsed,
        } => Update::Encoding {
            relative: relative.to_path_buf(),
            completed,
            total,
            elapsed,
        },
        _ => return None,
    };
    Some(update)
}

pub(super) async fn drain(
    updates: Option<mpsc::Receiver<Update>>,
    source: &Path,
    out: &mut impl Write,
    gate: &mut Gate,
) -> io::Result<()> {
    let Some(mut updates) = updates else {
        return Ok(());
    };
    let mut error = None;
    while let Some(update) = poll_fn(|cx| {
        gate.poll(cx);
        updates.poll_recv(cx)
    })
    .await
    {
        if gate.stop.load(Ordering::Acquire) {
            continue;
        }
        if let Err(output) = write_update(out, source, update) {
            gate.stop.store(true, Ordering::Release);
            error = Some(output);
        }
    }
    error.map_or(Ok(()), Err)
}

pub(in crate::fs) fn write_update(
    out: &mut impl Write,
    source: &Path,
    update: Update,
) -> io::Result<()> {
    match update {
        Update::Scanning(path, directory) => {
            out.write_all(if directory {
                b"Scanning directory `"
            } else {
                b"Scanning file `"
            })?;
            write_source_name(out, source, &path)?;
            out.write_all(b"'.\n")?;
        }
        Update::ScanComplete => out.write_all(b"Preprocessing complete.\n")?,
        Update::Extracted(path) => {
            out.write_all(b"Extracting meta data from file `")?;
            write_source_name(out, source, &path)?;
            out.write_all(b"' complete.\n")?;
        }
        Update::MetadataComplete => out.write_all(b"Meta data extraction has finished.\n")?,
        Update::Encoding {
            relative,
            completed,
            total,
            elapsed,
        } => {
            out.write_all(b"Publishing `")?;
            write_source_name(out, source, &relative)?;
            write!(out, "' at {completed}/{total} (")?;
            out.write_all(&gnunet_program_host::diagnostics::relative_time(
                remaining(completed, total, elapsed),
                true,
            ))?;
            out.write_all(b" remaining)\n")?;
        }
    }
    out.flush()
}

fn write_source_name(out: &mut impl Write, source: &Path, relative: &Path) -> io::Result<()> {
    let joined;
    let path = if relative.as_os_str().is_empty() {
        source
    } else {
        joined = source.join(relative);
        &joined
    };
    out.write_all(&crate::argument::native_bytes(path.as_os_str()))
}

fn remaining(completed: u64, total: u64, elapsed: Duration) -> u64 {
    if completed >= total {
        return 0;
    }
    if completed == 0 {
        return u64::MAX;
    }
    let remaining = elapsed
        .as_micros()
        .saturating_mul(u128::from(total - completed))
        / u128::from(completed);
    u64::try_from(remaining).unwrap_or(u64::MAX)
}
