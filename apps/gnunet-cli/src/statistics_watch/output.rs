//! One bounded immutable row and real borrowed-stdout cursor.
use super::{Failure, driver::Names};
use crate::foreground::Stdout;
use gnunet_client::statistics::{Selector, Statistic, WatchValue};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::AbsoluteTime;
use std::io::{self, Write};
pub(super) const WATCH_CAPACITY: usize = 8192;

pub(super) enum Style {
    Json,
    Text(Text),
}

pub(super) struct Text {
    pub quiet: bool,
    pub separator: Vec<u8>,
}

impl Text {
    fn row(
        &self,
        out: &mut impl Write,
        selector: Selector<'_>,
        value: u64,
        persistent: bool,
        watched_at: Option<AbsoluteTime>,
    ) -> io::Result<()> {
        let Some(time) = watched_at else {
            return self.columns(out, selector, persistent, std::iter::once(value));
        };
        if self.quiet {
            return writeln!(out, "{value}");
        }
        field(
            out,
            &gnunet_program_host::diagnostics::absolute_time(time)?,
            24,
        )?;
        out.write_all(&self.separator)?;
        out.write_all(b" ")?;
        self.label(out, selector, persistent)?;
        writeln!(out, "{value:16}")
    }

    fn columns(
        &self,
        out: &mut impl Write,
        selector: Selector<'_>,
        persistent: bool,
        values: impl Iterator<Item = u64>,
    ) -> io::Result<()> {
        if !self.quiet {
            self.label(out, selector, persistent)?;
        }
        for value in values {
            write!(out, "{value:16}")?;
            out.write_all(&self.separator)?;
        }
        out.write_all(b"\n")
    }

    fn label(
        &self,
        out: &mut impl Write,
        selector: Selector<'_>,
        persistent: bool,
    ) -> io::Result<()> {
        let separator = self.separator.as_slice();
        out.write_all(if persistent { b"!" } else { b" " })?;
        out.write_all(separator)?;
        field(out, selector.subsystem, 12)?;
        out.write_all(separator)?;
        out.write_all(b" ")?;
        if !separator.is_empty() {
            out.write_all(b"\"")?;
        }
        field(out, selector.name, 50)?;
        if separator.is_empty() {
            out.write_all(b": ")
        } else {
            out.write_all(b"\"")?;
            out.write_all(separator)?;
            out.write_all(b" ")
        }
    }
}

fn field(out: &mut impl Write, bytes: &[u8], width: usize) -> io::Result<()> {
    const PADDING: [u8; 50] = [b' '; 50];
    out.write_all(&PADDING[..width.saturating_sub(bytes.len())])?;
    out.write_all(bytes)
}

pub(super) struct Output {
    bytes: Vec<u8>,
    used: usize,
    capacity: usize,
    stdout: Stdout,
    style: Style,
}
struct Limited<'a>(&'a mut Vec<u8>, usize);
impl Write for Limited<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(data.len())
            .is_none_or(|n| n > self.1)
        {
            return Err(io::Error::other(
                "STATISTICS row exceeds original fixed output bound",
            ));
        }
        let needed = self
            .0
            .len()
            .checked_add(data.len())
            .ok_or_else(|| io::Error::other("STATISTICS output length overflow"))?;
        if needed > self.0.capacity() {
            let target = self.0.capacity().saturating_mul(2).max(needed).min(self.1);
            self.0
                .try_reserve_exact(target - self.0.len())
                .map_err(io::Error::other)?;
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Output {
    pub fn new(style: Style, capacity: usize) -> Result<Self, Failure> {
        let bytes = Vec::new();
        let stdout = Stdout::new()?;
        Ok(Self {
            bytes,
            used: 0,
            capacity,
            stdout,
            style,
        })
    }
    pub fn stage(
        &mut self,
        names: &Names,
        epoch: u64,
        index: u32,
        generation: u32,
        value: WatchValue,
        clock: &dyn RuntimeClock,
    ) -> Result<(), Failure> {
        if !self.bytes.is_empty() {
            return Err("previous actual WATCH row still owns stdout".into());
        }
        self.used = 0;
        let mut out = Limited(&mut self.bytes, self.capacity);
        if let Style::Text(text) = &self.style {
            return Ok(text.row(
                &mut out,
                names.selector(),
                value.value,
                value.persistent(),
                Some(clock.sample()?.now),
            )?);
        }
        write!(
            out,
            "{{\"event\":\"statistics_watch_value\",\"epoch\":{epoch},\"logical_index\":{index},\"logical_generation\":{generation},\"wid\":{},\"flags\":{},\"reserved\":{},\"value\":{},\"persistent\":{},\"subsystem\":",
            value.wid,
            value.flags,
            value.reserved,
            value.value,
            value.persistent()
        )?;
        serde_json::to_writer(&mut out, &String::from_utf8_lossy(&names.subsystem))?;
        out.write_all(b",\"name\":")?;
        serde_json::to_writer(&mut out, &String::from_utf8_lossy(&names.name))?;
        out.write_all(b",\"subsystem_bytes\":")?;
        serde_json::to_writer(&mut out, &names.subsystem)?;
        out.write_all(b",\"name_bytes\":")?;
        serde_json::to_writer(&mut out, &names.name)?;
        out.write_all(b"}\n")?;
        Ok(())
    }
    pub fn stage_get(&mut self, value: Statistic<'_>) -> Result<(), Failure> {
        if !self.bytes.is_empty() {
            return Err("previous STATISTICS row still owns stdout".into());
        }
        self.used = 0;
        let mut out = Limited(&mut self.bytes, self.capacity);
        if let Style::Text(text) = &self.style {
            return Ok(text.row(
                &mut out,
                value.selector,
                value.value,
                value.persistent(),
                None,
            )?);
        }
        write!(
            out,
            "{{\"event\":\"statistics_value\",\"uid\":{},\"persistent\":{},\"value\":{},\"subsystem\":",
            value.uid(),
            value.persistent(),
            value.value
        )?;
        serde_json::to_writer(&mut out, &String::from_utf8_lossy(value.selector.subsystem))?;
        out.write_all(b",\"name\":")?;
        serde_json::to_writer(&mut out, &String::from_utf8_lossy(value.selector.name))?;
        out.write_all(b",\"subsystem_bytes\":")?;
        serde_json::to_writer(&mut out, &value.selector.subsystem)?;
        out.write_all(b",\"name_bytes\":")?;
        serde_json::to_writer(&mut out, &value.selector.name)?;
        out.write_all(b"}\n")?;
        Ok(())
    }
    pub fn stage_terminal(&mut self, count: Option<u64>, noop: bool) -> Result<(), Failure> {
        if !self.bytes.is_empty() {
            return Err("previous STATISTICS row still owns stdout".into());
        }
        self.used = 0;
        if matches!(self.style, Style::Text(_)) {
            return Ok(());
        }
        let mut out = Limited(&mut self.bytes, self.capacity);
        if let Some(count) = count {
            writeln!(out, "{{\"event\":\"statistics_end\",\"count\":{count}}}")?;
        } else if noop {
            out.write_all(b"{\"event\":\"statistics_set_noop\"}\n")?;
        } else {
            out.write_all(b"{\"event\":\"statistics_set_confirmed\"}\n")?;
        }
        Ok(())
    }
    pub(super) fn stage_columns(
        &mut self,
        selector: Selector<'_>,
        persistent: bool,
        values: impl Iterator<Item = u64>,
    ) -> Result<(), Failure> {
        if !self.bytes.is_empty() {
            return Err("previous STATISTICS row still owns stdout".into());
        }
        let Style::Text(text) = &self.style else {
            return Err("TESTBED aggregation requires text output".into());
        };
        self.used = 0;
        text.columns(
            &mut Limited(&mut self.bytes, self.capacity),
            selector,
            persistent,
            values,
        )?;
        Ok(())
    }
    /// None means no positive byte progress; caller owns real timer/readiness wait.
    pub fn step(&mut self) -> io::Result<Option<bool>> {
        if self.bytes.is_empty() {
            return Ok(Some(true));
        }
        match self.stdout.write(&self.bytes[self.used..])? {
            Some(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "zero STATISTICS stdout write",
            )),
            Some(n) => {
                self.used += n;
                Ok(Some(self.used == self.bytes.len()))
            }
            None => Ok(None),
        }
    }
    pub fn pending(&self) -> (usize, usize) {
        (self.used, self.bytes.len())
    }
    pub fn release(&mut self) {
        self.bytes.clear();
        self.used = 0;
    }
    pub fn flush(&mut self) -> io::Result<()> {
        self.stdout.flush()
    }
}
