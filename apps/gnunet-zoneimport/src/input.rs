//! Bounded newline-framed hostnames and one original platform input owner.
use std::{io, ops::Range};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub(super) use unix::{Input, Retired};
#[cfg(windows)]
pub(super) use windows::{Input, Retired};
#[derive(Debug)]
pub(super) struct Names {
    bytes: Vec<u8>,
    lines: Vec<Range<usize>>,
    start: usize,
    maximum_bytes: usize,
    maximum_names: usize,
    line_bytes: usize,
    finished: bool,
}
impl Names {
    pub(super) fn new(
        maximum_bytes: usize,
        maximum_names: usize,
        initial_names: usize,
    ) -> io::Result<Self> {
        let mut lines = Vec::new();
        lines
            .try_reserve_exact(initial_names.min(maximum_names))
            .map_err(io::Error::other)?;
        Ok(Self {
            bytes: Vec::new(),
            lines,
            start: 0,
            maximum_bytes,
            maximum_names,
            line_bytes: 4096,
            finished: false,
        })
    }
    pub(super) fn push(&mut self, input: &[u8]) -> io::Result<()> {
        if self.finished
            || self
                .bytes
                .len()
                .checked_add(input.len())
                .is_none_or(|n| n > self.maximum_bytes)
        {
            return Err(io::Error::other(
                "bounded zoneimport input byte limit exceeded",
            ));
        }
        let required = self.bytes.len() + input.len();
        if required > self.bytes.capacity() {
            let target = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(4096)
                .max(required)
                .min(self.maximum_bytes);
            self.bytes
                .try_reserve_exact(target - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        let previous = self.bytes.len();
        self.bytes.extend_from_slice(input);
        for position in previous..self.bytes.len() {
            if self.bytes[position] == b'\n' {
                self.line(position)?;
                self.start = position + 1;
            } else if position - self.start >= self.line_bytes {
                return Err(io::Error::other(
                    "zoneimport input hostname exceeds4096bytes",
                ));
            }
        }
        Ok(())
    }
    fn line(&mut self, end: usize) -> io::Result<()> {
        let end = if end > self.start && self.bytes[end - 1] == b'\r' {
            end - 1
        } else {
            end
        };
        if self.lines.len() == self.maximum_names {
            return Err(io::Error::other(
                "bounded zoneimport input name limit exceeded",
            ));
        }
        if self.lines.len() == self.lines.capacity() {
            let target = self
                .lines
                .capacity()
                .saturating_mul(2)
                .max(1)
                .min(self.maximum_names);
            self.lines
                .try_reserve_exact(target - self.lines.len())
                .map_err(io::Error::other)?;
        }
        self.lines.push(self.start..end);
        Ok(())
    }
    pub(super) fn finish(&mut self) -> io::Result<()> {
        if !self.finished {
            if self.start < self.bytes.len() {
                self.line(self.bytes.len())?;
            }
            self.finished = true;
        }
        Ok(())
    }
    pub(super) fn len(&self) -> usize {
        self.lines.len()
    }
    pub(super) fn get(&self, index: usize) -> Option<&[u8]> {
        self.lines.get(index).map(|line| &self.bytes[line.clone()])
    }
}
