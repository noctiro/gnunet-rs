//! Logical page coordinates and ECMA-48 presentation axes.

use super::page::{Coordinate, LineEdit, Work};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Path {
    Forward,
    Reverse,
}

impl Path {
    pub(super) const fn from_parameter(value: usize) -> Option<Self> {
        match value {
            1 => Some(Self::Forward),
            2 => Some(Self::Reverse),
            _ => None,
        }
    }

    const fn position(self, index: usize, extent: usize) -> usize {
        match self {
            Self::Forward => index,
            Self::Reverse => extent - 1 - index,
        }
    }

    const fn motion(self, positive: bool, count: usize) -> Coordinate {
        match (self, positive) {
            (Self::Forward, true) | (Self::Reverse, false) => Coordinate::Forward(count),
            (Self::Forward, false) | (Self::Reverse, true) => Coordinate::Backward(count),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum ScreenMotion {
    Up,
    Down,
    Right,
    Left,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Reflow {
    KeepData,
    KeepDisplay,
}

impl Reflow {
    pub(super) const fn from_parameter(value: usize) -> Option<Self> {
        match value {
            // For the implementation-defined case use the data reading order.
            0 | 1 => Some(Self::KeepData),
            2 => Some(Self::KeepDisplay),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Orientation {
    Horizontal,
    Vertical,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Layout {
    orientation: Orientation,
    lines: Path,
    characters: Path,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            orientation: Orientation::Horizontal,
            lines: Path::Forward,
            characters: Path::Forward,
        }
    }
}

impl Layout {
    pub(super) const fn from_parameter(value: usize) -> Option<Self> {
        use Orientation::{Horizontal, Vertical};
        use Path::{Forward, Reverse};

        let (orientation, lines, characters) = match value {
            0 => (Horizontal, Forward, Forward),
            1 => (Vertical, Reverse, Forward),
            2 => (Vertical, Forward, Forward),
            3 => (Horizontal, Forward, Reverse),
            4 => (Vertical, Forward, Reverse),
            5 => (Horizontal, Reverse, Reverse),
            6 => (Horizontal, Reverse, Forward),
            7 => (Vertical, Reverse, Reverse),
            _ => return None,
        };
        Some(Self {
            orientation,
            lines,
            characters,
        })
    }

    pub(super) const fn with_path(self, path: Path) -> Self {
        Self {
            characters: path,
            ..self
        }
    }

    pub(super) const fn path(self) -> Path {
        self.characters
    }

    pub(super) const fn right_to_left(self) -> bool {
        matches!(
            (self.orientation, self.characters),
            (Orientation::Horizontal, Path::Reverse)
        )
    }

    /// Convert between character/line and physical row/column axes. The same
    /// transposition converts an extent or undirected coordinates either way.
    pub(super) const fn axes(self, first: usize, second: usize) -> (usize, usize) {
        match self.orientation {
            Orientation::Horizontal => (first, second),
            Orientation::Vertical => (second, first),
        }
    }

    pub(super) fn display(
        self,
        (row, column): (usize, usize),
        (rows, columns): (usize, usize),
    ) -> (usize, usize) {
        self.axes(
            self.lines.position(row, rows),
            self.characters.position(column, columns),
        )
    }

    pub(super) fn data(
        self,
        (y, x): (usize, usize),
        (rows, columns): (usize, usize),
    ) -> (usize, usize) {
        let (row, column) = self.axes(y, x);
        (
            self.lines.position(row, rows),
            self.characters.position(column, columns),
        )
    }

    pub(super) fn cursor_motion(
        self,
        motion: ScreenMotion,
        count: usize,
    ) -> (Coordinate, Coordinate) {
        let horizontal = matches!(motion, ScreenMotion::Left | ScreenMotion::Right);
        let positive = matches!(motion, ScreenMotion::Right | ScreenMotion::Down);
        if horizontal == matches!(self.orientation, Orientation::Horizontal) {
            (Coordinate::Same, self.characters.motion(positive, count))
        } else {
            (self.lines.motion(positive, count), Coordinate::Same)
        }
    }
}

/// Path changes apply from a line (or page) until the next entry. Resetting a
/// path truncates all later changes because its effect covers subsequent text.
#[derive(Default)]
pub(super) struct Paths(Vec<(usize, Path)>);

impl Paths {
    pub(super) fn from(&self, position: usize) -> Option<Path> {
        let end = self.0.partition_point(|&(at, _)| at <= position);
        self.0[..end].last().map(|&(_, path)| path)
    }

    pub(super) fn set_from(&mut self, position: usize, path: Path) -> Option<()> {
        let end = self.0.partition_point(|&(at, _)| at < position);
        self.0.truncate(end);
        if self.0.last().is_none_or(|&(_, previous)| previous != path) {
            self.0.try_reserve(1).ok()?;
            self.0.push((position, path));
        }
        Some(())
    }

    pub(super) fn shift(
        &mut self,
        start: usize,
        edit: LineEdit,
        limit: usize,
        work: &mut Work,
    ) -> Option<()> {
        let end = self.0.partition_point(|&(at, _)| at < start);
        let original = self.0.len();
        work.spend(original - end)?;
        match edit {
            LineEdit::Insert(count) => {
                let first_lost = limit.checked_sub(count).map_or(end, |last| {
                    self.0[end..].partition_point(|&(at, _)| at <= last) + end
                });
                self.0.truncate(first_lost);
                for (at, _) in &mut self.0[end..] {
                    *at += count;
                }
            }
            LineEdit::Delete(count) => {
                let after = start.saturating_add(count);
                let survived = self.0.partition_point(|&(at, _)| at <= after);
                // The last change inside the removed span still applies to
                // the next surviving line unless that line sets its own path.
                let keep = survived.saturating_sub(1).max(end);
                self.0.drain(end..keep);
                for (at, _) in &mut self.0[end..] {
                    *at = at.saturating_sub(count).max(start);
                }
            }
        }
        Some(())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
