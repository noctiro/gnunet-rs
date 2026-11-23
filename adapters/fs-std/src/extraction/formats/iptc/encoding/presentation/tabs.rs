//! ECMA-48 tab stops and their line scopes.

use super::{
    Glyph,
    directions::Cell,
    page::{LineEdit, Work},
};

#[derive(Clone, Copy)]
pub(in super::super) enum Axis {
    Column,
    Row,
}

#[derive(Clone, Copy)]
pub(super) enum Direction {
    Forward,
    Backward,
}

#[derive(Clone, Copy)]
pub(super) enum TabEdit {
    Set(Axis),
    Remove(Axis),
    ClearLine,
    ClearAxis(Axis),
    ClearAll,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum TabScope {
    #[default]
    Multiple,
    Single,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Alignment {
    TrailingEdge,
    LeadingEdge,
    Centre,
    Character(Glyph),
}

impl Alignment {
    pub(super) fn start(self, stop: usize, text: &[Cell]) -> Option<usize> {
        let before = match self {
            Self::TrailingEdge => 0,
            Self::LeadingEdge => text.len(),
            Self::Centre => text.len() / 2,
            Self::Character(target) => text
                .iter()
                .position(|cell| cell.glyph == target)
                .unwrap_or(0),
        };
        stop.checked_sub(before)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    Plain,
    Aligned(Alignment),
}

#[derive(Clone, Copy)]
enum Lines {
    All,
    This(usize),
    From(usize),
}

impl Lines {
    fn covers(self, row: usize) -> bool {
        match self {
            Self::All => true,
            Self::This(at) => row == at,
            Self::From(at) => row >= at,
        }
    }

    fn shift(self, at: usize, edit: LineEdit, limit: usize) -> Option<Self> {
        let row = match self {
            Self::All => return Some(self),
            Self::This(row) | Self::From(row) if row < at => return Some(self),
            Self::This(row) | Self::From(row) => row,
        };
        let moved = shift_position(row, at, edit, limit);
        match self {
            Self::This(_) => moved.map(Self::This),
            Self::From(_) => match edit {
                LineEdit::Insert(_) => moved.map(Self::From),
                LineEdit::Delete(_) => Some(Self::From(moved.unwrap_or(at))),
            },
            Self::All => Some(self),
        }
    }
}

#[derive(Clone, Copy)]
enum Change {
    At(usize, Option<Stop>),
    Clear,
}

impl Change {
    fn apply(self, stops: &mut Stops, work: &mut Work) -> Option<()> {
        match self {
            Self::At(at, stop) => stops.set(at, stop, work),
            Self::Clear => {
                *stops = Stops::default();
                Some(())
            }
        }
    }
}

struct ColumnEdit {
    lines: Lines,
    change: Change,
}

pub(super) struct Tabs {
    initial_columns: bool,
    column_edits: Vec<ColumnEdit>,
    effective: Option<(usize, Stops)>,
    rows: Stops,
    pub(super) scope: TabScope,
}

impl Default for Tabs {
    fn default() -> Self {
        Self {
            initial_columns: true,
            column_edits: Vec::new(),
            effective: None,
            rows: Stops::default(),
            scope: TabScope::Multiple,
        }
    }
}

impl Tabs {
    pub(super) fn has_custom_stops(&self) -> bool {
        !self.initial_columns || !self.column_edits.is_empty() || !self.rows.overrides.is_empty()
    }

    pub(super) fn target(
        &mut self,
        (row, column): (usize, usize),
        axis: Axis,
        direction: Direction,
        count: usize,
        limit: usize,
        work: &mut Work,
    ) -> Option<usize> {
        if count == 0 {
            return Some(match axis {
                Axis::Column => column,
                Axis::Row => row,
            });
        }
        let (stops, mut at, orthogonal) = match axis {
            Axis::Column => (self.columns_at(row, work)?, column, row),
            Axis::Row => (&self.rows, row, column),
        };
        let limit = limit.checked_sub(orthogonal)?;
        for _ in 0..count {
            let Some((next, _)) = stops.nearest(at, direction, work)? else {
                break;
            };
            if next > limit {
                return None;
            }
            at = next;
        }
        Some(at)
    }

    pub(super) fn next_column(
        &mut self,
        row: usize,
        column: usize,
        work: &mut Work,
    ) -> Option<(usize, Option<Alignment>)> {
        Some(
            match self
                .columns_at(row, work)?
                .nearest(column, Direction::Forward, work)?
            {
                None => (column, None),
                Some((at, Stop::Plain)) => (at, None),
                Some((at, Stop::Aligned(alignment))) => (at, Some(alignment)),
            },
        )
    }

    pub(super) fn field_start(
        &mut self,
        row: usize,
        column: usize,
        work: &mut Work,
    ) -> Option<usize> {
        let stops = self.columns_at(row, work)?;
        if stops.get(column).is_some() {
            return Some(column);
        }
        Some(
            stops
                .nearest(column, Direction::Backward, work)?
                .map_or(0, |(at, _)| at),
        )
    }

    fn columns_at(&mut self, row: usize, work: &mut Work) -> Option<&Stops> {
        if self
            .effective
            .as_ref()
            .is_none_or(|(cached, _)| *cached != row)
        {
            let mut stops = Stops {
                regular: self.initial_columns,
                overrides: Vec::new(),
            };
            work.spend(self.column_edits.len())?;
            for edit in &self.column_edits {
                if edit.lines.covers(row) {
                    edit.change.apply(&mut stops, work)?;
                }
            }
            self.effective = Some((row, stops));
        }
        self.effective.as_ref().map(|(_, stops)| stops)
    }

    pub(super) fn edit(
        &mut self,
        edit: TabEdit,
        (row, column): (usize, usize),
        work: &mut Work,
    ) -> Option<()> {
        let setting = matches!(edit, TabEdit::Set(_)).then_some(Stop::Plain);
        let affected = match self.scope {
            TabScope::Multiple => Lines::All,
            TabScope::Single => Lines::This(row),
        };
        match edit {
            TabEdit::Set(Axis::Row) | TabEdit::Remove(Axis::Row) => {
                self.rows.set(row, setting, work)?
            }
            TabEdit::Set(Axis::Column) | TabEdit::Remove(Axis::Column) => {
                self.record(affected, Change::At(column, setting), work)?;
            }
            TabEdit::ClearLine if self.scope == TabScope::Single => {
                self.record(affected, Change::Clear, work)?;
            }
            TabEdit::ClearLine | TabEdit::ClearAxis(Axis::Column) => self.clear_columns(),
            TabEdit::ClearAxis(Axis::Row) => self.rows = Stops::default(),
            TabEdit::ClearAll => {
                self.clear_columns();
                self.rows = Stops::default();
            }
        }
        Some(())
    }

    pub(super) fn align_from(
        &mut self,
        row: usize,
        column: usize,
        alignment: Option<Alignment>,
        work: &mut Work,
    ) -> Option<()> {
        self.record(
            Lines::From(row),
            Change::At(column, alignment.map(Stop::Aligned)),
            work,
        )
    }

    fn record(&mut self, lines: Lines, change: Change, work: &mut Work) -> Option<()> {
        work.spend(1)?;
        self.column_edits.try_reserve(1).ok()?;
        if let Some((row, stops)) = &mut self.effective
            && lines.covers(*row)
        {
            change.apply(stops, work)?;
        }
        self.column_edits.push(ColumnEdit { lines, change });
        Some(())
    }

    fn clear_columns(&mut self) {
        self.initial_columns = false;
        self.column_edits.clear();
        self.effective = None;
    }

    pub(super) fn shift_rows(
        &mut self,
        at: usize,
        edit: LineEdit,
        limit: usize,
        work: &mut Work,
    ) -> Option<()> {
        self.rows.shift(at, edit, limit, work)?;
        work.spend(self.column_edits.len())?;
        self.column_edits.retain_mut(|entry| {
            let Some(lines) = entry.lines.shift(at, edit, limit) else {
                return false;
            };
            entry.lines = lines;
            true
        });
        self.effective = None;
        Some(())
    }
}

#[derive(Default)]
struct Stops {
    regular: bool,
    overrides: Vec<(usize, Option<Stop>)>,
}

impl Stops {
    fn baseline(&self, at: usize) -> Option<Stop> {
        (self.regular && at != 0 && at.is_multiple_of(8)).then_some(Stop::Plain)
    }

    fn get(&self, at: usize) -> Option<Stop> {
        match self
            .overrides
            .binary_search_by_key(&at, |&(position, _)| position)
        {
            Ok(index) => self.overrides[index].1,
            Err(_) => self.baseline(at),
        }
    }

    fn set(&mut self, at: usize, setting: Option<Stop>, work: &mut Work) -> Option<()> {
        let baseline = self.baseline(at);
        match self
            .overrides
            .binary_search_by_key(&at, |&(position, _)| position)
        {
            Ok(index) if setting == baseline => {
                work.spend(self.overrides.len() - index)?;
                self.overrides.remove(index);
            }
            Ok(index) => self.overrides[index].1 = setting,
            Err(index) if setting != baseline => {
                work.spend(self.overrides.len() - index + 1)?;
                self.overrides.try_reserve(1).ok()?;
                self.overrides.insert(index, (at, setting));
            }
            Err(_) => {}
        }
        Some(())
    }

    fn nearest(
        &self,
        origin: usize,
        direction: Direction,
        work: &mut Work,
    ) -> Option<Option<(usize, Stop)>> {
        let mut cursor = origin;
        loop {
            work.spend(1)?;
            let regular = if self.regular {
                match direction {
                    Direction::Forward => (cursor / 8 + 1).checked_mul(8),
                    Direction::Backward => cursor
                        .checked_sub(1)
                        .map(|at| (at / 8) * 8)
                        .filter(|&at| at != 0),
                }
            } else {
                None
            };
            let custom = match direction {
                Direction::Forward => self
                    .overrides
                    .get(self.overrides.partition_point(|&(at, _)| at <= cursor)),
                Direction::Backward => {
                    self.overrides[..self.overrides.partition_point(|&(at, _)| at < cursor)].last()
                }
            }
            .copied();
            if let Some((at, setting)) = custom.filter(|&(at, _)| {
                regular.is_none_or(|regular| match direction {
                    Direction::Forward => at <= regular,
                    Direction::Backward => at >= regular,
                })
            }) {
                if let Some(stop) = setting {
                    return Some(Some((at, stop)));
                }
                cursor = at;
            } else {
                return Some(regular.map(|at| (at, Stop::Plain)));
            }
        }
    }

    fn shift(&mut self, at: usize, edit: LineEdit, limit: usize, work: &mut Work) -> Option<()> {
        work.spend(self.overrides.len())?;
        self.overrides.retain_mut(|(position, _)| {
            if *position < at {
                return true;
            }
            let Some(shifted) = shift_position(*position, at, edit, limit) else {
                return false;
            };
            *position = shifted;
            true
        });
        Some(())
    }
}

fn shift_position(position: usize, at: usize, edit: LineEdit, limit: usize) -> Option<usize> {
    match edit {
        LineEdit::Insert(count) => position
            .checked_add(count)
            .filter(|&position| position <= limit),
        LineEdit::Delete(count) => (position - at >= count).then(|| position - count),
    }
}
