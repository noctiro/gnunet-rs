//! A bounded ECMA-48 page in logical line and character order.

use std::ops::Range;

use super::tabs::{Alignment, Axis, Direction, TabEdit, TabScope, Tabs};
use super::{
    Glyph,
    directions::{Cell, Direction as TextDirection, Renderer},
    geometry::{Layout, Path, Paths, Reflow, ScreenMotion},
};

const BLANK: Cell = Cell::plain(Glyph::Scalar(' '));

#[derive(Clone, Copy)]
pub(super) enum Coordinate {
    Same,
    Absolute(usize),
    Forward(usize),
    Backward(usize),
}

impl Coordinate {
    pub(super) fn resolve(self, current: usize) -> Option<usize> {
        Some(match self {
            Self::Same => current,
            Self::Absolute(value) => value,
            Self::Forward(amount) => current.checked_add(amount)?,
            Self::Backward(amount) => current.saturating_sub(amount),
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum Erasure {
    After,
    Before,
    All,
}

#[derive(Clone, Copy)]
pub(super) enum Edit {
    Insert(usize),
    Delete(usize),
    Erase(usize),
}

#[derive(Clone, Copy)]
pub(super) enum LineEdit {
    Insert(usize),
    Delete(usize),
}

pub(super) struct Work(usize);

impl Work {
    pub(super) fn spend(&mut self, units: usize) -> Option<()> {
        self.0 = self.0.checked_sub(units)?;
        Some(())
    }
}

pub(super) struct Page {
    content: PageContent,
    row: usize,
    column: usize,
    limit: usize,
    work: Work,
    pending: Option<AlignedField>,
}

impl Page {
    pub(super) fn from_text(text: &str, limit: usize, input_bytes: usize) -> Option<Self> {
        let mut rows = Vec::new();
        for text in text.split('\n') {
            let mut cells = Vec::new();
            cells.try_reserve_exact(text.chars().count()).ok()?;
            cells.extend(
                text.chars()
                    .map(|character| Cell::plain(Glyph::Scalar(character))),
            );
            rows.try_reserve(1).ok()?;
            rows.push(Line {
                cells,
                bytes: text.len(),
            });
        }
        let row = rows.len() - 1;
        let column = rows[row].cells.len();
        let remaining_edit_work = limit.saturating_add(input_bytes).saturating_mul(16);
        Some(Self {
            content: PageContent {
                rows,
                bytes: text.len(),
                tabs: Tabs::default(),
                layout: Layout::default(),
                paths: Paths::default(),
            },
            row,
            column,
            limit,
            work: Work(remaining_edit_work),
            pending: None,
        })
    }

    pub(super) fn position(&mut self, row: Coordinate, column: Coordinate) -> Option<()> {
        self.finish_field()?;
        self.set_position(row, column)
    }

    pub(super) fn move_on_screen(&mut self, motion: ScreenMotion, count: usize) -> Option<()> {
        self.finish_field()?;
        let current = self.content.layout_for(self.row);
        let (row, column) = current.cursor_motion(motion, count);
        let target = row.resolve(self.row)?;
        if current.path() != self.content.layout_for(target).path() {
            // Motion along the line-progression axis preserves the physical
            // character position even when the new line has the opposite path.
            self.work.spend(self.content.rows.len())?;
            let columns = self.content.columns().max(self.column.checked_add(1)?);
            self.set_position(row, Coordinate::Absolute(columns - 1 - self.column))
        } else {
            self.set_position(row, column)
        }
    }

    pub(super) fn text_direction(&self) -> TextDirection {
        if self.content.layout_for(self.row).right_to_left() {
            TextDirection::Right
        } else {
            TextDirection::Left
        }
    }

    pub(super) fn select_path(&mut self, path: Path, reflow: Reflow) -> Option<()> {
        self.finish_field()?;
        let old = self.content.layout_for(self.row).path();
        if old != path && reflow == Reflow::KeepDisplay {
            self.work.spend(self.content.rows.len())?;
            let columns = self.content.columns();
            if let Some(line) = self.content.rows.get(self.row)
                && !line.cells.is_empty()
            {
                let gap = columns - line.cells.len();
                self.check_growth(gap, 0)?;
                self.work.spend(columns)?;
                let line = &mut self.content.rows[self.row];
                line.cells.try_reserve(gap).ok()?;
                line.cells.resize(columns, BLANK);
                line.cells.reverse();
                line.bytes += gap;
                self.content.bytes += gap;
            }
        }
        self.content.set_path_from(self.row, path)?;
        self.column = 0;
        Some(())
    }

    pub(super) fn select_layout(
        &mut self,
        layout: Layout,
        reflow: Reflow,
        limit: usize,
    ) -> Option<()> {
        self.finish_field()?;
        self.content
            .select_layout(layout, reflow, limit, &mut self.work)?;
        self.limit = limit;
        self.row = 0;
        self.column = 0;
        Some(())
    }

    pub(super) fn reflow_saved_page(
        &mut self,
        saved: &mut PageContent,
        layout: Layout,
        reflow: Reflow,
        limit: usize,
    ) -> Option<()> {
        saved.select_layout(layout, reflow, limit, &mut self.work)
    }

    fn set_position(&mut self, row: Coordinate, column: Coordinate) -> Option<()> {
        let row = row.resolve(self.row)?;
        let column = column.resolve(self.column)?;
        if row.checked_add(column)? > self.limit {
            return None;
        }
        self.row = row;
        self.column = column;
        Some(())
    }

    pub(super) fn tabulate(
        &mut self,
        axis: Axis,
        direction: Direction,
        count: usize,
    ) -> Option<()> {
        self.finish_field()?;
        let target = self.content.tabs.target(
            (self.row, self.column),
            axis,
            direction,
            count,
            self.limit,
            &mut self.work,
        )?;
        match axis {
            Axis::Column => self.set_position(Coordinate::Same, Coordinate::Absolute(target)),
            Axis::Row => self.set_position(Coordinate::Absolute(target), Coordinate::Same),
        }
    }

    pub(super) fn character_tab(&mut self) -> Option<()> {
        self.finish_field()?;
        let (column, alignment) =
            self.content
                .tabs
                .next_column(self.row, self.column, &mut self.work)?;
        self.set_position(Coordinate::Same, Coordinate::Absolute(column))?;
        self.pending = alignment.map(|alignment| AlignedField {
            column,
            alignment,
            cells: Vec::new(),
            bytes: 0,
        });
        Some(())
    }

    pub(super) fn align_column(
        &mut self,
        column: usize,
        alignment: Option<Alignment>,
    ) -> Option<()> {
        if column > self.limit {
            return None;
        }
        self.content
            .tabs
            .align_from(self.row, column, alignment, &mut self.work)
    }

    pub(super) fn finish_field(&mut self) -> Option<()> {
        if let Some(field) = self.pending.take()
            && !field.cells.is_empty()
        {
            let start = field.alignment.start(field.column, &field.cells)?;
            self.work.spend(field.cells.len())?;
            self.set_position(Coordinate::Same, Coordinate::Absolute(start))?;
            for cell in field.cells {
                self.write_cell(cell)?;
            }
        }
        Some(())
    }

    pub(super) fn tab_edit(&mut self, edit: TabEdit) -> Option<()> {
        self.content
            .tabs
            .edit(edit, (self.row, self.column), &mut self.work)
    }

    pub(super) fn tab_scope(&mut self, scope: TabScope) {
        self.content.tabs.scope = scope;
    }

    pub(super) fn justify_to_tab(&mut self) -> Option<()> {
        self.finish_field()?;
        let start = self
            .content
            .tabs
            .field_start(self.row, self.column, &mut self.work)?;
        let end = self.content.tabs.target(
            (self.row, self.column),
            Axis::Column,
            Direction::Forward,
            1,
            self.limit,
            &mut self.work,
        )?;
        if end == self.column {
            return Some(());
        }
        if let Some(line) = self.content.rows.get(self.row)
            && line.cells.len() > start
            && line.cells.len() < end
        {
            let gap = end - line.cells.len();
            self.check_growth(gap, 0)?;
            self.work.spend(end - start)?;
            let line = &mut self.content.rows[self.row];
            line.cells.try_reserve(gap).ok()?;
            line.cells.resize(end, BLANK);
            line.cells[start..end].rotate_right(gap);
            line.bytes += gap;
            self.content.bytes += gap;
        }
        self.column = end;
        Some(())
    }

    pub(super) fn push(&mut self, cell: Cell) -> Option<()> {
        if matches!(cell.glyph, Glyph::Scalar('\n')) {
            self.finish_field()?;
            if self.content.bytes == 0 {
                return Some(());
            }
            self.position(Coordinate::Forward(1), Coordinate::Absolute(0))?;
            return self.ensure_row();
        }
        if let Some(field) = &mut self.pending {
            let bytes = field.bytes.checked_add(cell.utf8_len())?;
            if bytes > self.limit {
                return None;
            }
            field.cells.try_reserve(1).ok()?;
            field.cells.push(cell);
            field.bytes = bytes;
            return Some(());
        }
        self.write_cell(cell)
    }

    fn write_cell(&mut self, value: Cell) -> Option<()> {
        let next = self.column.checked_add(1)?;
        self.ensure_row()?;
        let line = &mut self.content.rows[self.row];
        let before = line.bytes;
        line.write(
            self.column,
            value,
            (self.limit - self.content.bytes).checked_add(before)?,
        )?;
        self.content.bytes = self.content.bytes - before + line.bytes;
        self.column = next;
        Some(())
    }

    pub(super) fn edit_cells(&mut self, edit: Edit) -> Option<()> {
        self.finish_field()?;
        let Some(line) = self.content.rows.get(self.row) else {
            return Some(());
        };
        let start = self.column.min(line.cells.len());
        let suffix = line.cells.len() - start;
        let work = match edit {
            Edit::Insert(count) if suffix != 0 => suffix.saturating_add(count),
            Edit::Delete(count) if count != 0 => suffix,
            Edit::Erase(count) => suffix.min(count),
            _ => 0,
        };
        self.work.spend(work)?;
        let line = &mut self.content.rows[self.row];
        let before = line.bytes;
        match edit {
            Edit::Insert(count) if start < line.cells.len() => {
                if count > self.limit - self.content.bytes {
                    return None;
                }
                line.cells.try_reserve(count).ok()?;
                line.cells.resize(line.cells.len() + count, BLANK);
                line.cells[start..].rotate_right(count);
                line.bytes += count;
            }
            Edit::Insert(_) => {}
            Edit::Delete(count) => {
                let end = start.saturating_add(count).min(line.cells.len());
                if start != end {
                    line.bytes -= line
                        .cells
                        .drain(start..end)
                        .map(Cell::utf8_len)
                        .sum::<usize>();
                }
            }
            Edit::Erase(count) => {
                let end = start.saturating_add(count).min(line.cells.len());
                line.erase(start..end);
            }
        }
        self.content.bytes = self.content.bytes - before + line.bytes;
        Some(())
    }

    pub(super) fn edit_lines(&mut self, edit: LineEdit) -> Option<()> {
        self.finish_field()?;
        if matches!(edit, LineEdit::Insert(0) | LineEdit::Delete(0)) {
            return Some(());
        }
        self.content
            .tabs
            .shift_rows(self.row, edit, self.limit, &mut self.work)?;
        self.content
            .paths
            .shift(self.row, edit, self.limit, &mut self.work)?;
        self.column = 0;
        if self.row >= self.content.rows.len() {
            return Some(());
        }
        match edit {
            LineEdit::Insert(count) => {
                self.work
                    .spend((self.content.rows.len() - self.row).saturating_add(count))?;
                self.check_growth(count, 0)?;
                self.content.rows.try_reserve(count).ok()?;
                self.content
                    .rows
                    .resize_with(self.content.rows.len() + count, Line::default);
                self.content.rows[self.row..].rotate_right(count);
                self.content.bytes += count;
            }
            LineEdit::Delete(count) => {
                self.work.spend(self.content.rows.len() - self.row)?;
                self.remove_rows(
                    self.row..self.row.saturating_add(count).min(self.content.rows.len()),
                );
            }
        }
        Some(())
    }

    pub(super) fn erase_page(&mut self, erasure: Erasure) -> Option<()> {
        self.finish_field()?;
        match erasure {
            Erasure::After => {
                let start = self.row.saturating_add(1).min(self.content.rows.len());
                self.work.spend(self.content.rows.len() - start)?;
                self.remove_rows(start..self.content.rows.len());
            }
            Erasure::Before => {
                let end = self.row.min(self.content.rows.len());
                self.work.spend(end)?;
                for line in &mut self.content.rows[..end] {
                    self.content.bytes -= line.bytes;
                    *line = Line::default();
                }
            }
            Erasure::All => {
                self.work.spend(self.content.rows.len())?;
                self.remove_rows(0..self.content.rows.len());
                return Some(());
            }
        }
        self.erase_line(erasure)
    }

    pub(super) fn erase_line(&mut self, erasure: Erasure) -> Option<()> {
        self.finish_field()?;
        let Some(line) = self.content.rows.get(self.row) else {
            return Some(());
        };
        let len = line.cells.len();
        let range = match erasure {
            Erasure::After => self.column.min(len)..len,
            Erasure::Before => 0..self.column.saturating_add(1).min(len),
            Erasure::All => 0..len,
        };
        self.work.spend(range.len())?;
        let line = &mut self.content.rows[self.row];
        let before = line.bytes;
        line.erase(range);
        self.content.bytes -= before - line.bytes;
        Some(())
    }

    pub(super) fn cancel(&mut self, word: bool) -> Option<()> {
        if let Some(field) = &mut self.pending {
            let start = if word {
                field
                    .cells
                    .iter()
                    .rposition(|cell| cell.glyph == BLANK.glyph)
                    .unwrap_or(0)
            } else {
                field.cells.len().saturating_sub(1)
            };
            let erased = field
                .cells
                .drain(start..)
                .map(Cell::utf8_len)
                .sum::<usize>();
            self.work.spend(erased)?;
            field.bytes -= erased;
            return Some(());
        }
        let Some(line) = self.content.rows.get(self.row) else {
            return Some(());
        };
        let end = self.column.min(line.cells.len());
        let start = if word {
            line.cells[..end]
                .iter()
                .rposition(|cell| cell.glyph == BLANK.glyph)
                .unwrap_or(0)
        } else {
            end.saturating_sub(1)
        };
        self.column = start;
        self.edit_cells(Edit::Delete(end - start))
    }

    pub(super) fn content(&self) -> &PageContent {
        &self.content
    }

    pub(super) fn cursor(&self) -> (usize, usize) {
        (self.row, self.column)
    }

    pub(super) fn change_page(
        &mut self,
        mut next: PageContent,
        row: usize,
        limit: usize,
    ) -> PageContent {
        next.tabs.scope = self.content.tabs.scope;
        self.row = row;
        self.limit = limit;
        std::mem::replace(&mut self.content, next)
    }

    pub(super) fn account_page_move(&mut self, stored_pages: usize) -> Option<()> {
        self.work.spend(stored_pages.saturating_mul(2))
    }

    pub(super) fn into_content(self) -> PageContent {
        self.content
    }

    fn check_growth(&self, added: usize, removed: usize) -> Option<()> {
        (added <= self.limit - (self.content.bytes - removed)).then_some(())
    }

    fn ensure_row(&mut self) -> Option<()> {
        let (count, separators) = self.row_growth()?;
        self.check_growth(separators, 0)?;
        self.content.rows.try_reserve(count).ok()?;
        self.content
            .rows
            .resize_with(self.content.rows.len() + count, Line::default);
        self.content.bytes += separators;
        Some(())
    }

    fn row_growth(&self) -> Option<(usize, usize)> {
        let count = self
            .row
            .checked_add(1)?
            .saturating_sub(self.content.rows.len());
        Some((
            count,
            count.saturating_sub(usize::from(self.content.rows.is_empty())),
        ))
    }

    fn remove_rows(&mut self, range: Range<usize>) {
        let separators_before = self.content.rows.len().saturating_sub(1);
        self.content.bytes -= self
            .content
            .rows
            .drain(range)
            .map(|line| line.bytes)
            .sum::<usize>();
        self.content.bytes -= separators_before - self.content.rows.len().saturating_sub(1);
    }
}

struct AlignedField {
    column: usize,
    alignment: Alignment,
    cells: Vec<Cell>,
    bytes: usize,
}

#[derive(Default)]
pub(super) struct PageContent {
    rows: Vec<Line>,
    bytes: usize,
    tabs: Tabs,
    layout: Layout,
    paths: Paths,
}

impl PageContent {
    pub(super) fn with_layout(layout: Layout) -> Self {
        Self {
            layout,
            ..Self::default()
        }
    }

    pub(super) fn set_path_from(&mut self, row: usize, path: Path) -> Option<()> {
        self.paths.set_from(row, path)
    }

    fn layout_for(&self, row: usize) -> Layout {
        self.paths
            .from(row)
            .map_or(self.layout, |path| self.layout.with_path(path))
    }

    fn columns(&self) -> usize {
        self.rows
            .iter()
            .map(|line| line.cells.len())
            .max()
            .unwrap_or(0)
    }

    fn select_layout(
        &mut self,
        layout: Layout,
        reflow: Reflow,
        limit: usize,
        work: &mut Work,
    ) -> Option<()> {
        if reflow == Reflow::KeepDisplay && (layout != self.layout || !self.paths.is_empty()) {
            self.preserve_display(layout, limit, work)?;
        }
        if self.bytes > limit {
            return None;
        }
        self.layout = layout;
        self.paths = Paths::default();
        Some(())
    }

    fn preserve_display(&mut self, layout: Layout, limit: usize, work: &mut Work) -> Option<()> {
        work.spend(self.rows.len())?;
        let columns = self.columns();
        if columns == 0 {
            return Some(());
        }
        let old_extent = (self.rows.len(), columns);
        let physical = self.layout.axes(old_extent.0, old_extent.1);
        let extent = layout.axes(physical.0, physical.1);
        let mut used = extent.0 - 1;
        if used > limit {
            return None;
        }
        work.spend(extent.0)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(extent.0).ok()?;
        rows.resize_with(extent.0, Line::default);
        for (row, line) in self.rows.iter().enumerate() {
            let old_layout = self.layout_for(row);
            work.spend(line.cells.len())?;
            for (column, &cell) in line.cells.iter().enumerate() {
                let screen = old_layout.display((row, column), old_extent);
                let (row, column) = layout.data(screen, extent);
                let target = &mut rows[row];
                let before = target.bytes;
                target.write(column, cell, (limit - used).checked_add(before)?)?;
                used = used - before + target.bytes;
            }
        }
        self.rows = rows;
        self.bytes = used;
        Some(())
    }

    pub(super) fn len(&self) -> usize {
        self.bytes
    }

    pub(super) fn needs_storage(&self) -> bool {
        self.bytes != 0 || self.tabs.has_custom_stops() || !self.paths.is_empty()
    }

    pub(super) fn append_to(self, renderer: &mut Renderer<'_>) -> Option<()> {
        for (index, line) in self.rows.into_iter().enumerate() {
            renderer.breaks('\n', usize::from(index != 0))?;
            for cell in line.cells {
                renderer.cell(cell)?;
            }
        }
        Some(())
    }
}

#[derive(Default)]
struct Line {
    cells: Vec<Cell>,
    bytes: usize,
}

impl Line {
    fn write(&mut self, column: usize, value: Cell, limit: usize) -> Option<()> {
        let replaced = self.cells.get(column).copied().map_or(0, Cell::utf8_len);
        let gap = column.saturating_sub(self.cells.len());
        let bytes = (self.bytes - replaced)
            .checked_add(gap)?
            .checked_add(value.utf8_len())?;
        if bytes > limit {
            return None;
        }
        if let Some(cell) = self.cells.get_mut(column) {
            *cell = value;
        } else {
            self.cells.try_reserve(gap.checked_add(1)?).ok()?;
            self.cells.resize(column, BLANK);
            self.cells.push(value);
        }
        self.bytes = bytes;
        Some(())
    }

    fn erase(&mut self, range: Range<usize>) {
        let erased = self.cells[range.clone()]
            .iter()
            .copied()
            .map(Cell::utf8_len)
            .sum::<usize>();
        self.bytes -= erased;
        if range.end == self.cells.len() {
            self.cells.truncate(range.start);
        } else {
            self.bytes += range.len();
            self.cells[range].fill(BLANK);
        }
    }
}
