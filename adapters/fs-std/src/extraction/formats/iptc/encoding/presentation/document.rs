//! Sparse ECMA-48 pages with a single data cursor and a shared field budget.

use super::{
    directions::{Directions, Renderer},
    geometry::{Layout, Path, Paths, Reflow},
    page::{Coordinate, Page, PageContent},
    trim_leading_space,
};

pub(super) struct Document {
    active: Page,
    index: usize,
    inactive: Vec<StoredPage>,
    inactive_bytes: usize,
    home_row: usize,
    limit: usize,
    layout: Layout,
    page_paths: Paths,
}

struct StoredPage {
    index: usize,
    content: PageContent,
}

impl Document {
    pub(super) fn from_text(text: &str, limit: usize, input_bytes: usize) -> Option<Self> {
        Some(Self {
            active: Page::from_text(text, limit, input_bytes)?,
            index: 0,
            inactive: Vec::new(),
            inactive_bytes: 0,
            home_row: 0,
            limit,
            layout: Layout::default(),
            page_paths: Paths::default(),
        })
    }

    pub(super) fn active(&mut self) -> &mut Page {
        &mut self.active
    }

    pub(super) fn select_layout(&mut self, layout: Layout, reflow: Reflow) -> Option<()> {
        self.active.finish_field()?;
        let last = self
            .inactive
            .last()
            .map_or(self.index, |page| self.index.max(page.index));
        let available = self.limit.checked_sub(last)?;
        let mut remaining = available;
        self.active.account_page_move(self.inactive.len())?;
        for page in &mut self.inactive {
            self.active
                .reflow_saved_page(&mut page.content, layout, reflow, remaining)?;
            remaining = remaining.checked_sub(page.content.len())?;
        }
        self.active.select_layout(layout, reflow, remaining)?;
        self.layout = layout;
        self.page_paths = Paths::default();
        self.inactive_bytes = available - remaining;
        Some(())
    }

    pub(super) fn select_path(&mut self, path: Path, reflow: Reflow) -> Option<()> {
        self.active.select_path(path, reflow)?;
        let after = self
            .inactive
            .partition_point(|page| page.index <= self.index);
        self.active.account_page_move(self.inactive.len() - after)?;
        for page in &mut self.inactive[after..] {
            page.content.set_path_from(0, path)?;
        }
        self.page_paths.set_from(self.index.checked_add(1)?, path)
    }

    pub(super) fn set_home(&mut self, row: usize) -> Option<()> {
        if row > self.limit {
            return None;
        }
        self.home_row = row;
        Some(())
    }

    pub(super) fn form_feed(&mut self) -> Option<()> {
        self.switch(self.index.checked_add(1)?, self.home_row)
    }

    pub(super) fn move_to(&mut self, target: Coordinate) -> Option<()> {
        self.switch(target.resolve(self.index)?, self.active.cursor().0)
    }

    fn switch(&mut self, target: usize, row: usize) -> Option<()> {
        self.active.finish_field()?;
        if target == self.index {
            return Some(());
        }
        let stored = self
            .inactive
            .binary_search_by_key(&target, |page| page.index)
            .ok();
        let incoming = stored.map_or(0, |slot| self.inactive[slot].content.len());
        let outgoing = self.active.content();
        let keep = outgoing.needs_storage();
        let inactive_bytes = self
            .inactive_bytes
            .checked_sub(incoming)?
            .checked_add(outgoing.len())?;
        let last = self
            .inactive
            .last()
            .map_or(target, |page| target.max(page.index));
        let last = if keep { last.max(self.index) } else { last };
        let available = self.limit.checked_sub(last)?.checked_sub(inactive_bytes)?;
        if incoming.max(row.checked_add(self.active.cursor().1)?) > available {
            return None;
        }
        if keep || stored.is_some() {
            self.active
                .account_page_move(self.inactive.len().saturating_add(1))?;
        }
        if keep && stored.is_none() {
            self.inactive.try_reserve(1).ok()?;
        }
        let content = if let Some(slot) = stored {
            self.inactive.remove(slot).content
        } else {
            let layout = self
                .page_paths
                .from(target)
                .map_or(self.layout, |path| self.layout.with_path(path));
            PageContent::with_layout(layout)
        };
        let previous = self.active.change_page(content, row, available);
        if keep {
            let slot = self
                .inactive
                .partition_point(|page| page.index < self.index);
            self.inactive.insert(
                slot,
                StoredPage {
                    index: self.index,
                    content: previous,
                },
            );
        }
        self.index = target;
        self.inactive_bytes = inactive_bytes;
        Some(())
    }

    pub(super) fn render<'a>(
        mut self,
        out: &'a mut String,
        directions: &Directions,
    ) -> Option<&'a [u8]> {
        self.active.finish_field()?;
        out.clear();
        let active = self.active.into_content();
        let last = self
            .inactive
            .iter()
            .rev()
            .find(|page| page.content.len() != 0)
            .map_or(0, |page| page.index);
        let last = if active.len() == 0 {
            last
        } else {
            last.max(self.index)
        };
        let total = self
            .inactive_bytes
            .checked_add(active.len())?
            .checked_add(last)?;
        out.try_reserve(total).ok()?;
        let mut renderer = Renderer::new(out, directions, self.limit);
        let mut active = Some(active);
        let mut page_number = 0;
        for page in self.inactive {
            if page.index > self.index
                && let Some(active) = active.take()
            {
                append_page(&mut renderer, &mut page_number, self.index, active)?;
            }
            append_page(&mut renderer, &mut page_number, page.index, page.content)?;
        }
        if let Some(active) = active {
            append_page(&mut renderer, &mut page_number, self.index, active)?;
        }
        renderer.finish()?;
        let text = trim_leading_space(out.as_bytes());
        (!text.is_empty()).then_some(if last == 0 { text } else { out.as_bytes() })
    }
}

fn append_page(
    renderer: &mut Renderer<'_>,
    previous: &mut usize,
    index: usize,
    content: PageContent,
) -> Option<()> {
    if content.len() != 0 {
        renderer.breaks('\x0c', index - *previous)?;
        content.append_to(renderer)?;
        *previous = index;
    }
    Some(())
}
