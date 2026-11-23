//! Scoped ECMA-48 direction runs and their balanced Unicode text projection.

use std::num::NonZeroU32;

use super::Glyph;

// UAX #9 sets the maximum explicit embedding level to 125.
const MAX_LEVEL: u8 = 125;
const POP: char = '\u{2069}';

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Left,
    Right,
}

impl Direction {
    const fn reversed(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }

    const fn mark(self) -> char {
        match self {
            Self::Left => '\u{2066}',
            Self::Right => '\u{2067}',
        }
    }

    const fn next_level(self, current: u8) -> u8 {
        match self {
            Self::Left => (current + 2) & !1,
            Self::Right => (current + 1) | 1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Directed,
    Reversed,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Run(Option<NonZeroU32>);

impl Run {
    pub(super) const PLAIN: Self = Self(None);
}

#[derive(Clone, Copy)]
pub(super) struct Cell {
    pub(super) glyph: Glyph,
    pub(super) run: Run,
}

impl Cell {
    pub(super) const fn plain(glyph: Glyph) -> Self {
        Self {
            glyph,
            run: Run::PLAIN,
        }
    }

    pub(super) const fn utf8_len(self) -> usize {
        self.glyph.utf8_len()
    }
}

struct Scope {
    parent: Run,
    direction: Direction,
    kind: Kind,
    level: u8,
}

#[derive(Default)]
pub(super) struct Directions {
    scopes: Vec<Scope>,
    active: Run,
}

impl Directions {
    pub(super) fn open(&mut self, kind: Kind, direction: Direction) -> Option<()> {
        let level = direction.next_level(self.level(self.active));
        if level > MAX_LEVEL {
            return None;
        }
        let number = u32::try_from(self.scopes.len().checked_add(1)?).ok()?;
        self.scopes.try_reserve(1).ok()?;
        self.scopes.push(Scope {
            parent: self.active,
            direction,
            kind,
            level,
        });
        self.active = Run(Some(NonZeroU32::new(number)?));
        Some(())
    }

    pub(super) fn reverse(&mut self, base: Direction) -> Option<()> {
        let current = self
            .scope(self.active)
            .map_or(base, |scope| scope.direction);
        self.open(Kind::Reversed, current.reversed())
    }

    pub(super) fn close(&mut self, kind: Kind) -> Option<()> {
        let scope = self.scope(self.active)?;
        if scope.kind != kind {
            return None;
        }
        self.active = scope.parent;
        Some(())
    }

    pub(super) fn active(&self) -> Run {
        self.active
    }

    fn scope(&self, run: Run) -> Option<&Scope> {
        self.scopes.get(run.0?.get() as usize - 1)
    }

    fn level(&self, run: Run) -> u8 {
        // Use the larger of the two Unicode paragraph base levels so every
        // generated isolate still fits if a reader uses an RTL paragraph.
        self.scope(run).map_or(1, |scope| scope.level)
    }
}

pub(super) struct Renderer<'a> {
    out: &'a mut String,
    directions: &'a Directions,
    active: Run,
    limit: usize,
}

impl<'a> Renderer<'a> {
    pub(super) fn new(out: &'a mut String, directions: &'a Directions, limit: usize) -> Self {
        Self {
            out,
            directions,
            active: Run::PLAIN,
            limit,
        }
    }

    pub(super) fn breaks(&mut self, marker: char, count: usize) -> Option<()> {
        if count == 0 {
            return Some(());
        }
        self.transition(Run::PLAIN)?;
        self.reserve(count.checked_mul(marker.len_utf8())?)?;
        self.out.extend(std::iter::repeat_n(marker, count));
        Some(())
    }

    pub(super) fn cell(&mut self, cell: Cell) -> Option<()> {
        match cell.glyph {
            Glyph::Scalar(character) => self.character(character, cell.run),
            Glyph::Pair(first, second) => {
                self.character(first, cell.run)?;
                self.character(second, cell.run)
            }
        }
    }

    pub(super) fn finish(mut self) -> Option<()> {
        self.transition(Run::PLAIN)
    }

    fn character(&mut self, character: char, run: Run) -> Option<()> {
        if !self.directions.scopes.is_empty() {
            // A coded Unicode control cannot close or replace generated isolates.
            match character {
                '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => return None,
                '\x0a' | '\x0d' | '\x1c'..='\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}' => {
                    return self.breaks(character, 1);
                }
                _ => {}
            }
        }
        self.transition(run)?;
        self.reserve(character.len_utf8())?;
        self.out.push(character);
        Some(())
    }

    fn reserve(&mut self, bytes: usize) -> Option<()> {
        if bytes > self.limit.checked_sub(self.out.len())? {
            return None;
        }
        self.out.try_reserve(bytes).ok()
    }

    fn transition(&mut self, target: Run) -> Option<()> {
        if self.active == target {
            return Some(());
        }
        let (mut from, mut to) = (self.active, target);
        let mut closing = 0;
        let mut opening = ['\0'; MAX_LEVEL as usize];
        let mut depth = 0;
        // Walk both parent chains until they meet at their shared scope.
        while from != to {
            let from_level = self.directions.level(from);
            let to_level = self.directions.level(to);
            if from_level >= to_level {
                from = self.directions.scope(from)?.parent;
                closing += 1;
            }
            if to_level >= from_level {
                let scope = self.directions.scope(to)?;
                opening[depth] = scope.direction.mark();
                depth += 1;
                to = scope.parent;
            }
        }
        self.reserve((closing + depth) * POP.len_utf8())?;
        self.out.extend(std::iter::repeat_n(POP, closing));
        self.out.extend(opening[..depth].iter().rev().copied());
        self.active = target;
        Some(())
    }
}
