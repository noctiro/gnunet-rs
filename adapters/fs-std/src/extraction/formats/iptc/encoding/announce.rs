//! Code structure facilities from ECMA-35 Table 7.

use super::{Area, ControlSets, Slot, Width};

#[derive(Clone, Copy, Default)]
pub(super) struct Announcements(u32);

impl Announcements {
    pub(super) fn insert(&mut self, final_byte: u8) -> Option<()> {
        let new = match final_byte {
            b'A'..=b'N' | b'P' | b'R'..=b'W' | b'Z'..=b'\\' => flag(final_byte),
            _ => return None,
        };
        let combined = self.0 | new;
        let levels = flag(b'L') | flag(b'M') | flag(b'N');
        let fixed = flag(b'A') | flag(b'C') | flag(b'D');
        let locking = flag(b'P')
            | flag(b'R')
            | flag(b'S')
            | flag(b'T')
            | flag(b'U')
            | flag(b'V')
            | flag(b'W');
        if (combined & levels != 0 && combined.count_ones() != 1)
            || (combined & fixed != 0 && combined & locking != 0)
            || (combined & (flag(b'A') | flag(b'B') | flag(b'C') | flag(b'D'))).count_ones() > 1
        {
            return None;
        }
        self.0 = combined;
        Some(())
    }

    fn has(self, final_byte: u8) -> bool {
        self.0 & flag(final_byte) != 0
    }

    pub(super) fn level(self) -> Option<Level> {
        Some(match self.0 {
            value if value == flag(b'L') => Level::One,
            value if value == flag(b'M') => Level::Two,
            value if value == flag(b'N') => Level::Three,
            _ => return None,
        })
    }

    pub(super) fn constrain_lock(
        self,
        area: Area,
        slot: Slot,
        controls: &mut ControlSets,
    ) -> Option<()> {
        if let Some(level) = self.level() {
            return (level == Level::Three && matches!(area, Area::Right)).then_some(());
        }
        let (left, right) = match slot {
            Slot::G0 => (self.has(b'P'), false),
            Slot::G1 => (self.has(b'R'), self.has(b'S')),
            Slot::G2 => (self.has(b'T'), self.has(b'U')),
            Slot::G3 => (self.has(b'V'), self.has(b'W')),
        };
        match area {
            Area::Left if right && !left => controls.set_width(Width::Seven),
            Area::Left => Some(()),
            Area::Right if left && !right => None,
            Area::Right => controls.set_width(Width::Eight),
        }
    }
}

const fn flag(final_byte: u8) -> u32 {
    1 << (final_byte - b'A')
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Level {
    One,
    Two,
    Three,
}
