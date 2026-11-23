//! IIM coded-character-set declarations and per-dataset ISO 2022 state.

mod announce;
mod control;
mod latin6937;
mod multibyte;
mod presentation;
mod repertoire;
mod unicode;

use announce::{Announcements, Level};
use control::{C1Form, C1Set, C1Wire, ControlSets, PrimaryControls, Width};
use gnunet_fs::metadata::c_prefix;
use multibyte::DoubleByte94;
use presentation::{Effect, TablePosition, Text};
use repertoire::{Glyph, Graphic, Repertoire};
use unicode::Coding;

pub(super) struct Encoding(Profile);

impl Encoding {
    pub(super) const DEFAULT: Self = Self(Profile::Default);

    pub(super) fn declared(controls: &[u8]) -> Self {
        let profile = if controls.is_empty() || controls.len() > 32 {
            Profile::Unsupported
        } else if let Some(coding) = Coding::designated(controls) {
            Profile::Unicode(coding)
        } else {
            Graphics::initial(controls).map_or(Profile::Unsupported, Profile::Iso2022)
        };
        Self(profile)
    }

    pub(super) fn decode<'a>(
        &self,
        bytes: &'a [u8],
        output: &'a mut String,
        limit: usize,
    ) -> Option<&'a [u8]> {
        match self.0 {
            Profile::Default => {
                let bytes = c_prefix(bytes);
                Graphics::default_for(bytes).decode(bytes, output, limit)
            }
            Profile::Iso2022(initial) => initial.decode(c_prefix(bytes), output, limit),
            Profile::Unicode(coding) => coding.decode(bytes, output, limit),
            Profile::Unsupported => None,
        }
    }
}

enum Profile {
    Default,
    Unicode(Coding),
    Iso2022(Graphics),
    Unsupported,
}

fn append_text(out: &mut String, character: char, limit: usize) -> Option<()> {
    if out.is_empty() && matches!(character, '\x09'..='\x0d' | ' ') {
        return Some(());
    }
    let length = character.len_utf8();
    if length > limit.checked_sub(out.len())? {
        return None;
    }
    out.try_reserve(length).ok()?;
    out.push(character);
    Some(())
}

fn trim_leading_space(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|&byte| !matches!(byte, b'\x09'..=b'\x0d' | b' '))
        .unwrap_or(bytes.len());
    &bytes[first..]
}

#[derive(Clone, Copy)]
struct Graphics {
    designated: [Option<Repertoire>; 4],
    set_size: GraphicSetSize,
    layout: GraphicLayout,
    single_area: Area,
    controls: ControlSets,
    announcements: Announcements,
}

impl Graphics {
    fn new(left: Repertoire, controls: ControlSets) -> Self {
        Self {
            designated: [Some(left), None, None, None],
            set_size: GraphicSetSize::Any,
            layout: GraphicLayout::Extended {
                left: Slot::G0,
                right: Slot::G1,
            },
            single_area: Area::Left,
            controls,
            announcements: Announcements::default(),
        }
    }

    fn default_for(bytes: &[u8]) -> Self {
        // IIM §1:90 leaves the code width outside the packet envelope. The
        // IRV and default 8-bit GL graphics agree, so use the 7-bit controls
        // when no byte requires the eighth bit. ISO 4873 DV leaves C1/GR empty.
        let width = if bytes.is_ascii() {
            Width::Seven
        } else {
            Width::Eight
        };
        Self::new(Repertoire::Irv, ControlSets::undeclared(width))
    }

    fn initial(mut bytes: &[u8]) -> Option<Self> {
        // IIM 1:90 contains only control functions.
        let mut state = Self::new(Repertoire::Ascii, ControlSets::default());
        let mut used_lock = false;
        while let Some(byte) = take(&mut bytes) {
            match state.control(byte, &mut bytes)? {
                Control::Announce(facility) => state.announce(facility)?,
                control => {
                    used_lock |= matches!(control, Control::Lock(..));
                    state.apply(control, Part::Declaration)?;
                }
            }
        }
        if let Some(level) = state.announcements.level() {
            let [g0, g1, g2, g3] = state.designated;
            if used_lock || !matches!(g0, Some(Repertoire::Ascii)) {
                return None;
            }
            match level {
                Level::One if g2.is_some() || g3.is_some() => return None,
                Level::One => {
                    if state.controls.c1 == C1Set::ImplicitShifts {
                        state.controls.c1 = C1Set::Unassigned;
                    }
                }
                Level::Two | Level::Three
                    if g1.is_none()
                        || (g2.is_none() && g3.is_none())
                        || !matches!(state.controls.c1, C1Set::IsoIr77 | C1Set::IsoIr105) =>
                {
                    return None;
                }
                Level::Two | Level::Three => {}
            }
        }
        Some(state)
    }

    fn decode<'a>(
        mut self,
        mut bytes: &'a [u8],
        out: &'a mut String,
        limit: usize,
    ) -> Option<&'a [u8]> {
        if self.controls.primary.has_literal_whitespace()
            && !(self.positions_c0()
                && bytes
                    .iter()
                    .copied()
                    .any(|byte| Effect::iso646_position(byte).is_some()))
            && let Some(set) = self.designated[self.layout.left() as usize]
            && set.unchanged_ascii(bytes)
        {
            let text = trim_leading_space(bytes);
            return (!text.is_empty() && text.len() <= limit).then_some(text);
        }
        let mut text = Text::new(out, limit, bytes.len());
        let mut diacritic = None;
        while let Some(byte) = take(&mut bytes) {
            if byte <= 0x0d
                && self.positions_c0()
                && let Some(effect) = Effect::iso646_position(byte)
            {
                if diacritic.is_some() {
                    return None;
                }
                effect.project(&mut bytes, &mut text, |at| self.table_character(at))?;
                continue;
            }
            let graphic = match byte {
                0x09..=0x0d if self.controls.primary.has_literal_whitespace() => {
                    if diacritic.is_some() {
                        return None;
                    }
                    text.literal(char::from(byte))?;
                    continue;
                }
                0x00..=0x1f | 0x80..=0x9f => match self.control(byte, &mut bytes)? {
                    Control::Text(effect) => {
                        if diacritic.is_some() {
                            return None;
                        }
                        effect.project(&mut bytes, &mut text, |at| self.table_character(at))?;
                        continue;
                    }
                    Control::Utf8Switch => {
                        if diacritic.is_some() {
                            return None;
                        }
                        text.push_utf8(unicode::take_returning(&mut bytes)?)?;
                        continue;
                    }
                    Control::Alternate => {
                        let set = self.alternate_graphics()?;
                        let first = self.single_area.position(take(&mut bytes)?)?;
                        set.graphic(first, self.single_area, &mut bytes)?
                    }
                    Control::Single94 => {
                        let first = take(&mut bytes)?;
                        let set = self.designated[Slot::G2 as usize]?;
                        if !set.single_byte_94() {
                            return None;
                        }
                        set.graphic(first, Area::Left, &mut bytes)?
                    }
                    Control::Single(slot) => {
                        let first = self.single_area.position(take(&mut bytes)?)?;
                        self.designated[slot as usize]?.graphic(
                            first,
                            self.single_area,
                            &mut bytes,
                        )?
                    }
                    control => {
                        if diacritic.is_some()
                            && !matches!(control, Control::Lock(..) | Control::Designate(..))
                        {
                            return None;
                        }
                        text.commit_graphic()?;
                        self.apply(control, Part::Data)?;
                        continue;
                    }
                },
                0x20..=0x7f => {
                    let set = self.designated[self.layout.left() as usize]?;
                    match byte {
                        0x20 if set.is_94() => Graphic::Primary(' '),
                        0x7f if set.is_94() => {
                            if diacritic.is_some() {
                                return None;
                            }
                            text.commit_graphic()?;
                            continue;
                        }
                        _ => set.graphic(byte, Area::Left, &mut bytes)?,
                    }
                }
                _ => {
                    self.controls.set_width(Width::Eight)?;
                    let first = Area::Right.position(byte)?;
                    self.designated[self.layout.right()? as usize]?.graphic(
                        first,
                        Area::Right,
                        &mut bytes,
                    )?
                }
            };
            let glyph = match graphic {
                Graphic::Diacritic(mark) => {
                    if diacritic.replace(mark).is_some() {
                        return None;
                    }
                    continue;
                }
                graphic => match diacritic.take() {
                    Some(mark) => mark.compose(graphic)?,
                    None => graphic.into_glyph()?,
                },
            };
            text.decoded_graphic(glyph, self.controls.c1 == C1Set::IsoIr77)?;
        }
        if diacritic.is_some() {
            return None;
        }
        text.finish()
    }

    fn alternate_graphics(&self) -> Option<Repertoire> {
        // IR 26's SS invokes the other designated graphic set once. The
        // code contains no slot number, so the designation must be unique.
        let active = match self.single_area {
            Area::Left => self.layout.left(),
            Area::Right => self.layout.right()?,
        } as usize;
        let mut alternates = self
            .designated
            .iter()
            .enumerate()
            .filter_map(|(slot, set)| (slot != active).then_some(*set).flatten());
        let selected = alternates.next()?;
        alternates.next().is_none().then_some(selected)
    }

    fn control(&mut self, first: u8, bytes: &mut &[u8]) -> Option<Control> {
        let control = match first {
            0x0f if self.controls.primary.locking_shifts() => {
                Some(Control::Lock(Area::Left, Slot::G0))
            }
            0x0e if self.controls.primary.locking_shifts() => {
                Some(Control::Lock(Area::Left, Slot::G1))
            }
            0x1c if self.controls.primary == PrimaryControls::IsoIr36 => Some(Control::Single94),
            0x1c if self.controls.primary == PrimaryControls::Newspaper => Some(Control::Alternate),
            0x00..=0x1f if first != 0x1b && self.controls.primary == PrimaryControls::Newspaper => {
                Some(Control::Text(Effect::newspaper(first)?))
            }
            0x19 if self.controls.primary == PrimaryControls::IsoIr140 => {
                Some(Control::Single(Slot::G2))
            }
            0x80..=0x9f => self.controls.supplementary(first - 0x40, C1Form::Raw),
            0x1b => self.escape(bytes),
            _ => None,
        }?;
        match (self.announcements.level(), &control) {
            (Some(_), Control::Alternate | Control::Single94) => None,
            (Some(Level::One), Control::Single(_)) => None,
            (Some(_), Control::Single(_)) if first < 0x1b => None,
            _ => Some(control),
        }
    }

    fn positions_c0(&self) -> bool {
        self.controls.primary == PrimaryControls::Iso646 && self.controls.c1 == C1Set::IsoIr77
    }

    fn table_character(&mut self, position: TablePosition) -> Option<Glyph> {
        let byte = position.byte();
        let (area, slot) = if byte >= 0xa0 {
            self.controls.set_width(Width::Eight)?;
            (Area::Right, self.layout.right()?)
        } else {
            (Area::Left, self.layout.left())
        };
        let set = self.designated[slot as usize]?;
        if byte == 0x20 && set.is_94() {
            return Some(Glyph::Scalar(' '));
        }
        set.graphic(area.position(byte)?, area, &mut &[][..])?
            .into_glyph()
    }

    fn escape(&mut self, bytes: &mut &[u8]) -> Option<Control> {
        Some(match take(bytes)? {
            selector @ (b'('..=b'+') => {
                let slot = Slot::from_index(selector - b'(')?;
                Control::Designate(slot, Repertoire::set94(take(bytes)?)?)
            }
            selector @ (b'-'..=b'/') => {
                let slot = Slot::from_index(selector - b'-' + 1)?;
                Control::Designate(slot, Repertoire::set96(take(bytes)?)?)
            }
            b'$' => double_byte_designation(bytes, None)?,
            b'&' => {
                let revision = take(bytes)?;
                *bytes = bytes.strip_prefix(b"\x1b$")?;
                double_byte_designation(bytes, Some(revision))?
            }
            b'%' if take(bytes)? == b'G' => Control::Utf8Switch,
            b'!' => Control::Primary(match take(bytes)? {
                b'@' => PrimaryControls::Iso646,
                b'C' => PrimaryControls::Newspaper,
                b'D' => PrimaryControls::IsoIr36,
                b'G' => PrimaryControls::EscapeOnly,
                b'L' => PrimaryControls::IsoIr140,
                _ => return None,
            }),
            b'"' => Control::Supplementary(match take(bytes)? {
                b'C' => C1Set::IsoIr77,
                b'G' => C1Set::IsoIr105,
                _ => return None,
            }),
            b' ' => Control::Announce(take(bytes)?),
            b'n' => Control::Lock(Area::Left, Slot::G2),
            b'o' => Control::Lock(Area::Left, Slot::G3),
            b'~' => Control::Lock(Area::Right, Slot::G1),
            b'}' => Control::Lock(Area::Right, Slot::G2),
            b'|' => Control::Lock(Area::Right, Slot::G3),
            final_byte @ 0x40..=0x5f => {
                return self.controls.supplementary(final_byte, C1Form::Escaped);
            }
            _ => return None,
        })
    }

    fn apply(&mut self, control: Control, part: Part) -> Option<()> {
        if matches!(part, Part::Data)
            && self.announcements.level().is_some()
            && matches!(
                control,
                Control::Designate(..) | Control::Primary(_) | Control::Supplementary(_)
            )
        {
            return None;
        }
        match control {
            Control::Designate(slot, set) => {
                if !self.set_size.permits(set) {
                    return None;
                }
                self.designated[slot as usize] = Some(set);
            }
            Control::Lock(area, slot) => {
                self.designated[slot as usize]?;
                if matches!(area, Area::Left)
                    && matches!(self.layout, GraphicLayout::G0G1ByWidth { .. })
                {
                    self.controls.set_width(Width::Seven)?;
                }
                self.announcements
                    .constrain_lock(area, slot, &mut self.controls)?;
                self.layout.lock(area, slot)?;
            }
            Control::Primary(primary) => self.controls.primary = primary,
            Control::Supplementary(set) => self.controls.c1 = set,
            Control::Announce(_)
            | Control::Alternate
            | Control::Text(_)
            | Control::Utf8Switch
            | Control::Single94
            | Control::Single(_) => {
                return None;
            }
        }
        Some(())
    }

    fn announce(&mut self, facility: u8) -> Option<()> {
        // ECMA-35 §15.2.2, Table 7. These layouts constrain locking shifts
        // and normal GL/GR graphics independently of single shifts.
        self.announcements.insert(facility)?;
        self.layout = match (facility, self.layout) {
            (b'A', GraphicLayout::Extended { .. } | GraphicLayout::FixedG0) => {
                GraphicLayout::FixedG0
            }
            (b'B', GraphicLayout::Extended { left: Slot::G0, .. }) => {
                GraphicLayout::LockedG0G1 { g1: false }
            }
            (b'B', GraphicLayout::Extended { left: Slot::G1, .. }) => {
                GraphicLayout::LockedG0G1 { g1: true }
            }
            (b'B', layout @ GraphicLayout::LockedG0G1 { .. }) => layout,
            (b'C', GraphicLayout::Extended { .. } | GraphicLayout::FixedG0G1) => {
                self.controls.set_width(Width::Eight)?;
                GraphicLayout::FixedG0G1
            }
            (b'D', GraphicLayout::Extended { left: Slot::G0, .. }) => {
                GraphicLayout::G0G1ByWidth { g1: false }
            }
            (b'D', GraphicLayout::Extended { left: Slot::G1, .. }) => {
                self.controls.set_width(Width::Seven)?;
                GraphicLayout::G0G1ByWidth { g1: true }
            }
            (b'D', layout @ GraphicLayout::G0G1ByWidth { .. }) => layout,
            (b'A'..=b'D', _) => return None,
            (b'H' | b'I', _) => {
                if facility == b'H' || matches!(self.set_size, GraphicSetSize::SingleByte94) {
                    self.set_size = GraphicSetSize::SingleByte94;
                } else {
                    self.set_size = GraphicSetSize::SingleByte;
                }
                return self
                    .designated
                    .into_iter()
                    .flatten()
                    .all(|set| self.set_size.permits(set))
                    .then_some(());
            }
            (b'F', _) => return self.controls.select_c1_wire(C1Wire::Fixed(C1Form::Escaped)),
            (b'G', _) => return self.controls.select_c1_wire(C1Wire::ByWidth),
            (b'J', _) => return self.controls.set_width(Width::Seven),
            (b'K', _) => return self.controls.set_width(Width::Eight),
            (b'L'..=b'N', _) => {
                self.controls.set_width(Width::Eight)?;
                self.controls.select_c1_wire(C1Wire::ByWidth)?;
                self.set_size = GraphicSetSize::SingleByte;
                if !self
                    .designated
                    .into_iter()
                    .flatten()
                    .all(Repertoire::single_byte)
                {
                    return None;
                }
                match self.announcements.level()? {
                    Level::One | Level::Two => GraphicLayout::FixedG0G1,
                    Level::Three => GraphicLayout::Extended {
                        left: Slot::G0,
                        right: Slot::G1,
                    },
                }
            }
            (b'\\', _) => {
                self.controls.set_width(Width::Eight)?;
                self.single_area = Area::Right;
                return Some(());
            }
            // ACS 5 concerns transformation between widths. The individual
            // lock and single-shift facilities use the normal shift codes.
            _ => return Some(()),
        };
        Some(())
    }
}

fn double_byte_designation(bytes: &mut &[u8], revision: Option<u8>) -> Option<Control> {
    let (slot, final_byte) = match take(bytes)? {
        final_byte @ b'@'..=b'B' => (Slot::G0, final_byte),
        selector @ (b'('..=b'+') => (Slot::from_index(selector - b'(')?, take(bytes)?),
        _ => return None,
    };
    let plane = match revision {
        Some(revision) => DoubleByte94::revised(final_byte, revision)?,
        None => DoubleByte94::designated(final_byte)?,
    };
    Some(Control::Designate(slot, Repertoire::DoubleByte94(plane)))
}

enum Part {
    Declaration,
    Data,
}

fn take(bytes: &mut &[u8]) -> Option<u8> {
    let (&head, tail) = bytes.split_first()?;
    *bytes = tail;
    Some(head)
}

enum Control {
    Designate(Slot, Repertoire),
    Lock(Area, Slot),
    Single94,
    Single(Slot),
    Alternate,
    Text(Effect),
    Utf8Switch,
    Primary(PrimaryControls),
    Supplementary(C1Set),
    Announce(u8),
}

#[derive(Clone, Copy)]
enum GraphicSetSize {
    Any,
    SingleByte94,
    SingleByte,
}

impl GraphicSetSize {
    fn permits(self, set: Repertoire) -> bool {
        match self {
            Self::Any => true,
            Self::SingleByte94 => set.single_byte_94(),
            Self::SingleByte => set.single_byte(),
        }
    }
}

#[derive(Clone, Copy)]
enum GraphicLayout {
    Extended { left: Slot, right: Slot },
    FixedG0,
    LockedG0G1 { g1: bool },
    FixedG0G1,
    G0G1ByWidth { g1: bool },
}

impl GraphicLayout {
    fn left(self) -> Slot {
        match self {
            Self::Extended { left, .. } => left,
            Self::LockedG0G1 { g1: true } | Self::G0G1ByWidth { g1: true } => Slot::G1,
            Self::FixedG0
            | Self::FixedG0G1
            | Self::LockedG0G1 { g1: false }
            | Self::G0G1ByWidth { g1: false } => Slot::G0,
        }
    }

    fn right(self) -> Option<Slot> {
        match self {
            Self::Extended { right, .. } => Some(right),
            Self::FixedG0G1 | Self::G0G1ByWidth { .. } => Some(Slot::G1),
            Self::FixedG0 | Self::LockedG0G1 { .. } => None,
        }
    }

    fn lock(&mut self, area: Area, slot: Slot) -> Option<()> {
        match (self, area, slot) {
            (Self::Extended { left, .. }, Area::Left, slot) => *left = slot,
            (Self::Extended { right, .. }, Area::Right, slot) => *right = slot,
            (Self::LockedG0G1 { g1 } | Self::G0G1ByWidth { g1 }, Area::Left, Slot::G0) => {
                *g1 = false
            }
            (Self::LockedG0G1 { g1 } | Self::G0G1ByWidth { g1 }, Area::Left, Slot::G1) => {
                *g1 = true
            }
            _ => return None,
        }
        Some(())
    }
}

#[derive(Clone, Copy)]
enum Area {
    Left,
    Right,
}

impl Area {
    fn position(self, byte: u8) -> Option<u8> {
        match self {
            Self::Left if (0x20..=0x7f).contains(&byte) => Some(byte),
            Self::Right if byte >= 0xa0 => Some(byte & 0x7f),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum Slot {
    G0,
    G1,
    G2,
    G3,
}

impl Slot {
    fn from_index(index: u8) -> Option<Self> {
        [Self::G0, Self::G1, Self::G2, Self::G3]
            .get(usize::from(index))
            .copied()
    }

    fn single(final_byte: u8) -> Option<Self> {
        match final_byte {
            b'N' => Some(Self::G2),
            b'O' => Some(Self::G3),
            _ => None,
        }
    }
}
