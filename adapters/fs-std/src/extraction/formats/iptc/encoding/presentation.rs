//! Plain-text projection for registered IIM presentation controls.

mod directions;
mod document;
mod geometry;
mod page;
mod tabs;

use super::{C1Form, append_text, repertoire::Glyph, take, trim_leading_space};
use directions::{Cell, Direction as TextDirection, Directions, Kind as DirectionKind, Run};
use document::Document;
use geometry::{Layout, Path, Reflow, ScreenMotion};
use page::{Coordinate, Edit, Erasure, LineEdit, Page};
use tabs::{Alignment, Axis, Direction, TabEdit, TabScope};

const MAX_CSI_BYTES: usize = 32;
const MAX_TAB_EDITS: usize = MAX_CSI_BYTES.div_ceil(2);

pub(super) enum Effect {
    Character(char),
    Discard,
    EraseCharacter,
    EraseWord,
    CancelGraphic,
    Instruction,
    ControlString(C1Form),
    ControlSequence,
    Backspace,
    CarriageReturn,
    Index,
    ReverseIndex,
    CharacterTab,
    LineTab,
    TabSet(Axis),
    TabJustify,
    FormFeed,
}

impl Effect {
    pub(super) fn project(
        self,
        input: &mut &[u8],
        text: &mut Text<'_>,
        table_character: impl FnOnce(TablePosition) -> Option<Glyph>,
    ) -> Option<()> {
        if matches!(self, Self::CancelGraphic) {
            text.pending_graphic = None;
            return Some(());
        }
        if matches!(self, Self::ControlSequence) {
            return ControlSequence::read(input)?.apply(text, table_character);
        }
        text.commit_graphic()?;
        match self {
            Self::Character(character) => return text.push(Glyph::Scalar(character)),
            Self::Discard => {}
            Self::EraseCharacter => text.cancel(false)?,
            Self::EraseWord => text.cancel(true)?,
            Self::Instruction => {
                let end = input.iter().position(|&byte| matches!(byte, 0x0b | 0x0c))?;
                if input[end] != 0x0b {
                    return None;
                }
                *input = &input[end + 1..];
            }
            Self::ControlString(form) => consume_string(input, form)?,
            Self::Backspace => text
                .page()?
                .position(Coordinate::Same, Coordinate::Backward(1))?,
            Self::CarriageReturn => text
                .page()?
                .position(Coordinate::Same, Coordinate::Absolute(0))?,
            Self::Index => text
                .page()?
                .position(Coordinate::Forward(1), Coordinate::Same)?,
            Self::ReverseIndex => text
                .page()?
                .position(Coordinate::Backward(1), Coordinate::Same)?,
            Self::CharacterTab => text.outside_direction()?.character_tab()?,
            Self::LineTab => {
                text.outside_direction()?
                    .tabulate(Axis::Row, Direction::Forward, 1)?
            }
            Self::TabSet(axis) => text.page()?.tab_edit(TabEdit::Set(axis))?,
            Self::TabJustify => text.page()?.justify_to_tab()?,
            Self::FormFeed => text.document()?.form_feed()?,
            Self::CancelGraphic | Self::ControlSequence => {}
        }
        Some(())
    }

    pub(super) fn iso646_position(byte: u8) -> Option<Self> {
        Some(match byte {
            0x08 => Self::Backspace,
            0x09 => Self::CharacterTab,
            0x0a => Self::Index,
            0x0b => Self::LineTab,
            0x0c => Self::FormFeed,
            0x0d => Self::CarriageReturn,
            _ => return None,
        })
    }

    pub(super) fn newspaper(byte: u8) -> Option<Self> {
        Some(match byte {
            0x08 => Self::EraseCharacter,
            0x09 => Self::Character('\t'),
            0x0a | 0x0d | 0x1d..=0x1f => Self::Character('\n'),
            0x0c => Self::Instruction,
            0x11..=0x13 => Self::Discard,
            0x18 => Self::EraseWord,
            _ => return None,
        })
    }

    pub(super) fn iso6429(final_byte: u8, form: C1Form) -> Option<Self> {
        Some(match final_byte {
            b'D' => Self::Index,
            b'E' => Self::Character('\n'), // NEL
            b'H' => Self::TabSet(Axis::Column),
            b'I' => Self::TabJustify,
            b'J' => Self::TabSet(Axis::Row),
            b'M' => Self::ReverseIndex,
            b'F' | b'G' | b'K' | b'L' | b'V' | b'W' => Self::Discard,
            b'T' => Self::CancelGraphic,
            b'P' | b']' | b'^' | b'_' => Self::ControlString(form),
            b'[' => Self::ControlSequence,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct TablePosition(u8);

impl TablePosition {
    fn new(position: usize) -> Option<Self> {
        match u8::try_from(position).ok()? {
            byte @ (0x20..=0x7f | 0xa0..=0xff) => Some(Self(byte)),
            _ => None,
        }
    }

    pub(super) const fn byte(self) -> u8 {
        self.0
    }
}

enum AlignmentSpec {
    Edge(Alignment),
    Character(TablePosition),
    Remove,
}

enum DirectionControl {
    Open(TextDirection),
    Reverse,
    Close(DirectionKind),
}

pub(super) struct Text<'a> {
    out: &'a mut String,
    limit: usize,
    input_bytes: usize,
    document: Option<Document>,
    directions: Directions,
    // ISO-IR 77 can cancel or repeat the preceding graphic before it is written.
    pending_graphic: Option<Glyph>,
}

impl<'a> Text<'a> {
    pub(super) fn new(out: &'a mut String, limit: usize, input_bytes: usize) -> Self {
        out.clear();
        Self {
            out,
            limit,
            input_bytes,
            document: None,
            directions: Directions::default(),
            pending_graphic: None,
        }
    }

    pub(super) fn decoded_graphic(&mut self, glyph: Glyph, deferred: bool) -> Option<()> {
        self.commit_graphic()?;
        if deferred {
            self.pending_graphic = Some(glyph);
            Some(())
        } else {
            self.push(glyph)
        }
    }

    pub(super) fn literal(&mut self, character: char) -> Option<()> {
        self.commit_graphic()?;
        self.push(Glyph::Scalar(character))
    }

    pub(super) fn commit_graphic(&mut self) -> Option<()> {
        if let Some(graphic) = self.pending_graphic.take() {
            self.push(graphic)?;
        }
        Some(())
    }

    fn repeat(&mut self, count: usize) -> Option<()> {
        let graphic = self.pending_graphic.take()?;
        let copies = count.checked_add(1)?;
        if copies.checked_mul(graphic.utf8_len())? > self.limit {
            return None;
        }
        for _ in 0..copies {
            self.push(graphic)?;
        }
        Some(())
    }

    fn push(&mut self, glyph: Glyph) -> Option<()> {
        match glyph {
            Glyph::Scalar(character) if self.document.is_none() => {
                append_text(self.out, character, self.limit)
            }
            // A scalar pair occupies one graphic position. Preserve its
            // boundary even when the first cursor movement arrives later.
            _ => {
                let cell = Cell {
                    glyph,
                    run: self.directions.active(),
                };
                self.page()?.push(cell)
            }
        }
    }

    pub(super) fn push_utf8(&mut self, text: &str) -> Option<()> {
        self.commit_graphic()?;
        if let Some(document) = &mut self.document {
            let run = self.directions.active();
            for character in text.chars() {
                document.active().push(Cell {
                    glyph: Glyph::Scalar(character),
                    run,
                })?;
            }
        } else {
            let bytes = if self.out.is_empty() {
                trim_leading_space(text.as_bytes())
            } else {
                text.as_bytes()
            };
            let text = text.get(text.len() - bytes.len()..)?;
            if text.len() > self.limit.checked_sub(self.out.len())? {
                return None;
            }
            self.out.try_reserve(text.len()).ok()?;
            self.out.push_str(text);
        }
        Some(())
    }

    pub(super) fn finish(mut self) -> Option<&'a [u8]> {
        self.commit_graphic()?;
        if self.directions.active() != Run::PLAIN {
            return None;
        }
        match self.document {
            Some(document) => document.render(self.out, &self.directions),
            None => (!self.out.is_empty()).then_some(self.out.as_bytes()),
        }
    }

    fn page(&mut self) -> Option<&mut Page> {
        Some(self.document()?.active())
    }

    fn outside_direction(&mut self) -> Option<&mut Page> {
        self.direction_inactive()?;
        self.page()
    }

    fn direction_inactive(&self) -> Option<()> {
        (self.directions.active() == Run::PLAIN).then_some(())
    }

    fn direction_control(&mut self, control: DirectionControl) -> Option<()> {
        match control {
            DirectionControl::Open(direction) => {
                self.document()?;
                self.directions.open(DirectionKind::Directed, direction)
            }
            DirectionControl::Reverse => {
                let base = self.page()?.text_direction();
                self.directions.reverse(base)
            }
            DirectionControl::Close(kind) => self.directions.close(kind),
        }
    }

    fn document(&mut self) -> Option<&mut Document> {
        if self.document.is_none() {
            self.document = Some(Document::from_text(self.out, self.limit, self.input_bytes)?);
        }
        self.document.as_mut()
    }

    fn cancel(&mut self, word: bool) -> Option<()> {
        if let Some(document) = &mut self.document {
            return document.active().cancel(word);
        }
        // ISO-IR 26 KW also removes the word's delimiting space.
        let at = if word {
            self.out
                .rfind([' ', '\n'])
                .map_or(0, |at| at + usize::from(self.out.as_bytes()[at] == b'\n'))
        } else {
            self.out.char_indices().next_back().map_or(0, |(at, _)| at)
        };
        self.out.truncate(at);
        Some(())
    }
}

fn consume_string(input: &mut &[u8], form: C1Form) -> Option<()> {
    // ECMA-48 control strings end in ST, represented by the same C1 form as
    // the start. None of the control-string payload belongs to the text.
    loop {
        match take(input)? {
            0x9c if form == C1Form::Raw => return Some(()),
            0x1b if form == C1Form::Escaped => return (take(input)? == b'\\').then_some(()),
            0x20..=0x7e | 0x08..=0x0d | 0xa0..=0xff => {}
            _ => return None,
        }
    }
}

enum ControlSequence {
    Rendition,
    Viewport,
    Page(Coordinate),
    PageHome(usize),
    Position {
        row: Coordinate,
        column: Coordinate,
    },
    ScreenMotion(ScreenMotion, usize),
    Layout(Layout, Reflow),
    Path(Path, Reflow),
    Cells(Edit),
    Lines(LineEdit),
    EraseLine(Erasure),
    ErasePage(Erasure),
    Tab {
        axis: Axis,
        direction: Direction,
        count: usize,
    },
    TabEdit(TabEdit),
    TabEdits([Option<TabEdit>; MAX_TAB_EDITS]),
    TabScope(TabScope),
    AlignedTab(usize, AlignmentSpec),
    Repeat(usize),
    Direction(DirectionControl),
}

impl ControlSequence {
    fn read(input: &mut &[u8]) -> Option<Self> {
        let end = input
            .iter()
            .take(MAX_CSI_BYTES)
            .position(|byte| (0x40..=0x7e).contains(byte))?;
        let (arguments, rest) = input.split_at(end);
        let (&final_byte, rest) = rest.split_first()?;
        *input = rest;
        if let Some(argument) = arguments.strip_suffix(b" ") {
            return Some(match final_byte {
                b'P' => Self::Page(Coordinate::Absolute(number(argument, 1)?.checked_sub(1)?)),
                b'Q' => Self::Page(Coordinate::Forward(number(argument, 1)?)),
                b'R' => Self::Page(Coordinate::Backward(number(argument, 1)?)),
                b'i' => Self::PageHome(number(argument, 0)?.checked_sub(1)?),
                b'S' => {
                    let (layout, reflow) = pair(argument, Some((0, 0)))?;
                    Self::Layout(
                        Layout::from_parameter(layout)?,
                        Reflow::from_parameter(reflow)?,
                    )
                }
                b'k' => {
                    let (path, reflow) = pair(argument, None)?;
                    Self::Path(Path::from_parameter(path)?, Reflow::from_parameter(reflow)?)
                }
                b'`'..=b'd' => Self::alignment(final_byte, argument)?,
                _ => return None,
            });
        }
        if final_byte == b'm' {
            return arguments
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'9' | b';' | b':'))
                .then_some(Self::Rendition);
        }
        let mut arguments = arguments.split(|&byte| byte == b';');
        let first = arguments.next()?;
        use Coordinate::{Absolute, Backward, Forward, Same};
        let position = |row, column| Self::Position { row, column };
        if matches!(final_byte, b'H' | b'f') {
            let row = number(first, 1)?.checked_sub(1)?;
            let column = number(arguments.next().unwrap_or_default(), 1)?.checked_sub(1)?;
            return arguments
                .next()
                .is_none()
                .then(|| position(Absolute(row), Absolute(column)));
        }
        if final_byte == b'W' {
            let mut edits = [None; MAX_TAB_EDITS];
            for (index, parameter) in core::iter::once(first).chain(arguments).enumerate() {
                *edits.get_mut(index)? = Some(*CURSOR_TABULATION.get(number(parameter, 0)?)?);
            }
            return Some(Self::TabEdits(edits));
        }
        if arguments.next().is_some() {
            return None;
        }
        if matches!(final_byte, b'J' | b'K') {
            let erasure = match number(first, 0)? {
                0 => Erasure::After,
                1 => Erasure::Before,
                2 => Erasure::All,
                _ => return None,
            };
            return Some(if final_byte == b'J' {
                Self::ErasePage(erasure)
            } else {
                Self::EraseLine(erasure)
            });
        }
        if final_byte == b'g' {
            return Some(Self::TabEdit(*CLEAR_TABULATION.get(number(first, 0)?)?));
        }
        if matches!(final_byte, b'[' | b']') {
            return Some(Self::Direction(match (final_byte, number(first, 0)?) {
                (b'[', 0) => DirectionControl::Close(DirectionKind::Reversed),
                (b'[', 1) => DirectionControl::Reverse,
                (b']', 0) => DirectionControl::Close(DirectionKind::Directed),
                (b']', 1) => DirectionControl::Open(TextDirection::Left),
                (b']', 2) => DirectionControl::Open(TextDirection::Right),
                _ => return None,
            }));
        }
        let count = number(first, 1)?;
        let tab = |axis, direction| Self::Tab {
            axis,
            direction,
            count,
        };
        Some(match final_byte {
            b'@' => Self::Cells(Edit::Insert(count)),
            b'A' => Self::ScreenMotion(ScreenMotion::Up, count),
            b'B' => Self::ScreenMotion(ScreenMotion::Down, count),
            b'C' => Self::ScreenMotion(ScreenMotion::Right, count),
            b'D' => Self::ScreenMotion(ScreenMotion::Left, count),
            b'k' => position(Backward(count), Same),
            b'e' => position(Forward(count), Same),
            b'a' => position(Same, Forward(count)),
            b'j' => position(Same, Backward(count)),
            b'E' => position(Forward(count), Absolute(0)),
            b'F' => position(Backward(count), Absolute(0)),
            b'G' | b'`' => position(Same, Absolute(count.checked_sub(1)?)),
            b'I' => tab(Axis::Column, Direction::Forward),
            b'Y' => tab(Axis::Row, Direction::Forward),
            b'Z' => tab(Axis::Column, Direction::Backward),
            b'd' => position(Absolute(count.checked_sub(1)?), Same),
            b'b' => Self::Repeat(count),
            b'h' if count == 18 => Self::TabScope(TabScope::Single),
            b'l' if count == 18 => Self::TabScope(TabScope::Multiple),
            b'L' => Self::Lines(LineEdit::Insert(count)),
            b'M' => Self::Lines(LineEdit::Delete(count)),
            b'P' => Self::Cells(Edit::Delete(count)),
            b'X' => Self::Cells(Edit::Erase(count)),
            b'U' | b'V' => Self::Viewport,
            _ => return None,
        })
    }

    fn alignment(final_byte: u8, arguments: &[u8]) -> Option<Self> {
        let mut arguments = arguments.split(|&byte| byte == b';');
        let column = number(arguments.next()?, 0)?.checked_sub(1)?;
        let spec = match final_byte {
            b'`' => AlignmentSpec::Edge(Alignment::TrailingEdge),
            b'a' => AlignmentSpec::Edge(Alignment::LeadingEdge),
            b'b' => AlignmentSpec::Edge(Alignment::Centre),
            b'c' => {
                let target = number(arguments.next().unwrap_or_default(), 32)?;
                AlignmentSpec::Character(TablePosition::new(target)?)
            }
            b'd' => AlignmentSpec::Remove,
            _ => return None,
        };
        arguments
            .next()
            .is_none()
            .then_some(Self::AlignedTab(column, spec))
    }

    fn apply(
        self,
        text: &mut Text<'_>,
        table_character: impl FnOnce(TablePosition) -> Option<Glyph>,
    ) -> Option<()> {
        if let Self::Repeat(count) = self {
            return text.repeat(count);
        }
        text.commit_graphic()?;
        match self {
            // Display-page selection changes the viewport only. This projection
            // serializes all pages, so it requires no viewport state.
            Self::Rendition | Self::Viewport => return Some(()),
            Self::Page(coordinate) => return text.document()?.move_to(coordinate),
            Self::PageHome(row) => return text.document()?.set_home(row),
            Self::Direction(control) => return text.direction_control(control),
            Self::Layout(layout, reflow) => {
                text.direction_inactive()?;
                return text.document()?.select_layout(layout, reflow);
            }
            Self::Path(path, reflow) => {
                text.direction_inactive()?;
                return text.document()?.select_path(path, reflow);
            }
            Self::Tab {
                axis: Axis::Row,
                direction,
                count,
            } => {
                return text
                    .outside_direction()?
                    .tabulate(Axis::Row, direction, count);
            }
            _ => {}
        }
        let page = text.page()?;
        match self {
            Self::Position { row, column } => page.position(row, column)?,
            Self::ScreenMotion(motion, count) => page.move_on_screen(motion, count)?,
            Self::Cells(edit) => page.edit_cells(edit)?,
            Self::Lines(edit) => page.edit_lines(edit)?,
            Self::EraseLine(erasure) => page.erase_line(erasure)?,
            Self::ErasePage(erasure) => page.erase_page(erasure)?,
            Self::Tab {
                axis,
                direction,
                count,
            } => page.tabulate(axis, direction, count)?,
            Self::TabEdit(edit) => page.tab_edit(edit)?,
            Self::TabEdits(edits) => {
                for edit in edits.into_iter().flatten() {
                    page.tab_edit(edit)?;
                }
            }
            Self::TabScope(scope) => page.tab_scope(scope),
            Self::AlignedTab(column, spec) => {
                let alignment = match spec {
                    AlignmentSpec::Edge(alignment) => Some(alignment),
                    AlignmentSpec::Character(at) => {
                        Some(Alignment::Character(table_character(at)?))
                    }
                    AlignmentSpec::Remove => None,
                };
                page.align_column(column, alignment)?;
            }
            Self::Rendition
            | Self::Viewport
            | Self::Page(_)
            | Self::PageHome(_)
            | Self::Repeat(_)
            | Self::Direction(_)
            | Self::Layout(..)
            | Self::Path(..) => {}
        }
        Some(())
    }
}

const CURSOR_TABULATION: [TabEdit; 7] = [
    TabEdit::Set(Axis::Column),
    TabEdit::Set(Axis::Row),
    TabEdit::Remove(Axis::Column),
    TabEdit::Remove(Axis::Row),
    TabEdit::ClearLine,
    TabEdit::ClearAxis(Axis::Column),
    TabEdit::ClearAxis(Axis::Row),
];

const CLEAR_TABULATION: [TabEdit; 6] = [
    TabEdit::Remove(Axis::Column),
    TabEdit::Remove(Axis::Row),
    TabEdit::ClearLine,
    TabEdit::ClearAxis(Axis::Column),
    TabEdit::ClearAxis(Axis::Row),
    TabEdit::ClearAll,
];

fn number(bytes: &[u8], default: usize) -> Option<usize> {
    if bytes.is_empty() {
        return Some(default);
    }
    bytes.iter().try_fold(0_usize, |value, &byte| {
        let digit = byte.checked_sub(b'0').filter(|&digit| digit <= 9)?;
        value.checked_mul(10)?.checked_add(usize::from(digit))
    })
}

fn pair(bytes: &[u8], defaults: Option<(usize, usize)>) -> Option<(usize, usize)> {
    let mut arguments = bytes.split(|&byte| byte == b';');
    let first = arguments.next()?;
    let second = arguments.next().unwrap_or_default();
    if arguments.next().is_some() {
        return None;
    }
    let (first, second) = match defaults {
        Some((a, b)) => (number(first, a)?, number(second, b)?),
        None if !first.is_empty() && !second.is_empty() => (number(first, 0)?, number(second, 0)?),
        None => return None,
    };
    Some((first, second))
}

#[cfg(test)]
mod tests {
    use super::super::Encoding;

    #[test]
    fn projects_registered_newspaper_controls_and_shift() {
        let encoding = Encoding::declared(b"\x1b!C\x1b)A");
        let mut text = String::new();
        assert_eq!(
            encoding.decode(
                b"Story bad\x18 \x12now\x1c#\x1dline\x0cfont instructions\x0b!",
                &mut text,
                128,
            ),
            Some("Story now£\nline!".as_bytes())
        );
        assert_eq!(
            encoding.decode(b"line\rwrong\x18ok", &mut text, 32),
            Some(b"line\nok".as_slice()),
        );
        assert!(
            encoding
                .decode(b"line\x0cincomplete", &mut text, 32)
                .is_none()
        );
        let ambiguous = Encoding::declared(b"\x1b!C\x1b)A\x1b*J");
        assert!(ambiguous.decode(b"line\x1c#", &mut text, 32).is_none());
    }

    #[test]
    fn projects_iso6429_only_in_the_declared_c1_form() {
        let mut text = String::new();
        let escaped = Encoding::declared(b"\x1b\"C\x1b F");
        assert_eq!(
            escaped.decode(
                b"A\x1bEB\x1b[1;31m\x1bIstyled\x1b[0m\x1b]0;title\x1b\\!",
                &mut text,
                64,
            ),
            Some(b"A\n       Bstyled!".as_slice()),
        );
        let raw = Encoding::declared(b"\x1b\"C\x1b G\x1b K");
        assert_eq!(
            raw.decode(b"spellingg\x94 \x9b0mhere\x9dprivate\x9c", &mut text, 64),
            Some(b"spelling here".as_slice()),
        );
        assert!(raw.decode(b"A\x9dprivate\x1b\\", &mut text, 64).is_none());
        assert!(escaped.decode(b"A\x9b0m", &mut text, 64).is_none());
        assert!(escaped.decode(b"A\x1b[12", &mut text, 64).is_none());
    }

    #[test]
    fn projects_horizontal_and_vertical_tab_stops() {
        let encoding = Encoding::declared(b"\x1b\"C\x1b F");
        let mut text = String::new();
        for (input, expected) in [
            (b"A\tB".as_slice(), "A       B"),
            (b"A\x1b[5G\x1bH\x1b[2G\tB", "A   B"),
            (b"A\x1b[9G\x1b[g\x1b[2G\tB", "A               B"),
            (b"A\x1b[3g\tB", "AB"),
            (
                b"A\x1b[18h\x1b[5G\x1bH\x1b[2G\tB\x1bEC\tD",
                "A   B\nC       D",
            ),
            (
                b"A\x1b[18h\x1b[5G\x1bH\x1b[18l\x1b[g\x1b[2G\tB",
                "A       B",
            ),
            (b"A\x1b[17G\x1b[ZB", "A       B"),
            (b"A\x1b[2IB", "A               B"),
            (b"A\x1b[3d\x1bJ\x1b[1d\x0bB", "A\n\n B"),
            (b"A\x1b[3d\x1bJ\x1b[2d\x1b[L\x1b[1d\x1b[YB", "A\n\n\nB"),
            (b"A\x1b[3d\x1b[0;1W\x1b[1d\x1b[5g\x0b\tB", "AB"),
        ] {
            assert_eq!(
                encoding.decode(input, &mut text, 64),
                Some(expected.as_bytes()),
                "{input:?}"
            );
        }
        assert!(encoding.decode(b"A\tB", &mut text, 8).is_none());
        assert!(encoding.decode(b"A\x1b[7WB", &mut text, 64).is_none());
        assert!(
            encoding
                .decode(b"A\x1b[999999999IB", &mut text, 64)
                .is_none()
        );
        let raw = Encoding::declared(b"\x1b\"C\x1b K\x1b G");
        assert_eq!(
            raw.decode(b"A\x9b5G\x88\x9b2G\tB", &mut text, 64),
            Some(b"A   B".as_slice())
        );
    }

    #[test]
    fn page_positioning_preserves_the_data_cursor_and_field_budget() {
        let encoding = Encoding::declared(b"\x1b\"C\x1b F");
        let mut text = String::new();
        for (input, expected) in [
            (b"A\x1b[ QB\x1b[ RC".as_slice(), "A C\x0c B"),
            (b"A\x1b[3 i\x0cB", "A\x0c\n\n B"),
            (b"\x1b[3 PB", "\x0c\x0cB"),
            (b"A\x1b[UB\x1b[VC", "ABC"),
            (b"A\x0cB\x1b[2J\x1b[1GC", "A\x0cC"),
            (b"A\x0c", "A"),
        ] {
            assert_eq!(
                encoding.decode(input, &mut text, 64),
                Some(expected.as_bytes()),
                "{input:?}"
            );
        }
        assert_eq!(
            encoding.decode(b"A\x1b[3 PB", &mut text, 5),
            Some(b"A\x0c\x0c B".as_slice())
        );
        assert!(encoding.decode(b"A\x1b[3 PB", &mut text, 4).is_none());
        assert!(
            encoding
                .decode(b"A\x1b[99999999 QB", &mut text, 64)
                .is_none()
        );
        assert!(encoding.decode(b"A\x1b[ iB", &mut text, 64).is_none());
    }

    #[test]
    fn aligned_tabs_use_the_invoked_graphic_and_the_declaring_lines() {
        let mut text = String::new();
        let encoding = Encoding::declared(b"\x1b\"C\x1b F\x1b-A");
        for (input, expected) in [
            (b"id\x1b[7 `\tAB".as_slice(), "id    AB"),
            (b"id\x1b[7 a\tAB", "id  AB"),
            (b"id\x1b[7 b\tA\x1b[1mBC", "id   ABC"),
            (b"id\x1b[7;46 c\t12.34", "id  12.34"),
            (b"id\x1b[7 c\tab c", "id  ab c"),
            (b"id\x1b[7;163 c\t12\xa334", "id  12£34"),
            (b"id\x1b[7;46 c\tXYZ", "id    XYZ"),
            (b"A\x1bEB\x1b[7 a\tXY\x1b[1;2H\tC", "A       C\nB   XY"),
            (b"id\x1b[9 b\x1b[9 d\tX", "id              X"),
            (b"id\x1b[7 a\tAB\tX", "id  AB  X"),
            (b"id\x1b[7 a\tAB\x1bEZ", "id  AB\nZ"),
        ] {
            assert_eq!(
                encoding.decode(input, &mut text, 64),
                Some(expected.as_bytes()),
                "{input:?}"
            );
        }
        assert!(encoding.decode(b"\x1b[2 a\tXYZ", &mut text, 64).is_none());
        assert!(
            encoding
                .decode(b"id\x1b[7;150 c\tX", &mut text, 64)
                .is_none()
        );
        assert!(
            encoding
                .decode(b"id\x1b[999999 b\tX", &mut text, 64)
                .is_none()
        );
        assert!(encoding.decode(b"id\x1b[7 b\tABCD", &mut text, 7).is_none());
    }

    #[test]
    fn repetition_and_cancellation_apply_before_a_graphic_updates_the_page() {
        let mut text = String::new();
        let encoding = Encoding::declared(b"\x1b\"C\x1b F");
        assert_eq!(
            encoding.decode(b"a\x1b[3b!", &mut text, 5),
            Some(b"aaaa!".as_slice())
        );
        assert_eq!(
            encoding.decode(b"ABC\x1b[1Gx\x1bT", &mut text, 3),
            Some(b"ABC".as_slice())
        );
        assert_eq!(
            encoding.decode(b"ab\x1b[1G\x1bTQ", &mut text, 2),
            Some(b"Qb".as_slice())
        );
        assert_eq!(
            encoding.decode(b"abcd\x1bT", &mut text, 3),
            Some(b"abc".as_slice())
        );
        assert!(encoding.decode(b"a\x1b[9999999b!", &mut text, 64).is_none());
        assert!(encoding.decode(b"a\x1b[1m\x1b[b", &mut text, 64).is_none());

        let jis = Encoding::declared(b"\x1b\"C\x1b$(O");
        let expected = "か\u{309a}か\u{309a}か\u{309a}";
        assert_eq!(
            jis.decode(b"$w\x1b[2b", &mut text, 18),
            Some(expected.as_bytes())
        );
        assert!(jis.decode(b"$w\x1b[2b", &mut text, 17).is_none());
    }

    #[test]
    fn direction_scopes_preserve_logical_text_after_layout_edits() {
        let mut text = String::new();
        let encoding = Encoding::declared(b"\x1b\"C\x1b F");
        for (input, expected) in [
            (b"A\x1b[2]bc\x1b[]Z".as_slice(), "A\u{2067}bc\u{2069}Z"),
            (
                b"x\x1b[2]r\x1b[1[l\x1b[[s\x1b[0]y",
                "x\u{2067}r\u{2066}l\u{2069}s\u{2069}y",
            ),
            (
                b"A\x1b[2]b\x1b[]\x1b[1[c\x1b[[",
                "A\u{2067}b\u{2069}\u{2067}c\u{2069}",
            ),
            (
                b"A\x1b[2]b\x1bEc\x1b[]D",
                "A\u{2067}b\u{2069}\n\u{2067}c\u{2069}D",
            ),
            (b"A\x1b[2]bc\x1b[]\x1b[3GX", "A\u{2067}b\u{2069}X"),
            (b"A\x1b[2]\x1b[]B", "AB"),
            (
                b"A\x1b[2]b\x1b%G\xe2\x80\xa9\x1b%@c\x1b[]",
                "A\u{2067}b\u{2069}\u{2029}\u{2067}c\u{2069}",
            ),
        ] {
            assert_eq!(
                encoding.decode(input, &mut text, 64),
                Some(expected.as_bytes()),
                "{input:?}"
            );
        }
        let raw = Encoding::declared(b"\x1b\"C\x1b G\x1b K\x1b-H");
        let title = "A \u{2067}אב\u{2069} B";
        assert_eq!(
            raw.decode(b"A \x9b2]\xe0\xe1\x9b] B", &mut text, title.len()),
            Some(title.as_bytes())
        );
        assert!(
            raw.decode(b"A \x9b2]\xe0\xe1\x9b] B", &mut text, title.len() - 1)
                .is_none()
        );
    }

    #[test]
    fn direction_scope_boundaries_require_matching_controls() {
        let mut text = String::new();
        let encoding = Encoding::declared(b"\x1b\"C\x1b F");
        for rejected in [
            b"A\x1b[2]b".as_slice(),
            b"A\x1b[]b",
            b"A\x1b[2]b\x1b[[c",
            b"A\x1b[3]b\x1b[]",
            b"A\x1b[2]b\t\x1b[]c",
            b"A\x1b[2]b\x1b[Y\x1b[]c",
            b"A\x1b[2]\x1b%G\xe2\x81\xa9\x1b%@\x1b[]",
        ] {
            assert!(
                encoding.decode(rejected, &mut text, 64).is_none(),
                "{rejected:?}"
            );
        }
        let mut excess = b"\x1b[2]".repeat(63);
        excess.push(b'A');
        excess.extend_from_slice(&b"\x1b[]".repeat(63));
        assert!(encoding.decode(&excess, &mut text, 512).is_none());
    }

    #[test]
    fn presentation_directions_reflow_physical_positions_in_all_eight_layouts() {
        let encoding = Encoding::declared(b"\x1b\"C\x1b F");
        let mut text = String::new();
        let expected = [
            "AB\nCD", "BD\nAC", "AC\nBD", "BA\nDC", "CA\nDB", "DC\nBA", "CD\nAB", "DB\nCA",
        ];
        for (number, expected) in expected.into_iter().enumerate() {
            let mut input = *b"AB\x1bECD\x1b[0;2 S";
            input[8] = b'0' + number as u8;
            assert_eq!(
                encoding.decode(&input, &mut text, 5),
                Some(expected.as_bytes()),
                "{input:?}"
            );
        }
        assert_eq!(
            encoding.decode(b"ABC\x1bED\x1b[2;2 S", &mut text, 6),
            Some(b"AD\nB\nC".as_slice())
        );
        assert!(
            encoding
                .decode(b"ABC\x1bED\x1b[2;2 S", &mut text, 5)
                .is_none()
        );
        assert_eq!(
            encoding.decode(b"AB\x1bECD\x0c\x1b[HXY\x1b[2;2 S", &mut text, 20),
            Some(b"AC\nBD\x0cX\nY".as_slice()),
        );
    }

    #[test]
    fn screen_motion_and_character_paths_use_different_coordinates() {
        let encoding = Encoding::declared(b"\x1b\"C\x1b F");
        let mut text = String::new();
        for (input, expected) in [
            (b"AB\x1b[3;1 SX".as_slice(), "XB"),
            (b"\x1b[3 SAB\x1b[2CX\x1b[DY", "XBY"),
            (b"\x1b[1 SAB\x1b[2AX\x1b[DY", "XB\n Y"),
            (b"ABC\x1bExy\x1b[2;2 k", "ABC\n yx"),
            (b"ABC\x1bE\x1b[2;1 kxyz\x1b[1;1H\x1b[BX", "ABC\nxyX"),
            (b"\x1b[2;1 kA\x0cB\x1b[2CC", "A\x0cCB"),
            (b"\x1b[3 S\x1b[1[A\x1b[[", "\u{2066}A\u{2069}"),
        ] {
            assert_eq!(
                encoding.decode(input, &mut text, 32),
                Some(expected.as_bytes()),
                "{input:?}"
            );
        }
        assert!(encoding.decode(b"A\x1b[2 k", &mut text, 32).is_none());
        assert!(encoding.decode(b"A\x1b[8 S", &mut text, 32).is_none());
        assert!(
            encoding
                .decode(b"A\x1b[1]B\x1b[3 S\x1b[]", &mut text, 32)
                .is_none()
        );
    }

    #[test]
    fn positioned_text_edits_the_displayed_rows_and_cells() {
        let mut text = String::new();
        let escaped = Encoding::declared(b"\x1b\"C\x1b F");
        for (input, expected) in [
            (b"AB\x1bDC\x1bMD".as_slice(), "AB D\n  C"),
            (b"AB\x08x\rY", "Yx"),
            (b"AB\r\nD", "AB\nD"),
            (b"ABCDE\x1b[3G\x1b[2PX", "ABX"),
            (b"ABCD\x1b[2G\x1b[2@z", "Az BCD"),
            (b"alpha,beta\x1b[6G\x1b[X", "alpha beta"),
            (b"one\x1bEthree\x1b[2;1H\x1b[Ltwo", "one\ntwo\nthree"),
            (b"one\x1bEtwo\x1bEthree\x1b[2;2H\x1b[M", "one\nthree"),
            (b"one\x1bEtwo\x1b[1;2H\x1b[J", "o"),
            (b"123\x1b[2J\x1b[1Gbye", "bye"),
            (b"123\x1b[2K\x1b[2Gx", "x"),
            (b"a\x1b[2C\x1b%G\xc3\xa9\x1b%@!", "a  é!"),
        ] {
            assert_eq!(
                escaped.decode(input, &mut text, 64),
                Some(expected.as_bytes()),
                "{input:?}"
            );
        }
        let raw = Encoding::declared(b"\x1b\"C\x1b G\x1b K");
        assert_eq!(
            raw.decode(b"a\x9b3CX", &mut text, 5),
            Some(b"a   X".as_slice())
        );
        assert!(raw.decode(b"a\x9b3CX", &mut text, 4).is_none());
        for malformed in [
            b"a\x9b999999999999999999999999C".as_slice(),
            b"a\x9b?1P",
            b"a\x9b1;2;3H",
            b"a\x9b4K",
        ] {
            assert!(
                raw.decode(malformed, &mut text, 64).is_none(),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn a_jis_composition_is_one_editable_position() {
        let mut text = String::new();
        let encoding = Encoding::declared(b"\x1b\"C\x1b$(O");
        let glyph = "か\u{309a}";
        assert_eq!(encoding.decode(b"$w", &mut text, 6), Some(glyph.as_bytes()));
        assert!(encoding.decode(b"$w", &mut text, 5).is_none());
        assert_eq!(
            encoding.decode(b"$w\x1b[1D\x1b(BA", &mut text, 6),
            Some(b"A".as_slice()),
        );
        assert_eq!(
            encoding.decode(b"$w\x1b(BA\x1b[1G\x1b[X", &mut text, 7),
            Some(b"A".as_slice()),
        );
    }
}
