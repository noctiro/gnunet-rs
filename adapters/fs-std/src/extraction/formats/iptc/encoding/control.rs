//! Control set selection and the width and wire form of a coded dataset.

use super::{Control, Slot, presentation::Effect};

#[derive(Clone, Copy, Default)]
pub(super) struct ControlSets {
    pub(super) primary: PrimaryControls,
    pub(super) c1: C1Set,
    width: Option<Width>,
    c1_wire: C1Wire,
}

impl ControlSets {
    pub(super) fn undeclared(width: Width) -> Self {
        let primary = match width {
            Width::Seven => PrimaryControls::Iso646,
            Width::Eight => PrimaryControls::Default8,
        };
        Self {
            primary,
            c1: C1Set::Unassigned,
            width: Some(width),
            ..Self::default()
        }
    }

    pub(super) fn set_width(&mut self, width: Width) -> Option<()> {
        if self.width.is_some_and(|current| current != width) {
            return None;
        }
        self.width = Some(width);
        Some(())
    }

    pub(super) fn supplementary(&mut self, final_byte: u8, form: C1Form) -> Option<Control> {
        let control = match (self.c1, final_byte) {
            (C1Set::Unassigned, _) => return None,
            (_, b'N' | b'O') => Control::Single(Slot::single(final_byte)?),
            (C1Set::IsoIr77, byte) => Control::Text(Effect::iso6429(byte, form)?),
            _ => return None,
        };
        if self.c1_wire == C1Wire::ByWidth {
            self.set_width(match form {
                C1Form::Escaped => Width::Seven,
                C1Form::Raw => Width::Eight,
            })?;
        } else {
            if form == C1Form::Raw {
                self.set_width(Width::Eight)?;
            }
            self.select_c1_wire(C1Wire::Fixed(form))?;
        }
        Some(control)
    }

    pub(super) fn select_c1_wire(&mut self, wire: C1Wire) -> Option<()> {
        if self.c1_wire != C1Wire::Unspecified && self.c1_wire != wire {
            return None;
        }
        self.c1_wire = wire;
        Some(())
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) enum PrimaryControls {
    #[default]
    Iso646,
    Newspaper,
    IsoIr36,
    IsoIr140,
    Default8,
    EscapeOnly,
}

impl PrimaryControls {
    pub(super) fn has_literal_whitespace(self) -> bool {
        !matches!(self, Self::Newspaper | Self::EscapeOnly)
    }

    pub(super) fn locking_shifts(self) -> bool {
        !matches!(self, Self::Default8 | Self::EscapeOnly)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Width {
    Seven,
    Eight,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) enum C1Set {
    Unassigned,
    #[default]
    ImplicitShifts,
    IsoIr77,
    IsoIr105,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) enum C1Wire {
    #[default]
    Unspecified,
    Fixed(C1Form),
    ByWidth,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum C1Form {
    Escaped,
    Raw,
}
