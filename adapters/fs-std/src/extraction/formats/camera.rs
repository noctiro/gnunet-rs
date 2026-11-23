//! Shared camera measurement values and their GNU metadata text.

use std::num::NonZeroI64;

pub(super) const EXPOSURE: u32 = 97;
pub(super) const APERTURE: u32 = 98;
pub(super) const FOCAL_LENGTH: u32 = 102;
pub(super) const ISO_SPEED: u32 = 104;

#[derive(Clone, Copy)]
pub(super) struct Rational {
    pub(super) numerator: i64,
    pub(super) denominator: NonZeroI64,
}

impl Rational {
    pub(super) fn new(numerator: i64, denominator: i64) -> Option<Self> {
        Some(Self {
            numerator,
            denominator: NonZeroI64::new(denominator)?,
        })
    }

    pub(super) fn value(self) -> f64 {
        self.numerator as f64 / self.denominator.get() as f64
    }

    pub(super) fn exposure(self) -> Option<String> {
        let time = self.positive()?;
        let denominator = self.denominator.get();
        Some(if self.numerator == denominator {
            "1 s".to_owned()
        } else if denominator % self.numerator == 0 {
            format!("1/{} s", denominator / self.numerator)
        } else {
            format!("{} s", significant(time, 6))
        })
    }

    pub(super) fn aperture(self) -> Option<String> {
        self.positive()
            .map(|value| format!("F{}", significant(value, 2)))
    }

    pub(super) fn focal_length(self) -> Option<String> {
        self.positive().map(|length| format!("{length:.1} mm"))
    }

    fn positive(self) -> Option<f64> {
        let value = self.value();
        (value > 0.0).then_some(value)
    }
}

fn significant(value: f64, digits: i32) -> String {
    let scale = 10_f64.powi(digits - 1 - value.log10().floor() as i32);
    ((value * scale).round() / scale).to_string()
}
