//! Typed official round kinds and the immutable session schedule.
use crate::Error;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub(super) enum Round {
    Union = 0,
    Inventory = 1,
    Lead = 2,
    Echo = 3,
    Confirm = 5,
}
impl Round {
    pub(super) const fn from_wire(value: u16) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Union),
            1 => Ok(Self::Inventory),
            2 => Ok(Self::Lead),
            3 => Ok(Self::Echo),
            5 => Ok(Self::Confirm),
            _ => Err(Error::Malformed),
        }
    }
    pub(super) const fn wire(self) -> u16 {
        self as u16
    }
    pub(super) const fn preface(self) -> bool {
        matches!(self, Self::Union | Self::Inventory)
    }
    const fn slot(self, repetition: usize) -> usize {
        match self {
            Self::Union => 0,
            Self::Inventory => 1,
            Self::Lead => 2 + 3 * repetition,
            Self::Echo => 3 + 3 * repetition,
            Self::Confirm => 4 + 3 * repetition,
        }
    }
}
/// Only the validated constructor can select the original public schedule.
#[derive(Clone, Copy, Debug)]
pub(super) struct Schedule {
    start: u64,
    deadline: u64,
    repetitions: usize,
}
impl Schedule {
    pub(super) fn new(start: u64, deadline: u64, peers: usize) -> Result<Self, Error> {
        if start >= deadline {
            return Err(Error::Deadline);
        }
        if peers == 0 || peers > 2046 {
            return Err(Error::InvalidInput);
        }
        // This repetition count is observable through official round contexts.
        // Quorum thresholds retain their separate strict Byzantine fault bound.
        Ok(Self {
            start,
            deadline,
            repetitions: peers / 3 + 1,
        })
    }
    pub(super) const fn start(self) -> u64 {
        self.start
    }
    pub(super) const fn deadline(self) -> u64 {
        self.deadline
    }
    pub(super) const fn repetitions(self) -> usize {
        self.repetitions
    }
    pub(super) fn window(self, round: Round, repetition: usize) -> u64 {
        let periods = 3 + 3 * self.repetitions;
        let width = u128::from(self.deadline - self.start);
        self.start
            .saturating_add(
                ((width * (round.slot(repetition) + 1) as u128) / periods as u128) as u64,
            )
            .min(self.deadline)
    }
}
