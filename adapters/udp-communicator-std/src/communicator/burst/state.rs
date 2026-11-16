//! Exclusive burst phases and the original held-command capability.
use super::*;
pub(super) struct HeldInput;
pub(super) struct Command {
    pub serial: u64,
    pub peer: PeerId,
    pub rtt: u64,
    pub remote: SocketAddr,
    pub default: usize,
    pub hard: Instant,
    pub alarm: Pin<Box<Sleep>>,
    pub ignored: u64,
}
impl Command {
    pub fn report(self, outcome: Outcome) -> Report {
        Report {
            serial: self.serial,
            peer: self.peer,
            rtt_us: self.rtt,
            outcome,
            ignored_scan_datagrams: self.ignored,
        }
    }
}
pub(super) struct Chosen<'id> {
    pub selection: Selection<'id>,
    pub scan: native::Report,
}
pub(super) struct Retired {
    pub outcome: Outcome,
    pub input: Option<HeldInput>,
}
#[expect(
    clippy::large_enum_variant,
    reason = "Exactly one inline native utility exists per communicator; retain its original owner without an extra allocation or constructor failure boundary"
)]
pub(super) enum Phase<'id> {
    Waiting(HeldInput),
    Running(Burst<'id>),
    Selected(Chosen<'id>),
    Retired(Retired),
}
pub(super) struct Active<'id> {
    pub command: Command,
    pub phase: Phase<'id>,
}
pub(super) fn ended(owner: Burst<'_>, interrupted: Option<Error>) -> Retired {
    let scan = owner.report();
    let outcome = match owner.into_end() {
        Some(end) => Outcome::Stopped {
            cause: end.cause,
            scan: end.report,
            interrupted,
        },
        None => Outcome::Unobserved { scan, interrupted },
    };
    Retired {
        outcome,
        input: None,
    }
}
impl Phase<'_> {
    pub fn input_held(&self) -> bool {
        matches!(
            self,
            Self::Waiting(_) | Self::Retired(Retired { input: Some(_), .. })
        )
    }
    pub fn interrupt(self, cause: Error) -> Retired {
        match self {
            Self::Waiting(input) => Retired {
                outcome: Outcome::NotStarted(cause),
                input: Some(input),
            },
            Self::Running(owner) => ended(owner, Some(cause)),
            Self::Selected(chosen) => {
                drop(chosen.selection);
                Retired {
                    outcome: Outcome::Rejected {
                        scan: chosen.scan,
                        reason: Refusal::Protocol(cause),
                    },
                    input: None,
                }
            }
            Self::Retired(retired) => retired,
        }
    }
}
