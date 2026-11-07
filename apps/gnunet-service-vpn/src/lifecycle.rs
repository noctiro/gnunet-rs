//! Independent owned cleanup causes survive every normal/failed/drop path.
use crate::Failure;
use gnunet_vpn_host::{coordinator, server};
use std::{
    cell::RefCell,
    fmt,
    io::{self, Write},
    rc::Rc,
};
#[derive(Clone, Copy)]
pub(super) enum Stage {
    Discovery = 0,
    Coordinator = 1,
    Resolver = 2,
    Output = 3,
    Debt = 4,
    ConstructionIpc = 5,
    ConstructionCadet = 6,
    ConstructionTun = 7,
    ObservedIpc = 8,
    ObservedControl = 9,
    ObservedTun = 10,
}
const N: usize = 11;
const NAMES: [&str; N] = [
    "REGEX close",
    "Coordinator independent cleanup",
    "Resolver disconnect",
    "STOPPED output",
    "unresolved original debt",
    "construction IPC close",
    "construction CADET close",
    "construction TUN close",
    "observed IPC cleanup",
    "actual control failure",
    "actual TUN loss",
];
#[derive(Debug)]
struct Both {
    first: Failure,
    next: Failure,
}
impl fmt::Display for Both {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; independent additional cause: {}",
            self.first, self.next
        )
    }
}
impl std::error::Error for Both {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.first.as_ref())
    }
}
/// Diagnostic metadata only; never reconstructs old operation authority.
#[derive(Clone, Copy, Debug)]
pub(super) struct CadetFact {
    pub epoch: u64,
    pub channels: usize,
    pub pending: Option<(u64, bool)>,
}
impl CadetFact {
    pub fn from_original(loss: gnunet_cadet_host::Loss<'_>) -> Self {
        Self {
            epoch: loss.epoch.value(),
            channels: loss.channels,
            pending: loss.pending.map(|p| (p.transmit.value(), p.exposed)),
        }
    }
}
#[derive(Debug)]
pub(super) struct TunFact {
    epoch: gnunet_tun_host::Epoch,
    pending: Option<(u64, usize)>,
    cause: &'static str,
    short: Option<(usize, usize)>,
}
impl TunFact {
    pub fn from_original(loss: &gnunet_tun_host::Loss) -> Self {
        use gnunet_tun_host::LossCause;
        let (cause, short) = match &loss.cause {
            LossCause::Io(_) => ("Io", None),
            LossCause::Eof => ("Eof", None),
            LossCause::ShortWrite { bytes, expected } => ("ShortWrite", Some((*bytes, *expected))),
            LossCause::WriteZero => ("WriteZero", None),
            LossCause::Closed => ("Closed", None),
            LossCause::Capacity => ("Capacity", None),
        };
        Self {
            epoch: loss.epoch.clone(),
            pending: loss
                .pending
                .as_ref()
                .map(|id| (id.diagnostic(), id.helper_accepted_prefix())),
            cause,
            short,
        }
    }
}
impl fmt::Display for TunFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "epoch={:?} pending={:?} original-cause={} short={:?}",
            self.epoch, self.pending, self.cause, self.short
        )
    }
}
#[derive(Debug)]
pub(super) struct Facts {
    pub native: coordinator::Report,
    pub ipc: server::Report,
    pub cadet: Option<CadetFact>,
    pub tun: Option<TunFact>,
    pub unconfirmed_control_closes: u64,
    pub debt: coordinator::Debt,
    pub regex: Option<crate::discovery::Report>,
    pub regex_pending: usize,
}
impl fmt::Display for Facts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cadet = self.cadet.map(|c| (c.epoch, c.channels, c.pending));
        write!(
            f,
            "VPN native={:?}; IPC={:?}; original CADET metadata={cadet:?}; unconfirmed-control-closes={}; current debt={:?}; REGEX={:?}; regex-pending={}; downstream processing unclaimed",
            self.native,
            self.ipc,
            self.unconfirmed_control_closes,
            self.debt,
            self.regex,
            self.regex_pending
        )?;
        if let Some(tun) = &self.tun {
            write!(f, "; original TUN={tun}")?;
        }
        Ok(())
    }
}
#[derive(Default)]
struct State {
    errors: [Option<Failure>; N],
    facts: Option<Facts>,
    helper: Option<gnunet_tun_host::helper::Report>,
}
#[derive(Clone, Default)]
pub(super) struct Cleanup(Rc<RefCell<State>>);
struct Failed {
    original: Option<Failure>,
    state: State,
}
impl fmt::Debug for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_display(f)
    }
}
impl Failed {
    fn fmt_display(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VPN original={:?}", self.original)?;
        for (name, error) in NAMES.iter().zip(&self.state.errors) {
            if let Some(error) = error {
                write!(f, "; {name}: {error}")?;
            }
        }
        if let Some(helper) = &self.state.helper {
            write!(f, "; original helper={helper:?}")?;
        }
        if let Some(facts) = &self.state.facts {
            write!(f, "; {facts}")?;
        }
        Ok(())
    }
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_display(f)
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.state.errors.iter().find_map(Option::as_deref))
            .or_else(|| {
                self.state
                    .helper
                    .as_ref()
                    .filter(|report| report.failed())
                    .map(|report| report as &(dyn std::error::Error + 'static))
            })
    }
}
impl Cleanup {
    pub fn helper(&self, report: gnunet_tun_host::helper::Report) {
        self.0.borrow_mut().helper = Some(report);
    }
    pub fn retain(&self, stage: Stage, error: Failure) {
        let mut state = self.0.borrow_mut();
        let slot = &mut state.errors[stage as usize];
        // Multiple independent actual cleanup failures keep both owned objects;
        // no formatting/string classification replaces or drops a cause.
        *slot = Some(match slot.take() {
            Some(first) => Box::new(Both { first, next: error }),
            None => error,
        });
    }
    pub fn facts(&self, facts: Facts) {
        self.0.borrow_mut().facts = Some(facts);
    }
    pub fn coordinator(&self, errors: coordinator::CleanupErrors) {
        if !errors.is_empty() {
            self.retain(Stage::Coordinator, Box::new(errors));
        }
    }
    pub fn output(&self) -> io::Result<()> {
        let state = self.0.borrow();
        let facts = state
            .facts
            .as_ref()
            .ok_or_else(|| io::Error::other("VPN original close facts missing"))?;
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "STOPPED vpn {facts}; helper={:?}; actual independent errors retained separately",
            state.helper
        )?;
        out.flush()
    }
    pub fn finish<T>(&self, result: Result<T, Failure>) -> Result<T, Failure> {
        let state = std::mem::take(&mut *self.0.borrow_mut());
        if result.is_ok()
            && state.errors.iter().all(Option::is_none)
            && state.helper.as_ref().is_none_or(|report| !report.failed())
        {
            result
        } else {
            Err(Box::new(Failed {
                original: result.err(),
                state,
            }))
        }
    }
}
#[derive(Debug)]
pub(super) struct TunLoss(pub gnunet_tun_host::Loss);
impl fmt::Display for TunLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "actual original TUN loss {:?}", self.0)
    }
}
impl std::error::Error for TunLoss {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0.cause {
            gnunet_tun_host::LossCause::Io(error) => Some(error),
            _ => self
                .0
                .close_error
                .as_ref()
                .map(|e| e as &dyn std::error::Error),
        }
    }
}
#[derive(Debug)]
pub(super) struct Qualification {
    pub expected: String,
    pub observed: String,
    pub loss: gnunet_tun_host::Loss,
}
impl fmt::Display for Qualification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "verified TUN {} differs from configured IFNAME {}; actual original close={:?}",
            self.observed, self.expected, self.loss
        )
    }
}
impl std::error::Error for Qualification {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.loss
            .close_error
            .as_ref()
            .map(|e| e as &dyn std::error::Error)
    }
}
