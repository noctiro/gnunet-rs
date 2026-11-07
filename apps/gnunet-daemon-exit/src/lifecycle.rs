//! Bounded independent owned terminal causes and actual original cleanup facts.
use crate::Failure;
use std::{cell::RefCell, fmt, rc::Rc};
#[derive(Clone, Copy)]
pub(super) enum Stage {
    Shutdown,
    Resolver,
    Watch,
    Routes,
    Drain,
    Output,
    Logging,
    Tun,
    Constructor,
    Entropy,
    Debt,
    Advertisement,
}
const N: usize = 12;
const NAMES: [&str; N] = [
    "shutdown",
    "Resolver",
    "IPv6 observer",
    "route cleanup",
    "native drain",
    "output",
    "selected Logger",
    "original packet source",
    "construction cleanup",
    "entropy",
    "unsettled original debt",
    "DNS advertisement cleanup",
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
pub(super) struct Facts {
    pub native: gnunet_exit_host::runtime::Report,
    pub quiescent: bool,
    pub regex: crate::announcement::Report,
    pub unremoved_routes: usize,
}
impl fmt::Debug for Facts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Facts")
            .field("native", &self.native)
            .field("quiescent", &self.quiescent)
            .field("regex", &self.regex)
            .field("unremoved_routes", &self.unremoved_routes)
            .finish()
    }
}
#[derive(Default)]
struct State {
    errors: [Option<Failure>; N],
    facts: Option<Facts>,
    helper: Option<gnunet_tun_host::helper::Report>,
    dns_advertisement: Option<crate::dns_advertisement::Report>,
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
        write!(
            f,
            "EXIT original={:?}; facts={:?}; helper={:?}; DNS advertisement={:?}",
            self.original, self.state.facts, self.state.helper, self.state.dns_advertisement
        )?;
        for (name, error) in NAMES.iter().zip(&self.state.errors) {
            if let Some(error) = error {
                write!(f, "; {name}: {error}")?;
            }
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
                    .filter(|p| p.failed())
                    .map(|p| p as &dyn std::error::Error)
            })
    }
}
impl Cleanup {
    pub fn retain(&self, stage: Stage, error: Failure) {
        let mut s = self.0.borrow_mut();
        let slot = &mut s.errors[stage as usize];
        *slot = Some(match slot.take() {
            Some(first) => Box::new(Both { first, next: error }),
            None => error,
        });
    }
    pub fn facts(&self, facts: Facts) {
        self.0.borrow_mut().facts = Some(facts);
    }
    pub fn dns_advertisement(&self, report: crate::dns_advertisement::Report) {
        self.0.borrow_mut().dns_advertisement = Some(report);
    }
    pub fn helper(&self, report: gnunet_tun_host::helper::Report) {
        self.0.borrow_mut().helper = Some(report);
    }
    pub fn output(&self) -> std::io::Result<()> {
        use std::io::Write;
        let s = self.0.borrow();
        let mut out = std::io::stdout().lock();
        writeln!(
            out,
            "STOPPED exit facts={:?}; helper={:?}; DNS advertisement={:?}; independent causes retained; remote processing unclaimed",
            s.facts, s.helper, s.dns_advertisement
        )?;
        out.flush()
    }
    pub fn finish<T>(&self, result: Result<T, Failure>) -> Result<T, Failure> {
        let state = std::mem::take(&mut *self.0.borrow_mut());
        if result.is_ok()
            && state.errors.iter().all(Option::is_none)
            && state.helper.as_ref().is_none_or(|p| !p.failed())
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
        write!(f, "original EXIT packet-source loss: {:?}", self.0)
    }
}
impl std::error::Error for TunLoss {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0.cause {
            gnunet_tun_host::LossCause::Io(e) => Some(e),
            _ => self
                .0
                .close_error
                .as_ref()
                .map(|e| e as &dyn std::error::Error),
        }
    }
}
#[derive(Debug)]
pub(super) struct CancelledRoute(pub gnunet_tun_host::RouteProgress);
impl fmt::Display for CancelledRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original EXIT route cancellation: {:?}", self.0)
    }
}
impl std::error::Error for CancelledRoute {}
#[derive(Debug)]
pub(super) struct CancelledWatch(pub gnunet_tun_host::Ipv6Progress);
impl fmt::Display for CancelledWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original EXIT observer cancellation: {:?}", self.0)
    }
}
impl std::error::Error for CancelledWatch {}
