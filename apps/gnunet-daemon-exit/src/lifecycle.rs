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
    #[cfg(windows)]
    Readiness,
}
#[cfg(unix)]
const N: usize = 12;
#[cfg(windows)]
const N: usize = 13;
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
    #[cfg(windows)]
    "parent readiness notification",
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
    pub unremoved_routes: Vec<gnunet_tun_host::Action>,
    #[cfg(any(windows, target_os = "freebsd"))]
    pub recovery: crate::network::recovery::Report,
}
impl fmt::Debug for Facts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("Facts");
        out.field("native", &self.native)
            .field("quiescent", &self.quiescent)
            .field("regex", &self.regex)
            .field("unremoved_routes", &self.unremoved_routes);
        #[cfg(any(windows, target_os = "freebsd"))]
        out.field("recovery", &self.recovery);
        out.finish()
    }
}
#[derive(Default)]
struct State {
    errors: [Option<Failure>; N],
    facts: Option<Facts>,
    #[cfg(unix)]
    helper: Option<gnunet_tun_host::helper::Report>,
    dns_advertisement: Option<crate::dns_advertisement::Report>,
    packet_close: Option<gnunet_tun_host::Loss>,
}
impl State {
    fn helper_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[cfg(unix)]
        {
            self.helper
                .as_ref()
                .filter(|report| report.failed())
                .map(|report| report as &(dyn std::error::Error + 'static))
        }
        #[cfg(windows)]
        {
            None
        }
    }
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
            "EXIT original={:?}; facts={:?}; DNS advertisement={:?}; packet close={:?}",
            self.original, self.state.facts, self.state.dns_advertisement, self.state.packet_close
        )?;
        #[cfg(unix)]
        write!(f, "; helper={:?}", self.state.helper)?;
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
            .or_else(|| self.state.helper_failure())
    }
}
impl Cleanup {
    pub fn packet_close(&self, loss: gnunet_tun_host::Loss) {
        self.0.borrow_mut().packet_close = Some(loss);
    }
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
    #[cfg(unix)]
    pub fn helper(&self, report: gnunet_tun_host::helper::Report) {
        self.0.borrow_mut().helper = Some(report);
    }
    pub fn output(&self) -> std::io::Result<()> {
        use std::io::Write;
        let s = self.0.borrow();
        let mut out = std::io::stdout().lock();
        write!(
            out,
            "STOPPED exit facts={:?}; DNS advertisement={:?}; packet close={:?}",
            s.facts, s.dns_advertisement, s.packet_close
        )?;
        #[cfg(unix)]
        write!(out, "; helper={:?}", s.helper)?;
        writeln!(
            out,
            "; independent causes retained; remote processing unclaimed"
        )?;
        out.flush()
    }
    pub fn finish<T>(&self, result: Result<T, Failure>) -> Result<T, Failure> {
        let state = std::mem::take(&mut *self.0.borrow_mut());
        if result.is_ok()
            && state.errors.iter().all(Option::is_none)
            && state.helper_failure().is_none()
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
