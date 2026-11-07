//! Selected PROGRAM logger with once-only actual Ready output.
use crate::{Event, tls::Profile};
use gnunet_program_host::{logging::Logger, policy::Level, service, shared_clock::SharedClock};
use std::{
    io::{self, Write},
    net::SocketAddr,
};
pub(super) struct Reports {
    logger: Logger<'static>,
    clock: SharedClock,
    profile: Profile,
    first: Option<io::Error>,
    ready: bool,
    bound: Option<SocketAddr>,
}
impl Reports {
    pub fn new(logger: Logger<'static>, clock: SharedClock, profile: Profile) -> Self {
        Self {
            logger,
            clock,
            profile,
            first: None,
            ready: false,
            bound: None,
        }
    }
    pub fn failed(&self) -> bool {
        self.first.is_some()
    }
    pub fn take_failure(&mut self) -> Option<io::Error> {
        self.first.take()
    }
    fn retain(&mut self, result: io::Result<()>) {
        if self.first.is_none() {
            self.first = result.err()
        }
    }
    pub fn log(&mut self, site: &'static str, level: Level, args: std::fmt::Arguments<'_>) {
        if self.first.is_some() {
            return;
        }
        let result = service::diagnostic(&mut self.logger, &self.clock, site, level, args);
        self.retain(result)
    }
    pub fn event(&mut self, event: Event<'_>) {
        match &event {
            Event::Bound { address, .. } => {
                self.bound = Some(*address);
                self.log("quic.bound", Level::INFO, format_args!("{event:?}"))
            }
            Event::Ready { .. } => {
                if !self.ready && !self.failed() {
                    let profile = match self.profile {
                        Profile::Raw => "quic",
                        Profile::Http3 => "http3",
                    };
                    let result = (|| {
                        let mut out = io::stdout().lock();
                        writeln!(
                            out,
                            "READY communicator-{profile} address={:?} transport=registration-written pils=actual-public-identity peer-proposals=unauthenticated",
                            self.bound
                        )?;
                        out.flush()
                    })();
                    self.retain(result);
                    if !self.failed() {
                        self.ready = true
                    }
                }
                self.log("quic.ready", Level::INFO, format_args!("{event:?}"));
            }
            Event::Rejected(_) | Event::NatEnded(_) | Event::IdentityEnded { .. } => {
                self.log("quic.refused", Level::WARNING, format_args!("{event:?}"))
            }
            Event::ReversalUnsupported | Event::Unsupported => self.log(
                "quic.unsupported",
                Level::WARNING,
                format_args!("{event:?}"),
            ),
            Event::TransportLost { .. } => self.log(
                "quic.transport.lost",
                Level::WARNING,
                format_args!("{event:?}"),
            ),
            Event::TransportAttached { .. }
            | Event::TransportRegistered { .. }
            | Event::TransportRestored { .. } => self.log(
                "quic.transport.recovery",
                Level::INFO,
                format_args!("{event:?}"),
            ),
            Event::TransportOutputRetired { .. } | Event::IncomingRetired { .. } => self.log(
                "quic.transport.retired",
                Level::DEBUG,
                format_args!("{event:?}"),
            ),
            Event::Identity { .. }
            | Event::IdentityRetiring { .. }
            | Event::IdentityRestored { .. }
            | Event::IdentityDriverRetired { .. }
            | Event::Attached(_) => {
                self.log("quic.identity", Level::INFO, format_args!("{event:?}"))
            }
            Event::QueueRetired { .. } | Event::SendRetired { .. } => {
                self.log("quic.retired", Level::DEBUG, format_args!("{event:?}"))
            }
            _ => {}
        }
    }
    pub fn stopped<R: std::fmt::Debug>(
        &mut self,
        closed: &crate::Closed,
        metrics: crate::metrics::Metrics,
        statistics: Option<&R>,
    ) {
        self.log(
            "quic.stopped",
            Level::INFO,
            format_args!("original source closed: {closed:?}"),
        );
        if self.failed() {
            return;
        }
        let result = (|| {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "STOPPED communicator-{} ready-observed={} incoming-lost={} sends-retired={} original-sources=retired remote-delivery=not-claimed metrics={:?} statistics={:?}",
                match self.profile {
                    Profile::Raw => "quic",
                    Profile::Http3 => "http3",
                },
                self.ready,
                closed.incoming_lost,
                closed.sends_retired,
                metrics,
                statistics
            )?;
            out.flush()
        })();
        self.retain(result)
    }
}
