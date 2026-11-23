//! Original standalone readiness/control or a caller's embedded lifecycle.
use super::{Cause, Ready, Settings};
use crate::Report;
use gnunet_program_host::{reporting::Reporter, service::acknowledge_ready};
use gnunet_service_startup::StopSignals;
use std::{
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Clone, Copy)]
pub(super) struct Reports<'a>(Option<&'a Reporter>);

impl Reports<'_> {
    pub(super) fn register(self, cx: &Context<'_>) {
        if let Some(reporter) = self.0 {
            reporter.register(cx);
        }
    }

    pub(super) fn failed(self) -> bool {
        self.0.is_some_and(Reporter::failed)
    }

    #[track_caller]
    pub(super) fn debug(self, site: &'static str, args: fmt::Arguments<'_>) {
        if let Some(reporter) = self.0 {
            reporter.debug(site, args);
        }
    }

    #[track_caller]
    pub(super) fn warning(self, site: &'static str, args: fmt::Arguments<'_>) {
        if let Some(reporter) = self.0 {
            reporter.warning(site, args);
        }
    }

    pub(super) fn take_error(self) -> Option<io::Error> {
        self.0.and_then(Reporter::take_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn embedded_stop_is_consumed_before_native_drain() -> Result<(), Cause> {
        let mut source = std::pin::pin!(std::future::ready(Ok(())));
        let mut notify = |_| Err(io::Error::other("unexpected readiness"));
        let mut mode = Mode::Embedded {
            stop: Some(source.as_mut()),
            notify: &mut notify,
        };
        if !mode.stopping().await? || mode.stopping().await? {
            return Err("DHT stop was not observed exactly once".into());
        }
        Ok(())
    }
}

pub(super) enum Mode<'a> {
    Process {
        signals: StopSignals,
        reports: &'a Reporter,
        notify: Pin<&'a mut dyn Future<Output = Result<(), Cause>>>,
    },
    Embedded {
        stop: Option<Pin<&'a mut dyn Future<Output = io::Result<()>>>>,
        notify: &'a mut dyn FnMut(Ready) -> io::Result<()>,
    },
}

impl<'a> Mode<'a> {
    pub(super) fn reports(&self) -> Reports<'a> {
        Reports(match self {
            Self::Process { reports, .. } => Some(reports),
            Self::Embedded { .. } => None,
        })
    }

    pub(super) fn poll_stop(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Cause>> {
        match self {
            Self::Process { signals, .. } => signals
                .poll_stop(cx)
                .map_err(|error| Box::new(error) as Cause),
            Self::Embedded { stop, .. } => {
                let Some(future) = stop.as_mut() else {
                    return Poll::Pending;
                };
                match future.as_mut().poll(cx) {
                    Poll::Ready(result) => {
                        *stop = None;
                        Poll::Ready(result.map_err(Into::into))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    pub(super) async fn stopping(&mut self) -> Result<bool, Cause> {
        let reports = self.reports();
        poll_fn(|cx| {
            reports.register(cx);
            Poll::Ready(if reports.failed() {
                Ok(true)
            } else {
                match self.poll_stop(cx) {
                    Poll::Ready(result) => result.map(|()| true),
                    Poll::Pending => Ok(false),
                }
            })
        })
        .await
    }

    pub(super) async fn announce(
        &mut self,
        peer: Ready,
        count: usize,
        settings: &Settings,
    ) -> Result<(), Cause> {
        match self {
            Self::Embedded { notify, .. } => Ok(notify(peer)?),
            Self::Process {
                signals,
                reports,
                notify,
            } => {
                {
                    let mut out = io::stdout().lock();
                    write!(out, "READY dht peer=")?;
                    for byte in peer.peer {
                        write!(out, "{byte:02x}")?;
                    }
                    writeln!(
                        out,
                        " wire=0.29.1 listeners={count} core-underlay={} ip-underlay={}",
                        settings.native.underlays.gnunet,
                        settings.native.underlays.ip.is_some()
                    )?;
                    out.flush()?;
                }
                acknowledge_ready(notify.as_mut(), signals, reports, settings.shutdown_grace).await
            }
        }
    }

    pub(super) fn stopped(&self, report: &Report) -> io::Result<()> {
        if matches!(self, Self::Process { .. }) {
            let mut out = io::stdout().lock();
            writeln!(out, "STOPPED dht original={report:?}")?;
            out.flush()?;
        }
        Ok(())
    }
}
