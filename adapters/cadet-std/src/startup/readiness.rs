//! One readiness announcement for the original process or embedded supervisor.
use super::{Ready, control::Signals, reports::Reports};
use gnunet_program_host::{policy::Level, reporting::Reporter, service::native::Readiness};
use std::{
    error::Error,
    future::poll_fn,
    io::{self, Write},
    task::Poll,
};

pub(super) enum Destination<'a> {
    Process(Readiness<'a>, Reporter),
    Embedded(&'a mut dyn FnMut(Ready) -> io::Result<()>),
}

pub(super) struct Announcement<'a> {
    destination: Option<Destination<'a>>,
    reports: Reports,
}

impl<'a> Announcement<'a> {
    pub(super) fn new(destination: Destination<'a>, reports: Reports) -> Self {
        Self {
            destination: Some(destination),
            reports,
        }
    }

    pub(super) fn waits_for_core(&self) -> bool {
        matches!(self.destination, Some(Destination::Embedded(_)))
    }

    pub(super) async fn announce(
        &mut self,
        peer: [u8; 32],
        payload: Option<usize>,
        signals: &mut Signals<'_>,
    ) -> Result<(), Box<dyn Error>> {
        let Some(destination) = self.destination.take() else {
            return Ok(());
        };
        match destination {
            Destination::Process(readiness, reporter) => {
                if signals.requested() {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "CADET stopped before readiness",
                    )
                    .into());
                }
                self.announce_process(peer, payload)?;
                readiness.signal(signals.process()?, &reporter).await?;
            }
            Destination::Embedded(notify) => {
                let stopping = poll_fn(|cx| Poll::Ready(signals.poll(cx))).await;
                match stopping {
                    Poll::Ready(result) => result?,
                    Poll::Pending => notify(Ready { peer })?,
                }
            }
        }
        Ok(())
    }

    fn announce_process(&self, peer: [u8; 32], payload: Option<usize>) -> io::Result<()> {
        if self.reports.failed() {
            return Err(io::Error::other(
                "CADET actual selected logger failed before readiness; original error retained",
            ));
        }
        self.reports.message(
            Level::INFO,
            "cadet.ready",
            format_args!(
                "CADET actual verified PILS identity and {} owner ready",
                if payload.is_some() {
                    "CORE/PILS/Node"
                } else {
                    "local Server"
                }
            ),
        );
        if self.reports.failed() {
            return Err(io::Error::other(
                "CADET selected readiness diagnostic failed; original error retained",
            ));
        }
        let mut out = io::stdout().lock();
        write!(out, "READY cadet peer=")?;
        for byte in peer {
            write!(out, "{byte:02x}")?;
        }
        if let Some(bytes) = payload {
            writeln!(
                out,
                " peer-backend=core-direct monitoring=peers-tunnels-path-tunnel payload-pool-bytes={bytes}"
            )?;
        } else {
            writeln!(out, " peer-backend=unavailable monitoring=unsupported")?;
        }
        out.flush()
    }
}
