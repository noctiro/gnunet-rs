//! One verified local/node startup announcement and its original parent status.
use crate::control::Signals;
use gnunet_program_host::{policy::Level, reporting::Reporter, service::native::Readiness};
use std::{
    error::Error,
    io::{self, Write},
};

/// Exactly one real local-Server/peer-Node readiness announcement. Constructed
/// only in the serving process; the original startup capability is never cloned.
pub(super) struct Ready<'a> {
    state: State<'a>,
    reporter: Reporter,
}
enum State<'a> {
    Pending(Readiness<'a>),
    Consumed,
    Submitted,
}
impl<'a> Ready<'a> {
    pub(super) fn new(original: Readiness<'a>, reporter: Reporter) -> Self {
        Self {
            state: State::Pending(original),
            reporter,
        }
    }
    pub(super) async fn announce(
        &mut self,
        peer: [u8; 32],
        payload: Option<usize>,
        signals: &mut Signals,
    ) -> Result<(), Box<dyn Error>> {
        if matches!(self.state, State::Submitted) {
            return Ok(());
        }
        if signals.requested() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "CADET stopped before readiness",
            )
            .into());
        }
        let State::Pending(original) = std::mem::replace(&mut self.state, State::Consumed) else {
            return Err(io::Error::other("CADET original readiness already consumed").into());
        };
        if self.reporter.failed() {
            return Err(io::Error::other(
                "CADET actual selected logger failed before readiness; original error retained",
            )
            .into());
        }
        self.reporter.message(
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
        if self.reporter.failed() {
            return Err(io::Error::other(
                "CADET selected readiness diagnostic failed; original error retained",
            )
            .into());
        }
        {
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
            out.flush()?;
        }
        original.signal(signals, &self.reporter).await?;
        self.state = State::Submitted;
        Ok(())
    }
}
