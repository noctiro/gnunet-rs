//! Selected diagnostics and local READY output, separate from native notification.
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_transport_service_host::foreground::{Notice, Reports};
use std::io::{self, Write};
pub(super) fn notices(
    reports: Reporter,
    mut ready: impl FnMut() -> io::Result<()> + 'static,
) -> Reports {
    Reports::new(move |notice| match notice {
        Notice::Ready { peer } => {
            reports.message(
                Level::INFO,
                "transport.ready",
                format_args!("TRANSPORT actual Owner ready: {peer:?}"),
            );
            selected(&reports)?;
            let mut output = io::stdout().lock();
            write!(output, "READY ")?;
            for byte in peer.0 {
                write!(output, "{byte:02x}")?;
            }
            writeln!(output)?;
            output.flush()?;
            ready()
        }
        Notice::Diagnostic {
            level,
            site,
            message,
        } => {
            reports.message(level, site, message);
            selected(&reports)
        }
    })
}
fn selected(reports: &Reporter) -> io::Result<()> {
    if let Some(cause) = reports.take_error() {
        return Err(cause);
    }
    if reports.failed() {
        return Err(io::Error::other(
            "TRANSPORT selected diagnostics already failed",
        ));
    }
    Ok(())
}
