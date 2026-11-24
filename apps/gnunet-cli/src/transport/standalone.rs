//! The installed virtual-link listing and its two text output formats.

use super::{Command, Failure, Query, Request, Style, run_program};
use gnunet::wire::transport_monitor::Link;
use gnunet_program_host::{
    diagnostics::{peer_full, peer_short, relative_time},
    getopt::Options,
    helpers::{self, Target},
};
use std::{
    borrow::Cow,
    ffi::OsStr,
    fmt,
    io::{self, Write},
    time::Duration,
};

const BINARY: &[u8] = b"gnunet-transport";

struct Arguments {
    all: Target<i32>,
    peer: Target<Option<Vec<u8>>>,
    verbose: Target<i32>,
}

impl Arguments {
    fn new() -> Self {
        Self {
            all: Target::new(0),
            peer: Target::new(None),
            verbose: Target::new(0),
        }
    }

    fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::flag(
            b'a',
            b"all",
            b"Include virtual links that are not established yet",
            self.all.clone(),
        ));
        options.add(helpers::string(
            b'p',
            b"peer",
            b"PEERID",
            b"Show only the link to the selected peer",
            self.peer.clone(),
        ));
        options.add(helpers::flag(
            b'V',
            b"verbose",
            b"Show the full flow-control state of each link",
            self.verbose.clone(),
        ));
        options
    }

    fn request(&self, positional: &[Vec<u8>]) -> Result<Request, Failure> {
        if !positional.is_empty() {
            return Err("gnunet-transport takes no positional arguments".into());
        }
        let peer = self
            .peer
            .get()?
            .map(|bytes| {
                if bytes.len() != 52 {
                    return Err("expected a 52-character GNUnet peer identity".into());
                }
                crate::peer::parse(OsStr::new(std::str::from_utf8(&bytes)?))
            })
            .transpose()?
            .unwrap_or([0; 32]);
        Ok(Request {
            command: Command {
                query: Query::Links {
                    include_unconfirmed: self.all.get()? != 0,
                    peer,
                },
                continuous: false,
                duration: Duration::from_secs(30),
                style: Style::Links {
                    verbose: self.verbose.get()? != 0,
                },
            },
            unix: None,
        })
    }
}

pub(crate) fn run() -> Result<(), Failure> {
    let arguments = Arguments::new();
    run_program(
        BINARY,
        BINARY,
        b"Print information about the virtual links of the configured TRANSPORT service.",
        arguments.options(),
        std::env::args_os(),
        |positional| arguments.request(positional),
    )
}

fn column(out: &mut impl Write, value: &[u8], width: usize, right: bool) -> io::Result<()> {
    const SPACES: [u8; 14] = [b' '; 14];
    let padding = &SPACES[..width.saturating_sub(value.len())];
    if right {
        out.write_all(padding)?;
    }
    out.write_all(value)?;
    if !right {
        out.write_all(padding)?;
    }
    Ok(())
}

struct ByteSize(u64);
impl fmt::Display for ByteSize {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut size = self.0;
        let mut unit = "b";
        for next in ["KiB", "MiB", "GiB", "TiB"] {
            if size <= 5 * 1024 {
                break;
            }
            size /= 1024;
            unit = next;
        }
        write!(out, "{size} {unit}")
    }
}

pub(super) fn link(
    out: &mut impl Write,
    link: Link<'_>,
    first: bool,
    verbose: bool,
    now: u64,
) -> io::Result<()> {
    let route = if link.route == 0 {
        Cow::Borrowed("direct")
    } else {
        Cow::Owned(format!("dv ({} hops)", u64::from(link.distance) + 2))
    };
    let via = if link.communicators.is_empty() {
        b"-"
    } else {
        link.communicators
    };
    let rtt = relative_time(link.flow_rtt, true);
    if verbose {
        out.write_all(&peer_full(&link.target))?;
        write!(out, "\n  routed:                {route} over ")?;
        out.write_all(via)?;
        writeln!(out, " ({} queue(s))", link.queues)?;
        writeln!(
            out,
            "  established:           {}",
            if link.confirmed { "yes" } else { "no" }
        )?;
        writeln!(out, "  CORE receive window:   {}", link.core_receive_window)?;
        writeln!(out, "  stalled for CORE:      {} message(s)", link.stalled)?;
        writeln!(out, "  pending transmission:  {} message(s)", link.pending)?;
        writeln!(
            out,
            "  inbound window used:   {} of {}",
            ByteSize(link.incoming_used),
            ByteSize(link.incoming_window)
        )?;
        writeln!(
            out,
            "  outbound window used:  {} of {}",
            ByteSize(link.outbound_used),
            ByteSize(link.outbound_window)
        )?;
        writeln!(
            out,
            "  buffer used:           {} of {}",
            ByteSize(link.incoming_ram),
            ByteSize(link.available_window)
        )?;
        writeln!(
            out,
            "  estimated loss:        {} byte(s)",
            link.incoming_loss
        )?;
        out.write_all(b"  flow control RTT:      ")?;
        out.write_all(&rtt)?;
        out.write_all(b" (peer reports ")?;
        out.write_all(&relative_time(link.other_rtt, true))?;
        out.write_all(b")\n  last flow control:     ")?;
        out.write_all(&relative_time(
            now.saturating_sub(link.last_flow_transmission),
            true,
        ))?;
        return writeln!(
            out,
            " ago ({} retransmission(s))\n",
            link.flow_retransmissions
        );
    }
    if first {
        writeln!(
            out,
            "{:<10} {:<14} {:<12} {:>9} {:>8} {:>8} {:>10}",
            "PEER", "ROUTE", "VIA", "CORE-WIN", "STALLED", "PENDING", "RTT"
        )?;
    }
    column(out, &peer_short(Some(&link.target)), 10, false)?;
    out.write_all(b" ")?;
    column(out, route.as_bytes(), 14, false)?;
    out.write_all(b" ")?;
    column(out, via, 12, false)?;
    write!(
        out,
        " {:>9} {:>8} {:>8} ",
        link.core_receive_window, link.stalled, link.pending
    )?;
    column(out, &rtt, 10, true)?;
    out.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn official_transport_flags_select_the_virtual_link_request() -> Result<(), Failure> {
        let arguments = Arguments::new();
        let peer = [0x32; 32];
        let public = peer_full(&peer);
        let argv = ["gnunet-transport", "-aVp", std::str::from_utf8(&public)?].map(OsString::from);
        let parsed = arguments.options().run(BINARY, argv, false);
        let request = arguments.request(parsed.remaining().ok_or("options did not parse")?)?;
        if !matches!(
            request.command.query,
            Query::Links {
                include_unconfirmed: true,
                peer: actual,
            } if actual == peer
        ) || !matches!(request.command.style, Style::Links { verbose: true })
            || request.command.continuous
            || request.unix.is_some()
        {
            return Err("transport flags did not select the expected one-shot link query".into());
        }
        Ok(())
    }
}
