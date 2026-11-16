//! Numeric FreeBSD14 pfctl state records. Selection precedes every mutation;
//! unknown/truncated target records refuse the whole snapshot.
use std::{fmt, io, net::IpAddr};
const MAX_TARGETS: usize = 4096;
const MAX_LINE_BYTES: usize = 2048;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Id {
    state: u64,
    creator: u32,
}
impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}/{:08x}", self.state, self.creator)
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or incomplete numeric PF state record",
    )
}
fn endpoint(value: &str) -> io::Result<(IpAddr, u16)> {
    let (host, port) =
        if let Some((host, port)) = value.strip_suffix(']').and_then(|v| v.rsplit_once('[')) {
            (host, port)
        } else {
            value.rsplit_once(':').ok_or_else(invalid)?
        };
    Ok((
        host.parse().map_err(|_| invalid())?,
        port.parse().map_err(|_| invalid())?,
    ))
}
fn host<'a>(
    tokens: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) -> io::Result<(IpAddr, u16)> {
    let wire = endpoint(tokens.next().ok_or_else(invalid)?)?;
    if !tokens.peek().is_some_and(|token| token.starts_with('(')) {
        return Ok(wire);
    }
    let value = tokens.next().ok_or_else(invalid)?;
    endpoint(
        value
            .strip_prefix('(')
            .and_then(|v| v.strip_suffix(')'))
            .ok_or_else(invalid)?,
    )
}
fn selected(line: &str, local: &[IpAddr]) -> io::Result<bool> {
    let mut tokens = line.split_ascii_whitespace().peekable();
    let first = tokens.next().ok_or_else(invalid)?;
    let protocol = if matches!(first, "udp" | "17") {
        first
    } else {
        tokens.next().ok_or_else(invalid)?
    };
    if !matches!(protocol, "udp" | "17") {
        return Ok(false);
    }
    // A parenthesized endpoint is the stack-side address before NAT. A
    // forwarded flow with a local NAT gateway is not a locally originated flow.
    let source = host(&mut tokens)?;
    let direction = tokens.next().ok_or_else(invalid)?;
    if direction == "<-" {
        return Ok(false);
    }
    if direction != "->" {
        return Err(invalid());
    }
    let destination = host(&mut tokens)?;
    if !tokens.next().is_some_and(|value| value.contains(':')) {
        return Err(invalid());
    }
    Ok(local.contains(&source.0)
        && !matches!(source.0, IpAddr::V6(address) if address.is_unicast_link_local())
        && destination.1 == 53)
}
fn id(line: &str) -> io::Result<Id> {
    let mut tokens = line.split_ascii_whitespace();
    if tokens.next() != Some("id:") {
        return Err(invalid());
    }
    let state = tokens.next().ok_or_else(invalid)?;
    if state.len() != 16
        || !state.bytes().all(|b| b.is_ascii_hexdigit())
        || tokens.next() != Some("creatorid:")
    {
        return Err(invalid());
    }
    let creator = tokens.next().ok_or_else(invalid)?;
    if creator.len() != 8 || !creator.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let id = Id {
        state: u64::from_str_radix(state, 16).map_err(|_| invalid())?,
        creator: u32::from_str_radix(creator, 16).map_err(|_| invalid())?,
    };
    Ok(id)
}
pub(super) enum Selection {
    Dns(Vec<IpAddr>),
    Original(Vec<Id>),
}
enum Record {
    Other,
    Awaiting,
    Complete,
    Closed,
}
pub(super) struct Parser {
    selection: Selection,
    line: Vec<u8>,
    targets: Vec<Id>,
    record: Record,
}
impl Parser {
    pub fn new(selection: Selection) -> io::Result<Self> {
        let mut line = Vec::new();
        line.try_reserve_exact(MAX_LINE_BYTES)
            .map_err(io::Error::other)?;
        Ok(Self {
            selection,
            line,
            targets: Vec::new(),
            record: Record::Other,
        })
    }
    pub fn feed(&mut self, bytes: &[u8]) -> io::Result<()> {
        if matches!(self.record, Record::Closed) {
            return Err(invalid());
        }
        for part in bytes.split_inclusive(|b| *b == b'\n') {
            let end = part.last() == Some(&b'\n');
            let part = if end { &part[..part.len() - 1] } else { part };
            if part.len() > MAX_LINE_BYTES.saturating_sub(self.line.len()) {
                return Err(invalid());
            }
            self.line.extend_from_slice(part);
            if end {
                parse_line(
                    &self.line,
                    &self.selection,
                    &mut self.record,
                    &mut self.targets,
                )?;
                self.line.clear();
            }
        }
        Ok(())
    }
    pub fn close(&mut self) -> io::Result<()> {
        if !self.line.is_empty() || matches!(self.record, Record::Awaiting | Record::Closed) {
            return Err(invalid());
        }
        self.targets.sort_unstable();
        if self.targets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid());
        }
        self.record = Record::Closed;
        Ok(())
    }
    pub fn into_targets(self) -> io::Result<Vec<Id>> {
        if !matches!(self.record, Record::Closed) {
            return Err(invalid());
        }
        Ok(self.targets)
    }
}
fn parse_line(
    bytes: &[u8],
    selection: &Selection,
    record: &mut Record,
    targets: &mut Vec<Id>,
) -> io::Result<()> {
    let line = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    if line.contains('\0') {
        return Err(invalid());
    }
    if line.trim().is_empty() {
        return Ok(());
    }
    let first = line.split_ascii_whitespace().next().ok_or_else(invalid)?;
    let header = !line.as_bytes()[0].is_ascii_whitespace()
        || line.contains(" -> ")
        || line.contains(" <- ")
        || matches!(first, "udp" | "17");
    if header {
        if matches!(record, Record::Awaiting) {
            return Err(invalid());
        }
        let keep = match selection {
            Selection::Dns(local) => selected(line, local)?,
            Selection::Original(_) => {
                if !line.contains(" -> ") && !line.contains(" <- ") {
                    return Err(invalid());
                }
                true
            }
        };
        *record = if keep {
            Record::Awaiting
        } else {
            Record::Other
        };
    } else if matches!(record, Record::Awaiting | Record::Complete) {
        if line.trim_start().starts_with("id:") {
            if matches!(record, Record::Complete) {
                return Err(invalid());
            }
            let id = id(line)?;
            let keep = match selection {
                Selection::Dns(_) => {
                    // Creator0 is pfctl's wildcard and cannot authorize a kill.
                    if id.state == 0 || id.creator == 0 {
                        return Err(invalid());
                    }
                    true
                }
                Selection::Original(original) => original.binary_search(&id).is_ok(),
            };
            if keep {
                if targets.len() == MAX_TARGETS {
                    return Err(invalid());
                }
                targets.try_reserve(1).map_err(io::Error::other)?;
                targets.push(id);
            }
            *record = Record::Complete;
        } else if matches!(selection, Selection::Dns(_)) && !line.trim_start().starts_with("age ") {
            return Err(invalid());
        }
    }
    Ok(())
}
#[cfg(test)]
fn dns(bytes: &[u8], local: &[IpAddr]) -> io::Result<Vec<Id>> {
    let mut parser = Parser::new(Selection::Dns(local.to_vec()))?;
    parser.feed(bytes)?;
    parser.close()?;
    parser.into_targets()
}

#[cfg(test)]
mod tests;
