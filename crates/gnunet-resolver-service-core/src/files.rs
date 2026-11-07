//! Exact byte-line machine-file input without opening files or doing NSS/DNS I/O.
use core::net::IpAddr;

struct Lines<'a> {
    remaining: &'a [u8],
}
impl<'a> Lines<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
}
impl<'a> Iterator for Lines<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        // Original strchr stops at the first embedded NUL. Do not process this
        // or later lines, nor scan outside the actual file to find a newline.
        let end = self.remaining.iter().position(|b| *b == b'\n' || *b == 0)?;
        if self.remaining[end] == 0 {
            self.remaining = &[];
            return None;
        }
        let line = &self.remaining[..end];
        self.remaining = &self.remaining[end + 1..];
        Some(line)
    }
}
/// One retained native resolver-file field; no normalization is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverField<'a> {
    /// Exact suffix after the literal case-sensitive `nameserver ` prefix.
    NameServer(&'a [u8]),
    /// Entire suffix of the first literal `search ` line, not a domain list.
    Search(&'a [u8]),
}
/// Iterate native resolver settings, ignoring the final unterminated line.
pub struct ResolverFile<'a> {
    lines: Lines<'a>,
    saw_search: bool,
}
impl<'a> ResolverFile<'a> {
    /// Borrow a complete input file; no system file or hostname is consulted.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            lines: Lines::new(bytes),
            saw_search: false,
        }
    }
}
impl<'a> Iterator for ResolverFile<'a> {
    type Item = ResolverField<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        for line in self.lines.by_ref() {
            if let Some(value) = line.strip_prefix(b"nameserver ") {
                return Some(ResolverField::NameServer(value));
            }
            if !self.saw_search
                && let Some(value) = line.strip_prefix(b"search ")
            {
                self.saw_search = true;
                return Some(ResolverField::Search(value));
            }
        }
        None
    }
}
/// One independent hosts alias, in original parse order. The service prepends
/// each entry, so the final occurrence becomes the first matching alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Host<'a> {
    /// One numeric V4/V6 address; there is no port or reverse record.
    pub address: IpAddr,
    /// Exact raw alias bytes, without case/UTF8 normalization.
    pub alias: &'a [u8],
}
fn token<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
    let start = bytes.iter().position(|b| *b != b' ' && *b != b'\t')?;
    let rest = &bytes[start..];
    let end = rest
        .iter()
        .position(|b| *b == b' ' || *b == b'\t')
        .unwrap_or(rest.len());
    *bytes = &rest[end..];
    Some(&rest[..end])
}
/// Iterate native hosts aliases using the explicit ASCII/C whitespace profile.
/// Comments end at the last '#'; tokens after leading whitespace use only
/// space/tab, so trailing CR is retained in alias bytes as the C source does.
pub struct HostsFile<'a> {
    lines: Lines<'a>,
    aliases: &'a [u8],
    address: Option<IpAddr>,
}
impl<'a> HostsFile<'a> {
    /// Borrow complete machine-file bytes without allocation or file access.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            lines: Lines::new(bytes),
            aliases: &[],
            address: None,
        }
    }
}
impl<'a> Iterator for HostsFile<'a> {
    type Item = Host<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(address) = self.address
                && let Some(alias) = token(&mut self.aliases)
            {
                return Some(Host { address, alias });
            }
            let mut line = self.lines.next()?;
            if let Some(comment) = line.iter().rposition(|b| *b == b'#') {
                line = &line[..comment];
            }
            let first = line
                .iter()
                .position(|b| !matches!(*b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
                .unwrap_or(line.len());
            line = &line[first..];
            let Some(first) = token(&mut line) else {
                continue;
            };
            self.address = core::str::from_utf8(first)
                .ok()
                .and_then(|s| s.parse().ok());
            self.aliases = line;
        }
    }
}
