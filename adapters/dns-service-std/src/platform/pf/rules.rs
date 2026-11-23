//! Fixed delegated-anchor grammar and exact owner-label checks.
use std::io;
pub(super) const ANCHOR: &str = "gnunet-rs/dns";
pub(super) fn root_delegates(bytes: &[u8]) -> bool {
    let mut lines = bytes.split(|byte| *byte == b'\n').map(trim).filter(|line| {
        !line.is_empty() && !line.starts_with(b"scrub ") && !line.starts_with(b"scrub-anchor ")
    });
    // Delegation precedes other filter rules. The root policy remains owned by
    // the administrator; this helper never inserts or replaces a root rule.
    matches!(lines.next(), Some(line) if line == b"anchor \"gnunet-rs/dns\" all" || line == b"anchor \"gnunet-rs/dns\" quick all")
}
pub(super) fn trim(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let last = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(first, |at| at + 1);
    &bytes[first..last]
}
pub(super) fn owned(bytes: &[u8], label: &str) -> bool {
    let marker = format!("label \"{label}\"");
    let mut lines = bytes
        .split(|byte| *byte == b'\n')
        .map(trim)
        .filter(|line| !line.is_empty());
    for _ in 0..4 {
        if !lines.next().is_some_and(|line| {
            line.windows(marker.len())
                .any(|part| part == marker.as_bytes())
        }) {
            return false;
        }
    }
    lines.next().is_none()
}
pub(super) fn render(
    interface: &str,
    ipv4: std::net::Ipv4Addr,
    ipv6: std::net::Ipv6Addr,
    gid: u32,
    label: &str,
) -> io::Result<String> {
    if interface.is_empty()
        || interface.len() >= 16
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        || label.is_empty()
        || label.len() > 63
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(format!(
        "pass out quick route-to ({interface} {ipv4}) inet proto udp from any to any port 53 group != {gid} no state label \"{label}\"\npass out quick route-to ({interface} {ipv6}) inet6 proto udp from ! fe80::/9 to ! fe80::/9 port 53 group != {gid} no state label \"{label}\"\npass in quick on {interface} inet proto udp from any port 53 to any no state label \"{label}\"\npass in quick on {interface} inet6 proto udp from any port 53 to any no state label \"{label}\"\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delegation_cannot_follow_an_earlier_filter_decision() {
        assert!(root_delegates(b"scrub-anchor \"system\" all fragment reassemble\nanchor \"gnunet-rs/dns\" all\nblock drop all\n"));
        assert!(!root_delegates(
            b"pass out quick all\nanchor \"gnunet-rs/dns\" all\n"
        ));
        assert!(!root_delegates(b"anchor \"gnunet-rs/dns-other\" all\n"));
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure rule fixtures check ownership and injection boundaries without accessing PF"
    )]
    fn only_the_complete_original_rule_set_is_owned() -> io::Result<()> {
        let label = "gnunet-rs-dns-0123456789abcdef";
        let rules = render(
            "utun7",
            std::net::Ipv4Addr::LOCALHOST,
            std::net::Ipv6Addr::LOCALHOST,
            501,
            label,
        )?;
        assert!(owned(rules.as_bytes(), label));
        assert!(!owned(rules.as_bytes(), "gnunet-rs-dns-other"));
        assert!(!owned(format!("{rules}pass out all\n").as_bytes(), label));
        assert!(!owned(
            rules
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join("\n")
                .as_bytes(),
            label
        ));
        assert!(
            render(
                "utun0\npass all",
                std::net::Ipv4Addr::LOCALHOST,
                std::net::Ipv6Addr::LOCALHOST,
                501,
                label
            )
            .is_err()
        );
        Ok(())
    }
}
