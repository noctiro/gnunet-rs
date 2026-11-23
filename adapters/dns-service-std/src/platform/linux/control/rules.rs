//! Linux DNS marking arguments; no command, firewall or device access.

#[derive(Clone, Copy)]
pub(super) enum Family {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy)]
pub(super) enum Action {
    OwnerExemption,
    Intercept,
}

pub(super) struct Commands {
    pub add: Vec<String>,
    pub check: Vec<String>,
    pub remove: Vec<String>,
}

pub(super) fn commands(
    family: Family,
    action: Action,
    gid: &str,
    label: &str,
    mark: &str,
) -> Commands {
    let position = match action {
        Action::OwnerExemption => "1",
        Action::Intercept => "2",
    };
    let mut rule = vec!["-p", "udp", "--dport", "53"];
    match action {
        Action::OwnerExemption => {
            rule.extend(["-m", "owner", "--gid-owner", gid]);
        }
        Action::Intercept if matches!(family, Family::Ipv6) => {
            // The helper/TUN envelope cannot retain link-local or site-local
            // zones. Linux's IPv6 UNICAST type excludes unspecified, multicast
            // and IPv4-mapped addresses while retaining ordinary local unicast.
            rule.extend([
                "!",
                "-s",
                "fe80::/9",
                "!",
                "-d",
                "fe80::/9",
                "-m",
                "addrtype",
                "--src-type",
                "UNICAST",
                "--dst-type",
                "UNICAST",
            ]);
        }
        Action::Intercept => {
            // Linux classifies 0/8 and limited broadcasts as BROADCAST. Limit
            // directed broadcast classification to the original output device.
            let unsupported = "UNSPEC,BROADCAST,MULTICAST";
            rule.extend([
                "-m",
                "addrtype",
                "!",
                "--src-type",
                unsupported,
                "!",
                "--dst-type",
                unsupported,
                "--limit-iface-out",
            ]);
        }
    }
    let target = match action {
        Action::OwnerExemption => "ACCEPT",
        Action::Intercept => "MARK",
    };
    rule.extend(["-m", "comment", "--comment", label, "-j", target]);
    if matches!(action, Action::Intercept) {
        rule.extend(["--set-mark", mark]);
    }
    let command = |verb, position: Option<&str>| {
        ["-t", "mangle", verb, "OUTPUT"]
            .into_iter()
            .chain(position)
            .chain(rule.iter().copied())
            .map(str::to_owned)
            .collect()
    };
    Commands {
        add: command("-I", Some(position)),
        check: command("-C", None),
        remove: command("-D", None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet;
    use gnunet_types::Error;
    use std::net::Ipv6Addr;

    const MARK: &str = "257";

    fn selects(rule: &[String], selector: &str, address: Ipv6Addr) -> Result<bool, Error> {
        let index = rule
            .iter()
            .position(|argument| argument == selector)
            .ok_or(Error::NotFound)?;
        if index == 0 || rule[index - 1] != "!" {
            return Err(Error::Malformed);
        }
        let (network, bits) = rule
            .get(index + 1)
            .and_then(|prefix| prefix.split_once('/'))
            .ok_or(Error::Malformed)?;
        let network = network.parse::<Ipv6Addr>().map_err(|_| Error::Malformed)?;
        let bits = bits.parse::<u32>().map_err(|_| Error::Malformed)?;
        if !(1..=128).contains(&bits) {
            return Err(Error::Malformed);
        }
        let mask = u128::MAX << (128 - bits);
        Ok(u128::from(address) & mask != u128::from(network) & mask)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure generated-rule coverage must agree with the actual raw decoder's scope capability before any packet diversion"
    )]
    fn ipv6_capture_scope_matches_the_raw_helper_reply_capability() -> Result<(), Error> {
        let rule = commands(Family::Ipv6, Action::Intercept, "42", "original", MARK).add;
        let addresses = [
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfe7f, 0xffff, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfeff, 0xffff, 0, 0, 0, 0, 0, 1),
        ];
        for source in addresses {
            for destination in addresses {
                let mut segment = [0; 20];
                segment[..2].copy_from_slice(&53000_u16.to_be_bytes());
                segment[2..4].copy_from_slice(&53_u16.to_be_bytes());
                let mut raw = [0; 60];
                gnunet_vpn::packet::build(
                    packet::Address::V6(source.octets()),
                    packet::Address::V6(destination.octets()),
                    gnunet_vpn::packet::UDP,
                    &segment,
                    &mut raw,
                )?;
                let (_, tuple) = packet::decode_query(&raw)?;
                assert_eq!(
                    selects(&rule, "-s", source)? && selects(&rule, "-d", destination)?,
                    tuple.raw_scope_supported(false),
                    "helper capture and reply scope differ for {source} -> {destination}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn ipv6_marking_keeps_both_endpoint_zones_out_of_unscoped_capture() {
        let mark = commands(Family::Ipv6, Action::Intercept, "42", "original", MARK).add;
        for selector in ["-s", "-d"] {
            assert!(
                mark.windows(3)
                    .any(|row| row == ["!", selector, "fe80::/9"]),
                "missing scoped endpoint exclusion: {selector}"
            );
        }
        assert!(mark.ends_with(&["--set-mark".into(), MARK.into()]));
        let v4 = commands(Family::Ipv4, Action::Intercept, "42", "original", MARK).add;
        assert!(!v4.iter().any(|value| value == "fe80::/9"));
    }

    #[test]
    fn raw_capture_classifies_both_endpoints_before_marking() {
        let v4 = commands(Family::Ipv4, Action::Intercept, "42", "original", MARK);
        assert!(v4.add.windows(9).any(|row| row
            == [
                "-m",
                "addrtype",
                "!",
                "--src-type",
                "UNSPEC,BROADCAST,MULTICAST",
                "!",
                "--dst-type",
                "UNSPEC,BROADCAST,MULTICAST",
                "--limit-iface-out",
            ]));
        let v6 = commands(Family::Ipv6, Action::Intercept, "42", "original", MARK);
        assert!(v6.add.windows(6).any(|row| row
            == [
                "-m",
                "addrtype",
                "--src-type",
                "UNICAST",
                "--dst-type",
                "UNICAST",
            ]));
        for rule in [v4, v6] {
            assert_eq!(&rule.add[..5], ["-t", "mangle", "-I", "OUTPUT", "2"]);
            assert_eq!(&rule.check[..4], ["-t", "mangle", "-C", "OUTPUT"]);
            assert_eq!(&rule.remove[..4], ["-t", "mangle", "-D", "OUTPUT"]);
            assert_eq!(rule.add[5..], rule.check[4..]);
            assert_eq!(rule.check[4..], rule.remove[4..]);
        }
    }

    #[test]
    fn the_original_daemon_group_bypasses_marking_for_both_families() {
        for family in [Family::Ipv4, Family::Ipv6] {
            let exempt = commands(family, Action::OwnerExemption, "42", "original", MARK).add;
            assert_eq!(&exempt[..5], ["-t", "mangle", "-I", "OUTPUT", "1"]);
            assert!(
                exempt
                    .windows(4)
                    .any(|row| row == ["-m", "owner", "--gid-owner", "42"])
            );
            assert!(exempt.ends_with(&["-j".into(), "ACCEPT".into()]));
            assert!(!exempt.iter().any(|value| value == "fe80::/9"));
        }
    }
}
