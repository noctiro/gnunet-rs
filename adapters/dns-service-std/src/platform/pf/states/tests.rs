//! Numeric pfctl fixtures only. No PF utility, device or firewall is accessed.
use super::*;

#[test]
fn original_id_readback_cannot_hide_a_record_behind_a_changed_flow_predicate() -> io::Result<()> {
    let original = dns(b"all udp 10.0.0.1:53000 -> 192.0.2.53:53 SINGLE:SINGLE\n   id: 0000000000000001 creatorid: 12345678\n", &["10.0.0.1".parse().map_err(io::Error::other)?])?;
    let mut parser = Parser::new(Selection::Original(original))?;
    let after = b"all tcp 198.51.100.1:80 -> 198.51.100.2:8000 ESTABLISHED:ESTABLISHED\n   [1 + 2] [3 + 4]\n   id: 0000000000000001 creatorid: 12345678\nall udp 192.0.2.1:999 -> 192.0.2.2:80 SINGLE:SINGLE\n   id: 0000000000000002 creatorid: 00000000\n";
    for part in after.chunks(7) {
        parser.feed(part)?;
    }
    parser.close()?;
    let remaining = parser.into_targets()?;
    if remaining.len() != 1 || remaining[0].to_string() != "0000000000000001/12345678" {
        return Err(io::Error::other(
            "original PF state disappeared only from the selection predicate",
        ));
    }
    Ok(())
}

#[test]
fn only_local_outbound_dns_original_keys_are_selected() -> io::Result<()> {
    let local = [
        "10.0.0.1".parse().map_err(io::Error::other)?,
        "2001:db8::1".parse().map_err(io::Error::other)?,
        "fe80::1".parse().map_err(io::Error::other)?,
    ];
    let snapshot = b"all udp 10.0.0.1:53000 -> 192.0.2.53:53 MULTIPLE:SINGLE\n   age 00:00:01, expires in 00:01:00\n   id: 0000000000000001 creatorid: 12345678\nall tcp 10.0.0.1:53001 -> 192.0.2.53:53 ESTABLISHED:ESTABLISHED\n   id: 0000000000000002 creatorid: 12345678\nall udp 2001:db8::1[53000] -> 2001:db8::53[53] SINGLE:SINGLE\n   id: 0000000000000003 creatorid: 12345678\nall udp 10.0.0.1:53000 (10.2.0.1:53000) -> 192.0.2.53:53 SINGLE:SINGLE\n   id: 0000000000000004 creatorid: 12345678\nall udp 10.0.0.1:53000 -> 192.0.2.53:5353 SINGLE:SINGLE\n   id: 0000000000000005 creatorid: 12345678\nall udp 192.0.2.8:53000 <- 10.0.0.1:53 SINGLE:SINGLE\n   id: 0000000000000006 creatorid: 12345678\nall udp fe80::1[53000] -> 2001:db8::53[53] SINGLE:SINGLE\n   id: 0000000000000007 creatorid: 12345678\nall udp 192.0.2.1:53000 (10.0.0.1:53000) -> 192.0.2.53:5353 (192.0.2.53:53) SINGLE:SINGLE\n   id: 0000000000000008 creatorid: 87654321\n";
    let selected = dns(snapshot, &local)?;
    if selected.iter().map(ToString::to_string).collect::<Vec<_>>()
        != [
            "0000000000000001/12345678",
            "0000000000000003/12345678",
            "0000000000000008/87654321",
        ]
    {
        return Err(io::Error::other("PF DNS flow scope widened"));
    }
    Ok(())
}
#[test]
fn incomplete_or_unqualified_later_target_refuses_the_entire_snapshot() -> io::Result<()> {
    let local = ["10.0.0.1".parse().map_err(io::Error::other)?];
    let good = "all udp 10.0.0.1:53000 -> 192.0.2.53:53 SINGLE:SINGLE\n   id: 0000000000000001 creatorid: 12345678\n";
    for bad in [
        "all udp 10.0.0.1:53001 -> 192.0.2.53:53 SINGLE:SINGLE\n",
        "all udp 10.0.0.1:53001 ??? 192.0.2.53:53 SINGLE:SINGLE\n   id: 0000000000000002 creatorid: 12345678\n",
        "all udp 10.0.0.1:53001 -> 192.0.2.53:53 SINGLE:SINGLE\n   id: 0000000000000002 creatorid: 00000000\n",
        "all udp 10.0.0.1:53001 -> resolver.example:53 SINGLE:SINGLE\n   id: 0000000000000002 creatorid: 12345678\n",
        "all udp 10.0.0.1:53001 -> 192.0.2.53:53 SINGLE:SINGLE\n   id: 0000000000000001 creatorid: 12345678\n",
    ] {
        if dns(format!("{good}{bad}").as_bytes(), &local).is_ok() {
            return Err(io::Error::other(
                "PF accepted a prefix of an invalid snapshot",
            ));
        }
    }
    Ok(())
}
