//! Packed native ABI fixtures only. No PF device or control command is opened.
use super::*;
use std::{net::Ipv6Addr, time::Duration};

fn row(id: u8, direction: u8) -> [u8; STATE_BYTES] {
    let mut bytes = [0; STATE_BYTES];
    // Offsets are from the original Apple pfsync_state declaration/C layout,
    // independently of the byte decoder. NAT's gateway host is deliberately
    // different from the original stack-side LAN host.
    bytes[0] = id;
    bytes[8..12].copy_from_slice(b"en0\0");
    bytes[24..28].copy_from_slice(&[10, 0, 0, 1]);
    bytes[40..42].copy_from_slice(&53000_u16.to_be_bytes());
    bytes[48..52].copy_from_slice(&[198, 51, 100, 1]);
    bytes[64..66].copy_from_slice(&60000_u16.to_be_bytes());
    bytes[72..76].copy_from_slice(&[192, 0, 2, 53]);
    bytes[88..90].copy_from_slice(&53_u16.to_be_bytes());
    bytes[276..280].copy_from_slice(&[1, 2, 3, 4]);
    bytes[282] = 2;
    bytes[283] = 2;
    bytes[284] = 17;
    bytes[285] = direction;
    bytes
}
fn local() -> [IpAddr; 1] {
    [IpAddr::from([10, 0, 0, 1])]
}
fn ipv6_row(id: u8, source: Ipv6Addr, destination: Ipv6Addr) -> [u8; STATE_BYTES] {
    let mut bytes = row(id, 2);
    bytes[282] = 30;
    bytes[283] = 30;
    bytes[24..40].copy_from_slice(&source.octets());
    bytes[72..88].copy_from_slice(&destination.octets());
    bytes
}

#[test]
fn exact_stack_side_dns_selector_keeps_nat_addresses_and_other_flows_out() -> io::Result<()> {
    let good = row(1, 2);
    let mut tcp = row(2, 2);
    tcp[284] = 6;
    let incoming = row(3, 1);
    let mut forwarded = row(4, 2);
    forwarded[24..28].copy_from_slice(&[10, 0, 0, 2]);
    let targets = select(
        &[good, tcp, incoming, forwarded].concat(),
        &local(),
        Limits::default(),
    )?;
    if targets.ids.len() != 1 || targets.keys.len() != 1 {
        return Err(io::Error::other("native PF selector widened its DNS scope"));
    }
    let command = targets.keys[0].command();
    let bytes = abi::command_bytes(&command);
    if bytes[0..2] != [2, 17]
        || bytes[8..12] != [10, 0, 0, 1]
        || bytes[24..28] != [255; 4]
        || bytes[60..62] != 53000_u16.to_be_bytes()
        || bytes[64] != 2
        || bytes[72..76] != [192, 0, 2, 53]
        || bytes[88..92] != [255; 4]
        || bytes[124..126] != 53_u16.to_be_bytes()
        || bytes[128] != 2
        || bytes[136..140] != *b"en0\0"
    {
        return Err(io::Error::other(
            "native PF kill lost an exact selector field",
        ));
    }
    Ok(())
}

#[test]
fn all_native_states_for_the_same_local_dns_flow_share_the_exact_selector() -> io::Result<()> {
    let good = row(1, 2);
    let mut collision = row(2, 1);
    collision[24..48].copy_from_slice(&good[72..96]);
    collision[72..96].copy_from_slice(&good[24..48]);
    let targets = select(&[good, collision].concat(), &local(), Limits::default())?;
    if targets.ids.len() != 2 || targets.keys.len() != 1 {
        return Err(io::Error::other(
            "local DNS flow split across PF directions",
        ));
    }
    Ok(())
}

#[test]
fn a_later_malformed_row_or_duplicate_identity_refuses_the_whole_snapshot() -> io::Result<()> {
    let good = row(1, 2);
    let mut malformed = row(3, 2);
    malformed[282] = 0;
    for later in [malformed, good] {
        if select(&[good, later].concat(), &local(), Limits::default()).is_ok() {
            return Err(io::Error::other(
                "native PF admitted an ambiguous snapshot prefix",
            ));
        }
    }
    Ok(())
}

#[test]
fn original_identity_readback_ignores_a_changed_flow_predicate() -> io::Result<()> {
    let mut original = row(1, 2);
    let targets = select(&original, &local(), Limits::default())?;
    original[284] = 6;
    original[24..28].copy_from_slice(&[198, 51, 100, 55]);
    if absence(&original, &targets.ids).is_ok() {
        return Err(io::Error::other(
            "changed DNS predicate hid an original PF state",
        ));
    }
    original[0] = 2;
    absence(&original, &targets.ids)
}

#[test]
fn ipv6_uses_full_endpoint_masks_and_excludes_both_native_scoped_ranges() -> io::Result<()> {
    let source = "2001:db8::1"
        .parse::<std::net::Ipv6Addr>()
        .map_err(io::Error::other)?;
    let destination = "2001:db8::53"
        .parse::<std::net::Ipv6Addr>()
        .map_err(io::Error::other)?;
    let mut rows = vec![ipv6_row(1, source, destination)];
    let mut local = vec![source.into()];
    for prefix in [0xfe80, 0xfebf, 0xfec0, 0xfeff] {
        let scoped = Ipv6Addr::new(prefix, 0, 0, 0, 0, 0, 0, 1);
        local.push(scoped.into());
        rows.push(ipv6_row(rows.len() as u8 + 1, scoped, destination));
        let scoped_destination = ipv6_row(rows.len() as u8 + 1, source, scoped);
        rows.push(scoped_destination);
        let mut inbound = scoped_destination;
        inbound[0] = rows.len() as u8 + 1;
        inbound[285] = 1;
        inbound[24..48].copy_from_slice(&scoped_destination[72..96]);
        inbound[72..96].copy_from_slice(&scoped_destination[24..48]);
        rows.push(inbound);
    }
    let selected = select(&rows.concat(), &local, Limits::default())?;
    if selected.ids.len() != 1 || selected.keys.len() != 1 {
        return Err(io::Error::other("IPv6 PF DNS endpoint scope changed"));
    }
    let command = selected.keys[0].command();
    let bytes = abi::command_bytes(&command);
    if bytes[0] != 30
        || bytes[8..24] != source.octets()
        || bytes[24..40] != [255; 16]
        || bytes[72..88] != destination.octets()
        || bytes[88..104] != [255; 16]
    {
        return Err(io::Error::other(
            "IPv6 PF DNS selector lost its full address masks",
        ));
    }
    Ok(())
}

#[test]
fn invalid_raw_endpoints_leave_unrelated_pf_states_outside_retirement() -> io::Result<()> {
    for invalid in [[0, 0, 0, 0], [224, 0, 0, 53], [255, 255, 255, 255]] {
        for offset in [24, 72] {
            let mut excluded = row(2, 2);
            excluded[offset..offset + 4].copy_from_slice(&invalid);
            let selected = select(
                &[row(1, 2), excluded].concat(),
                &[local()[0], invalid.into()],
                Limits::default(),
            )?;
            if selected.ids.len() != 1 || selected.keys.len() != 1 {
                return Err(io::Error::other(format!(
                    "invalid raw IPv4 endpoint widened PF retirement: {invalid:?} at {offset}",
                )));
            }
        }
    }
    let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 53);
    for invalid in [
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x53),
        std::net::Ipv4Addr::new(192, 0, 2, 53).to_ipv6_mapped(),
        std::net::Ipv4Addr::new(224, 0, 0, 53).to_ipv6_mapped(),
        std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
        std::net::Ipv4Addr::BROADCAST.to_ipv6_mapped(),
    ] {
        for offset in [24, 72] {
            let mut excluded = ipv6_row(2, source, destination);
            excluded[offset..offset + 16].copy_from_slice(&invalid.octets());
            let selected = select(
                &[ipv6_row(1, source, destination), excluded].concat(),
                &[source.into(), invalid.into()],
                Limits::default(),
            )?;
            if selected.ids.len() != 1 || selected.keys.len() != 1 {
                return Err(io::Error::other(format!(
                    "invalid raw IPv6 endpoint widened PF retirement: {invalid} at {offset}",
                )));
            }
        }
    }
    Ok(())
}

#[test]
fn a_full_native_buffer_is_not_a_complete_snapshot_or_an_absence_receipt() -> io::Result<()> {
    let until = Instant::now() + Duration::from_secs(1);
    let mut bytes = Vec::new();
    let mut calls = 0;
    let limits = Limits {
        states: 2,
        targets: 2,
    };
    let result = capture(&mut bytes, limits, until, |request| {
        calls += 1;
        if calls == 1 {
            request.bytes = STATE_BYTES as i32;
        }
        // On the next calls, reporting exactly the supplied capacity models
        // the native API truncating at that row boundary without an error.
        Ok(())
    });
    if result.is_ok() || calls != 3 {
        return Err(io::Error::other("native PF accepted a full-buffer prefix"));
    }
    Ok(())
}

#[test]
fn an_overestimated_native_size_probe_can_still_return_a_complete_bounded_table() -> io::Result<()>
{
    let until = Instant::now() + Duration::from_secs(1);
    let mut bytes = Vec::new();
    let mut calls = 0;
    let limits = Limits {
        states: 2,
        targets: 2,
    };
    capture(&mut bytes, limits, until, |request| {
        calls += 1;
        match calls {
            1 => request.bytes = (STATE_BYTES * 1000) as i32,
            2 if request.bytes == (STATE_BYTES * 3) as i32 => request.bytes = 0,
            _ => {
                return Err(io::Error::other(
                    "native PF exceeded its table buffer bound",
                ));
            }
        }
        Ok(())
    })?;
    if calls != 2 || !bytes.is_empty() {
        return Err(io::Error::other(
            "native PF lost the complete empty table observation",
        ));
    }
    Ok(())
}
