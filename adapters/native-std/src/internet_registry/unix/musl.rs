use std::ffi::CStr;

// musl's getprotobyname scans its fixed, case-sensitive table and mutates
// process-global cursor and record state. Match the immutable data directly.
// https://git.musl-libc.org/cgit/musl/tree/src/network/proto.c?h=v1.2.5
// https://github.com/openharmony/third_party_musl/blob/master/src/network/proto.c
// Upstream copyright: ../../../licenses/musl-COPYRIGHT.
pub(super) fn protocol(name: &CStr) -> Option<u16> {
    let number = match name.to_bytes() {
        b"ip" => 0,
        b"icmp" => 1,
        b"igmp" => 2,
        b"ggp" => 3,
        b"ipencap" => 4,
        b"st" => 5,
        b"tcp" => 6,
        b"egp" => 8,
        b"pup" => 12,
        b"udp" => 17,
        b"hmp" => 20,
        b"xns-idp" => 22,
        b"rdp" => 27,
        b"iso-tp4" => 29,
        b"xtp" => 36,
        b"ddp" => 37,
        b"idpr-cmtp" => 38,
        b"ipv6" => 41,
        b"ipv6-route" => 43,
        b"ipv6-frag" => 44,
        b"idrp" => 45,
        b"rsvp" => 46,
        b"gre" => 47,
        b"esp" => 50,
        b"ah" => 51,
        b"skip" => 57,
        b"ipv6-icmp" => 58,
        b"ipv6-nonxt" => 59,
        b"ipv6-opts" => 60,
        b"rspf" => 73,
        b"vmtp" => 81,
        b"ospf" => 89,
        b"ipip" => 94,
        b"encap" => 98,
        b"pim" => 103,
        b"raw" => 255,
        _ => return None,
    };
    Some(number)
}

#[cfg(test)]
mod tests {
    use super::protocol;

    #[test]
    fn protocol_matches_musl_names_exactly() {
        assert_eq!(protocol(c"ip"), Some(0));
        assert_eq!(protocol(c"tcp"), Some(6));
        assert_eq!(protocol(c"TCP"), None);
        assert_eq!(protocol(c"ipv6-icmp"), Some(58));
        assert_eq!(protocol(c"icmpv6"), None);
        assert_eq!(protocol(c"raw"), Some(255));
    }
}
