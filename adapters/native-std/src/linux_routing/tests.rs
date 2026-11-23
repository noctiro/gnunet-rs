use super::*;

const PORT: u32 = 41;

fn target(family: Family) -> DirectDefault {
    DirectDefault {
        family,
        table: NonZeroU32::MIN.saturating_add(52),
        interface: NonZeroU32::MIN.saturating_add(6),
        metric: NonZeroU32::MIN.saturating_add(123),
    }
}

fn record(kind: u16, flags: u16, body: &[u8]) -> io::Result<Vec<u8>> {
    let size = Header::SIZE + body.len();
    let mut bytes = vec![0; size];
    Header {
        length: size as u32,
        kind,
        flags,
        sequence: REQUEST_SEQUENCE,
        port: PORT,
    }
    .write(&mut bytes)?;
    bytes[Header::SIZE..].copy_from_slice(body);
    Ok(bytes)
}

fn complete(status: i32, flags: u16) -> io::Result<Vec<u8>> {
    record(libc::NLMSG_DONE as u16, flags, &status.to_ne_bytes())
}

fn route(target: DirectDefault) -> io::Result<Vec<u8>> {
    let (_, request) = change_request(target, RouteChange::Install, PORT)?;
    record(
        libc::RTM_NEWROUTE,
        libc::NLM_F_MULTI as u16,
        &request[Header::SIZE..],
    )
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert the exact kernel dump completion contract"
)]
fn only_correlated_missing_table_is_a_vacancy() -> io::Result<()> {
    for family in [Family::Ipv4, Family::Ipv6] {
        let target = target(family);
        let done = complete(-libc::ENOENT, 0)?;
        let mut scan = Scan::default();
        assert!(scan.receive(&done, target, PORT, true)?);
        assert!(scan.inventory.is_empty());
        assert!(scan.receive(&done, target, PORT, false).is_err());
        assert!(scan.receive(&done, target, PORT + 1, true).is_err());
        let interrupted = complete(0, libc::NLM_F_DUMP_INTR as u16)?;
        assert!(scan.receive(&interrupted, target, PORT, true).is_err());
        let denied = complete(-libc::EPERM, 0)?;
        assert!(scan.receive(&denied, target, PORT, true).is_err());
        assert!(scan.receive(&complete(0, 0)?, target, PORT, true)?);

        assert!(!scan.receive(&route(target)?, target, PORT, true)?);
        assert!(scan.receive(&done, target, PORT, true).is_err());
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact native route and conflict classification"
)]
fn exact_default_is_distinguished_from_unrelated_and_conflicting_routes() -> io::Result<()> {
    for family in [Family::Ipv4, Family::Ipv6] {
        let target = target(family);
        let mut scan = Scan::default();
        let other_table = DirectDefault {
            table: target.table.saturating_add(1),
            ..target
        };
        assert!(!scan.receive(&route(other_table)?, target, PORT, false)?);
        assert!(scan.inventory.is_empty());

        let unrelated = DirectDefault {
            interface: target.interface.saturating_add(1),
            ..target
        };
        assert!(!scan.receive(&route(unrelated)?, target, PORT, false)?);
        assert!(!scan.inventory.is_empty());
        assert_eq!(scan.inventory.default_route(), DefaultPresence::Absent);

        let exact = route(target)?;
        assert!(!scan.receive(&exact, target, PORT, false)?);
        assert_eq!(scan.inventory.default_route(), DefaultPresence::Exact);
        assert!(!scan.inventory.is_exclusive_default());

        let mut scan = Scan::default();
        assert!(!scan.receive(&exact, target, PORT, true)?);
        assert!(scan.inventory.is_exclusive_default());
        assert!(!scan.receive(&exact, target, PORT, true)?);
        assert_eq!(scan.inventory.default_route(), DefaultPresence::Conflicting);

        let mut changed = exact;
        changed[Header::SIZE + 7] = libc::RTN_BLACKHOLE;
        let mut scan = Scan::default();
        assert!(!scan.receive(&changed, target, PORT, true)?);
        assert_eq!(scan.inventory.default_route(), DefaultPresence::Conflicting);
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert one mutation's exact echoed ACK contract"
)]
fn native_rejection_is_distinct_from_lost_mutation_acknowledgment() -> io::Result<()> {
    let target = target(Family::Ipv6);
    let (request, wire) = change_request(target, RouteChange::Install, PORT)?;
    assert_ne!(request.flags & libc::NLM_F_EXCL as u16, 0);
    let mut body = Vec::from(0_i32.to_ne_bytes());
    body.extend_from_slice(&wire[..Header::SIZE]);
    let reply = record(libc::NLMSG_ERROR as u16, 0, &body)?;
    assert!(matches!(
        acknowledgment(request, &reply)?,
        Acknowledgment::Applied
    ));
    body[..4].copy_from_slice(&(-libc::EEXIST).to_ne_bytes());
    let reply = record(libc::NLMSG_ERROR as u16, 0, &body)?;
    assert!(
        matches!(acknowledgment(request, &reply)?, Acknowledgment::Rejected(e) if e.kind() == io::ErrorKind::AlreadyExists)
    );
    let (different, _) = change_request(target, RouteChange::Remove, PORT)?;
    assert!(acknowledgment(different, &reply).is_err());
    Ok(())
}
